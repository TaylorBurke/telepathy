import io
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from telepathy import client
from telepathy.audit import AuditLog
from telepathy.broker import Broker, Limits
from telepathy.config import Config
from telepathy.daemon import Daemon
from telepathy.executor import ExecResult
from telepathy.policy import Policy

POLICY = """
[patterns]
word = '[a-z0-9]+'
[[auto]]
name = "echo"
argv = ["/usr/bin/echo", "@word..."]
"""
ASK = ["/usr/bin/pacman", "-Syu"]
ME = os.getuid()


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


class Env:
    def __init__(self, uids=None, executor=None, clock=None, **daemon_kw):
        self.dir = tempfile.mkdtemp(prefix="tp", dir="/tmp")
        self.cfg = Config(socket_path=f"{self.dir}/a.sock", admin_socket_path=f"{self.dir}/b.sock",
                          allowed_uids=tuple(uids) if uids is not None else (ME,))
        self.log = []
        self.calls = []

        def stub(argv, cwd, env, timeout, max_output):
            self.calls.append((tuple(argv), cwd, dict(env)))
            return ExecResult(0, b"out:" + " ".join(argv).encode())

        # clock=None: the daemon suite runs on Broker's real default (boottime).
        kw = {} if clock is None else {"clock": clock}
        self.broker = Broker(Policy.from_toml(POLICY), Limits(ttl=600), AuditLog(self.log.append),
                             **kw)
        self.daemon = Daemon(self.cfg, self.broker, executor or stub, admin_uids=(ME,),
                             **{"poll_interval": 0.005, **daemon_kw})
        self.daemon.start()

    def close(self):
        self.daemon.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    def agent(self, msg):
        return client.call(self.cfg.socket_path, msg)

    def admin(self, msg):
        return client.call(self.cfg.admin_socket_path, msg)

    def run(self, argv, **kw):
        out, err = io.BytesIO(), io.StringIO()
        code = client.run(argv, sock=self.cfg.socket_path, poll=0.02, out=out, err=err, **kw)
        return code, out.getvalue(), err.getvalue()

    def submit_ask(self):
        r = self.agent({"op": "submit", "argv": ASK, "cwd": "/tmp", "reason": "update"})
        self.assertion.assertTrue(r["ok"], r)
        return r["request"]["id"]

    def wait_pending(self, timeout=3.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            reqs = self.admin({"op": "list"})["requests"]
            if reqs:
                return reqs[0]["id"]
            time.sleep(0.02)
        raise AssertionError("no pending request appeared")

    def wait_state(self, rid, state, timeout=3.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.agent({"op": "status", "id": rid})["request"]["state"] == state:
                return
            time.sleep(0.02)
        raise AssertionError(f"request never reached {state}")

    def events(self):
        return [json.loads(x)["event"] for x in self.log]


class Base(unittest.TestCase):
    def make(self, **kw):
        env = Env(**kw)
        env.assertion = self
        self.addCleanup(env.close)
        return env


class EndToEnd(Base):
    def test_auto_rule_runs_without_a_human(self):
        env = self.make()
        code, out, err = env.run(["/usr/bin/echo", "hi"])
        self.assertEqual((code, out), (0, b"out:/usr/bin/echo hi"))
        self.assertEqual(len(env.calls), 1)
        self.assertEqual(env.calls[0][2]["HOME"], "/root")  # fixed env, not the agent's

    def test_ask_flow_approved_locally(self):
        env = self.make()
        result = []
        t = threading.Thread(target=lambda: result.append(env.run(ASK)))
        t.start()
        rid = env.wait_pending()
        self.assertEqual(env.calls, [])  # nothing runs before approval
        self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
        t.join(5)
        code, out, err = result[0]
        self.assertEqual((code, out), (0, b"out:/usr/bin/pacman -Syu"))
        self.assertIn("waiting for approval", err)
        self.assertEqual(env.events(), ["submitted", "approved", "run_start", "run_finish"])

    def test_denied_locally(self):
        env = self.make()
        result = []
        t = threading.Thread(target=lambda: result.append(env.run(ASK)))
        t.start()
        env.admin({"op": "deny", "id": env.wait_pending()})
        t.join(5)
        code, out, err = result[0]
        self.assertEqual(code, client.EXIT_REFUSED)
        self.assertIn("denied", err)
        self.assertEqual(env.calls, [])

    def test_policy_denied_never_queues(self):
        env = self.make()
        code, out, err = env.run(["/bin/sh", "-c", "id"])
        self.assertEqual(code, client.EXIT_REFUSED)
        self.assertIn("policy", err)
        self.assertEqual((env.calls, env.admin({"op": "list"})["requests"]), ([], []))

    def test_command_not_found_is_caught_client_side(self):
        env = self.make()
        code, _, err = env.run(["definitely-not-a-command-xyz"])
        self.assertEqual(code, client.EXIT_REFUSED)
        self.assertIn("command not found", err)
        self.assertEqual(env.events(), [])

    def test_exit_code_output_and_error_pass_through(self):
        env = self.make(executor=lambda *a: ExecResult(7, b"partial", True, "boom"))
        code, out, err = env.run(["/usr/bin/echo", "x"])
        self.assertEqual((code, out), (7, b"partial"))
        self.assertIn("boom", err)
        self.assertIn("truncated", err)

    def test_executor_crash_does_not_hang_the_request(self):
        def boom(*a):
            raise RuntimeError("kaput")

        env = self.make(executor=boom)
        code, out, err = env.run(["/usr/bin/echo", "x"])
        self.assertEqual(code, 1)
        self.assertIn("internal error", err)

    def test_audit_has_output_hash_not_content(self):
        env = self.make()
        env.run(["/usr/bin/echo", "hi"])
        fin = [json.loads(x) for x in env.log if '"run_finish"' in x][0]
        self.assertEqual(fin["output_bytes"], len(b"out:/usr/bin/echo hi"))
        self.assertEqual(len(fin["output_sha256"]), 64)
        self.assertNotIn("out:/usr/bin/echo", "".join(env.log))


class Authorization(Base):
    def test_uid_not_allowed(self):
        env = self.make(uids=(ME + 1,))
        r = env.agent({"op": "submit", "argv": ASK, "cwd": "/tmp"})
        self.assertEqual((r["ok"], r["code"]), (False, "forbidden"))
        self.assertIn("unauthorized", env.events())

    def test_other_users_cannot_see_a_request(self):
        env = self.make(uids=(ME, 4242))
        rid = env.submit_ask()
        r = env.daemon.handle_agent({"op": "status", "id": rid}, 4242)
        self.assertEqual(r["code"], "not_found")
        r = env.daemon.handle_agent({"op": "result", "id": rid}, 4242)
        self.assertEqual(r["code"], "not_found")

    def test_admin_socket_is_admin_only(self):
        env = self.make()
        rid = env.submit_ask()
        for op in ("list", "show", "approve", "deny"):
            r = env.daemon.handle_admin({"op": op, "id": rid}, 4242)
            self.assertEqual(r["code"], "forbidden", op)
        self.assertEqual(env.calls, [])

    def test_agent_cannot_approve_through_the_agent_socket(self):
        env = self.make()
        rid = env.submit_ask()
        r = env.agent({"op": "approve", "id": rid})
        self.assertEqual(r["code"], "bad_op")

    def test_socket_modes(self):
        env = self.make()
        self.assertEqual(os.stat(env.cfg.socket_path).st_mode & 0o777, 0o666)
        self.assertEqual(os.stat(env.cfg.admin_socket_path).st_mode & 0o777, 0o600)


class SingleUseAndExpiry(Base):
    def test_double_approve_runs_once(self):
        env = self.make()
        rid = env.submit_ask()
        self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
        second = env.admin({"op": "approve", "id": rid})
        self.assertEqual(second["code"], "conflict")
        env.wait_state(rid, "done")
        self.assertEqual(len(env.calls), 1)

    def test_expired_request_cannot_be_approved_or_run(self):
        clock = Clock()
        env = self.make(clock=clock)
        rid = env.submit_ask()
        clock.t += 601
        r = env.admin({"op": "approve", "id": rid})
        self.assertEqual(r["code"], "expired")
        self.assertEqual(env.calls, [])

    def test_result_not_ready_until_done(self):
        env = self.make()
        rid = env.submit_ask()
        r = env.agent({"op": "result", "id": rid})
        self.assertEqual((r["ok"], r["code"]), (False, "not_ready"))


class Protocol(Base):
    def raw(self, env, payload: bytes) -> dict:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(3)
        s.connect(env.cfg.socket_path)
        s.sendall(payload)
        with s.makefile("rb") as f:
            line = f.readline()
        s.close()
        return json.loads(line)

    def test_malformed_input(self):
        env = self.make()
        self.assertEqual(self.raw(env, b"not json\n")["code"], "bad_json")
        self.assertEqual(self.raw(env, b"[1,2]\n")["code"], "bad_request")
        self.assertEqual(self.raw(env, b'{"op":"nope"}\n')["code"], "bad_op")
        self.assertEqual(self.raw(env, b'{"op":"submit","argv":"ls -l","cwd":"/tmp"}\n')["code"],
                         "invalid")

    def test_result_before_done_is_not_ready_and_has_no_absolute_times(self):
        env = self.make()
        rid = env.submit_ask()
        r = env.agent({"op": "result", "id": rid})
        self.assertEqual(r["code"], "not_ready")
        self.assertEqual(r["request"]["state"], "pending")
        self.assertGreater(r["request"]["expires_in"], 0)
        self.assertNotIn("expires_at", r["request"])

    def test_unknown_id(self):
        env = self.make()
        self.assertEqual(env.agent({"op": "status", "id": "nope"})["code"], "not_found")
        self.assertEqual(env.agent({"op": "status", "id": 5})["code"], "invalid")


class Ctl(Base):
    def test_list_show_approve_deny(self):
        env = self.make()
        rid = env.submit_ask()
        out = io.StringIO()
        s = ["--socket", env.cfg.admin_socket_path]
        self.assertEqual(client.ctl_main(s + ["list"], out=out), 0)
        self.assertIn(rid, out.getvalue())
        self.assertIn("/usr/bin/pacman -Syu", out.getvalue())

        out = io.StringIO()
        self.assertEqual(client.ctl_main(s + ["approve", rid], out=out, confirm=lambda _: "n"), 1)
        self.assertIn("not approved", out.getvalue())
        self.assertIn("command: /usr/bin/pacman -Syu", out.getvalue())
        self.assertEqual(env.calls, [])

        self.assertEqual(client.ctl_main(s + ["approve", rid], out=io.StringIO(),
                                         confirm=lambda _: "y"), 0)
        env.wait_state(rid, "done")
        self.assertEqual(len(env.calls), 1)

        rid2 = env.submit_ask()
        self.assertEqual(client.ctl_main(s + ["deny", rid2], out=io.StringIO()), 0)
        self.assertEqual(env.agent({"op": "status", "id": rid2})["request"]["state"], "denied")

    def test_responses_carry_expires_in_and_resolved_not_absolute_times(self):
        env = self.make()
        link = os.path.join(env.dir, "lnk")
        os.symlink("/usr/share/doc", link)
        r = env.agent({"op": "submit", "argv": ["/usr/bin/ls", link], "cwd": "/tmp",
                       "reason": ""})
        rid = r["request"]["id"]
        views = [r["request"],
                 env.agent({"op": "status", "id": rid})["request"],
                 env.admin({"op": "list"})["requests"][0],
                 env.admin({"op": "show", "id": rid})["request"]]
        for v in views:
            self.assertGreater(v["expires_in"], 0)
            self.assertLessEqual(v["expires_in"], 600)
            self.assertNotIn("expires_at", v)
            self.assertNotIn("created_at", v)
            self.assertEqual(v["resolved"], {link: os.path.realpath("/usr/share/doc")})
        self.assertIn("resolved", env.admin({"op": "deny", "id": rid})["request"])

    def test_ctl_show_prints_symlink_note_and_remaining_time(self):
        out = io.StringIO()
        client._show({"id": "i", "short_hash": "h", "state": "pending", "cwd": "/tmp",
                      "argv": ["/usr/bin/ls", "/tmp/x"], "reason": "", "expires_in": 125.9,
                      "resolved": {"/tmp/x": "/etc/shadow"}}, out)
        text = out.getvalue()
        self.assertIn("/tmp/x is really /etc/shadow", text)
        self.assertIn("expires: in 125s", text)

    def test_daemon_not_running(self):
        self.assertEqual(client.ctl_main(["--socket", "/tmp/definitely-no-such.sock", "list"],
                                         out=io.StringIO()), 1)


class Cancel(Base):
    def cancel(self, env, rid):
        return env.agent({"op": "cancel", "id": rid})

    def test_cancel_pending(self):
        env = self.make()
        rid = env.submit_ask()
        r = self.cancel(env, rid)
        self.assertEqual((r["ok"], r["cancelled"], r["changed"]), (True, True, True))
        self.assertEqual(r["request"]["state"], "cancelled")
        self.assertEqual(env.admin({"op": "list"})["requests"], [])
        self.assertIn("cancelled", env.events())
        self.assertEqual(env.admin({"op": "approve", "id": rid})["code"], "conflict")
        self.assertEqual(env.calls, [])

    def test_cancel_approved_not_run(self):
        gate = threading.Event()
        started = threading.Event()

        def blocker(argv, cwd, env, timeout, max_output):
            started.set()
            gate.wait(5)
            return ExecResult(0, b"")

        env = self.make(executor=blocker)
        # Occupy the single worker so the next approved request waits in the queue.
        first = env.agent({"op": "submit", "argv": ["/usr/bin/echo", "a"], "cwd": "/tmp"})["request"]["id"]
        self.assertTrue(started.wait(3))
        rid = env.submit_ask()
        env.admin({"op": "approve", "id": rid})
        self.assertEqual(env.agent({"op": "status", "id": rid})["request"]["state"], "approved")
        r = self.cancel(env, rid)
        self.assertEqual((r["cancelled"], r["changed"]), (True, True))
        gate.set()
        env.wait_state(first, "done")
        time.sleep(0.2)  # the worker has now dequeued the cancelled one
        self.assertEqual(env.agent({"op": "status", "id": rid})["request"]["state"], "cancelled")
        self.assertNotIn(tuple(ASK), [c[0] for c in env.calls])

    def test_cancel_running_is_a_noop(self):
        gate = threading.Event()
        started = threading.Event()

        def blocker(argv, cwd, env, timeout, max_output):
            started.set()
            gate.wait(5)
            return ExecResult(0, b"")

        env = self.make(executor=blocker)
        rid = env.agent({"op": "submit", "argv": ["/usr/bin/echo", "a"], "cwd": "/tmp"})["request"]["id"]
        self.assertTrue(started.wait(3))
        r = self.cancel(env, rid)
        self.assertEqual((r["ok"], r["cancelled"], r["changed"], r["request"]["state"]),
                         (True, False, False, "running"))
        gate.set()
        env.wait_state(rid, "done")
        r = self.cancel(env, rid)
        self.assertEqual((r["cancelled"], r["request"]["state"]), (False, "done"))
        self.assertNotIn("cancelled", env.events())

    def test_cancel_unknown_id_and_bad_id(self):
        env = self.make()
        self.assertEqual(self.cancel(env, "nope")["code"], "not_found")
        self.assertEqual(env.agent({"op": "cancel", "id": 5})["code"], "invalid")

    def test_other_user_cannot_cancel(self):
        env = self.make(uids=(ME, 4242))
        rid = env.submit_ask()
        r = env.daemon.handle_agent({"op": "cancel", "id": rid}, 4242)
        self.assertEqual(r["code"], "not_found")  # same answer as an unknown id
        self.assertEqual(r, env.daemon.handle_agent({"op": "cancel", "id": "nope"}, 4242))
        self.assertEqual(env.agent({"op": "status", "id": rid})["request"]["state"], "pending")
        self.assertNotIn("cancelled", env.events())

    def test_root_may_cancel_anyones(self):
        env = self.make(uids=(ME, 0))
        rid = env.submit_ask()
        r = env.daemon.handle_agent({"op": "cancel", "id": rid}, 0)
        self.assertEqual((r["ok"], r["cancelled"]), (True, True))

    def test_disallowed_uid_cannot_cancel(self):
        env = self.make(uids=(ME,))
        rid = env.submit_ask()
        r = env.daemon.handle_agent({"op": "cancel", "id": rid}, 4242)
        self.assertEqual(r["code"], "forbidden")

    def test_cli_cancel(self):
        env = self.make()
        rid = env.submit_ask()
        for expect_code, text in ((0, "cancelled; it will not run"), (0, "already cancelled")):
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                code = client.main(["--socket", env.cfg.socket_path, "cancel", rid])
            self.assertEqual(code, expect_code)
            self.assertIn(text, err.getvalue())
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            code = client.main(["--socket", env.cfg.socket_path, "cancel", "nope"])
        self.assertEqual(code, client.EXIT_REFUSED)
        self.assertIn("telepathyd restarted", err.getvalue())


class Interrupt(Base):
    def interrupt_run(self, env, sock=None):
        """Run the client; ^C arrives during its first wait."""
        calls = []

        def sleep(_):
            calls.append(1)
            raise KeyboardInterrupt

        out, err = io.BytesIO(), io.StringIO()
        code = client.run(ASK, sock=sock or env.cfg.socket_path, poll=0.02, out=out, err=err,
                          sleep=sleep)
        return code, err.getvalue()

    def test_ctrl_c_cancels_the_request(self):
        env = self.make()
        code, err = self.interrupt_run(env)
        self.assertEqual(code, 130)
        self.assertIn("cancelled; it will not run", err)
        self.assertEqual(env.admin({"op": "list"})["requests"], [])
        self.assertIn("cancelled", env.events())

    def test_ctrl_c_after_it_started_says_so(self):
        gate = threading.Event()
        started = threading.Event()

        def blocker(argv, cwd, env_, timeout, max_output):
            started.set()
            gate.wait(5)
            return ExecResult(0, b"")

        env = self.make(executor=blocker)
        self.addCleanup(gate.set)
        calls = []

        def sleep(_):
            calls.append(1)
            started.wait(3)
            raise KeyboardInterrupt

        out, err = io.BytesIO(), io.StringIO()
        code = client.run(["/usr/bin/echo", "a"], sock=env.cfg.socket_path, poll=0.02,
                          out=out, err=err, sleep=sleep)
        self.assertEqual(code, 130)
        self.assertIn("already running and cannot be cancelled", err.getvalue())

    def test_ctrl_c_with_daemon_gone_does_not_hang(self):
        env = self.make()
        sock = env.cfg.socket_path
        out, err = io.BytesIO(), io.StringIO()

        def sleep(_):
            env.daemon.stop()
            raise KeyboardInterrupt

        t0 = time.monotonic()
        code = client.run(ASK, sock=sock, poll=0.02, out=out, err=err, sleep=sleep)
        self.assertEqual(code, 130)
        self.assertLess(time.monotonic() - t0, client.CANCEL_TIMEOUT + 1)
        self.assertIn("could not reach telepathyd to cancel", err.getvalue())

    def test_second_ctrl_c_during_cancel_is_swallowed(self):
        env = self.make()
        out, err = io.BytesIO(), io.StringIO()

        def sleep(_):
            raise KeyboardInterrupt

        with mock.patch.object(client, "call", side_effect=[
                client.call(env.cfg.socket_path, {"op": "submit", "argv": ASK, "cwd": "/tmp"}),
                KeyboardInterrupt]):
            code = client.run(ASK, sock=env.cfg.socket_path, out=out, err=err, sleep=sleep)
        self.assertEqual(code, 130)
        # a second ^C ends the handler silently; the exit code is still 130

    def test_cancel_and_result_use_neutral_wording(self):
        env = self.make()
        for cmd in ("cancel", "result"):
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                client.main(["--socket", env.cfg.socket_path, cmd, "nope"])
            self.assertIn("wrong id, not yours", err.getvalue())
            self.assertNotIn("nothing ran, resubmit", err.getvalue())

    def test_interrupt_survives_closed_stderr_and_second_ctrl_c(self):
        class Bad:
            def write(self, _):
                raise KeyboardInterrupt

            def flush(self):
                pass

        with mock.patch.object(client, "call", side_effect=OSError("x")):
            client._interrupted("abc", "/nope", Bad())  # must not raise
        client._interrupted(None, "/nope", Bad())

    def test_ctrl_c_before_submit_reply_documents_the_window(self):
        out, err = io.BytesIO(), io.StringIO()
        with mock.patch.object(client, "call", side_effect=KeyboardInterrupt):
            code = client.run(ASK, sock="/nope", out=out, err=err)
        self.assertEqual(code, 130)
        self.assertIn("stays pending until it expires", err.getvalue())

    def test_daemon_restart_gives_a_clear_message(self):
        env = self.make()

        def sleep(_):  # simulate a restart: the queue is gone
            env.daemon.broker = Broker(Policy.from_toml(POLICY), Limits(ttl=600),
                                       AuditLog(env.log.append))

        o, e = io.BytesIO(), io.StringIO()
        code = client.run(ASK, sock=env.cfg.socket_path, poll=0.02, out=o, err=e, sleep=sleep)
        self.assertEqual(code, client.EXIT_REFUSED)
        self.assertIn("telepathyd restarted; nothing ran, resubmit", e.getvalue())


class TransientCheck(Base):
    @staticmethod
    def _timeout_result():
        from telepathy import policy as policy_mod
        return policy_mod.CheckResult(
            policy_mod.Decision("deny", "timed out"),
            {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT}, "timeout")

    def test_run_time_check_timeout_is_retried_not_denied(self):
        from unittest import mock
        from telepathy import policy as policy_mod
        real = policy_mod.check_guarded
        calls = []

        def flaky(*a, **k):
            calls.append(1)
            if len(calls) == 2:  # submit is call 1; the first run attempt is call 2
                return self._timeout_result()
            return real(*a, **k)
        with mock.patch("telepathy.broker.check_guarded", flaky):
            env = self.make(retry_delay=0.02)
            rid = env.submit_ask()
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            env.wait_state(rid, "done")
        self.assertEqual(len(env.calls), 1)
        self.assertIn("run_unverified", env.events())
        self.assertNotIn("policy_denied_at_run", env.events())

    def test_retries_are_capped_then_the_request_is_denied(self):
        from unittest import mock
        from telepathy import policy as policy_mod
        real = policy_mod.check_guarded
        n = []

        def stuck(*a, **k):
            n.append(1)
            return real(*a, **k) if len(n) == 1 else self._timeout_result()
        with mock.patch("telepathy.broker.check_guarded", stuck):
            env = self.make(retry_delay=0.001, max_run_attempts=3)
            rid = env.submit_ask()
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            env.wait_state(rid, "denied")
        self.assertEqual(len(n) - 1, 3)  # exactly 3 run attempts
        self.assertEqual(env.events().count("run_unverified"), 3)
        self.assertIn("run_unverified_gave_up", env.events())
        self.assertEqual(env.calls, [])

    def test_stop_cancels_pending_retry_timers(self):
        from unittest import mock
        from telepathy import policy as policy_mod
        real = policy_mod.check_guarded
        n = []

        def stuck(*a, **k):
            n.append(1)
            return real(*a, **k) if len(n) == 1 else self._timeout_result()
        with mock.patch("telepathy.broker.check_guarded", stuck):
            env = self.make(retry_delay=3600)
            rid = env.submit_ask()
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            end = time.monotonic() + 5
            while not env.daemon._timers and time.monotonic() < end:
                time.sleep(0.01)
            timers = list(env.daemon._timers)
            self.assertEqual(len(timers), 1)
            env.daemon.stop()
        self.assertEqual(env.daemon._timers, set())
        timers[0].join(2)
        self.assertFalse(timers[0].is_alive())


class PreCheck(Base):
    """A run-time path check stuck on a hung mount must not block the worker."""

    @staticmethod
    def _timeout():
        from telepathy import policy as policy_mod
        return policy_mod.CheckResult(
            policy_mod.Decision("deny", "timed out"),
            {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT}, "timeout")

    def _gated(self, entered, gate):
        """check_guarded stand-in: ASK's checks after its submit wait on `gate`, then time out."""
        from telepathy import policy as policy_mod
        real = policy_mod.check_guarded
        seen = []

        def check(policy, argv, cwd, *a, **k):
            if list(argv) == ASK:
                seen.append(1)
                if len(seen) > 1:  # the submit check (first) is real
                    entered.set()
                    gate.wait(5)
                    return self._timeout()
            return real(policy, argv, cwd, *a, **k)
        return check

    def test_stuck_check_does_not_block_another_approved_request(self):
        from unittest import mock
        entered, gate = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        with mock.patch("telepathy.broker.check_guarded", self._gated(entered, gate)):
            env = self.make(retry_delay=3600)
            rid = env.submit_ask()
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            self.assertTrue(entered.wait(3))  # A's pre-check is now stuck
            t0 = time.monotonic()
            code, out, _ = env.run(["/usr/bin/echo", "b"])  # auto rule
            took = time.monotonic() - t0
            self.assertEqual((code, out), (0, b"out:/usr/bin/echo b"))
            self.assertLess(took, 2.0)
            self.assertEqual(env.agent({"op": "status", "id": rid})["request"]["state"], "approved")
            gate.set()

    def test_stop_during_a_stuck_precheck_schedules_and_queues_nothing(self):
        from unittest import mock
        entered, gate = threading.Event(), threading.Event()
        self.addCleanup(gate.set)
        with mock.patch("telepathy.broker.check_guarded", self._gated(entered, gate)):
            env = self.make(retry_delay=0.001)
            rid = env.submit_ask()
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            self.assertTrue(entered.wait(3))
            env.daemon.stop()
            gate.set()
            for t in [t for t in threading.enumerate() if t.name == "telepathy-precheck"]:
                t.join(3)
        self.assertEqual(env.daemon._timers, set())
        self.assertNotIn(rid, list(env.daemon._jobs.queue))
        self.assertEqual(env.calls, [])

    def test_busy_precheck_is_retried_then_runs(self):
        from unittest import mock
        from telepathy import policy as policy_mod
        real = policy_mod.check_guarded
        n = []

        def busy_once(policy, argv, cwd, *a, **k):
            n.append(1)
            if len(n) == 2:  # submit is call 1; the first pre-check finds no free slot
                return policy_mod.CheckResult(
                    policy_mod.Decision("deny", "busy"),
                    {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT}, "busy")
            return real(policy, argv, cwd, *a, **k)
        with mock.patch("telepathy.broker.check_guarded", busy_once):
            env = self.make(retry_delay=0.01)
            rid = env.submit_ask()
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            env.wait_state(rid, "done")
        self.assertEqual(len(env.calls), 1)
        ev = [json.loads(x) for x in env.log if '"run_unverified"' in x]
        self.assertEqual([(e["cause"], e["stage"]) for e in ev], [("busy", "precheck")])

    def test_precheck_crash_still_hands_the_request_to_the_worker(self):
        from unittest import mock
        env = self.make()
        rid = env.submit_ask()
        with mock.patch.object(env.broker, "precheck", side_effect=RuntimeError("x")), \
             mock.patch("sys.stderr", io.StringIO()):
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            env.wait_state(rid, "done")
        self.assertEqual(len(env.calls), 1)

    def test_precheck_and_run_time_failures_share_one_attempt_cap(self):
        from unittest import mock
        from telepathy import policy as policy_mod
        real = policy_mod.check_guarded
        n = []

        def alternate(policy, argv, cwd, *a, **k):
            n.append(1)
            if len(n) == 1:
                return real(policy, argv, cwd, *a, **k)  # submit
            # Odd calls (pre-checks) pass, even calls (begin_run) time out, and
            # vice versa later: every attempt fails at one of the two stages.
            return real(policy, argv, cwd, *a, **k) if len(n) == 2 else self._timeout()
        with mock.patch("telepathy.broker.check_guarded", alternate):
            env = self.make(retry_delay=0.001, max_run_attempts=3)
            rid = env.submit_ask()
            self.assertTrue(env.admin({"op": "approve", "id": rid})["ok"])
            env.wait_state(rid, "denied")
        # attempt 1: pre-check ok, begin_run timeout; attempts 2-3: pre-check timeout.
        self.assertEqual(env.events().count("run_unverified"), 3)
        self.assertIn("run_unverified_gave_up", env.events())
        self.assertEqual(env.calls, [])


class SkippedPrefixReport(Base):
    def setUp(self):
        from telepathy import policy as policy_mod
        self.pm = policy_mod
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="tp", dir="/tmp"))
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(os.path.join(self.d, "etc"))
        self.etc = os.path.join(self.d, "etc")
        self.pre = os.path.join(self.d, "etc", "pam.d")
        os.symlink(self.etc, self.pre)  # strict ancestor: skipped
        p = mock.patch.object(policy_mod, "PROTECTED_PREFIXES", (self.pre,))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(policy_mod.stop_skip_tracking)

    def records(self, log):
        return [json.loads(x) for x in log]

    def test_start_up_report_is_audited(self):
        from telepathy.daemon import report_skipped_prefixes
        log = []
        done = threading.Event()
        with mock.patch("sys.stderr", io.StringIO()) as err:
            t = report_skipped_prefixes(AuditLog(log.append), done)
            done.set()
            t.join(5)
        self.assertEqual([(r["event"], r["prefix"], r["resolved"]) for r in self.records(log)],
                         [("protected_prefix_skipped", self.pre, self.etc)])
        self.assertIn("too broad", err.getvalue())

    def test_later_repoint_is_audited_once_by_the_reporter_and_listed(self):
        from telepathy.daemon import report_skipped_prefixes
        log = []
        os.unlink(self.pre)
        os.makedirs(os.path.join(self.etc, "x"))
        os.symlink(os.path.join(self.etc, "x"), self.pre)  # narrow: nothing at start
        done = threading.Event()
        with mock.patch("sys.stderr", io.StringIO()):
            t = report_skipped_prefixes(AuditLog(log.append), done)
            self.assertEqual(log, [])
            os.unlink(self.pre)
            os.symlink(self.etc, self.pre)
            for _ in range(3):
                self.pm._protected_prefixes()
            end = time.monotonic() + 5
            while not log and time.monotonic() < end:
                time.sleep(0.01)
            env = self.make()
            resp = env.admin({"op": "list"})
            done.set()
            t.join(5)
        self.assertEqual([r["event"] for r in self.records(log)], ["protected_prefix_skipped"])
        self.assertEqual(resp["skipped_prefixes"], [{"prefix": self.pre, "resolved": self.etc}])

    def test_admin_list_does_not_resolve_paths(self):
        env = self.make()
        self.pm.start_skip_tracking({"/a": "/"})
        with mock.patch("os.path.realpath", side_effect=AssertionError("no fs on admin thread")):
            resp = env.admin({"op": "list"})
        self.assertEqual(resp["skipped_prefixes"], [{"prefix": "/a", "resolved": "/"}])

    def test_failed_audit_write_is_retried_not_lost(self):
        from telepathy.daemon import drain_skip_reports
        self.pm.start_skip_tracking({})
        self.pm._note_skipped({self.pre: self.etc})
        calls, log = [], []

        def sink(line):
            calls.append(1)
            if len(calls) < 3:
                raise OSError("disk")
            log.append(line)
        with mock.patch("sys.stderr", io.StringIO()):
            drain_skip_reports(AuditLog(sink), attempts=5, delay=0)
        self.assertEqual(len(calls), 3)
        self.assertEqual([r["event"] for r in self.records(log)], ["protected_prefix_skipped"])

    def test_persistent_audit_failure_is_bounded_and_logged_to_stderr(self):
        from telepathy.daemon import drain_skip_reports
        self.pm.start_skip_tracking({})
        self.pm._note_skipped({self.pre: self.etc})
        calls = []

        def sink(line):
            calls.append(1)
            raise OSError("disk")
        with mock.patch("sys.stderr", io.StringIO()) as err:
            drain_skip_reports(AuditLog(sink), attempts=3, delay=0)
        self.assertEqual(len(calls), 3)
        self.assertIn("cannot audit", err.getvalue())

    def test_ctl_list_note_goes_to_stderr_not_stdout(self):
        self.pm.start_skip_tracking({self.pre: self.etc})
        env = self.make()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stderr", err):
            self.assertEqual(
                client.ctl_main(["--socket", env.cfg.admin_socket_path, "list"], out=out), 0)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("note: protected prefix " + self.pre, err.getvalue())

    def test_main_emits_the_start_up_record(self):
        import signal
        import subprocess
        import sys
        cfgd = self.d
        audit = os.path.join(cfgd, "audit.jsonl")
        pol = os.path.join(cfgd, "policy.toml")
        open(pol, "w").close()
        cfg = os.path.join(cfgd, "config.toml")
        with open(cfg, "w") as f:
            f.write(f'socket_path = "{cfgd}/a.sock"\nadmin_socket_path = "{cfgd}/b.sock"\n'
                    f'web_socket_path = "{cfgd}/w.sock"\npolicy_path = "{pol}"\n'
                    f'audit_path = "{audit}"\nallowed_uids = [{ME}]\n')
        code = ("import sys, telepathy.policy as p\n"
                f"p.PROTECTED_PREFIXES = ({self.pre!r},)\n"
                "from telepathy.daemon import main\n"
                f"sys.exit(main(['--insecure-dev', '--config', {cfg!r}]))\n")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.Popen([sys.executable, "-c", code], cwd=root,
                                stderr=subprocess.PIPE, text=True)
        try:
            end = time.monotonic() + 10
            seen = []
            while time.monotonic() < end:
                if os.path.exists(audit):
                    with open(audit) as f:
                        seen = [json.loads(x) for x in f if x.strip()]
                    if any(r["event"] == "daemon_start" for r in seen):
                        break
                time.sleep(0.05)
        finally:
            proc.send_signal(signal.SIGTERM)
            err = proc.communicate(timeout=10)[1]
        skipped = [r for r in seen if r["event"] == "protected_prefix_skipped"]
        self.assertEqual(len(skipped), 1, (seen, err))
        self.assertEqual(skipped[0]["prefix"], self.pre)
        self.assertLess(seen.index(skipped[0]), [r["event"] for r in seen].index("daemon_start"))


class ClientErrors(unittest.TestCase):
    def test_daemon_not_running(self):
        out, err = io.BytesIO(), io.StringIO()
        code = client.run(["/usr/bin/echo", "x"], sock="/tmp/definitely-no-such.sock",
                          out=out, err=err)
        self.assertEqual(code, client.EXIT_REFUSED)
        self.assertIn("cannot reach telepathyd", err.getvalue())


if __name__ == "__main__":
    unittest.main()
