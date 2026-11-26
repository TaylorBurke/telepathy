import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from unittest import mock
import unittest

from telepathy.audit import AuditLog, FileSink
from telepathy.daemon import run_reopen_worker

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def lines(path):
    with open(path) as f:
        return [json.loads(x) for x in f.read().splitlines()]


def events(path):
    try:
        return [r["event"] for r in lines(path)]
    except (OSError, ValueError):  # not there yet, or read mid-write
        return []


class Reopen(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.path = os.path.join(self.d, "audit.jsonl")

    def test_rotate_then_reopen_splits_records(self):
        sink = FileSink(self.path)
        log = AuditLog(sink)
        log.write("before")
        os.rename(self.path, self.path + ".1")
        log.write("still_old_file")  # until reopen, the old inode gets it
        sink.reopen()
        log.write("after")
        sink.close()
        self.assertEqual([r["event"] for r in lines(self.path + ".1")], ["before", "still_old_file"])
        self.assertEqual([r["event"] for r in lines(self.path)], ["after"])

    def test_new_file_is_0600_even_with_loose_umask(self):
        old = os.umask(0)
        self.addCleanup(os.umask, old)
        sink = FileSink(self.path)
        os.rename(self.path, self.path + ".1")
        sink.reopen()
        sink.close()
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_reopen_fixes_loose_mode_of_existing_file(self):
        sink = FileSink(self.path)
        os.chmod(self.path, 0o666)
        sink.reopen()
        sink.close()
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_failed_reopen_keeps_old_fd(self):
        sink = FileSink(self.path)
        log = AuditLog(sink)
        sink.path = os.path.join(self.d, "missing-dir", "audit.jsonl")
        with self.assertRaises(OSError):
            sink.reopen()
        log.write("still_works")
        sink.close()
        self.assertEqual([r["event"] for r in lines(self.path)], ["still_works"])

    def test_concurrent_writes_and_rotations_lose_nothing(self):
        sink = FileSink(self.path)
        log = AuditLog(sink)
        writers, per = 8, 300
        rotations = 20

        def write(n):
            for i in range(per):
                log.write("e", w=n, i=i, pad="x" * 200)

        def rotate():
            for k in range(1, rotations + 1):
                time.sleep(0.005)
                os.rename(self.path, f"{self.path}.{k}")
                sink.reopen()

        rot = threading.Thread(target=rotate)
        ts = [threading.Thread(target=write, args=(n,)) for n in range(writers)]
        rot.start()
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        rot.join()
        sink.close()
        seen = set()
        for name in os.listdir(self.d):
            for r in lines(os.path.join(self.d, name)):  # every line parses whole
                seen.add((r["w"], r["i"]))
        self.assertEqual(len(seen), writers * per)


class DaemonSighup(unittest.TestCase):
    def start(self, d, **extra):
        policy = os.path.join(d, "policy.toml")
        open(policy, "w").close()
        cfg = os.path.join(d, "config.toml")
        with open(cfg, "w") as f:
            f.write(f'allowed_uids = [{os.getuid()}]\n'
                    f'socket_path = "{d}/a.sock"\nadmin_socket_path = "{d}/b.sock"\n'
                    f'policy_path = "{policy}"\naudit_path = "{d}/audit.jsonl"\n')
        p = subprocess.Popen(["python3", "-I", os.path.join(ROOT, "bin", "telepathyd"),
                              "--config", cfg, "--insecure-dev"], stderr=subprocess.PIPE)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        self.addCleanup(p.stderr.close)
        return p

    @staticmethod
    def wait_for(pred, tries=300):
        for _ in range(tries):
            if pred():
                return True
            time.sleep(0.1)
        return False

    def test_hup_burst_during_shutdown_does_not_hang(self):
        import signal
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = self.start(d)
        audit = os.path.join(d, "audit.jsonl")
        self.assertTrue(self.wait_for(lambda: os.path.exists(os.path.join(d, "hup-ok"))))
        p.send_signal(signal.SIGTERM)
        for _ in range(50):
            try:
                p.send_signal(signal.SIGHUP)
            except ProcessLookupError:
                break
        self.assertEqual(p.wait(timeout=30), 0)
        self.assertIn("daemon_stop", events(audit))

    def test_stale_flag_removed_and_marker_failure_is_loud(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        open(os.path.join(d, "audit-reopen-failed"), "w").close()  # left by a crashed run
        os.mkdir(os.path.join(d, "hup-ok"))  # cannot be removed or written as a file
        p = self.start(d)
        audit = os.path.join(d, "audit.jsonl")
        self.assertTrue(self.wait_for(lambda: "hup_marker_failed" in events(audit)))
        self.assertFalse(os.path.exists(os.path.join(d, "audit-reopen-failed")))
        p.terminate()
        p.wait(timeout=30)
        self.assertIn(b"cannot write", p.stderr.read())

    def test_sighup_reopens_in_running_daemon(self):
        import signal
        import time
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        audit = os.path.join(d, "audit.jsonl")
        policy = os.path.join(d, "policy.toml")
        open(policy, "w").close()
        cfg = os.path.join(d, "config.toml")
        with open(cfg, "w") as f:
            f.write(f'allowed_uids = [{os.getuid()}]\n'
                    f'socket_path = "{d}/a.sock"\nadmin_socket_path = "{d}/b.sock"\n'
                    f'policy_path = "{policy}"\naudit_path = "{audit}"\n')
        p = subprocess.Popen(["python3", "-I", os.path.join(ROOT, "bin", "telepathyd"),
                              "--config", cfg, "--insecure-dev"], stderr=subprocess.PIPE)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)

        def wait_for(pred):
            for _ in range(300):
                if pred():
                    return True
                time.sleep(0.1)
            return False

        marker = os.path.join(d, "hup-ok")
        self.assertTrue(wait_for(lambda: "daemon_start" in events(audit) and os.path.exists(marker)))
        os.rename(audit, audit + ".1")
        p.send_signal(signal.SIGHUP)
        self.assertTrue(wait_for(lambda: "audit_reopened" in events(audit)))
        self.assertEqual(os.stat(audit).st_mode & 0o777, 0o600)
        self.assertIn("daemon_start", events(audit + ".1"))
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(timeout=15), 0)
        p.stderr.close()
        self.assertIn("daemon_stop", events(audit))
        self.assertFalse(os.path.exists(marker))


class SinkEdges(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.path = os.path.join(self.d, "audit.jsonl")

    def test_close_idempotent_and_reopen_after_close_is_noop(self):
        sink = FileSink(self.path)
        sink.close()
        sink.close()
        sink.reopen()
        self.assertIsNone(sink._fd)
        with self.assertRaises(ValueError):
            sink("x\n")

    def test_close_failure_of_old_fd_after_swap_is_not_a_failed_reopen(self):
        sink = FileSink(self.path)
        real_close = os.close

        def bad_close(fd):
            real_close(fd)
            raise OSError(5, "boom")

        with mock.patch("telepathy.audit.os.close", bad_close):
            sink.reopen()  # must not raise
        sink("{}\n")
        sink.close()

    def test_short_writes_are_finished(self):
        sink = FileSink(self.path)
        real = os.write
        with mock.patch("telepathy.audit.os.write", lambda fd, b: real(fd, b[:3])):
            sink('{"a":1}\n')
        sink.close()
        self.assertEqual(lines(self.path), [{"a": 1}])

    def test_mid_record_failure_never_glues_next_record(self):
        sink = FileSink(self.path)
        real = os.write
        calls = {"n": 0}

        def flaky(fd, b):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(5, "boom")
            return real(fd, b[:4])

        with mock.patch("telepathy.audit.os.write", flaky):
            with self.assertRaises(OSError):
                sink('{"a":1}\n')
        sink('{"b":2}\n')
        sink.close()
        with open(self.path) as f:
            raw = f.read().splitlines()
        self.assertEqual(raw[-1], '{"b":2}')
        self.assertEqual(raw[0], '{"a"')  # the fragment sits on its own line

    def test_failure_of_the_terminating_newline_is_deferred(self):
        sink = FileSink(self.path)
        real = os.write
        calls = {"n": 0}

        def flaky(fd, b):
            calls["n"] += 1
            if calls["n"] in (2, 3):
                raise OSError(5, "boom")
            return real(fd, b[:4])

        with mock.patch("telepathy.audit.os.write", flaky):
            with self.assertRaises(OSError):
                sink('{"a":1}\n')
        sink('{"b":2}\n')
        sink.close()
        with open(self.path) as f:
            self.assertEqual(f.read().splitlines()[-1], '{"b":2}')


class ReopenWorker(unittest.TestCase):
    def test_failure_is_retried_then_succeeds_and_flag_clears(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "audit.jsonl")
        flag = os.path.join(d, "failed")
        sink = FileSink(path)
        audit = AuditLog(sink)
        good = sink.path
        sink.path = os.path.join(d, "nodir", "audit.jsonl")
        req, done = threading.Event(), threading.Event()
        t = threading.Thread(target=run_reopen_worker, args=(sink, audit, req, done, flag),
                             kwargs={"delays": (0.02, 0.02), "retry_every": 0.02}, daemon=True)
        with mock.patch("sys.stderr"):
            t.start()
            req.set()
            for _ in range(200):
                if os.path.exists(flag) and events(path).count("audit_reopen_failed") >= 3:
                    break
                time.sleep(0.02)
            self.assertTrue(os.path.exists(flag))
            self.assertGreaterEqual(events(path).count("audit_reopen_failed"), 3)  # recurring
            os.rename(path, path + ".1")
            sink.path = good  # the problem goes away
            for _ in range(200):
                if "audit_reopened" in events(path):
                    break
                time.sleep(0.02)
            done.set()
            req.set()
            t.join(5)
        self.assertIn("audit_reopened", events(path))
        self.assertFalse(os.path.exists(flag))
        sink.close()


HOOK = os.path.join(ROOT, "bin", "telepathy-logrotate-hook")


class RotateHook(unittest.TestCase):
    def run_hook(self, mode, active=True, marker=True, kill_ok=True):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        calls = os.path.join(d, "calls")
        fake = os.path.join(d, "systemctl")
        with open(fake, "w") as f:
            f.write(f'#!/bin/sh\necho "$@" >> {calls}\n'
                    'case "$1" in is-active) exit %d;; kill) exit %d;; esac\n'
                    % (0 if active else 3, 0 if kill_ok else 1))
        os.chmod(fake, 0o755)
        mk = os.path.join(d, "hup-ok")
        if marker:
            open(mk, "w").close()
        env = dict(os.environ, SYSTEMCTL=fake, MARKER=mk)
        r = subprocess.run(["bash", HOOK, mode], env=env, capture_output=True, text=True)
        sent = os.path.exists(calls) and "kill --kill-whom=main -s HUP telepathyd.service" in open(calls).read()
        return r.returncode, sent

    def test_prerotate_allows_only_active_daemon_with_marker(self):
        self.assertEqual(self.run_hook("prerotate")[0], 0)
        self.assertEqual(self.run_hook("prerotate", marker=False)[0], 1)
        self.assertEqual(self.run_hook("prerotate", active=False)[0], 1)

    def test_postrotate_signals_only_ready_daemon_and_never_fails(self):
        self.assertEqual(self.run_hook("postrotate"), (0, True))
        self.assertEqual(self.run_hook("postrotate", marker=False), (0, False))
        self.assertEqual(self.run_hook("postrotate", active=False), (0, False))
        self.assertEqual(self.run_hook("postrotate", kill_ok=False), (0, True))

    def test_bad_mode(self):
        self.assertEqual(self.run_hook("bogus")[0], 2)


@unittest.skipUnless(shutil.which("logrotate"), "logrotate not installed")
class LogrotateSnippet(unittest.TestCase):
    def test_snippet_parses(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        conf = os.path.join(d, "telepathy")
        # Point the rule at a log under d: logrotate -d stats the log, and on a
        # deployed host /var/log/telepathy is root-only.
        with open(os.path.join(ROOT, "etc", "logrotate.telepathy")) as f:
            text = f.read()
        head = "/var/log/telepathy/audit.jsonl {"
        self.assertIn(head, text)
        with open(conf, "w") as f:
            f.write(text.replace(head, os.path.join(d, "audit.jsonl") + " {"))
        r = subprocess.run(["logrotate", "-d", "-s", os.path.join(d, "state"), conf],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("error", r.stderr.lower())


if __name__ == "__main__":
    unittest.main()
