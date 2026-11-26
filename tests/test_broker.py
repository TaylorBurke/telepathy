import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from telepathy.broker import NotRunnable
from telepathy.audit import AuditLog, FileSink
from telepathy.broker import (
    Broker,
    CheckUnavailable,
    boottime,
    select_boottime,
    Expired,
    IntegrityFailure,
    Limits,
    NonceMismatch,
    PolicyDenied,
    RateLimited,
    UnknownRequest,
)
from telepathy import policy as policy_mod
from telepathy.policy import Policy
from telepathy.request import InvalidRequest, InvalidTransition, State

AUTO = """
[patterns]
pkg = '[a-z0-9@_+][a-z0-9@._+-]*'
[[auto]]
name = "pacman-install"
argv = ["/usr/bin/pacman", "-S", "--needed", "--noconfirm", "@pkg..."]
"""
ASK = ["/usr/bin/pacman", "-Syu"]
AUTO_ARGV = ["/usr/bin/pacman", "-S", "--needed", "--noconfirm", "htop"]


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.log = []
        self.b = Broker(Policy.from_toml(AUTO), Limits(ttl=600, max_pending=3, max_per_hour=5),
                        AuditLog(self.log.append, clock=self.clock), clock=self.clock,
                        link_trusted_uid=-1)  # links made by the test user count as the agent's, even as root

    def events(self):
        return [json.loads(x)["event"] for x in self.log]

    def submit(self, argv=ASK):
        return self.b.submit(argv, "/tmp", 1000, "because")


class Lifecycle(Base):
    def test_ask_approve_run_finish(self):
        r = self.submit()
        self.assertEqual(r.state, State.PENDING)
        n = self.b.issue_nonce(r.id)
        self.b.approve(r.id, n, "tailnet:phone")
        self.b.begin_run(r.id)
        self.b.finish(r.id, 0)
        self.assertEqual(self.b.get(r.id).state, State.DONE)
        self.assertEqual(self.events(),
                         ["submitted", "approved", "run_start", "run_finish"])

    def test_auto_rule_skips_the_human(self):
        r = self.submit(AUTO_ARGV)
        self.assertEqual(r.state, State.APPROVED)
        self.assertEqual(r.approver, "policy:pacman-install")
        self.b.begin_run(r.id)

    def test_deny_flow(self):
        r = self.submit()
        self.b.deny(r.id, "tailnet:phone")
        with self.assertRaises(InvalidTransition):
            self.b.begin_run(r.id)

    def test_policy_deny_is_not_queued(self):
        with self.assertRaises(PolicyDenied):
            self.b.submit(["/bin/sh", "-c", "id"], "/tmp", 1000)
        self.assertEqual(self.b.pending(), [])
        self.assertIn("policy_denied", self.events())

    def test_invalid_is_audited(self):
        with self.assertRaises(InvalidRequest):
            self.b.submit("pacman -Syu", "/tmp", 1000)
        self.assertIn("invalid", self.events())

    def test_unknown_id(self):
        with self.assertRaises(UnknownRequest):
            self.b.get("nope")


class SingleUse(Base):
    def test_cannot_run_twice(self):
        r = self.submit(AUTO_ARGV)
        self.b.begin_run(r.id)
        with self.assertRaises(InvalidTransition):
            self.b.begin_run(r.id)

    def test_cannot_run_unapproved(self):
        r = self.submit()
        with self.assertRaises(InvalidTransition):
            self.b.begin_run(r.id)

    def test_cannot_approve_twice(self):
        r = self.submit()
        n = self.b.issue_nonce(r.id)
        self.b.approve(r.id, n, "p")
        with self.assertRaises(InvalidTransition):
            self.b.approve(r.id, n, "p")

    def test_tampering_is_caught_at_run_time(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "p")
        r.argv = ("/usr/bin/rm", "-rf", "/")
        with self.assertRaises(IntegrityFailure):
            self.b.begin_run(r.id)
        self.assertEqual(r.state, State.DENIED)
        self.assertIn("integrity_failure", self.events())


class Cancel(Base):
    def test_cancel_pending_frees_the_slot(self):
        rs = [self.submit() for _ in range(3)]
        with self.assertRaises(RateLimited):
            self.submit()
        req, changed = self.b.cancel(rs[0].id, 1000)
        self.assertEqual((req.state, changed), (State.CANCELLED, True))
        self.submit()  # slot is free again
        self.assertIn("cancelled", self.events())

    def test_cancelled_cannot_be_approved(self):
        r = self.submit()
        n = self.b.issue_nonce(r.id)
        self.b.cancel(r.id, 1000)
        with self.assertRaises(InvalidTransition):
            self.b.approve(r.id, n, "phone")

    def test_cancel_approved_not_run_never_runs(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "phone")
        _, changed = self.b.cancel(r.id, 1000)
        self.assertTrue(changed)
        with self.assertRaises(InvalidTransition):
            self.b.begin_run(r.id)
        self.assertNotIn("run_start", self.events())

    def test_cancel_running_or_finished_is_a_noop(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "phone")
        self.b.begin_run(r.id)
        req, changed = self.b.cancel(r.id, 1000)
        self.assertEqual((req.state, changed), (State.RUNNING, False))
        self.b.finish(r.id, 0)
        req, changed = self.b.cancel(r.id, 1000)
        self.assertEqual((req.state, changed), (State.DONE, False))
        self.assertNotIn("cancelled", self.events())

    def test_cancel_twice_audits_once(self):
        r = self.submit()
        self.b.cancel(r.id, 1000)
        _, changed = self.b.cancel(r.id, 1000)
        self.assertFalse(changed)
        self.assertEqual(self.events().count("cancelled"), 1)

    def test_cancelled_can_never_reach_running_even_if_the_table_allowed_it(self):
        from telepathy import request as request_mod
        r = self.submit()
        self.b.cancel(r.id, 1000)
        allowed = dict(request_mod.TRANSITIONS)
        allowed[State.CANCELLED] = frozenset({State.RUNNING})
        with mock.patch.dict(request_mod.TRANSITIONS, allowed):
            with self.assertRaises(NotRunnable):
                self.b.begin_run(r.id)
        self.assertEqual(r.state, State.CANCELLED)
        self.assertIn("run_refused", self.events())
        self.assertNotIn("run_start", self.events())

    def test_begin_run_refuses_every_state_but_approved(self):
        r = self.submit()
        with self.assertRaises(NotRunnable):  # pending
            self.b.begin_run(r.id)

    def test_cancel_enforces_owner_or_root_atomically(self):
        r = self.submit()
        with self.assertRaises(UnknownRequest):
            self.b.cancel(r.id, 2000)
        self.assertEqual(r.state, State.PENDING)
        _, changed = self.b.cancel(r.id, 0)
        self.assertTrue(changed)

    def test_cancel_unknown_id(self):
        with self.assertRaises(UnknownRequest):
            self.b.cancel("nope", 1000)


class Nonces(Base):
    def test_wrong_nonce_rejected_and_audited(self):
        r = self.submit()
        self.b.issue_nonce(r.id)
        with self.assertRaises(NonceMismatch):
            self.b.approve(r.id, "guess", "p")
        self.assertEqual(self.b.get(r.id).state, State.PENDING)
        self.assertIn("approve_rejected", self.events())

    def test_approve_without_page_load(self):
        r = self.submit()
        with self.assertRaises(NonceMismatch):
            self.b.approve(r.id, "anything", "p")

    def test_nonce_never_logged(self):
        r = self.submit()
        n = self.b.issue_nonce(r.id)
        self.b.approve(r.id, n, "p")
        self.assertNotIn(n, "".join(self.log))


class Expiry(Base):
    def test_pending_expires(self):
        r = self.submit()
        self.clock.t += 600
        with self.assertRaises(Expired):
            self.b.issue_nonce(r.id)
        self.assertEqual(r.state, State.EXPIRED)

    def test_approved_but_unrun_expires(self):
        r = self.submit(AUTO_ARGV)
        self.clock.t += 601
        with self.assertRaises(Expired):
            self.b.begin_run(r.id)

    def test_approval_cannot_extend_ttl(self):
        r = self.submit()
        self.clock.t += 500
        self.b.approve(r.id, self.b.issue_nonce(r.id), "p")
        self.clock.t += 101
        with self.assertRaises(Expired):
            self.b.begin_run(r.id)

    def test_running_request_is_not_expired_midflight(self):
        r = self.submit(AUTO_ARGV)
        self.b.begin_run(r.id)
        self.clock.t += 10_000
        self.b.finish(r.id, 0)
        self.assertEqual(r.state, State.DONE)

    def test_sweep_reports_and_prunes(self):
        r = self.submit()
        self.clock.t += 601
        self.assertEqual(self.b.sweep(), [r.id])
        self.clock.t += 25 * 3600
        self.b.sweep()
        with self.assertRaises(UnknownRequest):
            self.b.get(r.id)


class Limiting(Base):
    def test_max_pending(self):
        for _ in range(3):
            self.submit()
        with self.assertRaises(RateLimited):
            self.submit()
        self.assertIn("rate_limited", self.events())

    def test_pending_slot_frees_on_decision(self):
        rs = [self.submit() for _ in range(3)]
        self.b.deny(rs[0].id, "p")
        self.submit()

    def test_per_hour_counts_even_denied_and_invalid(self):
        for _ in range(3):
            with self.assertRaises(PolicyDenied):
                self.b.submit(["/bin/sh"], "/tmp", 1000)
        for _ in range(2):
            with self.assertRaises(InvalidRequest):
                self.b.submit([], "/tmp", 1000)
        with self.assertRaises(RateLimited):
            self.submit()

    def test_window_slides(self):
        for _ in range(5):
            with self.assertRaises(PolicyDenied):
                self.b.submit(["/bin/sh"], "/tmp", 1000)
        self.clock.t += 3601
        self.submit()


class FileAudit(unittest.TestCase):
    def test_jsonl_mode_and_append(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            sink = FileSink(path)
            log = AuditLog(sink, clock=lambda: 5.0)
            log.write("a", id="1")
            log.write("b", id="2")
            sink.close()
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with open(path) as f:
                lines = f.read().splitlines()
            self.assertEqual([json.loads(x)["event"] for x in lines], ["a", "b"])
            sink2 = FileSink(path)  # reopening appends, never truncates
            AuditLog(sink2).write("c")
            sink2.close()
            with open(path) as f:
                self.assertEqual(len(f.read().splitlines()), 3)



class SymlinkRetarget(Base):
    def test_retarget_between_approve_and_run_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "x")
            os.symlink("/usr/share/doc", link)
            r = self.b.submit(["/usr/bin/tee", link], "/tmp", 1000, "")
            self.assertEqual(r.state, State.PENDING)
            self.b.approve(r.id, self.b.issue_nonce(r.id), "p")
            os.unlink(link)
            os.symlink("/etc/sudoers.d/evil", link)
            with self.assertRaises(PolicyDenied):
                self.b.begin_run(r.id)
        self.assertEqual(r.state, State.DENIED)
        self.assertIn("policy_denied_at_run", self.events())
        self.assertNotIn("run_start", self.events())

    def test_executable_retargeted_to_a_shell_between_approve_and_run_is_refused(self):
        bash = os.path.realpath("/bin/bash")
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(os.path.realpath(td), "tool")
            os.symlink("/usr/bin/true", exe)
            # Real files on disk here. The trust rule judges the *resolved* file, which
            # is root's /usr/bin/true at submit, but it also refuses user-owned
            # directories, so switch it off for the submit only to isolate the
            # run-time name re-check. (We cannot create root-owned files as a normal
            # user, so the trust re-check itself is covered with a mock below and
            # with a fake filesystem in test_policy.TrustWalk.)
            with mock.patch.object(policy_mod, "_untrusted_exe", return_value=None):
                r = self.b.submit([exe, "--x"], "/tmp", 1000, "")
            self.assertEqual(r.state, State.PENDING)
            self.b.approve(r.id, self.b.issue_nonce(r.id), "p")
            os.unlink(exe)
            os.symlink(bash, exe)
            with self.assertRaises(PolicyDenied) as cm:
                self.b.begin_run(r.id)
        self.assertIn("shell", cm.exception.decision.reason)
        self.assertEqual(r.state, State.DENIED)
        self.assertIn("policy_denied_at_run", self.events())
        self.assertNotIn("run_start", self.events())

    def test_executable_that_stops_being_trusted_is_refused_at_run(self):
        r = self.b.submit(["/usr/bin/true"], "/tmp", 1000, "")
        self.b.approve(r.id, self.b.issue_nonce(r.id), "p")
        with mock.patch.object(policy_mod, "_untrusted_exe", return_value="made untrusted"):
            with self.assertRaises(PolicyDenied):
                self.b.begin_run(r.id)
        self.assertEqual(r.state, State.DENIED)
        self.assertNotIn("run_start", self.events())

    def test_view_reports_a_symlinked_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            cwd = os.path.join(os.path.realpath(td), "work")
            os.symlink("/usr/share/doc", cwd)
            r = self.b.submit(["/usr/bin/ls", "-n"], cwd, 1000, "")
            v = self.b.view(r)
        self.assertEqual(v["resolved"], {cwd: os.path.realpath("/usr/share/doc")})

    def test_view_shows_resolved_paths(self):
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "x")
            os.symlink("/usr/share/doc", link)
            r = self.b.submit(["/usr/bin/ls", link], "/tmp", 1000, "")
            v = self.b.view(r)
        self.assertEqual(v["resolved"], {link: os.path.realpath("/usr/share/doc")})
        self.assertEqual(v["expires_in"], 600.0)
        self.assertNotIn("expires_at", v)


class ResolvedFrozenAtSubmit(Base):
    def _linked(self, td, target="/usr/share/doc"):
        link = os.path.join(os.path.realpath(td), "x")
        os.symlink(target, link)
        return link

    def _approved(self, argv):
        r = self.b.submit(argv, "/tmp", 1000, "")
        self.b.approve(r.id, self.b.issue_nonce(r.id), "p")
        return r

    def test_harmless_to_harmless_retarget_is_refused_and_audited(self):
        with tempfile.TemporaryDirectory() as td:
            link = self._linked(td)
            r = self._approved(["/usr/bin/ls", link])
            os.unlink(link)
            os.symlink("/usr/share/man", link)
            with self.assertRaises(PolicyDenied) as cm:
                self.b.begin_run(r.id)
        self.assertIn("resolves differently", str(cm.exception))
        self.assertEqual(r.state, State.DENIED)
        self.assertIn("symlink_changed_at_run", self.events())
        self.assertNotIn("run_start", self.events())
        ev = [json.loads(x) for x in self.log if "symlink_changed_at_run" in x][0]
        self.assertEqual(ev["before"], {link: os.path.realpath("/usr/share/doc")})
        self.assertEqual(ev["after"], {link: os.path.realpath("/usr/share/man")})

    def test_unchanged_link_still_runs(self):
        with tempfile.TemporaryDirectory() as td:
            link = self._linked(td)
            r = self._approved(["/usr/bin/ls", link])
            self.b.begin_run(r.id)
        self.assertEqual(r.state, State.RUNNING)

    def test_plain_path_that_becomes_a_link_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(os.path.realpath(td), "x")
            r = self._approved(["/usr/bin/ls", p])
            self.assertEqual(r.resolved, {})
            os.symlink("/usr/share/doc", p)
            with self.assertRaises(PolicyDenied):
                self.b.begin_run(r.id)
        self.assertIn("symlink_changed_at_run", self.events())

    def test_link_removed_before_run_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            link = self._linked(td)
            r = self._approved(["/usr/bin/ls", link])
            os.unlink(link)
            with self.assertRaises(PolicyDenied):
                self.b.begin_run(r.id)

    def test_dangling_link_unchanged_runs_and_retargeted_dangling_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            link = self._linked(td, os.path.join(os.path.realpath(td), "nope1"))
            r = self._approved(["/usr/bin/ls", link])
            self.assertEqual(r.resolved, {link: os.path.join(os.path.realpath(td), "nope1")})
            self.b.begin_run(r.id)
            self.assertEqual(r.state, State.RUNNING)
            link2 = os.path.join(os.path.realpath(td), "y")
            os.symlink(os.path.join(os.path.realpath(td), "a1"), link2)
            r2 = self._approved(["/usr/bin/ls", link2])
            os.unlink(link2)
            os.symlink(os.path.join(os.path.realpath(td), "a2"), link2)
            with self.assertRaises(PolicyDenied):
                self.b.begin_run(r2.id)

    def test_symlink_loop_is_stored_as_unresolvable(self):
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "loop")
            os.symlink(link, link)
            try:
                r = self.b.submit(["/usr/bin/ls", link], "/tmp", 1000, "")
            except PolicyDenied:
                return  # denied outright at submit is fine too
        self.assertEqual(r.resolved[link], policy_mod.UNRESOLVABLE)

    def test_resolved_is_stored_and_not_part_of_the_hash(self):
        with tempfile.TemporaryDirectory() as td:
            link = self._linked(td)
            r = self.b.submit(["/usr/bin/ls", link], "/tmp", 1000, "")
        self.assertEqual(r.resolved, {link: os.path.realpath("/usr/share/doc")})
        self.assertEqual(r.hash, r.recompute_hash())

    def test_view_and_get_do_not_touch_the_filesystem(self):
        with tempfile.TemporaryDirectory() as td:
            link = self._linked(td)
            r = self.b.submit(["/usr/bin/ls", link], "/tmp", 1000, "")
            os.unlink(link)
            os.symlink("/usr/share/man", link)
            with mock.patch.object(policy_mod.os.path, "realpath",
                                   side_effect=AssertionError("realpath on render")), \
                 mock.patch.object(policy_mod.os, "lstat",
                                   side_effect=AssertionError("lstat on render")):
                v = self.b.view(r)
                self.b.pending()
                self.b.view(self.b.get(r.id))
        # still the submit-time value, not the retargeted one
        self.assertEqual(v["resolved"], {link: os.path.realpath("/usr/share/doc")})

    def test_view_returns_a_copy(self):
        with tempfile.TemporaryDirectory() as td:
            link = self._linked(td)
            r = self.b.submit(["/usr/bin/ls", link], "/tmp", 1000, "")
            self.b.view(r)["resolved"].clear()
        self.assertTrue(r.resolved)

    def test_timeout_at_submit_is_shown_and_refused_at_run(self):
        import threading
        gate = threading.Event()

        def hang(argv, cwd, trusted_uid=0):
            gate.wait(5)
            return {}
        try:
            with mock.patch.object(policy_mod, "resolve_path_args", hang), \
                 mock.patch.object(policy_mod, "RESOLVE_TIMEOUT", 0.05):
                t0 = time.time()
                r = self._approved(ASK)
                self.assertLess(time.time() - t0, 2)
            self.assertEqual(r.resolved, {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT})
            with self.assertRaises(PolicyDenied) as cm:
                self.b.begin_run(r.id)
            self.assertIn("timed out", str(cm.exception))
            self.assertIn("symlink_unverified_at_run", self.events())
        finally:
            gate.set()

    def test_resolver_error_uses_its_own_marker_and_reason(self):
        with mock.patch.object(policy_mod, "resolve_path_args", side_effect=RuntimeError("x")):
            r = self._approved(ASK)
        self.assertIn(policy_mod.ERROR_KEY, r.resolved)
        self.assertNotIn(policy_mod.TIMED_OUT_KEY, r.resolved)
        with self.assertRaises(PolicyDenied) as cm:
            self.b.begin_run(r.id)
        self.assertIn("unexpected error", str(cm.exception))
        self.assertNotIn("timed out", str(cm.exception))

    def test_reresolve_timing_out_at_run_is_refused_with_its_own_reason(self):
        r = self._approved(ASK)
        with mock.patch.object(policy_mod, "resolve_path_args",
                               return_value={policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT}):
            with self.assertRaises(PolicyDenied) as cm:
                self.b.begin_run(r.id)
        self.assertIn("timed out", str(cm.exception))
        self.assertNotIn("differently", str(cm.exception))
        self.assertIn("symlink_unverified_at_run", self.events())
        self.assertNotIn("symlink_changed_at_run", self.events())
        self.assertEqual(r.state, State.DENIED)

    def test_reresolve_error_at_run_is_refused_with_its_own_reason(self):
        r = self._approved(ASK)
        with mock.patch.object(policy_mod, "resolve_path_args",
                               return_value={policy_mod.ERROR_KEY: policy_mod.ERROR}):
            with self.assertRaises(PolicyDenied) as cm:
                self.b.begin_run(r.id)
        self.assertIn("unexpected error", str(cm.exception))

    def test_request_never_frozen_is_refused(self):
        r = self._approved(ASK)
        r.resolved = None
        with self.assertRaises(PolicyDenied) as cm:
            self.b.begin_run(r.id)
        self.assertIn("never resolved", str(cm.exception))
        self.assertEqual(r.state, State.DENIED)
        self.assertNotIn("run_start", self.events())

    def test_unfrozen_request_view_does_not_crash(self):
        from telepathy.request import Request
        r = Request.new(ASK, "/tmp", 1000, "", 0.0, 600.0)
        self.assertIsNone(r.resolved)
        self.assertEqual(self.b.view(r)["resolved"], {})

    def test_unverified_helper(self):
        u = policy_mod.unverified
        self.assertIsNone(u({}))
        self.assertIsNone(u({"/a": "/b"}))
        self.assertIn("never", u(None))
        self.assertIn("timed out", u({policy_mod.TIMED_OUT_KEY: "x"}))
        self.assertIn("error", u({policy_mod.ERROR_KEY: "x"}))

    def test_resolver_exception_is_contained(self):
        with mock.patch.object(policy_mod, "resolve_path_args", side_effect=RuntimeError("x")):
            d, res, problem = policy_mod.check_guarded(Policy.empty(), ["/usr/bin/ls"], "/tmp")
        self.assertEqual(d.kind, "ask")
        self.assertIsNone(problem)
        self.assertEqual(res, {policy_mod.ERROR_KEY: policy_mod.ERROR})


class OneResolution(Base):
    """The targets frozen at submit (and shown to the approver) are the ones
    the deny rules checked, even when a link flips between evaluate and the freeze."""

    def _flip_before_freeze(self, link, target):
        real = policy_mod.resolve_path_args

        def flipping(*a, **kw):
            os.unlink(link)
            os.symlink(target, link)
            return real(*a, **kw)
        return mock.patch.object(policy_mod, "resolve_path_args", flipping)

    def test_link_flipped_to_protected_path_between_passes_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "x")
            os.symlink("/usr/share/doc", link)
            with self._flip_before_freeze(link, "/etc/sudoers"):
                with self.assertRaises(PolicyDenied) as cm:
                    self.b.submit(["/usr/bin/ls", link], "/tmp", 1000, "")
        self.assertIn("protected path", str(cm.exception))
        self.assertIn("/etc/sudoers", str(cm.exception))

    def test_link_resolving_into_a_telepathy_named_dir_is_not_newly_denied(self):
        # The "mentions telepathy" rule is about the argument as written.
        with tempfile.TemporaryDirectory() as td:
            td = os.path.realpath(td)
            real = os.path.join(td, "telepathy-checkout", "README.md")
            os.makedirs(os.path.dirname(real))
            open(real, "w").close()
            link = os.path.join(td, "x")
            os.symlink(real, link)
            chk = policy_mod.check_guarded(self.b.policy, ["/usr/bin/ls", link], "/tmp", -1)
        self.assertEqual(chk.decision.kind, "ask")
        self.assertEqual(chk.resolved, {link: real})

    def test_frozen_executable_target_gets_the_executable_checks(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(os.path.realpath(td), "tool")
            os.symlink("/usr/bin/ls", exe)
            # Flip argv[0] to a shell between evaluate and the freeze.
            with self._flip_before_freeze(exe, "/usr/bin/bash"):
                chk = policy_mod.check_guarded(self.b.policy, [exe], "/tmp", -1)
        self.assertEqual(chk.decision.kind, "deny")
        self.assertEqual(chk.resolved, {})
        self.assertIsNone(chk.problem)

    @unittest.skipIf(os.geteuid() == 0, "the planted file must not be root-owned")
    def test_flip_to_an_agent_owned_executable_is_denied_by_ownership(self):
        with tempfile.TemporaryDirectory() as td:
            td = os.path.realpath(td)
            exe = os.path.join(td, "tool")
            os.symlink("/usr/bin/ls", exe)
            mine = os.path.join(td, "harmless-name")  # not a denied name; owned by the test user
            with open(mine, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(mine, 0o755)
            with self._flip_before_freeze(exe, mine):
                chk = policy_mod.check_guarded(Policy.empty(), [exe], "/tmp", -1)
        self.assertEqual(chk.decision.kind, "deny")
        self.assertIn("not owned by root", chk.decision.reason)

    def test_flip_to_an_operator_denied_executable_is_denied(self):
        pol = Policy(extra_deny_exe=frozenset({"cat"}))
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(os.path.realpath(td), "tool")
            os.symlink("/usr/bin/ls", exe)
            with self._flip_before_freeze(exe, "/usr/bin/cat"):
                chk = policy_mod.check_guarded(pol, [exe], "/tmp", -1)
        self.assertEqual(chk.decision.kind, "deny")
        self.assertIn("cat", chk.decision.reason)

    def test_flip_to_a_trusted_harmless_executable_still_asks(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(os.path.realpath(td), "tool")
            os.symlink("/usr/bin/ls", exe)
            with self._flip_before_freeze(exe, "/usr/bin/cat"):
                chk = policy_mod.check_guarded(Policy.empty(), [exe], "/tmp", -1)
        self.assertEqual(chk.decision.kind, "ask")
        self.assertEqual(chk.resolved, {exe: os.path.realpath("/usr/bin/cat")})

    @unittest.skipIf(os.geteuid() == 0, "the planted file must not be root-owned")
    def test_exe_link_replaced_by_an_agent_file_leaves_no_entry_and_is_denied(self):
        # Executable, no frozen entry: the link is gone, so nothing is frozen.
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(os.path.realpath(td), "tool")
            os.symlink("/usr/bin/ls", exe)
            real = policy_mod.resolve_path_args

            def replace(*a, **kw):
                os.unlink(exe)
                with open(exe, "w") as f:
                    f.write("#!/bin/sh\n")
                os.chmod(exe, 0o755)
                return real(*a, **kw)
            with mock.patch.object(policy_mod, "resolve_path_args", replace):
                chk = policy_mod.check_guarded(Policy.empty(), [exe], "/tmp", -1)
        self.assertEqual(chk.decision.kind, "deny")
        self.assertIn("not owned by root", chk.decision.reason)

    def test_plain_trusted_exe_without_entry_still_asks(self):
        self.assertIsNone(Policy.empty().check_targets(["/usr/bin/ls", "-l"], {}, "/tmp"))

    def test_path_arg_without_entry_gets_the_protected_check(self):
        d = self.b.policy.check_targets(["/usr/bin/cat", "/etc/sudoers"], {}, "/tmp")
        self.assertEqual(d.kind, "deny")

    def test_relative_arg_without_frozen_cwd_is_checked_from_the_cwd(self):
        d = self.b.policy.check_targets(["/usr/bin/cat", "sudoers"], {}, "/etc")
        self.assertEqual(d.kind, "deny")

    def test_exe_name_as_written_is_denied_even_if_the_target_is_not(self):
        pol = Policy(extra_deny_exe=frozenset({"tool"}))
        d = pol.check_targets(["/x/tool"], {"/x/tool": "/usr/bin/ls"}, "/tmp")
        self.assertEqual(d.kind, "deny")

    def test_unresolvable_frozen_executable_is_denied(self):
        with mock.patch.object(policy_mod, "_exe_names", side_effect=OSError("loop")):
            d = self.b.policy.check_targets(["/a"], {"/a": "/b"})
        self.assertEqual(d.kind, "deny")
        self.assertIn("cannot resolve the executable", d.reason)

    def test_cwd_flipped_to_a_protected_dir_denies_relative_args(self):
        pre = None
        with tempfile.TemporaryDirectory() as td:
            td = os.path.realpath(td)
            safe = os.path.join(td, "safe"); os.makedirs(safe)
            prot = os.path.join(td, "prot"); os.makedirs(prot)
            cwd = os.path.join(td, "work")
            os.symlink(safe, cwd)
            with mock.patch.object(policy_mod, "PROTECTED_PREFIXES", (prot,)), \
                 self._flip_before_freeze(cwd, prot):
                chk = policy_mod.check_guarded(self.b.policy, ["/usr/bin/cat", "secret"], cwd, -1)
        self.assertEqual(chk.decision.kind, "deny")
        self.assertIn("protected path", chk.decision.reason)
        self.assertEqual(chk.resolved, {})

    def test_cwd_flip_leaves_absolute_args_and_plain_flags_alone(self):
        with tempfile.TemporaryDirectory() as td:
            td = os.path.realpath(td)
            safe = os.path.join(td, "safe"); os.makedirs(safe)
            other = os.path.join(td, "other"); os.makedirs(other)
            cwd = os.path.join(td, "work")
            os.symlink(safe, cwd)
            with self._flip_before_freeze(cwd, other):
                chk = policy_mod.check_guarded(self.b.policy, ["/usr/bin/ls", "-l", "x"], cwd, -1)
        self.assertEqual(chk.decision.kind, "ask")
        self.assertEqual(chk.resolved, {cwd: other})

    def test_unresolvable_frozen_cwd_is_denied(self):
        d = self.b.policy.check_targets(["/usr/bin/ls", "x"], {"/w": policy_mod.UNRESOLVABLE}, "/w")
        self.assertEqual(d.kind, "deny")

    def test_symlinked_cwd_is_not_newly_denied(self):
        with tempfile.TemporaryDirectory() as td:
            td = os.path.realpath(td)
            real = os.path.join(td, "telepathy-checkout")
            os.makedirs(real)
            cwd = os.path.join(td, "work")
            os.symlink(real, cwd)
            chk = policy_mod.check_guarded(self.b.policy, ["/usr/bin/ls"], cwd, -1)
        self.assertEqual(chk.decision.kind, "ask")
        self.assertEqual(chk.resolved, {cwd: real})

    def test_marker_from_resolution_skips_the_late_check_and_is_kept(self):
        marker = {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT}
        with mock.patch.object(policy_mod, "resolve_path_args", return_value=marker), \
             mock.patch.object(Policy, "check_targets") as late:
            chk = policy_mod.check_guarded(self.b.policy, ["/usr/bin/ls"], "/tmp", -1)
        late.assert_not_called()
        self.assertEqual(chk.decision.kind, "ask")
        self.assertEqual(chk.resolved, marker)

    def test_harmless_frozen_target_still_asks_and_is_kept(self):
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "x")
            os.symlink("/usr/share/doc", link)
            with self._flip_before_freeze(link, "/usr/share/man"):
                chk = policy_mod.check_guarded(self.b.policy, ["/usr/bin/ls", link], "/tmp", -1)
        self.assertEqual(chk.decision.kind, "ask")
        self.assertEqual(chk.resolved, {link: os.path.realpath("/usr/share/man")})

    def test_unresolvable_and_marker_targets_are_left_to_the_run_check(self):
        pol = self.b.policy
        self.assertIsNone(pol.check_targets(["/usr/bin/ls", "/a"], {"/a": policy_mod.UNRESOLVABLE}))
        self.assertIsNone(pol.check_targets(["/usr/bin/ls"], {}))

    def test_check_targets_raising_fails_closed_as_unverified(self):
        with mock.patch.object(Policy, "check_targets", side_effect=RuntimeError("x")), \
             mock.patch.object(policy_mod, "resolve_path_args", return_value={"/a": "/b"}):
            chk = policy_mod.check_guarded(self.b.policy, ["/usr/bin/ls", "/a"], "/tmp", -1)
        self.assertEqual(chk.resolved, {policy_mod.ERROR_KEY: policy_mod.ERROR})
        self.assertIsNotNone(policy_mod.unverified(chk.resolved))


class PreCheckBroker(Base):
    """Broker.precheck only reports transient check problems and changes nothing."""

    def _timeout(self, problem="timeout"):
        return policy_mod.CheckResult(policy_mod.Decision("deny", "x"),
                                      {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT}, problem)

    def _approved(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "p")
        return r

    def test_transient_problem_is_reported_and_audited_without_a_state_change(self):
        r = self._approved()
        for problem in ("timeout", "busy"):
            with mock.patch("telepathy.broker.check_guarded", return_value=self._timeout(problem)):
                self.assertEqual(self.b.precheck(r.id), problem)
            self.assertEqual(r.state, State.APPROVED)
        ev = [json.loads(x) for x in self.log if '"run_unverified"' in x]
        self.assertEqual([(e["stage"], e["cause"]) for e in ev],
                         [("precheck", "timeout"), ("precheck", "busy")])

    def test_ok_error_and_deny_go_to_the_worker(self):
        r = self._approved()
        self.assertIsNone(self.b.precheck(r.id))
        err = policy_mod.CheckResult(policy_mod.Decision("deny", "boom"),
                                     {policy_mod.ERROR_KEY: policy_mod.ERROR}, "error")
        with mock.patch("telepathy.broker.check_guarded", return_value=err):
            self.assertIsNone(self.b.precheck(r.id))
        deny = policy_mod.CheckResult(policy_mod.Decision("deny", "protected"), {})
        with mock.patch("telepathy.broker.check_guarded", return_value=deny):
            self.assertIsNone(self.b.precheck(r.id))
        self.assertEqual(r.state, State.APPROVED)
        self.assertNotIn("run_unverified", self.events())

    def test_not_approved_is_left_alone_quietly(self):
        pending = self.submit()
        cancelled = self.submit()
        self.b.cancel(cancelled.id, 1000)
        before = list(self.log)
        with mock.patch("telepathy.broker.check_guarded") as chk:
            for rid in (pending.id, cancelled.id, "nope"):
                self.assertIsNone(self.b.precheck(rid))
        chk.assert_not_called()
        self.assertEqual(self.log, before)

    def test_cancel_during_the_check_is_not_audited_as_unverified(self):
        r = self._approved()

        def cancel_meanwhile(*a, **k):
            self.b.cancel(r.id, 1000)
            return self._timeout()
        with mock.patch("telepathy.broker.check_guarded", cancel_meanwhile):
            self.assertIsNone(self.b.precheck(r.id))
        self.assertEqual(r.state, State.CANCELLED)
        self.assertNotIn("run_unverified", self.events())

    def test_expired_is_left_alone(self):
        r = self._approved()
        self.clock.t += 10_000
        self.b.sweep()
        with mock.patch("telepathy.broker.check_guarded") as chk:
            self.assertIsNone(self.b.precheck(r.id))
        chk.assert_not_called()


class MonotonicClock(unittest.TestCase):
    def test_select_boottime_uses_boottime_when_present(self):
        with mock.patch.object(time, "CLOCK_BOOTTIME", 7, create=True):
            clock = select_boottime()
            self.assertIsNot(clock, time.monotonic)
            with mock.patch("time.clock_gettime", return_value=42.0) as g:
                self.assertEqual(clock(), 42.0)
            g.assert_called_once_with(7)

    def test_select_boottime_falls_back_to_monotonic_when_missing(self):
        with mock.patch.object(time, "CLOCK_BOOTTIME", 7, create=True):
            del time.CLOCK_BOOTTIME  # hide it, as on macOS/Windows
            self.assertFalse(hasattr(time, "CLOCK_BOOTTIME"))
            self.assertIs(select_boottime(), time.monotonic)

    def test_default_clock_is_boottime(self):
        self.assertIs(Broker(Policy.empty()).clock, boottime)

    def test_suspend_gap_expires_requests(self):
        # CLOCK_MONOTONIC would not advance while suspended; CLOCK_BOOTTIME does.
        # Simulate a 2h suspend as a jump of the broker's (boottime) clock.
        now = [1000.0]
        b = Broker(Policy.empty(), Limits(ttl=600), clock=lambda: now[0])
        r = b.submit(["/usr/bin/x"], "/tmp", 1000, "")
        self.assertEqual(b.get(r.id).state, State.PENDING)
        now[0] += 7200
        with self.assertRaises(Expired):
            b.issue_nonce(r.id)
        self.assertEqual(r.state, State.EXPIRED)

    def test_wall_clock_steps_do_not_change_expiry_or_rate_window(self):
        now = [1000.0]
        b = Broker(Policy.empty(), Limits(ttl=600, max_per_hour=2), clock=lambda: now[0])
        with mock.patch("time.time", return_value=1e9):
            r = b.submit(["/usr/bin/x"], "/tmp", 1000, "")
            b.submit(["/usr/bin/y"], "/tmp", 1000, "")  # 2nd, still allowed
        for jump in (-10_000_000, +10_000_000):
            with mock.patch("time.time", return_value=1e9 + jump):
                self.assertEqual(b.get(r.id).state, State.PENDING)
                self.assertEqual(b.view(r)["expires_in"], 600)
                with self.assertRaises(RateLimited):
                    b.submit(["/usr/bin/z"], "/tmp", 1000, "")
        # The window only moves with the broker's own clock.
        now[0] += 3600
        with mock.patch("time.time", return_value=1e9):
            b.submit(["/usr/bin/z"], "/tmp", 1000, "")


class _HangHarness(Base):
    """A hung path stalls one request, not the broker, and the number of
    stuck workers is bounded. Synchronised with Events and Barriers; the
    wall-clock bounds below are only hang guards."""

    HANG = "/tmp/HANGMOUNT/x"
    GUARD = 10  # seconds: a hang guard, never a timing assertion

    def setUp(self):
        super().setUp()
        self.gate = threading.Event()      # set to let hung filesystem calls return
        self.entered = threading.Event()   # a call is now blocked
        self.armed = True
        real = os.path.realpath

        def realpath(p, *a, **k):
            if self.armed and "HANGMOUNT" in str(p):
                self.entered.set()
                self.gate.wait(self.GUARD)
            return real(p, *a, **k)
        self.addCleanup(self.gate.set)
        self._patch(mock.patch.object(policy_mod.os.path, "realpath", realpath))
        self._patch(mock.patch.object(policy_mod, "RESOLVE_TIMEOUT", 0.2))
        self._patch(mock.patch.object(policy_mod, "_CHECK_SLOTS",
                                      threading.BoundedSemaphore(4)))

    def _patch(self, p):
        p.start()
        self.addCleanup(p.stop)

    def _in_thread(self, fn):
        out = {}

        def run():
            try:
                out["r"] = fn()
            except BaseException as e:
                out["e"] = e
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t, out

    def _wait_slot_free(self, n=1):
        """Block until `n` guarded workers have really finished (slots back)."""
        got = []
        for _ in range(n):
            self.assertTrue(policy_mod._CHECK_SLOTS.acquire(timeout=self.GUARD))
            got.append(1)
        for _ in got:
            policy_mod._CHECK_SLOTS.release()

    def _hung_submit(self):
        return self._in_thread(
            lambda: self.b.submit(["/usr/bin/ls", self.HANG], "/tmp", 1000, ""))


class HungFilesystem(_HangHarness):
    """See _HangHarness."""

    def test_hung_submit_does_not_block_other_operations(self):
        self._patch(mock.patch.object(policy_mod, "RESOLVE_TIMEOUT", 60))  # stays stuck
        stuck, sout = self._hung_submit()
        self.assertTrue(self.entered.wait(self.GUARD))

        def others():
            other = self.b.submit(ASK, "/tmp", 1001, "")
            self.b.pending()
            self.b.get(other.id)
            self.b.view(other)
            self.b.issue_nonce(other.id)
            return other
        t, out = self._in_thread(others)
        t.join(self.GUARD)
        self.assertFalse(t.is_alive(), "other operations were blocked by a hung path")
        self.assertIn("r", out)
        self.assertTrue(stuck.is_alive())  # still stuck: the others did not wait for it
        self.gate.set()
        stuck.join(self.GUARD)
        self.assertIn("r", sout)

    def test_hung_evaluate_at_submit_fails_closed_with_its_own_event(self):
        t, out = self._hung_submit()
        t.join(self.GUARD)
        self.assertIsInstance(out["e"], PolicyDenied)
        self.assertEqual(out["e"].decision.kind, "deny")
        self.assertIn("check_timeout", self.events())
        self.assertNotIn("policy_denied", self.events())
        self.assertEqual(self.b.pending(), [])

    def test_failed_submit_releases_its_pending_slot(self):
        t, out = self._hung_submit()
        t.join(self.GUARD)
        self.assertEqual(self.b._inflight, 0)
        for _ in range(3):
            self.submit()  # max_pending is 3: all fit

    def test_evaluate_exception_fails_closed_with_its_own_event(self):
        with mock.patch.object(Policy, "evaluate", side_effect=RuntimeError("x")):
            with self.assertRaises(PolicyDenied):
                self.submit()
        self.assertIn("check_error", self.events())

    def test_hung_run_time_check_is_transient_and_leaves_request_approved(self):
        self.armed = False  # fast at submit and approval, hangs by run time
        r = self.b.submit(["/usr/bin/ls", self.HANG], "/tmp", 1000, "")
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        self.armed = True
        with self.assertRaises(CheckUnavailable):
            self.b.begin_run(r.id)
        self.assertEqual(r.state, State.APPROVED)
        self.assertIn("run_unverified", self.events())
        self.assertNotIn("run_start", self.events())
        self.assertNotIn("policy_denied_at_run", self.events())
        self.armed = False  # the mount recovers
        self.gate.set()
        self.assertIs(self.b.begin_run(r.id), r)
        self.assertEqual(r.state, State.RUNNING)

    def test_real_policy_deny_at_run_time_stays_terminal(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        with mock.patch.object(Policy, "evaluate",
                               return_value=policy_mod.Decision("deny", "protected")):
            with self.assertRaises(PolicyDenied):
                self.b.begin_run(r.id)
        self.assertEqual(r.state, State.DENIED)
        self.assertIn("policy_denied_at_run", self.events())

    def test_hang_in_resolve_alone_keeps_the_decision(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        def hang(argv, cwd, trusted_uid=0):
            gate.wait(self.GUARD)
            return {}
        with mock.patch.object(policy_mod, "resolve_path_args", hang):
            chk = policy_mod.check_guarded(Policy.from_toml(AUTO), AUTO_ARGV, "/tmp")
        self.assertIsNone(chk.problem)
        self.assertEqual(chk.decision.kind, "auto")
        self.assertEqual(chk.resolved, {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT})

    def test_late_worker_cannot_change_a_snapshotted_result(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        class Slow:
            def evaluate(self_, argv, cwd):
                gate.wait(self.GUARD)
                return policy_mod.Decision("ask", "late")
        chk = policy_mod.check_guarded(Slow(), ["/usr/bin/ls"], "/tmp")
        self.assertEqual(chk.problem, "timeout")
        self.assertEqual(chk.decision.kind, "deny")
        gate.set()
        self._wait_slot_free(4)  # the worker really finished
        self.assertEqual(chk.problem, "timeout")
        self.assertEqual(chk.resolved, {policy_mod.TIMED_OUT_KEY: policy_mod.TIMED_OUT})

    def test_worker_slots_are_bounded_and_freed_when_the_thread_finishes(self):
        self._patch(mock.patch.object(policy_mod, "_CHECK_SLOTS", threading.BoundedSemaphore(1)))
        t, out = self._hung_submit()
        t.join(self.GUARD)  # timed out after 0.2 s; its worker is still stuck
        self.assertIn("check_timeout", self.events())
        t2, out2 = self._in_thread(lambda: self.b.submit(ASK, "/tmp", 1000, ""))
        t2.join(self.GUARD)
        self.assertIsInstance(out2["e"], PolicyDenied)  # busy: no new thread was spawned
        self.assertIn("check_busy", self.events())
        self.assertEqual(self.b._inflight, 0)
        self.gate.set()
        self._wait_slot_free(1)  # freed by the worker finishing, not by the caller giving up
        self.assertIsNotNone(self.submit())

    def test_busy_at_run_time_is_transient(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        sem = threading.BoundedSemaphore(1)
        sem.acquire()
        with mock.patch.object(policy_mod, "_CHECK_SLOTS", sem):
            with self.assertRaises(CheckUnavailable):
                self.b.begin_run(r.id)
        self.assertEqual(r.state, State.APPROVED)
        self.assertIs(self.b.begin_run(r.id), r)

    def test_evaluate_crash_at_run_time_is_terminal(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        with mock.patch.object(Policy, "evaluate", side_effect=RuntimeError("x")):
            with self.assertRaises(PolicyDenied) as cm:
                self.b.begin_run(r.id)
        self.assertIn("unexpected error", str(cm.exception))
        self.assertEqual(r.state, State.DENIED)
        self.assertIn("policy_error_at_run", self.events())
        self.assertNotIn("run_unverified", self.events())

    def test_check_problem_at_submit_refunds_the_hourly_token(self):
        # max_per_hour is 5: six "try again" denials must not trip RateLimited
        for _ in range(6):
            with mock.patch.object(Policy, "evaluate", side_effect=RuntimeError("x")):
                with self.assertRaises(PolicyDenied):
                    self.submit()
        self.assertEqual(len(self.b._submits), 0)
        self.submit()

    def test_real_deny_still_costs_a_token(self):
        for _ in range(5):
            with self.assertRaises(PolicyDenied):
                self.b.submit(["/usr/bin/ls", "telepathy"], "/tmp", 1000, "")
        with self.assertRaises(RateLimited):
            self.submit()

    def test_audit_failure_does_not_leak_an_inflight_slot(self):
        def boom(line):
            if '"invalid"' in line:
                raise OSError("audit disk full")
            self.log.append(line)
        b = Broker(Policy.from_toml(AUTO), Limits(ttl=600, max_pending=3, max_per_hour=50),
                   AuditLog(boom, clock=self.clock), clock=self.clock, link_trusted_uid=-1)
        for _ in range(5):
            with self.assertRaises(OSError):
                b.submit([], "/tmp", 1000, "")
        self.assertEqual(b._inflight, 0)
        for _ in range(3):
            b.submit(ASK, "/tmp", 1000, "")

    def test_deny_without_resolution_resolves_to_empty(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        class Pol:
            def evaluate(self_, argv, cwd):
                return policy_mod.Decision("deny", "no")
        with mock.patch.object(policy_mod, "resolve_path_args",
                               side_effect=AssertionError("must not resolve a deny")):
            chk = policy_mod.check_guarded(Pol(), ["/x"], "/tmp")
        self.assertEqual((chk.decision.kind, chk.resolved, chk.problem), ("deny", {}, None))

    def test_deny_published_but_resolution_never_is_empty_not_timed_out(self):
        gate = threading.Event()
        self.addCleanup(gate.set)

        class SlowDeny:
            reason = "no"

            calls = 0

            @property
            def kind(self_):
                SlowDeny.calls += 1
                if SlowDeny.calls == 1:  # the worker, after publishing the decision
                    gate.wait(self.GUARD)
                return "deny"

        class Pol:
            def evaluate(self_, argv, cwd):
                return SlowDeny()
        # The caller's snapshot sees the deny but no resolution yet.
        chk = policy_mod.check_guarded(Pol(), ["/x"], "/tmp")
        self.assertEqual((chk.problem, chk.resolved), (None, {}))

    def _held_check(self, parties):
        """A check_guarded stand-in that blocks until `parties` callers are inside."""
        barrier = threading.Barrier(parties)
        real_check = policy_mod.check_guarded

        def held(*a, **k):
            barrier.wait(self.GUARD)
            return real_check(*a, **k)
        return barrier, held

    def test_cancel_wins_race_with_begin_run(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        barrier, held = self._held_check(2)  # begin_run + this test
        with mock.patch("telepathy.broker.check_guarded", held):
            t, out = self._in_thread(lambda: self.b.begin_run(r.id))
            # begin_run is inside its check, so the lock is free
            changed = self.b.cancel(r.id, 1000)[1]
            barrier.wait(self.GUARD)
            t.join(self.GUARD)
        self.assertTrue(changed)
        self.assertIsInstance(out["e"], NotRunnable)
        self.assertEqual(r.state, State.CANCELLED)
        self.assertNotIn("run_start", self.events())

    def test_expiry_during_check_wins_over_begin_run(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        barrier, held = self._held_check(2)
        with mock.patch("telepathy.broker.check_guarded", held):
            t, out = self._in_thread(lambda: self.b.begin_run(r.id))
            self.clock.t += 601
            barrier.wait(self.GUARD)
            t.join(self.GUARD)
        self.assertIsInstance(out["e"], Expired)
        self.assertNotIn("run_start", self.events())

    def test_concurrent_begin_runs_start_only_once(self):
        r = self.submit()
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        _, held = self._held_check(2)  # both are inside their check at once
        with mock.patch("telepathy.broker.check_guarded", held):
            ts = [self._in_thread(lambda: self.b.begin_run(r.id)) for _ in range(2)]
            for t, _ in ts:
                t.join(self.GUARD)
        self.assertEqual(self.events().count("run_start"), 1)
        self.assertEqual(sum("e" in o for _, o in ts), 1)
        self.assertEqual(self.events().count("run_refused"), 1)

    def test_max_pending_holds_under_concurrent_submits(self):
        n = 8
        barrier, held = self._held_check(4)  # the 3 admitted submits + this test
        with mock.patch("telepathy.broker.check_guarded", held):
            ts = [self._in_thread(lambda: self.b.submit(ASK, "/tmp", 1000, ""))
                  for _ in range(n)]
            barrier.wait(self.GUARD)  # exactly 3 reached the check; 5 were refused
            for t, _ in ts:
                t.join(self.GUARD)
        ok = [o for _, o in ts if "r" in o]
        limited = [o for _, o in ts if isinstance(o.get("e"), RateLimited)]
        self.assertEqual((len(ok), len(limited)), (3, n - 3))
        self.assertEqual(len(self.b.pending()), 3)
        self.assertEqual(self.b._inflight, 0)

    def test_check_time_does_not_eat_the_approval_window(self):
        real_check = policy_mod.check_guarded

        def slow(*a, **k):
            self.clock.t += 500  # the check "took" 500 s
            return real_check(*a, **k)
        with mock.patch("telepathy.broker.check_guarded", slow):
            r = self.submit()
        self.assertEqual(r.expires_at, self.clock.t + 600)


class FairCheckSlots(_HangHarness):
    """One agent's stuck submit checks cannot starve other agents' submits or
    the run-time checks of approved requests."""

    def setUp(self):
        super().setUp()
        self._patch(mock.patch.object(policy_mod, "_CHECK_SLOTS",
                                      threading.BoundedSemaphore(policy_mod.MAX_CHECK_WORKERS)))
        # A fresh quota per test: workers left over from other tests give back to
        # the quota they took from, never to this one.
        self._patch(mock.patch.object(policy_mod, "_SUBMIT_QUOTA", policy_mod._SubmitQuota()))
        self.b.limits = Limits(ttl=600, max_pending=50, max_per_hour=500)

    def _stuck(self, uid, n):
        """n submits by uid whose checks time out and stay stuck (holding quota)."""
        for _ in range(n):
            with self.assertRaises(PolicyDenied):
                self.b.submit(["/usr/bin/ls", self.HANG], "/tmp", uid, "")
        self.assertIn("check_timeout", self.events())

    def _release_all(self):
        self.gate.set()
        end = time.monotonic() + self.GUARD
        while policy_mod.submit_quota_snapshot()[0] and time.monotonic() < end:
            time.sleep(0.01)
        self._wait_slot_free(policy_mod.MAX_CHECK_WORKERS)

    def test_one_uid_at_its_cap_does_not_block_another_uid(self):
        self._stuck(1000, policy_mod.MAX_SUBMIT_CHECKS_PER_UID)
        self.assertEqual(policy_mod.submit_quota_snapshot(),
                         (3, {1000: 3}))
        with self.assertRaises(PolicyDenied) as cm:
            self.b.submit(ASK, "/tmp", 1000, "")  # over its own cap: busy, fails closed
        self.assertIn("try again", str(cm.exception))
        self.assertEqual(self.events()[-1], "check_busy")
        self.assertEqual(self.b.submit(ASK, "/tmp", 1001, "").state, State.PENDING)
        self._release_all()
        self.assertEqual(policy_mod.submit_quota_snapshot(), (0, {}))
        self.assertEqual(self.b.submit(ASK, "/tmp", 1000, "").state, State.PENDING)

    def test_submit_total_cap_keeps_slots_for_run_time_checks(self):
        approved = self.b.submit(ASK, "/tmp", 1002, "")
        self.b.approve(approved.id, self.b.issue_nonce(approved.id), "t")
        self._stuck(1000, 3)
        self._stuck(1001, 3)
        self.assertEqual(policy_mod.submit_quota_snapshot()[0], policy_mod.MAX_SUBMIT_CHECKS)
        with self.assertRaises(PolicyDenied):
            self.b.submit(ASK, "/tmp", 1002, "")  # total submit cap reached
        self.assertEqual(self.events()[-1], "check_busy")
        # The approved request's run-time check still gets one of the reserved slots.
        self.assertIs(self.b.begin_run(approved.id), approved)
        self._release_all()

    def test_run_time_checks_do_not_take_submit_quota(self):
        r = self.b.submit(ASK, "/tmp", 1000, "")
        self.b.approve(r.id, self.b.issue_nonce(r.id), "t")
        seen = []
        q = policy_mod._SUBMIT_QUOTA
        real = q.take
        with mock.patch.object(q, "take", side_effect=lambda uid: seen.append(uid) or real(uid)):
            self.assertIsNone(self.b.precheck(r.id))
            self.b.begin_run(r.id)
        self.assertEqual(seen, [])
        self.assertEqual(policy_mod.submit_quota_snapshot(), (0, {}))

    def test_quota_is_given_back_when_no_slot_is_free(self):
        sem = threading.BoundedSemaphore(1)
        sem.acquire()
        with mock.patch.object(policy_mod, "_CHECK_SLOTS", sem):
            with self.assertRaises(PolicyDenied):
                self.b.submit(ASK, "/tmp", 1000, "")
        self.assertEqual(self.events()[-1], "check_busy")
        self.assertEqual(policy_mod.submit_quota_snapshot(), (0, {}))

    def test_quota_and_slot_are_given_back_if_the_thread_cannot_start(self):
        with mock.patch.object(policy_mod.threading.Thread, "start",
                               side_effect=RuntimeError("can't start new thread")):
            with self.assertRaises(RuntimeError):
                policy_mod.check_guarded(Policy.empty(), ["/usr/bin/ls"], "/tmp", submitter=1000)
        self.assertEqual(policy_mod.submit_quota_snapshot(), (0, {}))
        self._wait_slot_free(policy_mod.MAX_CHECK_WORKERS)

    def test_check_error_gives_the_quota_back(self):
        with mock.patch.object(Policy, "evaluate", side_effect=RuntimeError("x")):
            for _ in range(policy_mod.MAX_SUBMIT_CHECKS_PER_UID + 1):
                with self.assertRaises(PolicyDenied):
                    self.b.submit(ASK, "/tmp", 1000, "")
        self.assertEqual(self.events().count("check_error"), policy_mod.MAX_SUBMIT_CHECKS_PER_UID + 1)
        self._release_all()
        self.assertEqual(policy_mod.submit_quota_snapshot(), (0, {}))

    def test_per_uid_share_only_with_several_allowed_uids(self):
        q = policy_mod._SUBMIT_QUOTA
        policy_mod.configure_submit_quota([1000])
        self.assertEqual(q.per_uid, policy_mod.MAX_SUBMIT_CHECKS)
        self._stuck(1000, 4)  # more than the per-uid share: a single uid may use the total
        self.assertEqual(policy_mod.submit_quota_snapshot(), (4, {1000: 4}))
        policy_mod.configure_submit_quota([1000, 1001])
        self.assertEqual(q.per_uid, policy_mod.MAX_SUBMIT_CHECKS_PER_UID)
        self._release_all()

    def test_busy_from_the_quota_gives_the_hourly_token_back(self):
        self.b.limits = Limits(ttl=600, max_pending=50, max_per_hour=4)
        self._stuck(1000, 3)   # 3 tokens, each given back (timeouts)
        with self.assertRaises(PolicyDenied):
            self.b.submit(ASK, "/tmp", 1000, "")   # busy: token given back too
        self._release_all()
        for _ in range(4):     # the whole hourly allowance is still there
            self.b.submit(ASK, "/tmp", 1000 + _, "")


if __name__ == "__main__":
    unittest.main()
