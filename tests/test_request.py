import unittest

from telepathy.request import (
    DEFAULT_ENV,
    InvalidRequest,
    InvalidTransition,
    Request,
    State,
    compute_hash,
    validate_argv,
)

ARGV = ["/usr/bin/pacman", "-S", "--needed", "htop"]


def make(**kw):
    args = dict(argv=ARGV, cwd="/tmp", uid=1000, reason="install htop", now=100.0, ttl=600.0)
    args.update(kw)
    return Request.new(**args)


class ValidateArgv(unittest.TestCase):
    def test_accepts_list(self):
        self.assertEqual(validate_argv(ARGV), tuple(ARGV))

    def test_rejects_shell_string(self):
        with self.assertRaises(InvalidRequest):
            validate_argv("pacman -S htop")

    def test_rejects_relative_exe(self):
        with self.assertRaises(InvalidRequest):
            validate_argv(["pacman", "-S", "htop"])

    def test_rejects_empty_and_non_string_and_nul(self):
        for bad in ([], ["/bin/ls", 3], ["/bin/ls", "a\0b"]):
            with self.assertRaises(InvalidRequest):
                validate_argv(bad)

    def test_rejects_oversize(self):
        with self.assertRaises(InvalidRequest):
            validate_argv(["/bin/ls"] + ["x"] * 300)
        with self.assertRaises(InvalidRequest):
            validate_argv(["/bin/ls", "x" * 9000])


class Hashing(unittest.TestCase):
    def test_stable_and_hex(self):
        h = compute_hash(ARGV, "/tmp", DEFAULT_ENV, 1000)
        self.assertEqual(h, compute_hash(ARGV, "/tmp", DEFAULT_ENV, 1000))
        self.assertEqual(len(h), 64)

    def test_every_field_matters(self):
        base = compute_hash(ARGV, "/tmp", DEFAULT_ENV, 1000)
        self.assertNotEqual(base, compute_hash(ARGV + ["x"], "/tmp", DEFAULT_ENV, 1000))
        self.assertNotEqual(base, compute_hash(ARGV, "/var", DEFAULT_ENV, 1000))
        self.assertNotEqual(base, compute_hash(ARGV, "/tmp", DEFAULT_ENV, 0))
        self.assertNotEqual(base, compute_hash(ARGV, "/tmp", (("PATH", "/evil"),), 1000))

    def test_argv_boundaries_not_ambiguous(self):
        a = compute_hash(["/bin/echo", "a b"], "/", DEFAULT_ENV, 1)
        b = compute_hash(["/bin/echo", "a", "b"], "/", DEFAULT_ENV, 1)
        self.assertNotEqual(a, b)

    def test_request_hash_matches_recompute(self):
        r = make()
        self.assertEqual(r.hash, r.recompute_hash())
        r.argv = r.argv + ("--extra",)
        self.assertNotEqual(r.hash, r.recompute_hash())


class StateMachine(unittest.TestCase):
    def test_happy_path(self):
        r = make()
        for s in (State.APPROVED, State.RUNNING, State.DONE):
            r.transition(s)
        self.assertEqual(r.state, State.DONE)

    def test_cannot_run_without_approval(self):
        with self.assertRaises(InvalidTransition):
            make().transition(State.RUNNING)

    def test_terminal_states_are_final(self):
        for terminal in (State.DENIED, State.EXPIRED):
            r = make()
            r.transition(terminal)
            for s in State:
                with self.assertRaises(InvalidTransition):
                    r.transition(s)

    def test_cannot_reapprove_or_rerun(self):
        r = make()
        r.transition(State.APPROVED)
        with self.assertRaises(InvalidTransition):
            r.transition(State.APPROVED)
        r.transition(State.RUNNING)
        with self.assertRaises(InvalidTransition):
            r.transition(State.RUNNING)


class Nonce(unittest.TestCase):
    def test_consume_once(self):
        r = make()
        n = r.issue_nonce()
        self.assertFalse(r.consume_nonce("wrong"))
        self.assertTrue(r.consume_nonce(n))
        self.assertFalse(r.consume_nonce(n))

    def test_reissue_invalidates_old(self):
        r = make()
        old = r.issue_nonce()
        new = r.issue_nonce()
        self.assertFalse(r.consume_nonce(old))
        self.assertTrue(r.consume_nonce(new))

    def test_none_and_non_string(self):
        r = make()
        self.assertFalse(r.consume_nonce("anything"))
        r.issue_nonce()
        self.assertFalse(r.consume_nonce(None))

    def test_public_view_hides_nonce(self):
        r = make()
        n = r.issue_nonce()
        self.assertNotIn(n, str(r.public(now=0.0)))


class Fields(unittest.TestCase):
    def test_expiry_and_reason_truncation(self):
        r = make(reason="x" * 2000)
        self.assertEqual(r.expires_at, 700.0)
        self.assertEqual(r.public(now=100.0)["expires_in"], 600.0)
        self.assertEqual(len(r.reason), 500)

    def test_expires_in_is_clamped_at_zero(self):
        r = make()
        self.assertEqual(r.public(now=r.expires_at)["expires_in"], 0.0)
        self.assertEqual(r.public(now=r.expires_at + 99)["expires_in"], 0.0)

    def test_bad_uid_and_cwd(self):
        for kw in ({"uid": -1}, {"uid": "0"}, {"uid": True}, {"cwd": "tmp"}):
            with self.assertRaises(InvalidRequest):
                make(**kw)


if __name__ == "__main__":
    unittest.main()
