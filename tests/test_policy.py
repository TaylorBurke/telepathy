import errno
import os
import threading
import time
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from telepathy import policy as policy_mod
from telepathy.policy import UNRESOLVABLE, Policy, PolicyError, resolve_path_args

TOML = """
[patterns]
pkg = '[a-z0-9@_+][a-z0-9@._+-]*'

[deny]
executables = ["dd"]

[[auto]]
name = "pacman-install"
argv = ["/usr/bin/pacman", "-S", "--needed", "--noconfirm", "@pkg..."]

[[auto]]
name = "restart-nginx"
argv = ["/usr/bin/systemctl", "restart", "nginx.service"]
"""


def ev(policy, *argv, cwd="/tmp"):
    return policy.evaluate(list(argv), cwd)


class Evaluate(unittest.TestCase):
    def setUp(self):
        self.p = Policy.from_toml(TOML)

    def test_auto_literal_and_variadic(self):
        d = ev(self.p, "/usr/bin/pacman", "-S", "--needed", "--noconfirm", "htop", "ripgrep")
        self.assertEqual((d.kind, d.rule), ("auto", "pacman-install"))
        self.assertEqual(ev(self.p, "/usr/bin/systemctl", "restart", "nginx.service").kind, "auto")

    def test_variadic_needs_at_least_one(self):
        self.assertEqual(
            ev(self.p, "/usr/bin/pacman", "-S", "--needed", "--noconfirm").kind, "ask")

    def test_option_injection_through_pattern_is_not_auto(self):
        d = ev(self.p, "/usr/bin/pacman", "-S", "--needed", "--noconfirm", "htop", "--overwrite=*")
        self.assertEqual(d.kind, "ask")

    def test_extra_args_break_literal_rule(self):
        self.assertEqual(
            ev(self.p, "/usr/bin/systemctl", "restart", "nginx.service", "--force").kind, "ask")

    def test_unknown_command_asks(self):
        self.assertEqual(ev(self.p, "/usr/bin/pacman", "-Syu").kind, "ask")

    def test_empty_policy_asks_for_everything(self):
        self.assertEqual(ev(Policy.empty(), "/usr/bin/ls").kind, "ask")


class Deny(unittest.TestCase):
    def setUp(self):
        self.p = Policy.from_toml(TOML)

    def test_shells_interpreters_wrappers(self):
        for exe in ("/bin/sh", "/usr/bin/bash", "/usr/bin/python3", "/usr/bin/python3.12",
                    "/usr/bin/perl", "/usr/bin/env", "/usr/bin/sudo", "/usr/bin/xargs",
                    "/usr/bin/node", "/usr/bin/timeout", "/usr/bin/systemd-run"):
            self.assertEqual(ev(self.p, exe, "x").kind, "deny", exe)

    def test_extra_deny_from_policy(self):
        self.assertEqual(ev(self.p, "/usr/bin/dd", "if=/dev/zero").kind, "deny")

    def test_protected_paths_absolute_relative_and_eq(self):
        self.assertEqual(ev(self.p, "/usr/bin/tee", "/etc/sudoers.d/x").kind, "deny")
        self.assertEqual(ev(self.p, "/usr/bin/cp", "x", "/etc/pam.d/sudo").kind, "deny")
        self.assertEqual(ev(self.p, "/usr/bin/cp", "x", "../etc/pam.d/sudo", cwd="/tmp").kind, "deny")
        self.assertEqual(ev(self.p, "/usr/bin/cp", "x", "pam.d/sudo", cwd="/etc").kind, "deny")
        self.assertEqual(ev(self.p, "/usr/bin/foo", "--conf=/etc/polkit-1/x").kind, "deny")

    def test_dotdot_cannot_hide_protected_path(self):
        self.assertEqual(ev(self.p, "/usr/bin/cp", "x", "/tmp/../etc/sudoers").kind, "deny")

    def test_mentions_telepathy(self):
        self.assertEqual(ev(self.p, "/usr/bin/systemctl", "stop", "telepathyd.service").kind, "deny")

    def test_deny_beats_auto(self):
        p = Policy.from_toml(TOML)
        # even if someone aims an auto-style argv at a protected path, deny wins
        self.assertEqual(
            ev(p, "/usr/bin/pacman", "-S", "--needed", "--noconfirm", "htop", "/etc/sudoers").kind,
            "deny")


class Symlinks(unittest.TestCase):
    def setUp(self):
        self.p = Policy.from_toml(TOML)
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.d = os.path.realpath(self._td.name)

    def link(self, name, target):
        path = os.path.join(self.d, name)
        os.symlink(target, path)
        return path

    def test_symlink_to_protected_file_is_denied(self):
        x = self.link("x", "/etc/sudoers.d/evil")
        d = ev(self.p, "/usr/bin/tee", x)
        self.assertEqual(d.kind, "deny")

    def test_relative_symlink_via_cwd_is_denied(self):
        self.link("x", "/etc/pam.d/login")
        self.assertEqual(ev(self.p, "/usr/bin/tee", "x", cwd=self.d).kind, "deny")

    def test_symlinked_parent_directory_is_denied(self):
        self.link("etc-pam", "/etc/pam.d")
        d = ev(self.p, "/usr/bin/tee", os.path.join(self.d, "etc-pam", "new-file"))
        self.assertEqual(d.kind, "deny")

    def test_symlink_in_option_value_is_denied(self):
        x = self.link("x", "/etc/telepathy")
        self.assertEqual(ev(self.p, "/usr/bin/foo", f"--config={x}/policy.toml").kind, "deny")

    def test_dotdot_after_a_symlink_is_resolved_physically(self):
        # link -> /etc/sudoers.d, so "link/../sudoers" is /etc/sudoers, but a
        # lexical normpath would turn it into "<dir>/sudoers".
        self.link("link", "/etc/sudoers.d")
        for arg in (os.path.join(self.d, "link", "..", "sudoers"), "link/../sudoers"):
            self.assertEqual(ev(self.p, "/usr/bin/tee", arg, cwd=self.d).kind, "deny", arg)

    def test_both_candidates_of_an_opt_value_are_reported(self):
        a = self.link("a", "/usr/share/doc")
        found = self.rpa([f"{a}={a}"])
        self.assertEqual(set(found), {a})  # whole arg is not a path; the value is
        b = self.link("b", "/usr/share/man")
        found = self.rpa([f"--x={b}"])
        self.assertEqual(found, {b: os.path.realpath("/usr/share/man")})

    # trusted_uid=-1: nobody is "root" here, so every link made by the test user
    # counts as the agent's, whatever uid the suite runs as.
    def rpa(self, argv, cwd=None):
        return resolve_path_args(argv, cwd or self.d, trusted_uid=-1)

    def test_plain_args_are_not_flagged(self):
        self.assertEqual(self.rpa(["ls", "-n", "plain.txt", "x/y"]), {})

    def test_links_owned_by_the_trusted_uid_are_ignored(self):
        x = self.link("x", "/usr/share/doc")
        with self.system_above():
            self.assertEqual(resolve_path_args([x], self.d, trusted_uid=os.getuid()), {})
        self.assertEqual(set(resolve_path_args([x], self.d, trusted_uid=-1)), {x})

    def as_root_owned(self):
        """Make every lstat report uid 0 and no group/other write, so the default trusted_uid=0 applies."""
        real = os.lstat

        def fake(path, *a, **k):
            st = real(path, *a, **k)
            f = list(st)
            f[stat.ST_UID] = 0
            f[stat.ST_MODE] = st.st_mode & ~0o022
            return os.stat_result(f)
        return mock.patch.object(policy_mod.os, "lstat", fake), \
            mock.patch.object(policy_mod, "_acl_untrusted", return_value=None)

    def test_default_trusted_uid_ignores_root_owned_link_in_a_root_owned_chain(self):
        x = self.link("x", "/usr/share/doc")
        a, b = self.as_root_owned()
        with a, b:
            # no trusted_uid argument: the production default (0)
            self.assertEqual(resolve_path_args([x], self.d), {})
            self.assertEqual(resolve_path_args(["ls"], x), {})
            self.assertEqual(policy_mod._untrusted_links(x), [])
        # same link, real lstat: owned by the test user, so reported under uid 0 unless we are root
        if os.getuid() != 0:
            self.assertEqual(set(resolve_path_args([x], self.d)), {x})

    def test_dangling_agent_link_is_reported_with_its_target(self):
        target = os.path.join(self.d, "not-yet")
        x = self.link("x", target)
        self.assertEqual(policy_mod._untrusted_links(x, -1), [x])
        self.assertEqual(self.rpa([x]), {x: target})
        # a path through the dangling link reports where the file would be created
        self.assertEqual(self.rpa(["x/new.txt"]), {"x/new.txt": os.path.join(target, "new.txt")})

    def test_dangling_link_with_trusted_owner_is_quiet(self):
        x = self.link("x", os.path.join(self.d, "not-yet"))
        a, b = self.as_root_owned()
        with a, b:
            self.assertEqual(policy_mod._untrusted_links(x), [])

    def system_above(self):
        """Pretend everything above self.d (/tmp, /) is trusted, so only self.d and below are judged."""
        base = os.path.realpath(self.d)
        real = policy_mod._untrusted_node

        def node(st, path, uid, what):
            return None if len(path) < len(base) else real(st, path, uid, what)
        return mock.patch.object(policy_mod, "_untrusted_node", node)

    def test_trusted_link_in_an_agent_writable_dir_is_reported(self):
        me = os.getuid()
        x = self.link("x", "/usr/share/doc")
        os.chmod(self.d, 0o755)  # only the owner (our stand-in for root) can write
        with self.system_above():
            self.assertEqual(resolve_path_args([x], self.d, trusted_uid=me), {})
            for mode in (0o757, 0o775):  # other-write; group-write with a non-root group
                os.chmod(self.d, mode)
                if mode == 0o775 and os.stat(self.d).st_gid == 0:
                    continue
                self.assertEqual(set(resolve_path_args([x], self.d, trusted_uid=me)), {x}, oct(mode))

    def test_trusted_link_under_an_agent_writable_ancestor_is_reported(self):
        # /srv/agent writable, /srv/agent/sub "root" 755, link inside: the agent
        # can still rename sub away and put its own tree in its place.
        me = os.getuid()
        sub = os.path.join(self.d, "sub")
        os.mkdir(sub, 0o755)
        os.chmod(sub, 0o755)
        x = os.path.join(sub, "x")
        os.symlink("/usr/share/doc", x)
        os.chmod(self.d, 0o755)
        with self.system_above():
            self.assertEqual(resolve_path_args([x], self.d, trusted_uid=me), {})
            os.chmod(self.d, 0o757)
            self.assertEqual(set(resolve_path_args([x], self.d, trusted_uid=me)), {x})

    def test_trusted_link_in_a_dir_with_a_writable_acl_is_reported(self):
        me = os.getuid()
        x = self.link("x", "/usr/share/doc")
        os.chmod(self.d, 0o755)
        with self.system_above(), \
             mock.patch.object(policy_mod, "_acl_untrusted", return_value="ACL grants write"):
            self.assertEqual(set(resolve_path_args([x], self.d, trusted_uid=me)), {x})

    def test_dir_chain_is_cached_within_one_call(self):
        me = os.getuid()
        self.link("b", "/usr/share/doc")
        self.link("a", os.path.join(os.path.realpath(self.d), "b"))  # two hops, same directory
        calls = []
        real = policy_mod._untrusted_node

        def node(st, path, uid, what):
            calls.append(path)
            return real(st, path, uid, what)
        with mock.patch.object(policy_mod, "_untrusted_node", node):
            policy_mod._untrusted_links(os.path.join(self.d, "a"), me)
        self.assertEqual(len(calls), len(set(calls)))

    def test_dir_that_cannot_be_inspected_is_not_trusted(self):
        me = os.getuid()
        with self.system_above():
            os.chmod(self.d, 0o755)
            self.assertTrue(policy_mod._dir_chain_trusted(self.d, me, {}))
        for exc in (OSError(5, "io"), ValueError("nul")):
            with mock.patch.object(policy_mod.os, "lstat", side_effect=exc):
                self.assertFalse(policy_mod._dir_chain_trusted(self.d, me, {}))

    def test_relative_arg_crossing_a_link_in_cwd_is_reported(self):
        self.link("x", "/usr/share/doc")
        self.assertEqual(self.rpa(["x/file"]), {"x/file": os.path.realpath("/usr/share/doc/file")})

    def test_symlinked_cwd_is_reported_once_not_per_arg(self):
        outer = self.link("outer", "/usr/share/doc")
        self.assertEqual(self.rpa(["ls", "-n"], cwd=outer), {outer: os.path.realpath("/usr/share/doc")})

    def test_dotdot_after_a_link_reports_the_physical_target(self):
        self.link("link", "/etc/sudoers.d")
        got = self.rpa(["link/../sudoers"])
        self.assertEqual(got, {"link/../sudoers": "/etc/sudoers"})

    def test_absolute_link_target_resets_the_walk(self):
        self.link("a", "/usr/share")
        got = self.rpa([os.path.join(self.d, "a", "doc")])
        self.assertEqual(list(got.values()), [os.path.realpath("/usr/share/doc")])

    def test_symlink_loop_is_reported_as_unresolvable_not_dropped(self):
        a = os.path.join(self.d, "a")
        b = os.path.join(self.d, "b")
        os.symlink(b, a)
        os.symlink(a, b)
        self.assertEqual(self.rpa([a]), {a: UNRESOLVABLE})
        self.assertEqual(self.rpa(["a/x"]), {"a/x": UNRESOLVABLE})

    def test_nul_byte_in_cwd_or_arg_is_reported_not_raised(self):
        self.assertEqual(self.rpa(["ls"], cwd="/tmp/a\0b"), {"/tmp/a\0b": UNRESOLVABLE})
        self.assertEqual(self.rpa(["/tmp/a\0b"]), {"/tmp/a\0b": UNRESOLVABLE})

    def test_unresolvable_path_fails_closed(self):
        self.assertEqual(ev(self.p, "/usr/bin/cat", "/tmp/a\0b").kind, "deny")

    def test_harmless_symlink_is_not_denied(self):
        x = self.link("x", "/usr/share/doc")
        self.assertEqual(ev(self.p, "/usr/bin/ls", x).kind, "ask")

    def test_resolve_path_args_reports_only_differences(self):
        x = self.link("x", "/etc/hostname")
        plain = os.path.join(self.d, "plain")
        found = self.rpa(["/usr/bin/cat", x, plain, "-n"])
        self.assertEqual(found, {x: os.path.realpath("/etc/hostname")})


def _real(name):
    path = shutil.which(name)
    return os.path.realpath(path) if path else None


class Executable(unittest.TestCase):
    """The deny list and the root-trust rule apply to what argv[0] really is."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = os.path.realpath(self.tmp.name)
        self.p = Policy.from_toml(TOML)
        self.bash = _real("bash")
        self.true = _real("true")
        if not (self.bash and self.true):
            self.skipTest("bash/true not found")

    def link(self, name, target):
        path = os.path.join(self.d, name)
        os.symlink(target, path)
        return path

    def test_symlink_to_a_shell_is_denied_by_resolved_name(self):
        d = ev(self.p, self.link("foo", self.bash), "-c", "id")
        self.assertEqual(d.kind, "deny")
        self.assertIn("shell", d.reason)

    def test_symlink_chain_to_a_shell_is_denied(self):
        a = self.link("b", self.bash)
        d = ev(self.p, self.link("a", a), "-c", "id")
        self.assertEqual((d.kind, "shell" in d.reason), ("deny", True))

    def test_symlink_to_an_interpreter_is_denied(self):
        py = _real("python3")
        if not py:
            self.skipTest("no python3")
        self.assertEqual(ev(self.p, self.link("tool", py), "x").kind, "deny")

    def test_resolved_name_is_checked_against_policy_deny_list_too(self):
        p = Policy.from_toml('[deny]\nexecutables = ["true"]\n')
        d = ev(p, self.link("harmless", self.true))
        self.assertEqual((d.kind, "denied by policy" in d.reason), ("deny", True))

    def test_copy_of_a_binary_in_an_agent_dir_is_denied(self):
        copy = os.path.join(self.d, "ls")
        shutil.copy(self.true, copy)
        d = ev(self.p, copy)
        self.assertEqual(d.kind, "deny")
        self.assertIn("not owned by root", d.reason)

    def test_dangling_and_looping_links_are_denied_by_the_directory_rule(self):
        # realpath does not raise on a loop or a dangling link; what denies these
        # is that the agent-owned directory above them is not trusted.
        self.assertEqual(ev(self.p, self.link("gone", os.path.join(self.d, "nope"))).kind, "deny")
        a, b = os.path.join(self.d, "a"), os.path.join(self.d, "b")
        os.symlink(b, a)
        os.symlink(a, b)
        self.assertEqual(ev(self.p, a).kind, "deny")

    def test_an_unresolvable_argv0_is_denied(self):
        with mock.patch.object(policy_mod, "_exe_names", side_effect=OSError("loop")):
            d = ev(self.p, "/usr/bin/true")
        self.assertEqual((d.kind, "cannot resolve" in d.reason), ("deny", True))

    def test_resolved_interpreter_name_variants_are_denied(self):
        for n in ("pythonw", "python3.12", "perl5.40.0-thread", "perl5.40.0-thread-multi",
                  "luajit-2.1.0-beta3", "pypy3.10-v7.3.17", "lua5.4"):
            self.assertIsNotNone(policy_mod._denied_exe({n}), n)
        for n in ("python-config", "pacman", "perlbrew"):
            self.assertIsNone(policy_mod._denied_exe({n}), n)

    def test_nul_byte_in_argv0_is_denied_not_raised(self):
        self.assertEqual(ev(self.p, "/usr/bin/a\0b").kind, "deny")

    def test_system_executables_still_work(self):
        if os.stat("/usr/bin").st_uid != 0:
            self.skipTest("/usr/bin is not root-owned on this host")
        self.assertEqual(ev(Policy.empty(), self.true).kind, "ask")
        self.assertEqual(ev(Policy.empty(), "/bin/true").kind, "ask")  # /bin is a root link
        self.assertEqual(ev(Policy.empty(), "/usr/bin/not-installed-yet").kind, "ask")

    def test_policy_passes_its_trusted_uid_to_the_check(self):
        with mock.patch.object(policy_mod, "_untrusted_exe", return_value=None) as m:
            ev(Policy(trusted_uid=1234), self.true)
        m.assert_called_once_with(self.true, 1234)

    def test_an_unresolvable_auto_rule_target_is_rejected_at_load(self):
        toml = '[[auto]]\nname = "x"\nargv = ["/usr/bin/true"]\n'
        with mock.patch.object(policy_mod, "_exe_names", side_effect=OSError("loop")):
            with self.assertRaises(PolicyError):
                Policy.from_toml(toml)

    def test_auto_rule_whose_target_is_a_link_to_a_shell_is_rejected_at_load(self):
        toml = f'[[auto]]\nname = "x"\nargv = ["{self.link("ls", self.bash)}"]\n'
        with self.assertRaises(PolicyError):
            Policy.from_toml(toml)


class TrustWalk(unittest.TestCase):
    """The directory walk of _untrusted_exe, against a fake filesystem (we cannot
    make root-owned directories as a normal user)."""

    DIR, FILE = 0o040000, 0o100000

    @staticmethod
    def acl(*entries):
        """Raw system.posix_acl_access value from (tag, perm, id) entries."""
        import struct
        return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *e) for e in entries)

    BASE = [(1, 7, 0xFFFFFFFF), (4, 5, 0xFFFFFFFF), (0x10, 5, 0xFFFFFFFF), (0x20, 5, 0xFFFFFFFF)]

    def check(self, modes, exe="/fake/bin/tool", uid=0, xattrs=None):
        xattrs = xattrs or {}

        def fake_xattr(path, name, **k):
            v = xattrs.get(path)
            if v is None:
                raise OSError(errno.ENODATA, "no data")
            if isinstance(v, Exception):
                raise v
            return v

        def fake(path, *a, **k):
            if path not in modes:
                raise FileNotFoundError(path)
            uid, gid, mode = modes[path]
            return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))

        with mock.patch.object(policy_mod.os, "lstat", side_effect=fake), \
                mock.patch.object(policy_mod.os, "getxattr", side_effect=fake_xattr), \
                mock.patch.object(policy_mod.os.path, "realpath", side_effect=lambda x: x):
            return policy_mod._untrusted_exe(exe, uid)

    def tree(self, **over):
        t = {"/": (0, 0, self.DIR | 0o755), "/fake": (0, 0, self.DIR | 0o755),
             "/fake/bin": (0, 0, self.DIR | 0o755),
             "/fake/bin/tool": (0, 0, self.FILE | 0o755)}
        t.update(over)
        return t

    def test_trusted_uid_decides_who_counts_as_owner(self):
        t = {k: (1000, g, m) for k, (u, g, m) in self.tree().items()}
        self.assertIsNone(self.check(t, uid=1000))
        self.assertIsNotNone(self.check(t, uid=0))

    def test_all_root_owned_passes(self):
        self.assertIsNone(self.check(self.tree()))

    def test_world_writable_directory_above_is_refused(self):
        why = self.check(self.tree(**{"/fake/bin": (0, 0, self.DIR | 0o777)}))
        self.assertIn("directory above it /fake/bin", why)

    def test_a_directory_far_above_is_checked_too(self):
        why = self.check(self.tree(**{"/fake": (0, 0, self.DIR | 0o757)}))
        self.assertIn("/fake", why)

    def test_directory_owned_by_someone_else_is_refused(self):
        self.assertIsNotNone(self.check(self.tree(**{"/fake": (1000, 0, self.DIR | 0o755)})))

    def test_group_write_is_fine_for_group_root_only(self):
        self.assertIsNone(self.check(self.tree(**{"/fake/bin": (0, 0, self.DIR | 0o775)})))
        why = self.check(self.tree(**{"/fake/bin": (0, 50, self.DIR | 0o2775)}))  # root:staff
        self.assertIn("/fake/bin", why)

    def test_writable_leaf_is_refused(self):
        self.assertIn("executable /fake/bin/tool",
                      self.check(self.tree(**{"/fake/bin/tool": (0, 0, self.FILE | 0o757)})))

    def test_missing_leaf_still_checks_its_directories(self):
        t = self.tree(**{"/fake/bin": (0, 0, self.DIR | 0o777)})
        del t["/fake/bin/tool"]
        self.assertIn("/fake/bin", self.check(t))
        t["/fake/bin"] = (0, 0, self.DIR | 0o755)
        self.assertIsNone(self.check(t))

    def test_non_regular_leaf_is_refused(self):
        for mode in (self.DIR | 0o755, 0o010000 | 0o755, 0o140000 | 0o755):  # dir, fifo, socket
            with self.subTest(mode=oct(mode)):
                why = self.check(self.tree(**{"/fake/bin/tool": (0, 0, mode)}))
                self.assertIn("not a regular file", why)

    def test_no_acl_is_fine_for_enodata_and_enotsup(self):
        for e in (errno.ENODATA, errno.ENOTSUP):
            with self.subTest(errno=e):
                self.assertIsNone(self.check(
                    self.tree(), xattrs={"/fake/bin/tool": OSError(e, "x")}))

    def test_other_xattr_errors_fail_closed(self):
        for e in (errno.EACCES, errno.EIO, errno.ENOENT, errno.ERANGE):
            with self.subTest(errno=e):
                why = self.check(self.tree(), xattrs={"/fake/bin/tool": OSError(e, "x")})
                self.assertEqual(why, "cannot inspect ACL of /fake/bin/tool")

    def test_xattr_error_on_a_directory_fails_closed(self):
        why = self.check(self.tree(), xattrs={"/fake/bin": PermissionError(13, "x")})
        self.assertEqual(why, "cannot inspect ACL of /fake/bin")

    def test_plain_acl_with_no_named_entries_passes(self):
        self.assertIsNone(self.check(self.tree(), xattrs={"/fake/bin/tool": self.acl(*self.BASE)}))

    def test_named_user_with_write_is_refused(self):
        a = self.acl(*self.BASE, (2, 6, 1000))
        why = self.check(self.tree(), xattrs={"/fake/bin/tool": a})
        self.assertEqual(why, "ACL on /fake/bin/tool grants write to user 1000")

    def test_named_user_read_only_passes(self):
        a = self.acl(*self.BASE, (2, 5, 1000))
        self.assertIsNone(self.check(self.tree(), xattrs={"/fake/bin/tool": a}))

    def test_named_trusted_user_with_write_passes(self):
        a = self.acl(*self.BASE, (2, 6, 0))
        self.assertIsNone(self.check(self.tree(), xattrs={"/fake/bin/tool": a}))

    def test_named_group_with_write_is_refused_but_group_root_is_not(self):
        a = self.acl(*self.BASE, (8, 6, 50))
        self.assertIn("write to group 50", self.check(self.tree(), xattrs={"/fake/bin/tool": a}))
        a = self.acl(*self.BASE, (8, 6, 0))
        self.assertIsNone(self.check(self.tree(), xattrs={"/fake/bin/tool": a}))

    def test_acl_on_a_parent_directory_is_refused(self):
        a = self.acl(*self.BASE, (2, 7, 1000))
        why = self.check(self.tree(), xattrs={"/fake": a})
        self.assertIn("ACL on /fake grants write to user 1000", why)

    def test_restricting_mask_does_not_excuse_a_named_write(self):
        a = self.acl((1, 7, 0xFFFFFFFF), (2, 6, 1000), (4, 5, 0xFFFFFFFF),
                     (0x10, 4, 0xFFFFFFFF), (0x20, 5, 0xFFFFFFFF))
        self.assertIn("1000", self.check(self.tree(), xattrs={"/fake/bin/tool": a}))

    def test_malformed_acl_fails_closed(self):
        import struct
        cases = {
            "empty": b"",
            "short": b"\x02\x00",
            "bad version": struct.pack("<I", 3) + struct.pack("<HHI", 1, 7, 0),
            "truncated entry": self.acl(*self.BASE) + b"\x01",
            "unknown tag": self.acl(*self.BASE, (0x99, 6, 0)),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                why = self.check(self.tree(), xattrs={"/fake/bin/tool": raw})
                self.assertEqual(why, "malformed ACL on /fake/bin/tool")

    def test_group_obj_write_is_refused_for_a_non_root_group(self):
        # with named entries the mode's group bits show the mask (r-x here)
        a = self.acl((1, 7, 0xFFFFFFFF), (2, 4, 1000), (4, 7, 0xFFFFFFFF),
                     (0x10, 5, 0xFFFFFFFF), (0x20, 5, 0xFFFFFFFF))
        t = self.tree(**{"/fake/bin/tool": (0, 50, self.FILE | 0o755)})
        why = self.check(t, xattrs={"/fake/bin/tool": a})
        self.assertEqual(why, "ACL on /fake/bin/tool grants write to its group 50")
        t = self.tree(**{"/fake/bin/tool": (0, 0, self.FILE | 0o755)})
        self.assertIsNone(self.check(t, xattrs={"/fake/bin/tool": a}))

    def test_trusted_uid_exempts_named_user_but_not_groups(self):
        t = {k: (1000, 0, m) for k, (u, g, m) in self.tree().items()}
        a = self.acl(*self.BASE, (2, 6, 1000))
        self.assertIsNone(self.check(t, uid=1000, xattrs={"/fake/bin/tool": a}))
        g = self.acl(*self.BASE, (8, 6, 1000))
        self.assertIn("group 1000", self.check(t, uid=1000, xattrs={"/fake/bin/tool": g}))

    def test_trusted_uid_named_user_acl_on_a_directory_passes(self):
        a = self.acl(*self.BASE, (2, 7, 0))
        self.assertIsNone(self.check(self.tree(), xattrs={"/fake/bin": a}))

    def test_device_node_and_symlink_leaves_are_refused(self):
        for mode in (0o060000, 0o020000, 0o120000):  # block, char, symlink
            with self.subTest(mode=oct(mode)):
                why = self.check(self.tree(**{"/fake/bin/tool": (0, 0, mode | 0o755)}))
                self.assertIn("not a regular file", why)

    def test_perm_bits_above_7_are_malformed(self):
        for perm in (8, 0x10, 0xFFFF):
            with self.subTest(perm=perm):
                a = self.acl(*self.BASE, (2, perm, 0))
                self.assertEqual(self.check(self.tree(), xattrs={"/fake/bin/tool": a}),
                                 "malformed ACL on /fake/bin/tool")

    def test_absurd_entry_count_is_malformed(self):
        a = self.acl(*([(2, 4, 0)] * 1025))
        self.assertEqual(self.check(self.tree(), xattrs={"/fake/bin/tool": a}),
                         "malformed ACL on /fake/bin/tool")

    def test_missing_getxattr_fails_closed(self):
        with mock.patch.object(policy_mod.os, "getxattr", side_effect=AttributeError):
            self.assertEqual(policy_mod._acl_untrusted("/x", 0, 0), "cannot inspect ACL of /x")

    def test_real_system_binary_is_still_trusted(self):
        try:
            st = os.stat(os.path.realpath("/usr/bin/ls"))
        except OSError:
            self.skipTest("/usr/bin/ls not present")
        if st.st_uid != 0:
            self.skipTest("/usr/bin/ls is not root-owned on this host")
        self.assertIsNone(policy_mod._untrusted_exe("/usr/bin/ls", 0))

    def walk_with_lstat_error(self, exc, bad="/fake/bin/tool"):
        modes = self.tree()

        def fake(path, *a, **k):
            if path == bad:
                raise exc
            uid, gid, mode = modes[path]
            return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))

        with mock.patch.object(policy_mod.os, "lstat", side_effect=fake), \
                mock.patch.object(policy_mod.os, "getxattr",
                                  side_effect=OSError(errno.ENODATA, "none")), \
                mock.patch.object(policy_mod.os.path, "realpath", side_effect=lambda x: x):
            return policy_mod._untrusted_exe("/fake/bin/tool", 0)

    def test_uninspectable_path_fails_closed(self):
        # anything but not-found (EACCES, EIO, a NUL in the path) is a refusal
        for exc in (PermissionError(13, "denied"), OSError(5, "io"),
                    NotADirectoryError(20, "nd"), ValueError("embedded null byte")):
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(self.walk_with_lstat_error(exc),
                                 "cannot inspect /fake/bin/tool")

    def test_uninspectable_directory_above_fails_closed(self):
        self.assertEqual(
            self.walk_with_lstat_error(PermissionError(13, "denied"), bad="/fake"),
            "cannot inspect /fake")

    def test_uninspectable_path_is_refused_through_evaluate(self):
        with mock.patch.object(policy_mod.os, "lstat", side_effect=PermissionError(13, "x")):
            self.assertEqual(ev(Policy.empty(), "/usr/bin/ls").kind, "deny")


class ProtectedPrefixLinks(unittest.TestCase):
    """A protected prefix that is itself a symlink still protects its target."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = os.path.realpath(self.tmp.name)
        os.makedirs(os.path.join(self.d, "real", "sudoers.d"))
        os.symlink(os.path.join(self.d, "real"), os.path.join(self.d, "etc"))
        patcher = mock.patch.object(
            policy_mod, "PROTECTED_PREFIXES", (os.path.join(self.d, "etc", "sudoers.d"),))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_real_target_of_a_linked_prefix_is_denied(self):
        arg = os.path.join(self.d, "real", "sudoers.d", "x")
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", arg).kind, "deny")

    def test_written_form_is_still_denied(self):
        arg = os.path.join(self.d, "etc", "sudoers.d", "x")
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", arg).kind, "deny")

    def test_a_retargeted_prefix_link_is_picked_up_on_the_next_evaluation(self):
        other = os.path.join(self.d, "other", "sudoers.d")
        os.makedirs(other)
        arg = os.path.join(other, "x")
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", arg).kind, "ask")
        os.unlink(os.path.join(self.d, "etc"))
        os.symlink(os.path.join(self.d, "other"), os.path.join(self.d, "etc"))
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", arg).kind, "deny")

    def test_unrelated_sibling_is_allowed(self):
        arg = os.path.join(self.d, "real", "other")
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", arg).kind, "ask")


class BroadResolvedPrefix(unittest.TestCase):
    """A prefix linked to a broad directory must not deny everything under it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = os.path.realpath(self.tmp.name)
        os.makedirs(os.path.join(self.d, "shared", "other"))
        self.pre = os.path.join(self.d, "etc", "pam.d")
        os.makedirs(os.path.dirname(self.pre))
        os.symlink(os.path.join(self.d, "shared"), self.pre)
        patcher = mock.patch.object(policy_mod, "PROTECTED_PREFIXES", (self.pre,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_link_to_a_strict_ancestor_is_skipped_and_reported(self):
        os.unlink(self.pre)
        os.symlink(os.path.join(self.d, "etc"), self.pre)
        self.assertEqual(policy_mod.skipped_protected_prefixes(),
                         ((self.pre, os.path.join(self.d, "etc")),))
        arg = os.path.join(self.d, "etc", "unrelated")
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", arg).kind, "ask")

    def test_literal_prefix_still_denied_when_resolved_is_skipped(self):
        os.unlink(self.pre)
        os.symlink(os.path.join(self.d, "etc"), self.pre)
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", self.pre + "/x").kind, "deny")

    def test_link_to_root_is_skipped(self):
        os.unlink(self.pre)
        os.symlink("/", self.pre)
        self.assertEqual(policy_mod.skipped_protected_prefixes(), ((self.pre, "/"),))
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", "/usr/share/x").kind, "ask")

    def test_relocated_shallow_dedicated_target_stays_denied(self):
        # a one-component dedicated dir (/sudoers.d style) is NOT broad
        ded = os.path.join(self.d, "sudoers.d")
        os.makedirs(ded)
        os.unlink(self.pre)
        os.symlink(ded, self.pre)
        self.assertEqual(policy_mod.skipped_protected_prefixes(), ())
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", os.path.join(ded, "x")).kind, "deny")

    def test_ordinary_relocation_is_still_enforced_and_not_reported(self):
        self.assertEqual(policy_mod.skipped_protected_prefixes(), ())
        arg = os.path.join(self.d, "shared", "x")
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", arg).kind, "deny")
        self.assertEqual(
            ev(Policy.empty(), "/usr/bin/tee", os.path.join(self.d, "shared", "other", "x")).kind,
            "deny")

    def test_broad_helper(self):
        b = policy_mod._broad
        self.assertTrue(b("/etc/pam.d", "/etc"))
        self.assertTrue(b("/usr/share/polkit-1", "/usr/share"))
        self.assertTrue(b("/etc/pam.d", "/"))
        self.assertTrue(b("/etc/pam.d", "/etc/"))  # trailing slash
        self.assertTrue(b("/etc/pam.d/", "/etc"))
        self.assertFalse(b("/etc/pam.d", "/usr"))  # shallow but not an ancestor
        self.assertFalse(b("/etc/pam.d", "/sudoers.d"))
        self.assertFalse(b("/etc/pam.d", "relative/target"))
        self.assertFalse(b("/etc/pam.d", "/etc/pam.d/"))  # same path
        self.assertFalse(b("/etc/pam.d", "/srv/pam.d"))
        self.assertFalse(b("/etc/sudoers", "/etc/sudoers.real"))  # not an ancestor


    def test_realpath_failure_keeps_the_literal_prefix_only(self):
        real = os.path.realpath
        for exc in (OSError(5, "io"), ValueError("embedded null byte")):
            def fake(path, *a, **k):
                if path == self.pre:
                    raise exc
                return real(path, *a, **k)

            with self.subTest(exc=type(exc).__name__), \
                    mock.patch.object(policy_mod.os.path, "realpath", side_effect=fake):
                self.assertEqual(policy_mod._protected_prefixes(), (self.pre,))
                self.assertEqual(policy_mod.skipped_protected_prefixes(), ())
                self.assertEqual(
                    ev(Policy.empty(), "/usr/bin/tee", self.pre + "/x").kind, "deny")


class SkippedPrefixReevaluation(unittest.TestCase):
    """A link repointed after start is queued once per change, not per request."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = os.path.realpath(self.tmp.name)
        os.makedirs(os.path.join(self.d, "shared"))
        os.makedirs(os.path.join(self.d, "etc"))
        self.etc = os.path.join(self.d, "etc")
        self.pre = os.path.join(self.d, "etc", "pam.d")
        os.symlink(os.path.join(self.d, "shared"), self.pre)
        p = mock.patch.object(policy_mod, "PROTECTED_PREFIXES", (self.pre,))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(policy_mod.stop_skip_tracking)
        policy_mod.start_skip_tracking(dict(policy_mod.skipped_protected_prefixes()))

    def repoint(self, target):
        tmp = self.pre + ".new"  # atomic, so a concurrent evaluation never sees a gap
        os.symlink(target, tmp)
        os.replace(tmp, self.pre)

    def events(self):
        return policy_mod.drain_skip_events()[0]

    def test_repoint_to_broad_is_queued_once(self):
        self.repoint(self.etc)
        for _ in range(3):
            self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", self.etc + "/x").kind, "ask")
        self.assertEqual(self.events(), [("protected_prefix_skipped", self.pre, self.etc)])
        self.assertEqual(policy_mod.skipped_snapshot(), ((self.pre, self.etc),))

    def test_back_to_narrow_is_unskipped(self):
        self.repoint(self.etc)
        ev(Policy.empty(), "/usr/bin/tee", "/tmp/x")
        self.repoint(os.path.join(self.d, "shared"))
        for _ in range(3):
            ev(Policy.empty(), "/usr/bin/tee", "/tmp/x")
        self.assertEqual([e[0] for e in self.events()],
                         ["protected_prefix_skipped", "protected_prefix_unskipped"])

    def test_unchanged_set_queues_nothing(self):
        for _ in range(3):
            ev(Policy.empty(), "/usr/bin/tee", "/tmp/x")
        self.assertEqual(self.events(), [])

    def test_untracked_is_a_noop(self):
        policy_mod.stop_skip_tracking()
        self.repoint(self.etc)
        self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", self.pre + "/x").kind, "deny")
        self.assertEqual(self.events(), [])
        self.assertEqual(policy_mod.skipped_snapshot(), ())

    def test_transient_resolution_failure_keeps_previous_state(self):
        self.repoint(self.etc)
        ev(Policy.empty(), "/usr/bin/tee", "/tmp/x")
        self.events()
        real = os.path.realpath

        def flaky(p, *a, **k):
            if p == self.pre:
                raise OSError("boom")
            return real(p, *a, **k)
        with mock.patch.object(policy_mod.os.path, "realpath", side_effect=flaky):
            # the literal prefix still denies; nothing is reported or flipped
            self.assertEqual(policy_mod._protected_prefixes(), (self.pre,))
            self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", self.pre + "/x").kind, "deny")
        self.assertEqual(self.events(), [])
        self.assertEqual(policy_mod.skipped_snapshot(), ((self.pre, self.etc),))

    def test_queue_is_bounded_drop_oldest_with_counter(self):
        with mock.patch.object(policy_mod, "SKIP_QUEUE_MAX", 2), \
                mock.patch.object(policy_mod, "_skip_events",
                                  policy_mod.collections.deque(maxlen=2)):
            for i in range(3):
                policy_mod._note_skipped({self.pre: f"/r{i}"})
            ev_, dropped = policy_mod.drain_skip_events()
        self.assertEqual(len(ev_), 2)
        self.assertGreater(dropped, 0)

    def test_concurrent_evaluations_give_ordered_once_per_change_events(self):
        self.repoint(self.etc)
        stop = threading.Event()
        errs = []

        def worker():
            while not stop.is_set():
                try:
                    if ev(Policy.empty(), "/usr/bin/tee", "/tmp/x").kind != "ask":
                        errs.append("decision")
                except Exception as e:
                    errs.append(e)

        ts = [threading.Thread(target=worker) for _ in range(8)]
        for t in ts:
            t.start()
        time.sleep(0.2)
        self.repoint(os.path.join(self.d, "shared"))
        time.sleep(0.2)
        stop.set()
        for t in ts:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual([e[0] for e in self.events()],
                         ["protected_prefix_skipped", "protected_prefix_unskipped"])

    def test_evaluation_never_blocks_on_reporting(self):
        # there is no observer to block or raise: even a consumer that never drains
        # cannot slow or change a check
        self.repoint(self.etc)
        for _ in range(policy_mod.SKIP_QUEUE_MAX * 2):
            self.assertEqual(ev(Policy.empty(), "/usr/bin/tee", self.pre + "/x").kind, "deny")



class Loading(unittest.TestCase):
    def bad(self, text):
        with self.assertRaises(PolicyError):
            Policy.from_toml(text)

    def test_rejects_invalid(self):
        self.bad("not = [toml")
        self.bad("[bogus]\nx = 1")
        self.bad("[patterns]\np = '('")
        self.bad("[patterns]\np = '.*'")  # matches option-looking values
        self.bad("[patterns]\np = '-?[a-z]+'")
        self.bad('[[auto]]\nargv = ["ls"]')  # relative exe
        self.bad('[[auto]]\nargv = ["/bin/sh", "-c", "x"]')  # never auto a shell
        self.bad('[[auto]]\nargv = ["/usr/bin/pacman", "@nope"]')
        self.bad('[patterns]\np = "[a-z]+"\n[[auto]]\nargv = ["/usr/bin/x", "@p...", "y"]')
        self.bad('[patterns]\np = "[a-z]+"\n[[auto]]\nargv = ["@p"]')
        self.bad('[[auto]]\nname = "a"\nargv = ["/usr/bin/x"]\n[[auto]]\nname = "a"\nargv = ["/usr/bin/y"]')
        self.bad('[deny]\nallow = ["x"]')

    def test_empty_document_ok(self):
        self.assertEqual(Policy.from_toml("").rules, ())


if __name__ == "__main__":
    unittest.main()
