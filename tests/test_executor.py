import os
import signal
import sys
import tempfile
import time
import unittest

from telepathy import executor
from telepathy.executor import run_command

ENV = {"PATH": "/usr/bin", "LANG": "C.UTF-8"}


class RunCommand(unittest.TestCase):
    def test_output_and_zero_exit(self):
        r = run_command(["/usr/bin/echo", "hello", "world"], "/tmp", ENV)
        self.assertEqual((r.exit_code, r.output, r.truncated, r.error), (0, b"hello world\n", False, None))

    def test_nonzero_exit_passes_through(self):
        self.assertEqual(run_command(["/usr/bin/false"], "/tmp", ENV).exit_code, 1)

    def test_stderr_is_merged(self):
        r = run_command(["/usr/bin/ls", "/definitely/not/here"], "/tmp", ENV)
        self.assertNotEqual(r.exit_code, 0)
        self.assertIn(b"No such file", r.output)

    def test_no_shell_interpretation(self):
        r = run_command(["/usr/bin/echo", "$HOME;", "`id`", "*"], "/tmp", ENV)
        self.assertEqual(r.output, b"$HOME; `id` *\n")

    def test_environment_is_exactly_what_was_given(self):
        r = run_command(["/usr/bin/printenv", "A"], "/tmp", {"A": "1", "PATH": "/usr/bin"})
        self.assertEqual(r.output, b"1\n")
        r = run_command(["/usr/bin/printenv", "HOME"], "/tmp", {"PATH": "/usr/bin"})
        self.assertEqual(r.exit_code, 1)  # not inherited from the daemon

    def test_cwd(self):
        r = run_command(["/usr/bin/pwd"], "/usr", ENV)
        self.assertEqual(r.output, b"/usr\n")

    def test_stdin_is_closed(self):
        t = time.monotonic()
        r = run_command(["/usr/bin/cat"], "/tmp", ENV, timeout=5)
        self.assertEqual((r.exit_code, r.output), (0, b""))
        self.assertLess(time.monotonic() - t, 3)

    def test_output_cap_drains_without_blocking(self):
        r = run_command(["/usr/bin/head", "-c", "200000", "/dev/zero"], "/tmp", ENV,
                        timeout=10, max_output=1000)
        self.assertEqual((r.exit_code, len(r.output), r.truncated), (0, 1000, True))

    def test_timeout_kills(self):
        t = time.monotonic()
        r = run_command(["/usr/bin/sleep", "30"], "/tmp", ENV, timeout=0.3)
        self.assertEqual(r.exit_code, 124)
        self.assertIn("timed out", r.error)
        self.assertLess(time.monotonic() - t, 5)

    def test_missing_and_unexecutable(self):
        self.assertEqual(run_command(["/nonexistent/tool"], "/tmp", ENV).exit_code, 127)
        self.assertEqual(run_command(["/usr/bin/true"], "/nonexistent/dir", ENV).exit_code, 127)
        self.assertEqual(run_command(["/etc/passwd"], "/tmp", ENV).exit_code, 126)


PY = sys.executable

SETSID_CHILD = """
import os, sys, time
if os.fork() == 0:
    os.setsid()
    open(sys.argv[1], 'w').write(str(os.getpid()))
    time.sleep(60)
else:
    time.sleep(60)
"""

# The middle process lives long enough to be seen, then exits: the grandchild is
# re-parented to init (or a subreaper) with a new session.
DOUBLE_FORK = """
import os, sys, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        open(sys.argv[1], 'w').write(str(os.getpid()))
        time.sleep(60)
    else:
        # wait for the handshake, then give the tracker several scans
        while not os.path.exists(sys.argv[1]):
            time.sleep(0.01)
        time.sleep(0.8)
        os._exit(0)
else:
    time.sleep(60)
"""


def _read(path):
    with open(path) as f:
        return f.read()


def _alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


HAVE_PROC = os.path.exists("/proc/self/stat") and executor._CHILDREN_OK


@unittest.skipUnless(HAVE_PROC, "needs /proc with task/*/children")
class DetachedDescendants(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.pidfile = os.path.join(self.dir.name, "pid")
        self.addCleanup(self.dir.cleanup)
        self.addCleanup(self._reap)

    def _pid(self):
        try:
            return int(_read(self.pidfile))
        except (OSError, ValueError):
            return None

    def _reap(self):  # kill only the pid this test started
        pid = self._pid()
        if pid and _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    def _run(self, script, timeout):
        r = run_command([PY, "-c", script, self.pidfile], "/tmp", ENV, timeout=timeout)
        pid = self._pid()
        self.assertEqual(r.exit_code, 124)
        self.assertIsNotNone(pid, "descendant never started")
        end = time.monotonic() + 2
        while _alive(pid) and time.monotonic() < end:
            time.sleep(0.02)
        self.assertFalse(_alive(pid), "detached descendant survived the timeout")

    def test_setsid_child_is_killed(self):
        self._run(SETSID_CHILD, 3.0)

    def test_reparented_double_fork_grandchild_is_killed(self):
        self._run(DOUBLE_FORK, 3.0)


class FakeProc:
    """Fake /proc whose kill() behaves like the kernel."""

    def __init__(self, table, kids):
        self.table, self.kids, self.sent, self.groups = table, kids, [], []

    def kill(self, pid, sig):
        self.sent.append((pid, sig))
        if sig == signal.SIGKILL:
            self.table.pop(pid, None)
        elif sig == signal.SIGSTOP and pid in self.table:
            self.table[pid].state = "T"

    def killpg(self, pgid, sig):
        self.groups.append((pgid, sig))

    def children(self, pid):
        return [c for c in self.kids.get(pid, []) if c in self.table]


@unittest.skipUnless(HAVE_PROC, "needs /proc with task/*/children")
class GroupKill(unittest.TestCase):
    def test_group_is_killed_even_when_root_already_exited(self):
        import subprocess
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        pidfile = os.path.join(d.name, "pid")
        proc = subprocess.Popen(
            ["/bin/sh", "-c", f"sleep 1000 & echo $! > {pidfile}; exit 0"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)

        def cleanup():
            try:
                pid = int(_read(pidfile))
                if _alive(pid):
                    os.kill(pid, signal.SIGKILL)
            except (OSError, ValueError):
                pass
            proc.wait()
        self.addCleanup(cleanup)
        end = time.monotonic() + 5
        while time.monotonic() < end:
            st = executor._stat(proc.pid)
            if st and st.zombie and os.path.exists(pidfile) and _read(pidfile).strip():
                break
            time.sleep(0.01)
        pid = int(_read(pidfile))
        self.assertTrue(_alive(pid))
        self.assertTrue(executor._kill_tree(proc.pid, {}))  # nothing tracked
        end = time.monotonic() + 2
        while _alive(pid) and time.monotonic() < end:
            time.sleep(0.02)
        self.assertFalse(_alive(pid), "orphan in the command's group survived")


class RecycledPid(unittest.TestCase):
    def test_recycled_pid_is_neither_followed_nor_signalled(self):
        S = executor._Stat
        table = {100: S(1, "10"),   # the command
                 500: S(1, "99"),   # recorded as starttime 55: recycled
                 600: S(500, "77")}  # child of the recycled pid
        kids = {100: [], 500: [600], 600: []}
        known = {500: "55"}
        executor._scan_descendants(100, known, table.get, lambda p: kids.get(p, []))
        self.assertEqual(known, {100: "10"})
        fp = FakeProc(table, kids)
        executor._kill_tree(100, {500: "55"}, table.get, fp.children,
                            kill=fp.kill, killpg=fp.killpg)
        signalled = {p for p, _ in fp.sent}
        self.assertNotIn(500, signalled)
        self.assertNotIn(600, signalled)
        self.assertIn((100, signal.SIGKILL), fp.groups)

    def test_new_descendant_reusing_a_pid_replaces_stale_entry(self):
        S = executor._Stat
        table = {100: S(1, "10"), 500: S(100, "99")}
        known = {500: "55"}
        executor._scan_descendants(100, known, table.get,
                                   lambda p: [500] if p == 100 else [])
        self.assertEqual(known, {100: "10", 500: "99"})


if __name__ == "__main__":
    unittest.main()
