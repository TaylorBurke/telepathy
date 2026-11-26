"""Per-command cgroups.

The real tests need a cgroup v2 directory this process may create children in.
Unprivileged, that is a delegated user scope, so `InScope` re-runs this module
under `systemd-run --user --scope -p Delegate=yes` and the `Real*` classes run
only there (TELEPATHY_CGROUP_TESTS=1). Without systemd --user it is skipped.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from telepathy import cgroup, executor
from telepathy.executor import run_command

ENV = {"PATH": "/usr/bin", "LANG": "C.UTF-8"}
PY = sys.executable
INNER = os.environ.get("TELEPATHY_CGROUP_TESTS") == "1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


class OwnDirAndProbe(unittest.TestCase):
    """Pure parsing and the fallback decision: no cgroup access needed."""

    def _file(self, text):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "cgroup")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_v2_line_is_parsed(self):
        with mock.patch.object(cgroup, "CGROUP_ROOT", "/"):
            self.assertEqual(cgroup.own_dir(self._file("0::/tmp\n")), "/tmp")

    def test_v1_or_missing_gives_none(self):
        self.assertIsNone(cgroup.own_dir(self._file("1:name=systemd:/x\n")))
        self.assertIsNone(cgroup.own_dir("/nonexistent/cgroup"))

    def test_probe_rejects_a_plain_directory(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        self.assertIsNone(cgroup.probe(d))  # no cgroup.kill in a mkdir'd child
        self.assertEqual(os.listdir(d), [])  # and the probe dir is gone

    def test_probe_of_nothing_is_none(self):
        self.assertIsNone(cgroup.probe("/nonexistent/base"))

    def test_fallback_is_used_when_not_configured(self):
        self.assertIsNone(executor._CGROUP_BASE)
        r = run_command(["/usr/bin/echo", "hi"], "/tmp", ENV)
        self.assertEqual((r.exit_code, r.output), (0, b"hi\n"))


@unittest.skipIf(INNER, "already inside the scope")
class InScope(unittest.TestCase):
    def test_real_cgroup_tests_pass_in_a_delegated_user_scope(self):
        if not shutil.which("systemd-run"):
            self.skipTest("systemd-run not available")
        probe = subprocess.run(["systemd-run", "--user", "--scope", "-q", "-p", "Delegate=yes",
                                "--", "/usr/bin/true"], capture_output=True, text=True)
        if probe.returncode != 0:
            self.skipTest(f"no systemd --user scope: {probe.stderr.strip()[:200]}")
        r = subprocess.run(
            ["systemd-run", "--user", "--scope", "-q", "-p", "Delegate=yes",
             "--setenv=TELEPATHY_CGROUP_TESTS=1", "--working-directory=" + ROOT, "--",
             PY, "-m", "unittest", "-v", "tests.test_cgroup"],
            capture_output=True, text=True, timeout=120, env={**os.environ,
                                                              "TELEPATHY_CGROUP_TESTS": "1"})
        self.assertEqual(r.returncode, 0, r.stderr[-4000:])
        real = [l for l in r.stderr.splitlines() if ".RealCgroup." in l]
        self.assertGreaterEqual(len(real), 10, r.stderr[-2000:])
        self.assertEqual([l for l in real if "skipped" in l], [])  # every real test ran


@unittest.skipUnless(INNER, "runs inside a delegated scope (see InScope)")
class RealCgroup(unittest.TestCase):
    def setUp(self):
        self.base = cgroup.probe()
        if self.base is None:
            self.fail("probe failed inside the delegated scope")
        executor.configure_cgroups(self.base)
        self.addCleanup(executor.configure_cgroups, None)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.pidfile = os.path.join(self.tmp, "pid")
        self.addCleanup(self._kill_leftover)

    def _kill_leftover(self):
        for name in os.listdir(self.base):
            if name.startswith(cgroup.PREFIX):
                d = os.path.join(self.base, name)
                try:
                    cgroup.kill(d)
                    cgroup.wait_empty(d, 5)
                except OSError:
                    pass
                cgroup.remove(d)

    def _cmd_dirs(self):
        return [n for n in os.listdir(self.base) if n.startswith(cgroup.PREFIX)]

    def _pid(self):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            try:
                with open(self.pidfile) as f:
                    return int(f.read())
            except (OSError, ValueError):
                time.sleep(0.01)
        self.fail("descendant never started")

    def _gone(self, pid):
        end = time.monotonic() + 3
        while _alive(pid) and time.monotonic() < end:
            time.sleep(0.01)
        return not _alive(pid)

    # -- the timeout kill ------------------------------------------------

    def test_setsid_and_double_fork_descendants_die_on_timeout(self):
        script = """
import os, sys, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        open(sys.argv[1], 'w').write(str(os.getpid()))
        time.sleep(60)
    os._exit(0)
time.sleep(60)
"""
        r = run_command([PY, "-c", script, self.pidfile], "/tmp", ENV, timeout=1.0)
        self.assertEqual(r.exit_code, 124)
        self.assertNotIn("survive", r.error)
        self.assertTrue(self._gone(self._pid()))
        self.assertEqual(self._cmd_dirs(), [])

    def test_fast_double_fork_that_orphans_itself_at_once_dies(self):
        # The case /proc polling can miss: no process lives long enough to be seen.
        script = """
import os, sys, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        open(sys.argv[1], 'w').write(str(os.getpid()))
        time.sleep(60)
    os._exit(0)
os.wait()
time.sleep(60)
"""
        with mock.patch.object(executor, "_scan_descendants",
                               side_effect=AssertionError("no /proc polling with cgroups")):
            r = run_command([PY, "-c", script, self.pidfile], "/tmp", ENV, timeout=1.0)
        self.assertEqual(r.exit_code, 124)
        self.assertTrue(self._gone(self._pid()))

    def test_many_children_are_all_killed(self):
        script = """
import os, sys, time
pids = []
for _ in range(40):
    p = os.fork()
    if p == 0:
        os.setsid()
        time.sleep(60)
        os._exit(0)
    pids.append(p)
open(sys.argv[1], 'w').write(" ".join(map(str, pids)))
time.sleep(60)
"""
        r = run_command([PY, "-c", script, self.pidfile], "/tmp", ENV, timeout=1.5)
        self.assertEqual(r.exit_code, 124)
        with open(self.pidfile) as f:
            pids = [int(p) for p in f.read().split()]
        self.assertEqual(len(pids), 40)
        self.assertTrue(all(self._gone(p) for p in pids))

    # -- normal runs -----------------------------------------------------

    def test_normal_run_is_unchanged_and_its_cgroup_removed(self):
        r = run_command(["/usr/bin/sh", "-c", "echo out; echo err >&2; exit 3"], self.tmp, ENV)
        self.assertEqual(r.exit_code, 3)
        self.assertEqual(sorted(r.output.split()), [b"err", b"out"])
        self.assertIsNone(r.error)
        self.assertEqual(self._cmd_dirs(), [])

    def test_command_runs_inside_its_own_cmd_cgroup(self):
        r = run_command(["/usr/bin/cat", "/proc/self/cgroup"], "/tmp", ENV)
        self.assertEqual(r.exit_code, 0)
        path = r.output.decode().strip().split("::", 1)[1]
        self.assertEqual(os.path.dirname(os.path.join(cgroup.CGROUP_ROOT, path.lstrip("/"))),
                         self.base)
        self.assertTrue(os.path.basename(path).startswith(cgroup.PREFIX))

    def test_environment_and_cwd_are_exactly_what_was_given(self):
        for env in ({"PATH": "/usr/bin", "X": "1"},          # no locale: PEP 538 territory
                    {"PATH": "/usr/bin", "LANG": "C", "LD_LIBRARY_PATH": "/nonexistent",
                     "Y": "a=b c\tq"}):
            r = run_command(["/usr/bin/env", "-0"], self.tmp, env)
            self.assertEqual(r.exit_code, 0, r.error)
            got = dict(i.split("=", 1) for i in r.output.decode().split("\0") if i)
            self.assertEqual(got, env)
        r = run_command(["/usr/bin/pwd"], self.tmp, ENV)
        self.assertEqual(r.output.decode().strip(), os.path.realpath(self.tmp))

    def test_signal_dispositions_match_the_fallback_path(self):
        cmd = ["/usr/bin/grep", "^SigIgn:", "/proc/self/status"]
        r = run_command(cmd, "/tmp", ENV)
        executor.configure_cgroups(None)
        plain = run_command(cmd, "/tmp", ENV)
        executor.configure_cgroups(self.base)
        self.assertEqual(r.output, plain.output)
        ign = int(r.output.split()[1], 16)
        for sig in (signal.SIGPIPE, signal.SIGXFSZ):
            self.assertFalse(ign & (1 << (sig - 1)), f"{sig!r} is ignored in the command")

    def test_command_that_closes_stdout_early_still_times_out_with_cgroup_kill(self):
        script = """
import os, sys, time
if os.fork() == 0:
    os.setsid()
    open(sys.argv[1], 'w').write(str(os.getpid()))
    os.close(1); os.close(2)
    time.sleep(60)
os.close(1); os.close(2)
time.sleep(60)
"""
        r = run_command([PY, "-c", script, self.pidfile], "/tmp", ENV, timeout=1.0)
        self.assertEqual(r.exit_code, 124)
        self.assertTrue(self._gone(self._pid()))

    def test_probe_requires_a_working_join(self):
        with mock.patch.object(cgroup.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 1)):
            self.assertIsNone(cgroup.probe(self.base))
        self.assertEqual(cgroup.probe(self.base), self.base)
        self.assertEqual(self._cmd_dirs(), [])

    def test_daemon_level_sweep_uses_the_configured_base(self):
        os.mkdir(os.path.join(self.base, cgroup.PREFIX + "stale"))
        self.assertEqual(executor.sweep_cgroups(), 1)
        executor.configure_cgroups(None)
        self.assertEqual(executor.sweep_cgroups(), 0)
        executor.configure_cgroups(self.base)

    def test_leftovers_of_a_normal_exit_keep_running_then_are_swept(self):
        script = """
import os, sys, time
if os.fork() == 0:
    os.setsid()
    null = os.open(os.devnull, os.O_RDWR)  # a daemon lets go of the command's output
    os.dup2(null, 1); os.dup2(null, 2)
    open(sys.argv[1], 'w').write(str(os.getpid()))
    time.sleep(60)
    os._exit(0)
"""
        r = run_command([PY, "-c", script, self.pidfile], "/tmp", ENV, timeout=10)
        self.assertEqual(r.exit_code, 0)
        pid = self._pid()
        self.assertTrue(_alive(pid))  # user's choice: left running
        self.assertEqual(len(self._cmd_dirs()), 1)
        os.kill(pid, signal.SIGKILL)
        self.assertTrue(self._gone(pid))
        end = time.monotonic() + 3
        while cgroup.populated(os.path.join(self.base, self._cmd_dirs()[0])) \
                and time.monotonic() < end:
            time.sleep(0.01)
        self.assertEqual(cgroup.sweep(self.base), 1)
        self.assertEqual(self._cmd_dirs(), [])

    # -- start failures: nothing runs -------------------------------------

    def test_missing_command_and_cwd(self):
        r = run_command(["/nonexistent/x"], "/tmp", ENV)
        self.assertEqual((r.exit_code, r.error), (127, "command or working directory not found"))
        r = run_command(["/usr/bin/true"], "/nonexistent-dir", ENV)
        self.assertEqual(r.exit_code, 127)
        self.assertEqual(self._cmd_dirs(), [])

    def test_unexecutable_file(self):
        p = os.path.join(self.tmp, "noexec")
        open(p, "w").close()
        r = run_command([p], "/tmp", ENV)
        self.assertEqual((r.exit_code, r.error), (126, "permission denied"))

    def test_join_failure_never_runs_the_command(self):
        fake = os.path.join(self.tmp, "fakecg")
        os.mkdir(fake)
        procs = os.path.join(fake, "cgroup.procs")
        open(procs, "w").close()
        os.chmod(procs, 0o444)
        marker = os.path.join(self.tmp, "ran")
        if os.geteuid() == 0:
            self.skipTest("root can write a 0444 file")
        with mock.patch.object(cgroup, "create", return_value=fake):
            r = run_command(["/usr/bin/touch", marker], "/tmp", ENV)
        self.assertEqual(r.exit_code, 126)
        self.assertIn("was not run", r.error)
        self.assertFalse(os.path.exists(marker))

    def _fake_helper(self, body):
        p = os.path.join(self.tmp, "helper.py")
        with open(p, "w") as f:
            f.write(body)
        return mock.patch.object(executor, "HELPER", p)

    def test_helper_dying_before_the_join_is_not_run(self):
        marker = os.path.join(self.tmp, "ran")
        with self._fake_helper("import os; os._exit(1)\n"):
            r = run_command(["/usr/bin/touch", marker], "/tmp", ENV)
        self.assertEqual(r.exit_code, 126)
        self.assertIn("was not run", r.error)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(self._cmd_dirs(), [])

    def test_helper_stalling_before_exec_is_killed_and_not_run(self):
        with self._fake_helper("import time; time.sleep(30)\n"), \
             mock.patch.object(executor, "JOIN_TIMEOUT", 0.3):
            t0 = time.monotonic()
            r = run_command(["/usr/bin/true"], "/tmp", ENV)
        self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual(r.exit_code, 126)
        self.assertIn("did not confirm its start in time", r.error)
        self.assertEqual(self._cmd_dirs(), [])

    def test_cgroup_kill_failure_falls_back_to_the_group_kill_and_says_so(self):
        with mock.patch.object(cgroup, "kill", side_effect=OSError(5, "EIO")), \
             self.assertLogs("telepathy.executor", "WARNING"):
            r = run_command([PY, "-c", "import time; time.sleep(60)"], "/tmp", ENV, timeout=0.5)
        self.assertEqual(r.exit_code, 124)
        self.assertIn("cgroup kill failed", r.error)

    def test_survivors_after_cgroup_kill_are_reported(self):
        with mock.patch.object(cgroup, "wait_empty", return_value=False):
            r = run_command([PY, "-c", "import time; time.sleep(60)"], "/tmp", ENV, timeout=0.5)
        self.assertEqual(r.exit_code, 124)
        self.assertIn("survived the kill", r.error)

    def test_sweep_skips_a_fresh_dir_not_yet_released(self):
        d = cgroup.create(self.base)
        self.assertEqual(cgroup.sweep(self.base), 0)
        self.assertTrue(os.path.isdir(d))
        self.assertTrue(cgroup.remove(d))
        self.assertFalse(os.path.exists(d))

    def test_bad_environment_is_refused_and_nothing_leaks(self):
        for env in ({"A": "1\0LD_PRELOAD=/x"}, {"A=B": "1"}, {"": "1"}):
            r = run_command(["/usr/bin/true"], "/tmp", env)
            self.assertEqual(r.exit_code, 126)
            self.assertIn("invalid environment", r.error)
        self.assertEqual(self._cmd_dirs(), [])

    def test_popen_value_error_releases_the_cgroup(self):
        with self.assertRaises(ValueError):
            run_command(["/usr/bin/true", "a\0b"], "/tmp", ENV)
        self.assertEqual(self._cmd_dirs(), [])
        self.assertEqual(cgroup._active, set())

    def test_pipe_failure_releases_the_cgroup(self):
        with mock.patch.object(executor.os, "pipe", side_effect=OSError(24, "EMFILE")):
            r = run_command(["/usr/bin/true"], "/tmp", ENV)
        self.assertEqual(r.exit_code, 126)
        self.assertEqual(self._cmd_dirs(), [])
        self.assertEqual(cgroup._active, set())

    def test_output_cap_still_drains(self):
        r = run_command([PY, "-c", "import sys; sys.stdout.write('x' * 300000)"], "/tmp", ENV,
                        max_output=1000)
        self.assertEqual((r.exit_code, len(r.output), r.truncated), (0, 1000, True))


if __name__ == "__main__":
    unittest.main()
