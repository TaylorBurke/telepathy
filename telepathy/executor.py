"""Run one approved command and capture its (size-capped) output."""

from __future__ import annotations

import errno
import logging
import os
import select
import signal
import subprocess
import sys
import time
from dataclasses import dataclass

from . import cgroup

HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_exec_helper.py")
JOIN_TIMEOUT = 10.0  # the helper only opens a file and execs; a hang here is a bug

# Set once at daemon start by `configure_cgroups` (None: /proc-polling fallback).
_CGROUP_BASE: str | None = None


def configure_cgroups(base: str | None) -> None:
    """Use per-command cgroups under `base` (from `cgroup.probe`), or None for the fallback."""
    global _CGROUP_BASE
    _CGROUP_BASE = base


def sweep_cgroups() -> int:
    """Remove empty `cmd-*` dirs (left by processes that outlived their command)."""
    base = _CGROUP_BASE
    return cgroup.sweep(base) if base is not None else 0


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    output: bytes = b""
    truncated: bool = False
    error: str | None = None


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


_log = logging.getLogger("telepathy.executor")


class _Stat:
    __slots__ = ("ppid", "start", "state")

    def __init__(self, ppid: int, start: str, state: str = "S"):
        self.ppid, self.start, self.state = ppid, start, state

    @property
    def zombie(self) -> bool:
        return self.state in ("Z", "X")


def _stat(pid: int):
    """Parse /proc/<pid>/stat, or None if the process is gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read().decode("ascii", "replace")
        rest = data[data.rindex(")") + 2:].split()
        return _Stat(int(rest[1]), rest[19], rest[0])
    except (OSError, ValueError, IndexError):
        return None


def _probe_children_file() -> bool:
    """True if this kernel provides /proc/<pid>/task/<tid>/children."""
    try:
        return any(os.path.exists(f"/proc/self/task/{t}/children")
                   for t in os.listdir("/proc/self/task"))
    except OSError:
        return False


_CHILDREN_OK = _probe_children_file()


def _children(pid: int):
    """Direct children of pid, or None when the kernel lacks the children file
    (decided once at import). A thread or process that vanishes mid-read is
    simply skipped."""
    if not _CHILDREN_OK:
        return None
    out = []
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return out  # gone (or unreadable): no children to follow
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/children") as f:
                out += [int(x) for x in f.read().split()]
        except (OSError, ValueError):
            continue  # thread exited; its children belong to the group leader scan
    return out


def _children_from_table():
    """Fallback: full /proc listing as a ppid -> [pid] map."""
    kids: dict[int, list[int]] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return kids
    for name in names:
        if name.isdigit():
            st = _stat(int(name))
            if st:
                kids.setdefault(st.ppid, []).append(int(name))
    return kids


def proc_available() -> bool:
    return os.path.exists("/proc/self/stat")


def _scan_descendants(root: int, known: dict[int, str],
                      read_stat=_stat, read_children=_children) -> bool:
    """Refresh `known` (pid -> starttime) with root and its live descendants.

    Entries from earlier scans seed the walk only while their pid still has the
    recorded starttime and is not a zombie; others are dropped, so a recycled
    pid is never followed or signalled and the set stays small. A pid found
    again by the walk replaces any stale entry. Returns True if it had to fall
    back to a full /proc listing.
    """
    cache: dict[int, object] = {}
    raw_stat = read_stat

    def read_stat(pid):
        if pid not in cache:
            cache[pid] = raw_stat(pid)
        return cache[pid]

    fresh: dict[int, str] = {}
    seeds = [root]
    for pid, start in known.items():
        st = read_stat(pid)
        if pid != root and st and st.start == start and not st.zombie:
            seeds.append(pid)
            fresh[pid] = start
    table = None
    queue, seen = list(seeds), set()
    while queue:
        pid = queue.pop()
        if pid in seen:
            continue
        seen.add(pid)
        st = read_stat(pid)
        if st and not st.zombie:
            fresh[pid] = st.start
        kids = read_children(pid) if table is None else None
        if kids is None:
            if table is None:
                table = _children_from_table()
            kids = table.get(pid, [])
        for c in kids:
            if c not in seen:
                queue.append(c)
    known.clear()
    known.update(fresh)
    return table is not None


def _live(known: dict[int, str], read_stat=_stat) -> list[int]:
    out = []
    for pid, start in known.items():
        st = read_stat(pid)
        if st and st.start == start and not st.zombie:
            out.append(pid)
    return out


def _signal_pid(pid: int, start: str, sig, read_stat, kill) -> None:
    """Signal pid only if it still has the recorded starttime.

    With pidfd the handle is opened first and the identity checked after, so
    the signal can only reach the process we verified. Without pidfd the
    recheck narrows (does not close) the window before os.kill.
    """
    fd = None
    try:
        if kill is os.kill and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            try:
                fd = os.pidfd_open(pid)
            except OSError:
                fd = None
        st = read_stat(pid)
        if not st or st.start != start or st.zombie:
            return
        if fd is not None:
            signal.pidfd_send_signal(fd, sig)
        else:
            kill(pid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    finally:
        if fd is not None:
            os.close(fd)


def _signal_all(root: int, targets: dict, sig, read_stat, kill, killpg) -> None:
    try:
        killpg(root, sig)
    except (ProcessLookupError, PermissionError):
        pass
    for p, start in targets.items():
        _signal_pid(p, start, sig, read_stat, kill)


def _wait_stopped(pids, read_stat, limit: float = 0.05) -> None:
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if all((st := read_stat(p)) is None or st.state in ("T", "t", "Z", "X")
               for p in pids):
            return
        time.sleep(0.002)


def _kill_tree(root: int, known: dict[int, str], read_stat=_stat,
               read_children=_children, kill=os.kill, killpg=os.killpg) -> bool:
    """Stop, then kill, the process group and every tracked descendant.

    SIGSTOP freezes the tree so it cannot fork while we enumerate it; we rescan
    until the set is stable, then SIGKILL. Bounded at 20 passes. The group is
    always sent SIGKILL, even with no tracked pid alive (e.g. the command
    exited leaving an orphan in its group). Returns True when no live tracked
    process is left.
    """
    prev = None
    for _ in range(20):
        _scan_descendants(root, known, read_stat, read_children)
        live = _live(known, read_stat)
        if not live:
            _signal_all(root, {}, signal.SIGKILL, read_stat, kill, killpg)
            return True
        targets = {p: known[p] for p in live}
        _signal_all(root, targets, signal.SIGSTOP, read_stat, kill, killpg)
        _wait_stopped(live, read_stat)
        if prev != set(live):
            prev = set(live)
            continue
        _signal_all(root, targets, signal.SIGKILL, read_stat, kill, killpg)
        prev = None
        time.sleep(0.01)
    _scan_descendants(root, known, read_stat, read_children)
    live = _live(known, read_stat)
    _signal_all(root, {p: known[p] for p in live}, signal.SIGKILL, read_stat, kill, killpg)
    return not _live(known, read_stat)


def run_command(argv, cwd: str, env, timeout: float = 300.0,
                max_output: int = 262144) -> ExecResult:
    """exec argv directly (never via a shell) with a fixed environment.

    stdin is /dev/null; stdout and stderr are merged and capped at max_output
    bytes (the rest is drained and dropped so the child never blocks). On
    timeout the whole process group and all tracked descendants (including
    setsid'd ones) are killed and the exit code is 124.
    """
    base = _CGROUP_BASE
    if base is not None:
        return _run_in_cgroup(argv, cwd, env, timeout, max_output, base)
    try:
        proc = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
    except FileNotFoundError:
        return ExecResult(127, error="command or working directory not found")
    except PermissionError:
        return ExecResult(126, error="permission denied")
    except OSError as e:
        return ExecResult(126, error=f"cannot execute: {e.strerror or e}")

    buf = bytearray()
    truncated = False
    timed_out = False
    tree_error = ""
    fd = proc.stdout.fileno()
    deadline = time.monotonic() + timeout
    known: dict[int, str] = {}
    next_scan = 0.0
    scan_every = 0.25
    while True:
        now = time.monotonic()
        if now >= next_scan:
            # Remember descendants while they are still linked to us, so ones
            # that later get re-parented to init can still be killed.
            if _scan_descendants(proc.pid, known):
                scan_every = 1.0  # full /proc listing is costly: go coarser
            next_scan = now + scan_every
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        ready, _, _ = select.select([fd], [], [], min(remaining, 0.25))
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        room = max_output - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            truncated = True

    if timed_out:
        if not proc_available():
            _log.warning("/proc unavailable: only the process group was killed")
            _kill_group(proc.pid)
            tree_error = "; /proc unavailable, detached descendants may survive"
        elif not _kill_tree(proc.pid, known):
            _log.warning("process tree still alive after kill passes (pid %s)", proc.pid)
            tree_error = "; some descendants may have survived the kill"
    proc.stdout.close()
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_group(proc.pid)
        rc = proc.wait()

    if timed_out:
        return ExecResult(124, bytes(buf), truncated, f"timed out after {timeout:g}s{tree_error}")
    if rc < 0:
        return ExecResult(128 + (-rc), bytes(buf), truncated, f"killed by signal {-rc}")
    return ExecResult(rc, bytes(buf), truncated)


def _env_blob(env) -> bytes:
    """NUL-separated KEY=VALUE for the helper; refuses what execve(2) cannot carry
    (NUL anywhere, '=' or nothing in a key), as Popen(env=) would."""
    items = []
    for k, v in dict(env).items():
        kb, vb = os.fsencode(k), os.fsencode(v)
        if not kb or b"=" in kb or b"\0" in kb or b"\0" in vb:
            raise ValueError(f"bad environment entry {k!r}")
        items.append(kb + b"=" + vb)
    return b"\0".join(items)


def _exec_error(stage: str, err: int) -> ExecResult:
    if stage == "join":
        return ExecResult(126, error="could not place the command in its cgroup "
                                     f"({os.strerror(err)}); it was not run")
    if err == errno.ENOENT:
        return ExecResult(127, error="command or working directory not found")
    if err in (errno.EACCES, errno.EPERM):
        return ExecResult(126, error="permission denied")
    return ExecResult(126, error=f"cannot execute: {os.strerror(err)}")


def _read_all(fd: int, timeout: float) -> bytes | None:
    """Read `fd` to EOF; None if it stays open past `timeout`."""
    out = b""
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], left)
        if not ready:
            return None
        chunk = os.read(fd, 256)
        if not chunk:
            return out
        out += chunk


def _run_in_cgroup(argv, cwd: str, env, timeout: float, max_output: int,
                   base: str) -> ExecResult:
    """`run_command` with the command in its own cgroup: the timeout kill is
    `cgroup.kill`, which nothing the command starts can escape, and no /proc polling."""
    try:
        blob = _env_blob(env)
    except (TypeError, ValueError) as e:
        return ExecResult(126, error=f"invalid environment ({e}); it was not run")
    try:
        d = cgroup.create(base)
    except OSError as e:
        return ExecResult(126, error=f"could not create the command's cgroup ({e.strerror}); "
                                     "it was not run")

    def close_all(*fds):
        for f in fds:
            try:
                os.close(f)
            except OSError:
                pass
    try:
        r, w = os.pipe()
        try:
            envr, envw = os.pipe()
        except OSError:
            close_all(r, w)
            raise
    except OSError as e:
        cgroup.remove(d)
        return ExecResult(126, error=f"cannot execute: {e.strerror or e}")
    try:
        # The helper gets an empty environment; the command's exact one goes over
        # envr and is handed to execve unchanged.
        proc = subprocess.Popen(
            [sys.executable, "-I", HELPER, os.path.join(d, "cgroup.procs"), str(w), str(envr),
             "--", *argv],
            cwd=cwd,
            env={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            pass_fds=(w, envr),
        )
    except FileNotFoundError:
        close_all(r, w, envr, envw)
        cgroup.remove(d)
        return ExecResult(127, error="command or working directory not found")
    except OSError as e:
        close_all(r, w, envr, envw)
        cgroup.remove(d)
        return ExecResult(126, error=f"cannot execute: {e.strerror or e}")
    except BaseException:  # e.g. ValueError for a NUL byte: release, then propagate
        close_all(r, w, envr, envw)
        cgroup.remove(d)
        raise
    close_all(w, envr)
    try:
        view = memoryview(blob)
        while view:  # small (a fixed env); the helper reads it before anything else
            n = os.write(envw, view)
            view = view[n:]
    except OSError:
        pass  # the helper died; it then never writes "joined" and is reported below
    finally:
        os.close(envw)
    try:
        msg = _read_all(r, JOIN_TIMEOUT)
    finally:
        os.close(r)
    if msg != b"joined\n":
        # The helper failed, hung or died before exec. Kill everything in the cgroup
        # (a slow exec after the join may already have started the command).
        # The helper's group first, so it cannot join after the cgroup was emptied.
        _kill_group(proc.pid)
        try:
            cgroup.kill(d)
            cgroup.wait_empty(d, 5)
        except OSError:
            pass
        proc.stdout.close()
        proc.wait()
        cgroup.remove(d)
        if msg is None:
            return ExecResult(126, error="the command did not confirm its start in time; "
                                         "everything in its cgroup was killed")
        stage, _, num = msg.decode("ascii", "replace").removeprefix("joined\n").partition(" ")
        try:
            return _exec_error(stage, int(num))
        except ValueError:
            return ExecResult(126, error="the command could not be started; it was not run")

    buf = bytearray()
    truncated = False
    timed_out = False
    fd = proc.stdout.fileno()
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        room = max_output - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            truncated = True

    if not timed_out:
        # EOF on stdout does not mean the command is done (it may have closed its
        # output and kept running): wait for it up to the same deadline.
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    tree_error = ""
    if timed_out:
        try:
            cgroup.kill(d)
            if not cgroup.wait_empty(d, 5):
                tree_error = "; some processes in the command's cgroup survived the kill"
        except OSError as e:
            _log.warning("cgroup.kill failed for %s: %s", d, e)
            _kill_group(proc.pid)
            tree_error = "; cgroup kill failed, detached descendants may survive"
    proc.stdout.close()
    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_group(proc.pid)
        rc = proc.wait()
    # Leftovers of a normal exit keep running (by design); their directory goes
    # once it is empty, here or in a later sweep.
    cgroup.remove(d)
    cgroup.sweep(base)

    if timed_out:
        return ExecResult(124, bytes(buf), truncated, f"timed out after {timeout:g}s{tree_error}")
    if rc < 0:
        return ExecResult(128 + (-rc), bytes(buf), truncated, f"killed by signal {-rc}")
    return ExecResult(rc, bytes(buf), truncated)

