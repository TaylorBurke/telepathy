"""Per-command cgroups: a timeout kills everything a command started.

The daemon's unit has `Delegate=yes`, so telepathyd owns its own cgroup v2
directory. Each approved command runs in a child `cmd-<n>/` of it, joined by the
exec helper before the command's first instruction (`_exec_helper.py`), and a
timeout writes `cgroup.kill`, which SIGKILLs every member at once: a `setsid`,
a double fork or a fork bomb cannot escape, because cgroup membership is
inherited. (An approved command runs as root and could still move itself out
on purpose; approval remains the guarantee.)

The daemon itself stays in its cgroup: with no controllers enabled in
`cgroup.subtree_control` the no-internal-processes rule does not apply. Without
cgroup v2, delegation or `cgroup.kill` (kernel < 5.14), `probe` returns None and
the executor keeps its /proc-polling fallback.

After a normal exit, processes the command left behind keep running (as before
this change); their `cmd-*` directory is removed once it is empty, by `sweep`.
"""

from __future__ import annotations

import itertools
import os
import subprocess
import sys
import threading
import time

CGROUP_ROOT = "/sys/fs/cgroup"
PREFIX = "cmd-"
_seq = itertools.count(1)
_active: set[str] = set()  # created by this process and not yet released
_active_lock = threading.Lock()


def own_dir(proc_self_cgroup: str = "/proc/self/cgroup") -> str | None:
    """This process's cgroup v2 directory, or None (cgroup v1 / hybrid / no /proc)."""
    try:
        with open(proc_self_cgroup) as f:
            for line in f:
                hier, _, path = line.rstrip("\n").partition("::")
                if hier == "0" and path.startswith("/"):
                    d = os.path.join(CGROUP_ROOT, path.lstrip("/"))
                    return d if os.path.isdir(d) else None
    except OSError:
        pass
    return None


def populated(d: str) -> bool:
    """True while any process is in `d` or below. A missing dir is empty."""
    try:
        with open(os.path.join(d, "cgroup.events")) as f:
            for line in f:
                k, _, v = line.partition(" ")
                if k == "populated":
                    return v.strip() != "0"
    except FileNotFoundError:
        return False
    return True  # unreadable: assume busy, never rmdir blindly


def kill(d: str) -> None:
    """SIGKILL every process in `d` and below, atomically (kernel >= 5.14)."""
    with open(os.path.join(d, "cgroup.kill"), "w") as f:
        f.write("1")


def wait_empty(d: str, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while populated(d):
        if time.monotonic() >= end:
            return False
        time.sleep(0.01)
    return True


def remove(d: str) -> bool:
    """Release `d` (sweep may take it from now on) and rmdir it if it is empty;
    False while processes remain in it."""
    with _active_lock:
        _active.discard(d)
    try:
        os.rmdir(d)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def create(base: str) -> str:
    """A fresh, empty `cmd-<n>` child of `base`."""
    while True:
        d = os.path.join(base, f"{PREFIX}{os.getpid()}-{next(_seq)}")
        with _active_lock:
            try:
                os.mkdir(d, 0o755)
            except FileExistsError:
                continue
            _active.add(d)  # a fresh, still empty dir must not be swept before its join
            return d


def sweep(base: str) -> int:
    """Remove empty `cmd-*` children of `base` (leftovers that have exited). Returns how many."""
    n = 0
    try:
        names = os.listdir(base)
    except OSError:
        return 0
    for name in names:
        if name.startswith(PREFIX):
            d = os.path.join(base, name)
            with _active_lock:
                if d in _active:
                    continue
            if os.path.isdir(d) and not populated(d):
                try:
                    os.rmdir(d)
                    n += 1
                except OSError:
                    pass
    return n


def probe(base: str | None = None) -> str | None:
    """`base` (default: our own cgroup) if per-command cgroups work there, else None.

    Works means: a child can be created, has `cgroup.kill`, `cgroup.procs` and
    `cgroup.events`, a throwaway process can join it, and it can be removed again.
    """
    base = base if base is not None else own_dir()
    if base is None:
        return None
    try:
        d = create(base)
    except OSError:
        return None
    try:
        ok = all(os.path.exists(os.path.join(d, f))
                 for f in ("cgroup.kill", "cgroup.procs", "cgroup.events"))
        if ok:
            # A throwaway child must be able to join, or every command would
            # fail at its join instead of using the fallback.
            r = subprocess.run(
                [sys.executable, "-I", "-c",
                 "import sys; f = open(sys.argv[1], 'w'); f.write('0'); f.close()",
                 os.path.join(d, "cgroup.procs")],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10)
            ok = r.returncode == 0 and wait_empty(d, 5)
    except (OSError, subprocess.SubprocessError):
        ok = False
    finally:
        remove(d)
    return base if ok else None
