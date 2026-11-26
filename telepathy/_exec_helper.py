"""Join a cgroup, then exec the approved command (run by the executor).

    python3 -I _exec_helper.py <cgroup.procs path> <error fd> <env fd> -- argv0 [args...]

The helper itself runs with an empty environment; the command's exact
environment arrives on <env fd> as NUL-separated KEY=VALUE entries and is
passed to execve unchanged (Python's own startup, e.g. PEP 538 locale coercion,
must not leak into it).

Runs in the freshly forked child, before the command, so the command and
everything it starts are in the cgroup from its first instruction (no
`preexec_fn`, which is unsafe in the threaded daemon). Failures are reported
on <error fd> (close-on-exec) as "<stage> <errno>", and the command is then
never executed. After joining it writes "joined"; a successful exec then closes
the fd with nothing more, so the executor sees exactly "joined" and EOF. A
helper that dies before that (startup failure, bad arguments) writes nothing,
which the executor also reports as "not run".

    join <errno>   could not enter the cgroup (exit 126)
    exec <errno>   execv failed (exit 127 for ENOENT, else 126)

Standard library only, no imports from telepathy: it must start fast and must
not depend on the daemon's import path.
"""

import errno
import os
import signal
import sys


def main() -> None:
    if len(sys.argv) < 6 or sys.argv[4] != "--":
        os._exit(2)  # no "joined" written: the executor reports "not run"
    procs, errfd, envfd = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    argv = sys.argv[5:]
    os.set_inheritable(errfd, False)
    raw = b""
    while True:
        chunk = os.read(envfd, 65536)
        if not chunk:
            break
        raw += chunk
    os.close(envfd)
    env = {}
    for item in raw.split(b"\0"):
        if item:
            k, _, v = item.partition(b"=")
            env[k] = v
    try:
        fd = os.open(procs, os.O_WRONLY)
        try:
            os.write(fd, b"0")
        finally:
            os.close(fd)
    except OSError as e:
        os.write(errfd, f"join {e.errno}".encode())
        os._exit(126)
    os.write(errfd, b"joined\n")  # positive signal: anything short of this was "not run"
    # Python ignores these at startup and ignored signals survive execve; the
    # command must start with the defaults, as it does without the helper.
    for sig in (signal.SIGPIPE, signal.SIGXFSZ):
        signal.signal(sig, signal.SIG_DFL)
    try:
        os.execve(argv[0], argv, env)
    except OSError as e:
        os.write(errfd, f"exec {e.errno}".encode())
        os._exit(127 if e.errno == errno.ENOENT else 126)


if __name__ == "__main__":
    main()
