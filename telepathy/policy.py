"""Policy: deny > auto > ask.

Loaded from /etc/telepathy/policy.toml (root-owned). The agent can never change
it. Rules can only *add* denials on top of the built-in ones; nothing in the
file can weaken the built-ins.
"""

from __future__ import annotations

import collections
import errno
import itertools
import os
import re
import stat
import struct
import threading
import tomllib
from dataclasses import dataclass
from typing import NamedTuple

# Shells, interpreters and wrappers that turn "one approved command" into
# "arbitrary code". Matching is on the basename of argv[0].
BUILTIN_DENY_EXE = frozenset(
    {
        "sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "ash", "busybox",
        "sudo", "su", "doas", "pkexec", "run0", "systemd-run",
        "env", "xargs", "nice", "nohup", "timeout", "setsid", "stdbuf", "script",
        "nsenter", "chroot", "unshare", "awk", "gawk", "mawk", "expect", "socat",
    }
)
BUILTIN_DENY_EXE_RE = re.compile(
    r"^(python|pypy|perl|ruby|node|nodejs|deno|bun|lua|luajit|php|tclsh|wish|guile|ghc|runghc)w?(-?[0-9][0-9A-Za-z.\-]*)?$"
)

# Paths whose modification would let the agent weaken or bypass telepathy
# (or the rest of the privilege model). Arguments are checked both as written and
# with symlinks resolved (the daemon runs as root, so it can see through links
# the agent made), against each prefix both as written and resolved (the host may
# have relocated e.g. /etc/sudoers.d behind a link); it is re-checked just before
# running, since a link can be retargeted after approval. Indirect access (a command that happens to write
# there) is still the job of the human approval, not of this list.
PROTECTED_PREFIXES = (
    "/etc/telepathy",
    "/etc/sudoers",
    "/etc/pam.d",
    "/etc/polkit-1",
    "/usr/share/polkit-1",
    "/usr/lib/telepathy",
    "/usr/local/lib/telepathy",
    "/var/lib/telepathy",
    "/var/log/telepathy",
    "/etc/systemd/system/telepathy",
    "/usr/lib/systemd/system/telepathy",
)

UNRESOLVABLE = "(symlink loop or unresolvable path)"
TIMED_OUT = "(resolution timed out: a slow or hung filesystem)"
TIMED_OUT_KEY = "(path resolution)"
ERROR = "(resolution failed with an unexpected error)"
ERROR_KEY = "(path resolution error)"
RESOLVE_TIMEOUT = 5.0

OPTION_PROBES = ("-x", "--x", "-")


class PolicyError(ValueError):
    """The policy file is invalid."""


@dataclass(frozen=True)
class Decision:
    kind: str  # "deny" | "auto" | "ask"
    reason: str = ""
    rule: str | None = None


@dataclass(frozen=True)
class _Token:
    literal: str | None = None
    pattern: re.Pattern | None = None
    variadic: bool = False


@dataclass(frozen=True)
class AutoRule:
    name: str
    tokens: tuple[_Token, ...]

    def matches(self, argv) -> bool:
        toks = self.tokens
        last = toks[-1]
        if last.variadic:
            fixed = toks[:-1]
            if len(argv) < len(fixed) + 1:
                return False
            head, tail = argv[: len(fixed)], argv[len(fixed):]
            return _match_fixed(fixed, head) and all(last.pattern.fullmatch(a) for a in tail)
        if len(argv) != len(toks):
            return False
        return _match_fixed(toks, argv)


def _match_fixed(toks, args) -> bool:
    for t, a in zip(toks, args):
        if t.literal is not None:
            if a != t.literal:
                return False
        elif not t.pattern.fullmatch(a):
            return False
    return True


def _under(path: str, prefix: str) -> bool:
    # Plain prefix match on purpose: "/etc/sudoers" must also catch
    # "/etc/sudoers.d/x", and "/etc/systemd/system/telepathy" the unit files.
    return path.startswith(prefix)


def _normalize(arg: str, cwd: str) -> str:
    return os.path.normpath(arg if arg.startswith("/") else os.path.join(cwd, arg))


def _candidates(arg: str) -> list[str]:
    out = [arg]
    if "=" in arg:  # --config=/etc/telepathy/x
        out.append(arg.split("=", 1)[1])
    return [c for c in out if c]


def _joined(c: str, cwd: str) -> str:
    return c if c.startswith("/") else os.path.join(cwd, c)


def _real(c: str, cwd: str) -> str:
    # realpath on the *unnormalised* path: it applies ".." after following
    # symlinks, as the kernel does. normpath first would turn "link/../x" into
    # "x" and hide where it really goes.
    return os.path.realpath(_joined(c, cwd))


def _untrusted_links(path: str, trusted_uid: int = 0) -> list[str]:
    """Symlinks crossed while resolving `path` that the agent could have made or steered.

    Links owned by `trusted_uid` (/bin -> usr/bin, /home -> ...) are part of the
    system and stay quiet, but only while the directory holding the link and
    every ancestor of it are out of the agent's reach: a root-made link under an
    agent-writable directory can be swapped or its directory renamed, so it is
    reported like the agent's own. Links owned by anyone else are always
    reported. Raises OSError on a loop or too many hops.
    """
    from stat import S_ISLNK

    found: list[str] = []
    cache: dict[str, bool] = {}
    cur, hops = "/", 0
    stack = [p for p in reversed(path.split("/")) if p]
    while stack:
        part = stack.pop()
        if part == ".":
            continue
        if part == "..":
            cur = os.path.dirname(cur)
            continue
        nxt = os.path.join(cur, part)
        try:
            st = os.lstat(nxt)
        except OSError:
            cur = nxt  # does not exist (yet): nothing further to resolve
            continue
        if not S_ISLNK(st.st_mode):
            cur = nxt
            continue
        hops += 1
        if hops > 40:
            raise OSError("too many symlinks")
        if st.st_uid != trusted_uid or not _dir_chain_trusted(cur, trusted_uid, cache):
            found.append(nxt)
        target = os.readlink(nxt)
        if target.startswith("/"):
            cur = "/"
        stack.extend(p for p in reversed(target.split("/")) if p)
    return found


def resolve_path_args(argv, cwd: str, trusted_uid: int = 0) -> dict[str, str]:
    """Map each path that goes through an untrusted symlink to its real target.

    Covers the working directory and every path argument. Keyed by the path as
    written (for `--opt=/path`, the part after `=`), so two candidates from one
    argument are both reported. Used by the approval page and `telepathyctl`, so
    it stays quiet for system links (owned by `trusted_uid`, root, in a directory the
    agent cannot write) and for plain
    arguments like `-n`: a warning that always fires gets ignored. A loop or
    over-long chain is reported as unresolvable rather than dropped.
    """
    found: dict[str, str] = {}
    try:
        base = os.path.realpath(cwd)
        os.lstat(base)  # raises ValueError on a NUL byte, like the checks below
    except ValueError:
        return {cwd: UNRESOLVABLE}
    except OSError:
        pass  # a cwd that does not exist yet is the executor's problem, not a link
    try:
        if _untrusted_links(cwd, trusted_uid):
            found[cwd] = base
    except (OSError, ValueError):
        found[cwd] = UNRESOLVABLE
    for a in argv:
        for c in _candidates(a):
            # Relative args resolve from the *real* cwd: a link in the cwd is
            # reported once, above, not on every argument such as "-n".
            joined = _joined(c, base)
            try:
                if _untrusted_links(joined, trusted_uid):
                    found[c] = os.path.realpath(joined)
            except OSError:
                found[c] = UNRESOLVABLE
            except ValueError:
                found[c] = UNRESOLVABLE
    return found


# At most this many guarded workers may be alive at once. A worker stuck on a hung
# mount cannot be killed, so each timed-out check keeps its slot until the thread
# really finishes; when all are taken, checks fail closed at once instead of
# spawning more threads.
MAX_CHECK_WORKERS = 8
_CHECK_SLOTS = threading.BoundedSemaphore(MAX_CHECK_WORKERS)
# Fairness: submit checks may hold at most MAX_SUBMIT_CHECKS slots in all and
# a per-uid share of them, so one agent's paths on a hung mount cannot make every
# other agent's submits fail closed, and the remaining slots stay free for
# run-time checks of already approved requests (which a human or an auto rule
# allowed, so they are not capped per uid). Counted while the worker thread is
# alive, like the slot itself. The per-uid share only helps when agents run as
# different uids; the daemon sets it to the total when only one uid is allowed
# (`configure_submit_quota`), so a single-uid host is not made stricter.
MAX_SUBMIT_CHECKS = 6
MAX_SUBMIT_CHECKS_PER_UID = 3


class _SubmitQuota:
    def __init__(self, total: int = MAX_SUBMIT_CHECKS, per_uid: int = MAX_SUBMIT_CHECKS_PER_UID):
        self.total, self.per_uid = total, per_uid
        self._lock = threading.Lock()
        self._n = 0
        self._by_uid: dict[int, int] = {}

    def take(self, uid: int) -> bool:
        with self._lock:
            if self._n >= self.total or self._by_uid.get(uid, 0) >= self.per_uid:
                return False
            self._n += 1
            self._by_uid[uid] = self._by_uid.get(uid, 0) + 1
            return True

    def give(self, uid: int) -> None:
        with self._lock:
            self._n -= 1
            left = self._by_uid.get(uid, 0) - 1
            if left > 0:
                self._by_uid[uid] = left
            else:
                self._by_uid.pop(uid, None)

    def snapshot(self) -> tuple[int, dict[int, int]]:
        with self._lock:
            return self._n, dict(self._by_uid)


_SUBMIT_QUOTA = _SubmitQuota()


def configure_submit_quota(allowed_uids) -> None:
    """Per-uid share only when several uids may submit; otherwise the total."""
    q = _SUBMIT_QUOTA
    q.per_uid = MAX_SUBMIT_CHECKS_PER_UID if len(set(allowed_uids)) > 1 else q.total


def submit_quota_snapshot() -> tuple[int, dict[int, int]]:
    """(submit checks alive, per uid); for tests and diagnostics."""
    return _SUBMIT_QUOTA.snapshot()


class CheckResult(NamedTuple):
    decision: "Decision"
    resolved: dict
    # None: the decision is a real answer. Otherwise the check itself failed and
    # `decision` is a fail-closed deny that is not a verdict on the command:
    # "timeout" (evaluate did not finish), "busy" (no free worker slot), "error"
    # (evaluate raised).
    problem: str | None = None


def check_guarded(policy, argv, cwd: str, trusted_uid: int = 0,
                  timeout: float | None = None, submitter: int | None = None) -> CheckResult:
    """`policy.evaluate` plus `resolve_path_args`, in one worker thread under one time limit.

    The only place the broker touches the filesystem for a request, called without
    the broker lock, so a hung mount (NFS, FUSE) stalls only this request. Python
    cannot interrupt a blocked realpath, so the worker is a daemon thread that is
    abandoned on timeout; it holds one of `MAX_CHECK_WORKERS` slots until it really
    finishes, and with none free the check fails closed immediately (`busy`).
    `submitter` (the agent uid, for submit-time checks only) also takes the submit
    quota above; over it the check is `busy` too. Run-time checks pass None.

    The worker publishes its results under a lock; after the join the caller marks
    the box cancelled and snapshots it once, so a late write cannot mix a timeout
    decision with a real resolution. If only the resolution did not finish (or
    raised), the decision stands and `resolved` is the timeout (or error) marker,
    which `unverified` reports and the run-time check refuses. A deny skips the
    resolution (`resolved` is then `{}`).
    """
    slots = _CHECK_SLOTS  # the worker must release the very semaphore it took
    quota = _SUBMIT_QUOTA  # ... and give back to the very quota it took from
    busy = CheckResult(Decision(
        "deny", "too many path checks are stuck (slow or hung filesystem); try again"),
        {TIMED_OUT_KEY: TIMED_OUT}, "busy")
    if submitter is not None and not quota.take(submitter):
        return busy
    if not slots.acquire(blocking=False):
        if submitter is not None:
            quota.give(submitter)
        return busy

    def release():
        slots.release()
        if submitter is not None:
            quota.give(submitter)
    lock = threading.Lock()
    box: dict = {"cancelled": False}

    def publish(**kw):
        with lock:
            if not box["cancelled"]:
                box.update(kw)

    def work():
        try:
            try:
                d = policy.evaluate(argv, cwd)
            except Exception:
                publish(error=True)
                return
            publish(d=d)
            if d.kind == "deny":
                publish(r={})
                return
            try:
                r = resolve_path_args(argv, cwd, trusted_uid)
            except Exception:
                r = {ERROR_KEY: ERROR}
            if unverified(r) is None:
                try:
                    late = policy.check_targets(argv, r, cwd)
                except Exception:
                    late, r = None, {ERROR_KEY: ERROR}
                if late is not None:
                    publish(d=late, r={})  # one write: a deny never carries targets
                    return
            publish(r=r)
        finally:
            release()  # when the thread ends, not when the caller gives up

    try:
        t = threading.Thread(target=work, daemon=True, name="telepathy-check")
        t.start()
    except BaseException:
        release()
        raise
    t.join(RESOLVE_TIMEOUT if timeout is None else timeout)
    with lock:
        box["cancelled"] = True
        snap = dict(box)
    if snap.get("error"):
        return CheckResult(Decision(
            "deny", "policy evaluation failed with an unexpected error"),
            {ERROR_KEY: ERROR}, "error")
    d = snap.get("d")
    if d is None:
        return CheckResult(Decision(
            "deny", "path checks timed out (slow or hung filesystem); try again"),
            {TIMED_OUT_KEY: TIMED_OUT}, "timeout")
    r = snap.get("r")
    if r is None:  # a deny needs no resolution; otherwise it did not finish
        r = {} if d.kind == "deny" else {TIMED_OUT_KEY: TIMED_OUT}
    return CheckResult(d, r)


def _broad(literal: str, real: str) -> bool:
    """True when a resolved prefix is too broad to protect by itself.

    Only when a host link points the prefix at "/" or at a strict ancestor of it
    (/etc/pam.d -> /etc): matching on it would deny every argument under a shared
    directory. Anything else, however shallow, stays enforced (fail closed). The
    literal prefix applies either way, so nothing real is unprotected.
    """
    real = real.rstrip("/")
    if real == "":
        return True
    lit = literal.rstrip("/")
    return real != lit and (lit + "/").startswith(real + "/")


def _resolved(pre: str):
    """(resolved, broad) when the prefix is a link to somewhere else, else None."""
    try:
        real = os.path.realpath(pre)
    except (OSError, ValueError):
        return None
    if real == pre:
        return None
    return real, _broad(pre, real)


# Skipped-prefix tracking. Resolution is dynamic, so a link repointed after start is
# noticed at evaluation time. Module-level state (one policy per daemon process):
# `_skip_last` is the committed set (literal -> resolved; None until the daemon
# starts tracking) and `_skip_events` the ordered, bounded queue of changes for the
# daemon's reporter thread. Both are guarded by `_skip_lock`, held only for dict and
# deque operations (never I/O), and events are enqueued while it is held, so they are
# ordered by commit. Evaluation never writes audit or stderr itself.
SKIP_QUEUE_MAX = 256
_skip_lock = threading.Lock()
_skip_last: dict[str, str] | None = None
_skip_events: collections.deque = collections.deque(maxlen=SKIP_QUEUE_MAX)
_skip_dropped = 0
_skip_wake = threading.Event()
_skip_seq = itertools.count(1)  # observation order: taken before resolving
_skip_seen = 0  # newest observation committed; an older one is stale and ignored


def start_skip_tracking(initial: dict[str, str]) -> None:
    """Seed the cache with `initial` (the set the caller just reported) and start diffing."""
    global _skip_last, _skip_dropped
    with _skip_lock:
        _skip_last = dict(initial)
        _skip_events.clear()
        _skip_dropped = 0


def stop_skip_tracking() -> None:
    global _skip_last
    with _skip_lock:
        _skip_last = None
        _skip_events.clear()


def skipped_snapshot() -> tuple[tuple[str, str], ...]:
    """The cached skipped set; no filesystem access, safe on any thread."""
    with _skip_lock:
        return tuple(sorted((_skip_last or {}).items()))


def drain_skip_events() -> tuple[list[tuple[str, str, str]], int]:
    """Pop all queued (event, prefix, resolved) changes and the count dropped on overflow."""
    global _skip_dropped
    with _skip_lock:
        ev = list(_skip_events)
        _skip_events.clear()
        dropped, _skip_dropped = _skip_dropped, 0
    return ev, dropped


def wait_skip_events(timeout: float) -> None:
    _skip_wake.wait(timeout)
    _skip_wake.clear()


def _note_skipped(cur: dict[str, str], failed=(), seq: int | None = None) -> None:
    """Commit `cur` and queue one event per difference from the last set.

    A prefix in `failed` (resolution raised) keeps its previous state, so a transient
    error neither reports nor flips it. Never blocks on I/O and never raises.
    """
    global _skip_last, _skip_dropped, _skip_seen
    try:
        with _skip_lock:
            last = _skip_last
            if last is None:
                return
            if seq is not None:
                if seq < _skip_seen:
                    return  # resolved before a newer observation already committed
                _skip_seen = seq
            cur = dict(cur)
            for p in failed:
                if p in last:
                    cur[p] = last[p]
            if last == cur:
                return
            _skip_last = cur
            events = [("protected_prefix_unskipped", p, r) for p, r in last.items()
                      if cur.get(p) != r]
            events += [("protected_prefix_skipped", p, r) for p, r in cur.items()
                       if last.get(p) != r]
            for e in events:
                if len(_skip_events) == _skip_events.maxlen:
                    _skip_dropped += 1  # the deque discards the oldest
                _skip_events.append(e)
        _skip_wake.set()
    except Exception:  # reporting must never affect the decision
        pass


def _protected_prefixes() -> tuple[str, ...]:
    # Read PROTECTED_PREFIXES at call time (tests patch it) and resolve each one
    # every time: a host link can change, and realpath on a short list is cheap.
    seq = next(_skip_seq)  # before resolving, so a slow thread cannot commit stale state
    out = list(PROTECTED_PREFIXES)
    skipped: dict[str, str] = {}
    failed = []
    for pre in PROTECTED_PREFIXES:
        try:
            real = os.path.realpath(pre)
        except (OSError, ValueError):
            failed.append(pre)
            continue
        if real == pre:
            continue
        if _broad(pre, real):
            skipped[pre] = real
        else:
            out.append(real)
    _note_skipped(skipped, failed, seq)
    return tuple(out)


def skipped_protected_prefixes() -> tuple[tuple[str, str], ...]:
    """(literal, resolved) pairs whose resolved form is ignored as too broad.

    Does a fresh resolution; the daemon calls it once at start, reports the result and
    seeds the cache with it. Later changes arrive through `drain_skip_events`.
    """
    out = []
    for pre in PROTECTED_PREFIXES:
        r = _resolved(pre)
        if r and r[1]:
            out.append((pre, r[0]))
    return tuple(out)


def _exe_names(exe: str) -> set[str]:
    """Basenames of argv[0] as written and after following every symlink.

    Raises OSError/ValueError when it cannot be resolved. Note: on a host whose
    coreutils are symlinks to busybox, the resolved name is "busybox", which is
    denied; Arch is fine.
    """
    return {os.path.basename(exe), os.path.basename(os.path.realpath(exe))}


def _denied_exe(names, extra=frozenset()) -> str | None:
    for n in sorted(names):
        if n in BUILTIN_DENY_EXE or BUILTIN_DENY_EXE_RE.match(n):
            return f"{n} is a shell/interpreter/wrapper"
        if n in extra:
            return f"{n} is denied by policy"
    return None


_ACL_XATTR = "system.posix_acl_access"
_ACL_VERSION = 2
_ACL_USER, _ACL_GROUP_OBJ, _ACL_GROUP = 0x02, 0x04, 0x08
_ACL_MAX_ENTRIES = 1024
_ACL_KNOWN_TAGS = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20}  # user_obj user group_obj group mask other
_ACL_WRITE = 0x02


def _acl_untrusted(path: str, trusted_uid: int, file_gid: int) -> str | None:
    """Why the POSIX access ACL on `path` grants write to someone untrusted, or None.

    Parsed from the raw xattr (stdlib only, no getfacl): a u32 version (2) and
    then 8-byte entries of u16 tag, u16 perm, u32 id. Owner and other entries
    are mirrored in the mode bits, but once named entries exist the mode's
    group bits hold the MASK, so the group_obj entry (the file's own group) is
    hidden too and is checked here against `file_gid`. Exemptions: a named user
    is trusted only if it is `trusted_uid`; a named group or the file's group
    only if it is gid 0 (root's group, as in the mode-bit check; it does not
    follow `trusted_uid`). The mask is deliberately ignored: a restricting mask can be loosened by a
    chmod, so a named write grant is refused regardless. No ACL (ENODATA, or a
    filesystem without xattrs) is fine; any other failure or an unparseable
    value is refused.
    """
    try:
        raw = os.getxattr(path, _ACL_XATTR, follow_symlinks=False)
    except AttributeError:  # no os.getxattr on this platform: cannot look, so refuse
        return f"cannot inspect ACL of {path}"
    except OSError as e:
        if e.errno in (errno.ENODATA, errno.ENOTSUP):
            return None
        return f"cannot inspect ACL of {path}"
    except ValueError:
        return f"cannot inspect ACL of {path}"
    if (len(raw) < 4 or (len(raw) - 4) % 8 or (len(raw) - 4) // 8 > _ACL_MAX_ENTRIES
            or struct.unpack_from("<I", raw)[0] != _ACL_VERSION):
        return f"malformed ACL on {path}"
    for off in range(4, len(raw), 8):
        tag, perm, ident = struct.unpack_from("<HHI", raw, off)
        if tag not in _ACL_KNOWN_TAGS or perm > 7:
            return f"malformed ACL on {path}"
        if not perm & _ACL_WRITE:
            continue
        if tag == _ACL_USER and ident != trusted_uid:
            return f"ACL on {path} grants write to user {ident}"
        if tag == _ACL_GROUP_OBJ and file_gid != 0:
            return f"ACL on {path} grants write to its group {file_gid}"
        if tag == _ACL_GROUP and ident != 0:
            return f"ACL on {path} grants write to group {ident}"
    return None


def _mode_untrusted(st, trusted_uid: int) -> bool:
    return bool(st.st_uid != trusted_uid or st.st_mode & 0o002
                or (st.st_mode & 0o020 and st.st_gid != 0))


def _untrusted_node(st, path: str, trusted_uid: int, what: str) -> str | None:
    """Why the file/dir `path` (lstat result `st`) is not out of the agent's reach, or None.

    Owned by `trusted_uid`, no other-write, group-write only for group 0, and no
    POSIX ACL granting write to a named user or group. Shared by the executable
    check and the symlink-trust check so both use one bar.
    """
    if _mode_untrusted(st, trusted_uid):
        return f"{what} {path} is not owned by root or is writable by others"
    return _acl_untrusted(path, trusted_uid, st.st_gid)


def _dir_chain_trusted(path: str, trusted_uid: int, cache: dict) -> bool:
    """True if directory `path` and every ancestor are out of the agent's reach.

    An agent-writable ancestor can rename or replace the whole subtree, so the
    walk goes to `/`. Anything that cannot be inspected is not trusted (fail
    closed). `cache` (per `_untrusted_links` call) avoids repeated lstat/ACL work.
    """
    todo = []
    cur = path
    result = True
    while True:
        if cur in cache:
            result = cache[cur]
            break
        todo.append(cur)
        try:
            st = os.lstat(cur)
            ok = stat.S_ISDIR(st.st_mode) and _untrusted_node(st, cur, trusted_uid, "directory") is None
        except (OSError, ValueError):
            ok = False
        if not ok:
            result = False
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    for d in todo:  # a directory is trusted only if all of its ancestors are too
        cache[d] = result
    return result


def _untrusted_exe(exe: str, trusted_uid: int = 0) -> str | None:
    """Why the executable behind argv[0] cannot be trusted to run as root, or None.

    A copy of a shell under another name passes any name check, so the real file
    and every directory above it must be owned by `trusted_uid` and not writable
    by others; group-write is tolerated only for group 0 (root), since some hosts
    use e.g. root:staff 2775 for /usr/local and that group is not root's to
    vouch for. A file that does not exist yet is not refused by itself
    (it cannot run, and `begin_run` re-evaluates this check if it appears), but
    the directories above it still have to be trusted. The file itself must be
    a regular file, and neither it nor any directory may carry a POSIX ACL that
    grants write to a named user or group other than the trusted ones. Immutable
    flags are not consulted: they only ever make a file harder to change.
    """
    real = os.path.realpath(exe)
    cur = real
    while True:
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            cur = os.path.dirname(cur)
            continue
        except (OSError, ValueError):
            return f"cannot inspect {cur}"
        what = "executable" if cur == real else "directory above it"
        if _mode_untrusted(st, trusted_uid):
            return f"{what} {cur} is not owned by root or is writable by others"
        if cur == real and not stat.S_ISREG(st.st_mode):
            return f"executable {cur} is not a regular file"
        why = _acl_untrusted(cur, trusted_uid, st.st_gid)
        if why:
            return why
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _touches_protected(arg: str, cwd: str) -> bool:
    prefixes = _protected_prefixes()
    for c in _candidates(arg):
        forms = [_normalize(c, cwd)]
        try:
            # Also resolves symlinked parent directories of a not-yet-existing file.
            forms.append(_real(c, cwd))
        except (OSError, ValueError):
            return True  # cannot resolve it: fail closed
        if any(_under(f, p) for f in forms for p in prefixes):
            return True
    return False


class Policy:
    def __init__(self, patterns=None, rules=(), extra_deny_exe=frozenset(), trusted_uid: int = 0):
        self.trusted_uid = trusted_uid  # tests pass their own uid
        self.patterns = dict(patterns or {})
        self.rules = tuple(rules)
        self.extra_deny_exe = frozenset(extra_deny_exe)

    # -- evaluation -------------------------------------------------------

    def evaluate(self, argv, cwd: str) -> Decision:
        try:
            names = _exe_names(argv[0])
        except (OSError, ValueError):
            return Decision("deny", "cannot resolve the executable (symlink loop or bad path)")
        why = _denied_exe(names, self.extra_deny_exe)
        if why:
            return Decision("deny", why)
        why = _untrusted_exe(argv[0], self.trusted_uid)
        if why:
            return Decision("deny", why)
        for a in argv:
            if "telepathy" in a.lower():
                return Decision("deny", "mentions telepathy itself; do this at a local terminal")
            if _touches_protected(a, cwd):
                return Decision("deny", f"touches a protected path: {a}")
        for rule in self.rules:
            if rule.matches(argv):
                return Decision("auto", "matched an auto rule", rule.name)
        return Decision("ask", "needs human approval")

    def check_targets(self, argv, resolved, cwd: str | None = None) -> "Decision | None":
        """Re-run evaluate's filesystem-dependent deny rules after the freeze.

        `evaluate` and the freeze (`resolve_path_args`) are separate filesystem
        passes, so a link flipped between them could freeze (and show the
        approver) a target the deny rules never saw. This is a re-check,
        not a single pass; it covers every input of `evaluate` that depends on
        the filesystem, whether or not the freeze recorded an entry for it:

        - executable (names and ownership): on the frozen target of argv[0] if
          there is one, else on argv[0] itself (a link replaced by a file
          leaves no entry);
        - each path argument: the frozen target, if any, against the protected
          prefixes, and the argument again as `evaluate` checks it, resolved from
          the frozen cwd when the cwd was frozen (relative arguments follow it).

        The cwd itself is not checked (evaluate never did), but a frozen cwd
        that cannot be resolved fails closed. The "mentions telepathy" rule is
        about the text as written and stays in `evaluate`. Markers (timeout,
        error) never reach here (see `unverified`). Returns a deny, or None.
        """
        bad = (UNRESOLVABLE, TIMED_OUT, ERROR)
        base = cwd
        if cwd is not None and cwd in resolved:
            base = resolved[cwd]
            if base in bad or not base.startswith("/"):
                return Decision("deny", f"the working directory {cwd} cannot be resolved")
        if argv:
            exe = resolved.get(argv[0], argv[0])
            if exe in bad:
                return Decision("deny", "cannot resolve the executable (symlink loop or bad path)")
            try:
                names = _exe_names(exe) | {os.path.basename(argv[0])}
            except (OSError, ValueError):
                return Decision("deny", "cannot resolve the executable (symlink loop or bad path)")
            why = _denied_exe(names, self.extra_deny_exe) or _untrusted_exe(exe, self.trusted_uid)
            if why:
                return Decision("deny", why)
        prefixes = _protected_prefixes()
        for a in argv:
            for c in _candidates(a):
                real = resolved.get(c)
                if real is not None and real not in bad and any(_under(real, p) for p in prefixes):
                    return Decision("deny", f"touches a protected path: {c} resolves to {real}")
            if base is not None and _touches_protected(a, base):
                return Decision("deny", f"touches a protected path: {a}")
        return None

    # -- loading ----------------------------------------------------------

    @classmethod
    def empty(cls) -> "Policy":
        return cls()

    @classmethod
    def from_toml(cls, text: str) -> "Policy":
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise PolicyError(f"invalid TOML: {e}") from e
        unknown = set(doc) - {"patterns", "deny", "auto"}
        if unknown:
            raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")

        patterns: dict[str, re.Pattern] = {}
        for name, expr in (doc.get("patterns") or {}).items():
            if not isinstance(expr, str):
                raise PolicyError(f"pattern {name!r} must be a string")
            try:
                rx = re.compile(expr)
            except re.error as e:
                raise PolicyError(f"pattern {name!r} does not compile: {e}") from e
            for probe in OPTION_PROBES:
                if rx.fullmatch(probe):
                    raise PolicyError(
                        f"pattern {name!r} matches option-looking values like {probe!r}"
                    )
            patterns[name] = rx

        deny = doc.get("deny") or {}
        if set(deny) - {"executables"}:
            raise PolicyError("[deny] only supports 'executables'")
        extra = deny.get("executables") or []
        if not all(isinstance(x, str) and x for x in extra):
            raise PolicyError("[deny].executables must be a list of non-empty strings")

        rules = []
        seen = set()
        for i, raw in enumerate(doc.get("auto") or []):
            name = raw.get("name", f"auto-{i}")
            if set(raw) - {"name", "argv"}:
                raise PolicyError(f"auto rule {name!r}: unknown keys")
            if name in seen:
                raise PolicyError(f"duplicate auto rule name {name!r}")
            seen.add(name)
            rules.append(cls._parse_rule(name, raw.get("argv"), patterns))
        return cls(patterns, rules, frozenset(extra))

    @staticmethod
    def _parse_rule(name, argv, patterns) -> AutoRule:
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise PolicyError(f"auto rule {name!r}: argv must be a non-empty list of strings")
        if not argv[0].startswith("/"):
            raise PolicyError(f"auto rule {name!r}: argv[0] must be a literal absolute path")
        try:
            names = _exe_names(argv[0])
        except (OSError, ValueError) as e:
            raise PolicyError(f"auto rule {name!r}: cannot resolve {argv[0]!r}: {e}") from e
        if _denied_exe(names):
            raise PolicyError(f"auto rule {name!r}: {_denied_exe(names)}; it can never be auto-approved")
        tokens = []
        for idx, tok in enumerate(argv):
            if tok.startswith("@"):
                if idx == 0:
                    raise PolicyError(f"auto rule {name!r}: argv[0] cannot be a pattern")
                variadic = tok.endswith("...")
                ref = tok[1:-3] if variadic else tok[1:]
                if variadic and idx != len(argv) - 1:
                    raise PolicyError(f"auto rule {name!r}: '...' only allowed on the last token")
                if ref not in patterns:
                    raise PolicyError(f"auto rule {name!r}: unknown pattern {ref!r}")
                tokens.append(_Token(pattern=patterns[ref], variadic=variadic))
            else:
                tokens.append(_Token(literal=tok))
        return AutoRule(name, tuple(tokens))


def unverified(resolved) -> str | None:
    """Why a frozen/fresh resolution cannot be trusted, or None if it is usable.

    None (never frozen), a timeout marker and an error marker all mean the paths
    were not verified; callers must refuse to run, not compare.
    """
    if resolved is None:
        return "the request's paths were never resolved at submit"
    if TIMED_OUT_KEY in resolved:
        return "path resolution timed out (slow or hung filesystem)"
    if ERROR_KEY in resolved:
        return "path resolution failed with an unexpected error"
    return None
