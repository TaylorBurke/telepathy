"""Request model: validation, canonical hashing, and the state machine."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from enum import Enum

MAX_ARGC = 256
MAX_ARG_LEN = 8192
MAX_TOTAL_LEN = 65536
MAX_REASON_LEN = 500

# Fixed environment every approved command runs with. The agent cannot supply
# its own (LD_PRELOAD, PATH tricks, ...), and it is part of the hash.
DEFAULT_ENV: tuple[tuple[str, str], ...] = (
    ("HOME", "/root"),
    ("LANG", "C.UTF-8"),
    ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin"),
)


class InvalidRequest(ValueError):
    """The submitted request is malformed."""


class InvalidTransition(RuntimeError):
    """The requested state change is not allowed."""


class State(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    RUNNING = "running"
    DONE = "done"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


TRANSITIONS: dict[State, frozenset[State]] = {
    State.PENDING: frozenset({State.APPROVED, State.DENIED, State.EXPIRED, State.CANCELLED}),
    # approved -> denied is a revoke (or an integrity failure at run time).
    # approved -> cancelled is the submitter withdrawing it before it started.
    State.APPROVED: frozenset({State.RUNNING, State.DENIED, State.EXPIRED, State.CANCELLED}),
    State.RUNNING: frozenset({State.DONE}),
    State.DONE: frozenset(),
    State.DENIED: frozenset(),
    State.EXPIRED: frozenset(),
    State.CANCELLED: frozenset(),
}

TERMINAL = frozenset({State.DONE, State.DENIED, State.EXPIRED, State.CANCELLED})


def validate_argv(argv) -> tuple[str, ...]:
    """argv must be a non-empty list of NUL-free strings with an absolute exe.

    A shell string is rejected on purpose: telepathy never invokes a shell, and
    the human must see exactly the words that will be exec'd.
    """
    if isinstance(argv, (str, bytes)) or not isinstance(argv, (list, tuple)):
        raise InvalidRequest("argv must be a list of strings, not a shell string")
    if not argv:
        raise InvalidRequest("argv is empty")
    if len(argv) > MAX_ARGC:
        raise InvalidRequest(f"argv has more than {MAX_ARGC} entries")
    total = 0
    for a in argv:
        if not isinstance(a, str):
            raise InvalidRequest("argv entries must be strings")
        if "\0" in a:
            raise InvalidRequest("argv entries must not contain NUL")
        if len(a) > MAX_ARG_LEN:
            raise InvalidRequest(f"an argv entry exceeds {MAX_ARG_LEN} bytes")
        total += len(a)
    if total > MAX_TOTAL_LEN:
        raise InvalidRequest(f"argv exceeds {MAX_TOTAL_LEN} bytes in total")
    if not argv[0].startswith("/"):
        raise InvalidRequest("argv[0] must be an absolute path (resolve it client-side)")
    return tuple(argv)


def validate_cwd(cwd) -> str:
    if not isinstance(cwd, str) or not cwd.startswith("/") or "\0" in cwd:
        raise InvalidRequest("cwd must be an absolute path")
    return cwd


def validate_reason(reason) -> str:
    if reason is None:
        return ""
    if not isinstance(reason, str) or "\0" in reason:
        raise InvalidRequest("reason must be a string")
    return reason[:MAX_REASON_LEN]


def compute_hash(argv, cwd: str, env, uid: int) -> str:
    """sha256 over a canonical encoding of everything that determines the exec."""
    doc = {
        "argv": list(argv),
        "cwd": cwd,
        "env": [list(p) for p in env],
        "uid": uid,
    }
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


@dataclass
class Request:
    id: str
    argv: tuple[str, ...]
    cwd: str
    env: tuple[tuple[str, str], ...]
    uid: int
    reason: str
    created_at: float
    expires_at: float
    hash: str
    state: State = State.PENDING
    approver: str | None = None
    decided_at: float | None = None
    exit_code: int | None = None
    # Symlink resolution of the path arguments, frozen at submit (see
    # policy.resolve_path_args). Not part of the hash: it describes the
    # filesystem at submit time, and begin_run compares it against the filesystem
    # at run time.
    # None means it was never frozen; begin_run refuses that rather than compare.
    resolved: dict | None = None
    _nonce: str | None = None

    @classmethod
    def new(cls, argv, cwd, uid, reason, now: float, ttl: float) -> "Request":
        argv = validate_argv(argv)
        cwd = validate_cwd(cwd)
        reason = validate_reason(reason)
        if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0:
            raise InvalidRequest("uid must be a non-negative integer")
        return cls(
            id=secrets.token_hex(8),
            argv=argv,
            cwd=cwd,
            env=DEFAULT_ENV,
            uid=uid,
            reason=reason,
            created_at=now,
            expires_at=now + ttl,
            hash=compute_hash(argv, cwd, DEFAULT_ENV, uid),
        )

    @property
    def short_hash(self) -> str:
        return self.hash[:8]

    def recompute_hash(self) -> str:
        return compute_hash(self.argv, self.cwd, self.env, self.uid)

    def transition(self, new: State) -> None:
        if new not in TRANSITIONS[self.state]:
            raise InvalidTransition(f"{self.state.value} -> {new.value}")
        self.state = new

    # Per-request approval nonce: issued when the approval page is rendered and
    # consumed by a successful approve, so a stale tab or a forwarded link
    # cannot approve.
    def issue_nonce(self) -> str:
        if self.state is not State.PENDING:
            raise InvalidTransition(f"cannot issue a nonce in state {self.state.value}")
        self._nonce = secrets.token_urlsafe(16)
        return self._nonce

    def consume_nonce(self, candidate) -> bool:
        if self._nonce is None or not isinstance(candidate, str):
            return False
        if not hmac.compare_digest(self._nonce, candidate):
            return False
        self._nonce = None
        return True

    def public(self, now: float) -> dict:
        """What an approver or the agent may see. Never includes the nonce.

        Times are monotonic and meaningless outside this process, so only the
        remaining lifetime is exposed. `now` is the broker's clock reading.
        """
        return {
            "id": self.id,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "uid": self.uid,
            "reason": self.reason,
            "expires_in": max(0.0, self.expires_at - now),
            "hash": self.hash,
            "short_hash": self.short_hash,
            "state": self.state.value,
            "approver": self.approver,
            "exit_code": self.exit_code,
        }
