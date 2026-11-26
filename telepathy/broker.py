"""Broker: the request queue and every rule about who may do what, when."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass

from .audit import AuditLog
from .policy import Decision, Policy, check_guarded, unverified
from .request import TERMINAL, InvalidRequest, InvalidTransition, Request, State


def _linux_boottime() -> float:
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def select_boottime():
    """Pick the clock: seconds since boot, unaffected by wall-clock steps *and*
    counting suspend.

    Linux's CLOCK_MONOTONIC (time.monotonic) stops while the machine is
    suspended, which would let a pending request outlive its TTL across a
    lid-close. CLOCK_BOOTTIME keeps counting. Falls back to time.monotonic where
    it does not exist.
    """
    if hasattr(time, "CLOCK_BOOTTIME"):
        return _linux_boottime
    return time.monotonic


boottime = select_boottime()


class BrokerError(Exception):
    pass


class PolicyDenied(BrokerError):
    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision


class RateLimited(BrokerError):
    pass


class UnknownRequest(BrokerError):
    pass


class NonceMismatch(BrokerError):
    pass


class CheckUnavailable(BrokerError):
    """The run-time path check could not finish (slow filesystem, no free worker).

    Transient: the request is left as it was (still approved, same expiry) and the
    caller may try again. Nothing was verified, so nothing may run on this attempt.
    """


class NotRunnable(BrokerError, InvalidTransition):
    """begin_run was asked to start a request that is not approved."""


class Expired(BrokerError):
    pass


class IntegrityFailure(BrokerError):
    pass


@dataclass(frozen=True)
class Limits:
    ttl: float = 600.0
    max_pending: int = 5
    max_per_hour: int = 20


class Broker:
    def __init__(self, policy: Policy, limits: Limits = Limits(), audit: AuditLog | None = None,
                 clock=boottime, link_trusted_uid: int = 0):
        # `clock` must be monotonic and keep counting through suspend: expiry and
        # rate windows must not move when the wall clock is stepped, nor pause
        # while the machine sleeps. Wall time is only for the audit log's ts.
        self.policy = policy
        self.limits = limits
        self.audit = audit or AuditLog()
        self.clock = clock
        # Separate from policy.trusted_uid on purpose: test policies keep that at 0 so
        # their /usr/bin executables pass the exe check, while the link tests need
        # "no link is root's" (-1) to behave the same whatever uid runs the suite.
        self.link_trusted_uid = link_trusted_uid
        self._reqs: dict[str, Request] = {}
        self._submits: deque[float] = deque()
        # Guards in-memory state only. Never held across filesystem work: a hung
        # mount must stall one request, not the daemon.
        self._lock = threading.RLock()
        self._inflight = 0  # submits between slot reservation and enqueue (max_pending)

    # -- helpers ----------------------------------------------------------

    def view(self, req: Request) -> dict:
        """The public, JSON-safe form of a request, relative to this broker's clock."""
        d = req.public(self.clock())
        d["resolved"] = dict(req.resolved or {})  # frozen at submit: no filesystem access here
        return d

    def _get(self, rid: str) -> Request:
        req = self._reqs.get(rid)
        if req is None:
            raise UnknownRequest(rid)
        self._expire_if_due(req)
        return req

    def _expire_if_due(self, req: Request) -> None:
        if req.state in (State.PENDING, State.APPROVED) and self.clock() >= req.expires_at:
            req.transition(State.EXPIRED)
            self.audit.write("expired", id=req.id, hash=req.hash)

    def _note_submit(self) -> float:
        now = self.clock()
        while self._submits and now - self._submits[0] >= 3600:
            self._submits.popleft()
        if len(self._submits) >= self.limits.max_per_hour:
            self.audit.write("rate_limited", reason="per_hour")
            raise RateLimited("too many requests in the last hour")
        self._submits.append(now)
        return now

    # -- agent side -------------------------------------------------------

    def submit(self, argv, cwd: str, uid: int, reason: str = "") -> Request:
        with self._lock:
            stamp = self._note_submit()
            self.sweep()
            # In-flight submits hold a slot while they are checked outside the lock,
            # so concurrent submits cannot overshoot max_pending. The slot is held
            # for at most the check time limit and is always given back (finally).
            pending = sum(r.state is State.PENDING for r in self._reqs.values())
            if pending + self._inflight >= self.limits.max_pending:
                self.audit.write("rate_limited", reason="max_pending")
                raise RateLimited("too many requests are waiting for approval")
            self._inflight += 1
        released = False
        try:
            try:
                req = Request.new(argv, cwd, uid, reason, self.clock(), self.limits.ttl)
            except InvalidRequest as e:
                self.audit.write("invalid", reason=str(e))
                raise
            # Filesystem work, guarded and without the lock. The decision and the
            # frozen targets (shown to the approver, compared again in begin_run)
            # come from one worker under one time limit.
            chk = check_guarded(self.policy, req.argv, req.cwd, self.link_trusted_uid,
                                submitter=uid)
            decision, resolved = chk.decision, chk.resolved
            with self._lock:
                # Count only what is enqueued: the slot is given back as soon as the
                # check returns, so a denied or timed-out submit does not keep it.
                self._inflight -= 1
                released = True
                if chk.problem:
                    # The check failed; this says nothing about the command itself,
                    # so "try again" must not eat the hourly allowance.
                    try:
                        self._submits.remove(stamp)
                    except ValueError:
                        pass
                    self.audit.write(f"check_{chk.problem}", hash=req.hash, argv=list(req.argv),
                                     reason=decision.reason)
                    raise PolicyDenied(decision)
                if decision.kind == "deny":
                    self.audit.write("policy_denied", hash=req.hash, argv=list(req.argv),
                                     reason=decision.reason)
                    raise PolicyDenied(decision)
                # The approval window starts when the request is enqueued, not when the
                # (possibly slow) check began.
                now = self.clock()
                req.created_at = now
                req.expires_at = now + self.limits.ttl
                req.resolved = resolved
                self._reqs[req.id] = req
                self.audit.write("submitted", id=req.id, hash=req.hash, argv=list(req.argv),
                                 cwd=req.cwd, uid=req.uid, reason=req.reason,
                                 decision=decision.kind)
                if decision.kind == "auto":
                    req.transition(State.APPROVED)
                    req.approver = f"policy:{decision.rule}"
                    req.decided_at = self.clock()
                    self.audit.write("auto_approved", id=req.id, hash=req.hash, rule=decision.rule)
                return req
        finally:
            if not released:
                with self._lock:
                    self._inflight -= 1

    def get(self, rid: str) -> Request:
        with self._lock:
            return self._get(rid)

    def pending(self) -> list[Request]:
        with self._lock:
            self.sweep()
            return [r for r in self._reqs.values() if r.state is State.PENDING]

    # -- approver side ----------------------------------------------------

    def issue_nonce(self, rid: str) -> str:
        with self._lock:
            req = self._get(rid)
            if req.state is State.EXPIRED:
                raise Expired(rid)
            return req.issue_nonce()

    def approve(self, rid: str, nonce: str, approver: str) -> Request:
        with self._lock:
            req = self._get(rid)
            if req.state is State.EXPIRED:
                raise Expired(rid)
            if req.state is not State.PENDING:
                req.transition(State.APPROVED)  # raises InvalidTransition
            if not req.consume_nonce(nonce):
                self.audit.write("approve_rejected", id=req.id, hash=req.hash,
                                 approver=approver, reason="bad_nonce")
                raise NonceMismatch(rid)
            req.transition(State.APPROVED)
            req.approver = approver
            req.decided_at = self.clock()
            self.audit.write("approved", id=req.id, hash=req.hash, approver=approver)
            return req

    def cancel(self, rid: str, uid: int) -> tuple[Request, bool]:
        """Withdraw a request that has not started. Returns (request, changed).

        Only the submitting uid or root may cancel; anyone else gets UnknownRequest,
        the same as for an id that does not exist. The check and the state change
        happen under one lock. Safe to repeat: a pending or approved-not-run request
        becomes cancelled (freeing its max_pending slot; begin_run refuses it);
        anything else (running, done, denied, expired, already cancelled) is left
        exactly as it is and `changed` is False.
        """
        with self._lock:
            req = self._get(rid)
            if req.uid != uid and uid != 0:
                raise UnknownRequest(rid)
            if req.state not in (State.PENDING, State.APPROVED):
                return req, False
            was = req.state
            req.transition(State.CANCELLED)
            self.audit.write("cancelled", id=req.id, hash=req.hash, by=f"uid:{uid}",
                             was=was.value)
            return req, True

    def deny(self, rid: str, approver: str) -> Request:
        with self._lock:
            req = self._get(rid)
            req.transition(State.DENIED)
            req.approver = approver
            req.decided_at = self.clock()
            self.audit.write("denied", id=req.id, hash=req.hash, approver=approver)
            return req

    # -- execution side ---------------------------------------------------

    def _runnable(self, rid: str) -> Request:
        """Under the lock: the request if it may start now, else raise. No filesystem."""
        req = self._get(rid)
        if req.state is State.EXPIRED:
            raise Expired(rid)
        # Explicit guard, not left to the transition table: only an approved
        # request may start (cancelled, denied, done, running, pending never).
        if req.state is not State.APPROVED:
            self.audit.write("run_refused", id=req.id, hash=req.hash, state=req.state.value)
            raise NotRunnable(f"{req.state.value} request cannot run")
        if req.recompute_hash() != req.hash:
            req.transition(State.DENIED)
            self.audit.write("integrity_failure", id=req.id, hash=req.hash)
            raise IntegrityFailure(rid)
        return req

    def begin_run(self, rid: str) -> Request:
        """Move approved -> running, re-verifying expiry and the hash first.

        The filesystem re-check runs without the lock (a hung path stalls only this
        run, bounded by the guard, and fails closed). The state is then validated
        again under the lock, so a cancel, expiry or concurrent begin_run that landed
        meanwhile wins: only a request still APPROVED goes to RUNNING.
        """
        with self._lock:
            req = self._runnable(rid)
            argv, cwd = req.argv, req.cwd
        # The agent controls symlinks. First: a link that was harmless at
        # approval may point into a protected path now, so re-run the deny rules;
        # same pass, same time limit, as the fresh resolution.
        chk = check_guarded(self.policy, argv, cwd, self.link_trusted_uid)
        decision, now = chk.decision, chk.resolved
        with self._lock:
            req = self._runnable(rid)  # cancel / expiry / another begin_run may have won
            if chk.problem == "error":
                # The evaluator itself crashed: fail closed for good, as before.
                self._deny_at_run(req, "policy_error_at_run", decision)
            if chk.problem:
                # Timeout or busy, not a verdict: leave the request approved so a
                # retry can succeed.
                self.audit.write("run_unverified", id=req.id, hash=req.hash,
                                 reason="path check timed out; try again",
                                 cause=chk.problem)
                raise CheckUnavailable("path check timed out; try again")
            if decision.kind == "deny":
                self._deny_at_run(req, "policy_denied_at_run", decision)
            # Then compare where the paths point now with what the approver saw: a
            # link retargeted harmless -> harmless is still an unapproved command.
            # A resolution that was never frozen, or failed at submit or now, cannot
            # be compared, so it is refused with its own reason.
            why = unverified(req.resolved) or unverified(now)
            if why:
                self._deny_at_run(req, "symlink_unverified_at_run", Decision("deny", why),
                                  before=req.resolved, after=now)
            if now != req.resolved:
                self._deny_at_run(req, "symlink_changed_at_run", Decision(
                    "deny", "a path argument resolves differently than when it was submitted"),
                    before=req.resolved, after=now)
            req.transition(State.RUNNING)
            self.audit.write("run_start", id=req.id, hash=req.hash)
            return req

    def precheck(self, rid: str) -> str | None:
        """Run the run-time path check ahead of the serial worker, changing nothing.

        Returns the check's transient problem ("timeout" or "busy") when the request
        is still approved and the check could not finish, so the caller can retry
        later without blocking the worker; else None, and the request goes to the
        worker, whose `begin_run` checks again right before exec and alone decides
        (deny, refuse, run). Never transitions or denies; reads state quietly (no
        `run_refused` audit), since `begin_run` reports that.
        """
        with self._lock:
            req = self._reqs.get(rid)
            if req is None or req.state is not State.APPROVED:
                return None
            argv, cwd = req.argv, req.cwd
        chk = check_guarded(self.policy, argv, cwd, self.link_trusted_uid)
        if chk.problem not in ("timeout", "busy"):
            return None
        with self._lock:
            req = self._reqs.get(rid)
            if req is None or req.state is not State.APPROVED:
                return None
            self.audit.write("run_unverified", id=req.id, hash=req.hash,
                             reason="path check timed out; try again",
                             cause=chk.problem, stage="precheck")
        return chk.problem

    def give_up(self, rid: str, attempts: int) -> bool:
        """Deny an approved request whose run-time path check never completed.

        Called by the daemon after its retry cap. Only acts on a request that is
        still APPROVED; returns whether it did.
        """
        with self._lock:
            req = self._get(rid)
            if req.state is not State.APPROVED:
                return False
            req.transition(State.DENIED)
            self.audit.write("run_unverified_gave_up", id=req.id, hash=req.hash,
                             attempts=attempts,
                             reason="path checks kept timing out; the request was not run")
            return True

    def _deny_at_run(self, req: Request, event: str, decision: Decision, **extra) -> None:
        req.transition(State.DENIED)
        self.audit.write(event, id=req.id, hash=req.hash, argv=list(req.argv),
                         reason=decision.reason, **extra)
        raise PolicyDenied(decision)

    def finish(self, rid: str, exit_code: int, extra: dict | None = None) -> Request:
        """Record completion. `extra` (output length/hash, ...) goes to the audit log."""
        with self._lock:
            req = self._get(rid)
            req.transition(State.DONE)
            req.exit_code = exit_code
            self.audit.write("run_finish", id=req.id, hash=req.hash, exit_code=exit_code,
                             **(extra or {}))
            return req

    # -- maintenance ------------------------------------------------------

    def sweep(self) -> list[str]:
        """Expire anything overdue and forget old terminal requests."""
        with self._lock:
            expired = []
            for req in list(self._reqs.values()):
                was = req.state
                self._expire_if_due(req)
                if was is not req.state and req.state is State.EXPIRED:
                    expired.append(req.id)
                if req.state in TERMINAL and self.clock() - req.created_at > 24 * 3600:
                    del self._reqs[req.id]
            return expired
