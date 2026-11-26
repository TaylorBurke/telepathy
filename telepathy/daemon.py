"""telepathyd: the root daemon.

Two unix sockets, newline-delimited JSON, one request/response per connection.
Caller identity always comes from SO_PEERCRED, never from the message.

  agent socket  (0666, uid must be in allowed_uids): submit, status, result, cancel
  admin socket  (0600, uid must be root):            list, show, approve, deny

Approved requests are executed by a single worker thread, one at a time. Each
first passes a pre-check in its own thread (`_enqueue`), so a path check stuck on
a hung mount is retried later instead of blocking the worker.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import queue
import signal
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
import traceback
from collections import OrderedDict

from .audit import AuditLog, FileSink
from .broker import (Broker, BrokerError, CheckUnavailable, Expired, IntegrityFailure, Limits,
                     NonceMismatch, PolicyDenied, RateLimited, UnknownRequest)
from .config import Config, ConfigError, require_secure_file
from . import cgroup
from .executor import ExecResult, configure_cgroups, run_command, sweep_cgroups
from .notify import NtfyNotifier, WebhookNotifier
from .policy import (Policy, PolicyError, configure_submit_quota, drain_skip_events, skipped_protected_prefixes,
                     skipped_snapshot, start_skip_tracking, wait_skip_events)
from .request import InvalidRequest, InvalidTransition, State
from .web import WebApp, WebHandler

MAX_LINE = 512 * 1024
MAX_RESULTS = 64
RETRY_DELAY = 2.0  # first backoff before retrying a run whose path check was unavailable
MAX_RUN_ATTEMPTS = 5  # total begin_run attempts; backoff doubles: 2, 4, 8, 16 s
POLL_INTERVAL = 0.2  # serve_forever() poll; tests inject a smaller one
PEERCRED = struct.Struct("3i")


def _err(code: str, message: str, **extra) -> dict:
    return {"ok": False, "code": code, "error": message, **extra}


class Daemon:
    def __init__(self, cfg: Config, broker: Broker, executor=run_command, admin_uids=(0,),
                 retry_delay: float = RETRY_DELAY, max_run_attempts: int = MAX_RUN_ATTEMPTS,
                 poll_interval: float = POLL_INTERVAL):
        self.cfg = cfg
        self.broker = broker
        self.executor = executor
        self.admin_uids = tuple(admin_uids)
        self.web = (WebApp(self, cfg.approver_logins, cfg.approver_ips)
                    if cfg.approver_logins and cfg.approver_ips else None)
        # Called (in their own threads) with {"id", "short_hash"} when a request
        # needs a human. Never given the command.
        self.on_pending: list = []
        self._results: OrderedDict[str, dict] = OrderedDict()
        self._rlock = threading.Lock()
        self._jobs: queue.Queue = queue.Queue()
        self._servers: list[_Server] = []
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self.retry_delay = retry_delay
        # serve_forever() wake-up; stop() waits up to one interval per server.
        self.poll_interval = poll_interval
        self.max_run_attempts = max_run_attempts
        self._attempts: dict[str, int] = {}  # shared by pre-check threads and the worker
        self._alock = threading.Lock()
        self._timers: set[threading.Timer] = set()
        self._tlock = threading.Lock()

    # -- shared plumbing --------------------------------------------------

    def _guarded(self, fn) -> dict:
        try:
            return fn()
        except PolicyDenied as e:
            return _err("policy_denied", f"denied by policy: {e.decision.reason}")
        except RateLimited as e:
            return _err("rate_limited", str(e))
        except UnknownRequest:
            return _err("not_found", "no such request")
        except Expired:
            return _err("expired", "request expired")
        except NonceMismatch:
            return _err("bad_nonce", "approval nonce mismatch")
        except IntegrityFailure:
            return _err("integrity", "request failed its integrity check and was denied")
        except InvalidTransition as e:
            return _err("conflict", f"invalid state change: {e}")
        except InvalidRequest as e:
            return _err("invalid", str(e))

    def _owned(self, rid, uid: int):
        if not isinstance(rid, str):
            raise InvalidRequest("id must be a string")
        req = self.broker.get(rid)
        if req.uid != uid:
            raise UnknownRequest(rid)  # don't reveal other users' requests
        return req

    # -- agent protocol ---------------------------------------------------

    def handle_agent(self, msg: dict, uid: int) -> dict:
        if uid not in self.cfg.allowed_uids:
            self.broker.audit.write("unauthorized", socket="agent", uid=uid)
            return _err("forbidden", "uid not allowed")
        op = msg.get("op")
        if op == "submit":
            return self._guarded(lambda: self._submit(msg, uid))
        if op == "status":
            return self._guarded(lambda: {"ok": True,
                                          "request": self.broker.view(self._owned(msg.get("id"), uid))})
        if op == "result":
            return self._guarded(lambda: self._result(msg.get("id"), uid))
        if op == "cancel":
            return self._guarded(lambda: self._cancel(msg.get("id"), uid))
        return _err("bad_op", "unknown op")

    def _cancel(self, rid, uid: int) -> dict:
        # Owner-or-root is enforced inside the broker, atomically with the change.
        if not isinstance(rid, str):
            raise InvalidRequest("id must be a string")
        req, changed = self.broker.cancel(rid, uid)
        return {"ok": True, "cancelled": req.state is State.CANCELLED, "changed": changed,
                "request": self.broker.view(req)}

    def _submit(self, msg: dict, uid: int) -> dict:
        req = self.broker.submit(msg.get("argv"), msg.get("cwd"), uid, msg.get("reason", ""))
        if req.state is State.APPROVED:  # auto rule
            self._enqueue(req.id)
        elif req.state is State.PENDING:
            self._fire_pending(req)
        return {"ok": True, "request": self.broker.view(req)}

    def _fire_pending(self, req) -> None:
        info = {"id": req.id, "short_hash": req.short_hash}
        for fn in self.on_pending:
            threading.Thread(target=self._run_notifier, args=(fn, info), daemon=True).start()

    def _run_notifier(self, fn, info: dict) -> None:
        via = getattr(fn, "kind", "hook")  # a fixed label, never the URL
        try:
            fn(info)
        except Exception as e:  # a notification problem must never affect the request
            # Only the exception class: its message could contain the secret URL.
            self.broker.audit.write("notify_failed", id=info["id"], via=via, error=type(e).__name__)
        else:
            self.broker.audit.write("notified", id=info["id"], via=via)

    def _result(self, rid, uid: int) -> dict:
        req = self._owned(rid, uid)
        if req.state is not State.DONE:
            return _err("not_ready", f"request is {req.state.value}", request=self.broker.view(req))
        with self._rlock:
            res = self._results.get(req.id)
        if res is None:
            return _err("gone", "result is no longer available")
        return {"ok": True, "request": self.broker.view(req), "result": res}

    # -- admin protocol ---------------------------------------------------

    def handle_admin(self, msg: dict, uid: int) -> dict:
        if uid not in self.admin_uids:
            self.broker.audit.write("unauthorized", socket="admin", uid=uid)
            return _err("forbidden", "admin only")
        op = msg.get("op")
        if op == "list":
            return {"ok": True, "requests": [self.broker.view(r) for r in self.broker.pending()],
                    "skipped_prefixes": [{"prefix": p, "resolved": r}
                                         for p, r in skipped_snapshot()]}
        rid = msg.get("id")
        if not isinstance(rid, str):
            return _err("invalid", "id must be a string")
        if op == "show":
            return self._guarded(lambda: {"ok": True, "request": self.broker.view(self.broker.get(rid))})
        if op == "approve":
            return self._guarded(lambda: self._admin_approve(rid, uid))
        if op == "deny":
            return self._guarded(lambda: {"ok": True,
                                          "request": self.broker.view(self.deny(rid, f"local:uid{uid}"))})
        return _err("bad_op", "unknown op")

    def _admin_approve(self, rid: str, uid: int) -> dict:
        nonce = self.broker.issue_nonce(rid)
        return {"ok": True, "request": self.broker.view(self.approve(rid, nonce, f"local:uid{uid}"))}

    # -- decisions (also the entry points for the web approver later) ------

    def approve(self, rid: str, nonce: str, approver: str):
        req = self.broker.approve(rid, nonce, approver)
        self._enqueue(rid)
        return req

    def deny(self, rid: str, approver: str):
        return self.broker.deny(rid, approver)

    # -- execution --------------------------------------------------------

    def _enqueue(self, rid: str) -> None:
        """Pre-check an approved request in its own thread, then queue it for the worker.

        Only a transient check problem (timeout, busy) is filtered here: it goes to
        `_retry_later`, sharing the attempt cap with run-time `CheckUnavailable`.
        Everything else is queued, and `begin_run` decides. Requests therefore reach
        the worker in pre-check completion order, not approval order. A mount that
        hangs after the pre-check passes can still block the worker once.
        """
        if self._stop.is_set():
            return
        t = threading.Thread(target=self._precheck_then_queue, args=(rid,),
                             daemon=True, name="telepathy-precheck")
        t.start()

    def _precheck_then_queue(self, rid: str) -> None:
        try:
            problem = self.broker.precheck(rid)
        except Exception:  # never lose the request: let the worker decide
            traceback.print_exc(file=sys.stderr)
            problem = None
        if self._stop.is_set():
            return
        if problem:
            self._retry_later(rid)
        else:
            self._jobs.put(rid)

    def process(self, rid: str) -> None:
        """Run one approved request to completion (called by the worker)."""
        try:
            req = self.broker.begin_run(rid)
        except CheckUnavailable:
            self._retry_later(rid)
            return
        except (BrokerError, InvalidTransition):
            with self._alock:
                self._attempts.pop(rid, None)
            return  # expired, tampered with, or already handled: not run
        with self._alock:
            self._attempts.pop(rid, None)
        try:
            res = self.executor(req.argv, req.cwd, dict(req.env),
                                self.cfg.exec_timeout, self.cfg.max_output)
        except Exception as e:  # never leave a request stuck in "running"
            traceback.print_exc(file=sys.stderr)
            res = ExecResult(1, error=f"internal error: {type(e).__name__}")
        self._remember(rid, res)  # before finish: "done" implies the result exists
        self.broker.finish(rid, res.exit_code, {
            "output_bytes": len(res.output),
            "output_sha256": hashlib.sha256(res.output).hexdigest(),
            "truncated": res.truncated,
            "error": res.error,
        })

    def _retry_later(self, rid: str) -> None:
        """The run-time path check was unavailable (transient): retry with backoff,
        at most `max_run_attempts` times in all (or until the request expires), then
        give up and deny. Timers are tracked so stop() can cancel them."""
        with self._alock:
            n = self._attempts.get(rid, 0) + 1
            self._attempts[rid] = n
            if n >= self.max_run_attempts:
                self._attempts.pop(rid, None)
        if n >= self.max_run_attempts:
            self.broker.give_up(rid, n)
            return

        def fire():
            with self._tlock:
                self._timers.discard(t)
            self._enqueue(rid)  # through the pre-check again; a no-op after stop()
        t = threading.Timer(self.retry_delay * 2 ** (n - 1), fire)
        t.daemon = True
        with self._tlock:
            if self._stop.is_set():
                return
            self._timers.add(t)
        t.start()

    def _remember(self, rid: str, res: ExecResult) -> None:
        with self._rlock:
            self._results[rid] = {
                "exit_code": res.exit_code,
                "output_b64": base64.b64encode(res.output).decode("ascii"),
                "truncated": res.truncated,
                "error": res.error,
            }
            while len(self._results) > MAX_RESULTS:
                self._results.popitem(last=False)

    def _worker(self) -> None:
        while True:
            rid = self._jobs.get()
            if rid is None:
                return
            try:
                self.process(rid)
            except Exception:
                traceback.print_exc(file=sys.stderr)

    def _sweeper(self) -> None:
        while not self._stop.wait(30):
            self.broker.sweep()
            try:
                sweep_cgroups()  # leftovers of a normal exit that have since ended
            except Exception:
                traceback.print_exc(file=sys.stderr)

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        specs = [(self.cfg.socket_path, self.handle_agent, 0o666, _Handler),
                 (self.cfg.admin_socket_path, self.handle_admin, 0o600, _Handler)]
        if self.web is not None:
            # Root-only on purpose: the approver identity header is trusted
            # because only tailscaled (root) can connect here. See web.py.
            specs.append((self.cfg.web_socket_path, self.web, 0o600, WebHandler))
        for path, dispatch, mode, handler in specs:
            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
            srv = _Server(path, dispatch, mode, handler)
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": self.poll_interval},
                                 daemon=True)
            t.start()
            self._servers.append(srv)
            self._threads.append(t)
        for target in (self._worker, self._sweeper):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        with self._tlock:
            timers, self._timers = list(self._timers), set()
        for t in timers:
            t.cancel()
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()
            try:
                os.unlink(srv.server_address)
            except OSError:
                pass
        self._servers.clear()
        self._jobs.put(None)
        for t in self._threads:
            t.join(timeout=2)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        try:
            _pid, uid, _gid = PEERCRED.unpack(
                sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size))
            line = self.rfile.readline(MAX_LINE + 1)
            if not line:
                return
            if len(line) > MAX_LINE:
                resp = _err("too_large", "request too large")
            else:
                try:
                    msg = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    resp = _err("bad_json", "request is not valid JSON")
                else:
                    if isinstance(msg, dict):
                        resp = self.server.dispatch(msg, uid)
                    else:
                        resp = _err("bad_request", "expected a JSON object")
        except OSError:
            return
        except Exception:
            traceback.print_exc(file=sys.stderr)
            resp = _err("internal", "internal error")
        try:
            self.wfile.write(json.dumps(resp, separators=(",", ":")).encode("utf-8") + b"\n")
        except OSError:
            pass


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, dispatch, mode: int, handler=_Handler):
        self.dispatch = dispatch
        try:
            if stat.S_ISSOCK(os.lstat(path).st_mode):
                os.unlink(path)  # stale socket from a previous run
        except FileNotFoundError:
            pass
        old = os.umask(0o177)  # never briefly world-accessible
        try:
            super().__init__(path, handler)
        finally:
            os.umask(old)
        os.chmod(path, mode)


HUP_MARKER = "hup-ok"  # in the runtime dir: "this daemon handles SIGHUP"
REOPEN_FAILED_FLAG = "audit-reopen-failed"  # present while the audit log cannot be reopened


def run_reopen_worker(sink, audit, request, done, fail_flag=None,
                      delays=(0.5, 1, 2, 4), retry_every=60.0) -> None:
    """On each request, reopen the audit file; retry with backoff, then every
    `retry_every` seconds, and make failure loud until it succeeds."""
    def flag(on: bool) -> None:
        if not fail_flag:
            return
        try:
            if on:
                with open(fail_flag, "w"):
                    pass
            else:
                os.unlink(fail_flag)
        except OSError:
            pass

    def safe_audit(event: str, **fields) -> None:
        try:
            audit.write(event, **fields)
        except Exception as e:  # the worker must outlive any audit trouble
            print(f"telepathyd: cannot write audit record {event}: {e}", file=sys.stderr)

    while True:
        request.wait()
        if done.is_set():
            return
        request.clear()
        attempt = 0
        while not done.is_set():
            try:
                sink.reopen()
            except Exception as e:
                flag(True)
                safe_audit("audit_reopen_failed", error=type(e).__name__, attempt=attempt + 1)
                print(f"telepathyd: cannot reopen audit log (attempt {attempt + 1}); still writing "
                      f"to the old file: {e}", file=sys.stderr)
                delay = delays[attempt] if attempt < len(delays) else retry_every
                attempt += 1
                if done.wait(delay):
                    return
            else:
                flag(False)
                safe_audit("audit_reopened")
                break


def _report_skip_event(audit, event: str, literal: str, real: str,
                       attempts: int = 5, delay: float = 0.2) -> bool:
    """Audit one skip change, retrying a failed write a bounded number of times."""
    for i in range(attempts):
        try:
            audit.write(event, prefix=literal, resolved=real)
            break
        except Exception as e:
            if i == attempts - 1:
                print(f"telepathyd: cannot audit {event} for {literal!r} -> {real!r}: {e}",
                      file=sys.stderr)
                return False
            time.sleep(delay)
    try:
        if event == "protected_prefix_skipped":
            print(f"telepathyd: protected prefix {literal!r} resolves to {real!r}, too broad "
                  "to protect by itself; only the literal path is enforced", file=sys.stderr)
        else:
            print(f"telepathyd: protected prefix {literal!r} no longer resolves to {real!r}",
                  file=sys.stderr)
    except Exception:
        pass
    return True


def drain_skip_reports(audit, **kw) -> None:
    """Write every queued skip change (and an overflow notice) to the audit log."""
    events, dropped = drain_skip_events()
    if dropped:
        try:
            audit.write("protected_prefix_events_dropped", count=dropped)
        except Exception as e:
            print(f"telepathyd: {dropped} protected-prefix events dropped: {e}", file=sys.stderr)
    for ev in events:
        _report_skip_event(audit, *ev, **kw)


def report_skipped_prefixes(audit, done: threading.Event | None = None) -> threading.Thread:
    """Report the prefixes skipped as too broad now, then every later change.

    One resolution feeds both the start-up report and the change cache. Later changes
    are queued by policy evaluation and written by a reporter thread, never by the
    evaluating thread. With `done`, the thread drains once more and exits when it is set.
    """
    now = skipped_protected_prefixes()
    start_skip_tracking(dict(now))
    for literal, real in now:
        _report_skip_event(audit, "protected_prefix_skipped", literal, real)

    def loop():
        while True:
            wait_skip_events(0.5)
            drain_skip_reports(audit)
            if done is not None and done.is_set():
                drain_skip_reports(audit)
                return

    t = threading.Thread(target=loop, name="skip-reporter", daemon=True)
    t.start()
    return t


def load_notifiers(cfg: Config, secure: bool = True) -> list:
    """One notifier per configured secret URL file (ntfy, webhook, or both)."""
    out = []
    for path, kind in ((cfg.ntfy_url_file, NtfyNotifier), (cfg.webhook_url_file, WebhookNotifier)):
        if path:
            if secure:
                require_secure_file(path, secret=True)
            with open(path, encoding="utf-8") as f:
                out.append(kind(f.read().strip(), cfg.public_url))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="telepathyd")
    ap.add_argument("--config", default="/etc/telepathy/config.toml")
    ap.add_argument("--insecure-dev", action="store_true",
                    help="skip the root-ownership checks (development only)")
    args = ap.parse_args(argv)

    try:
        if not args.insecure_dev:
            if os.geteuid() != 0:
                raise ConfigError("must run as root")
            require_secure_file(args.config)
        with open(args.config, encoding="utf-8") as f:
            cfg = Config.from_toml(f.read())
        if not args.insecure_dev:
            require_secure_file(cfg.policy_path)
        with open(cfg.policy_path, encoding="utf-8") as f:
            policy = Policy.from_toml(f.read())
        notifiers = load_notifiers(cfg, secure=not args.insecure_dev)
        os.makedirs(os.path.dirname(cfg.audit_path), mode=0o700, exist_ok=True)
        sink = FileSink(cfg.audit_path)
        audit = AuditLog(sink)
    except (ConfigError, PolicyError, OSError) as e:
        print(f"telepathyd: {e}", file=sys.stderr)
        return 2

    configure_submit_quota(cfg.allowed_uids)  # per-uid share only with several uids
    # Per-command cgroups for an airtight timeout kill, else /proc polling.
    cg_base = cgroup.probe()
    configure_cgroups(cg_base)
    if cg_base is not None:
        cgroup.sweep(cg_base)  # empty cmd-* dirs left by a previous run
    else:
        print("telepathyd: per-command cgroups unavailable (no cgroup v2 delegation or "
              "cgroup.kill); timeouts fall back to /proc polling", file=sys.stderr)
    broker = Broker(policy, Limits(cfg.ttl, cfg.max_pending, cfg.max_per_hour), audit)
    daemon = Daemon(cfg, broker, admin_uids=(os.geteuid(),) if args.insecure_dev else (0,))
    daemon.on_pending.extend(notifiers)
    done = threading.Event()  # tells the reopen worker to stop
    rundir = os.path.dirname(cfg.admin_socket_path)
    hup_marker = os.path.join(rundir, HUP_MARKER)
    fail_flag = os.path.join(rundir, REOPEN_FAILED_FLAG)
    for stale in (hup_marker, fail_flag):  # leftovers of a crashed run must not vouch for us
        try:
            os.unlink(stale)
        except OSError:
            pass
    # Signals: the handler does one async-signal-safe os.write to a pipe and
    # nothing else (no locks, no Event.set: a handler that interrupts a thread
    # holding that lock would deadlock). The main thread reads the pipe below.
    # SIGHUP must be handled before anything is served: its default action
    # terminates the process.
    sig_r, sig_w = os.pipe()
    os.set_blocking(sig_w, False)  # the handler must never block

    def on_signal(signum, _frame):
        try:
            os.write(sig_w, b"h" if signum == signal.SIGHUP else b"q")
        except OSError:  # pipe full: a wake-up is already pending
            pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_signal)
    reopen = threading.Event()
    threading.Thread(target=run_reopen_worker, name="audit-reopen", daemon=True,
                     args=(sink, audit, reopen, done, fail_flag)).start()
    skip_reporter = report_skipped_prefixes(audit, done)
    daemon.start()
    audit.write("daemon_start", allowed_uids=list(cfg.allowed_uids), rules=len(policy.rules),
                cgroups=cg_base is not None)
    # Last: tells logrotate that this daemon is up and survives SIGHUP.
    try:
        with open(hup_marker, "w"):
            pass
    except OSError as e:
        print(f"telepathyd: cannot write {hup_marker}: {e}; logrotate would rotate the audit "
              "log without the daemon reopening it", file=sys.stderr)
        audit.write("hup_marker_failed", error=type(e).__name__)
        if not args.insecure_dev:
            done.set()
            reopen.set()
            skip_reporter.join(2)
            daemon.stop()
            audit.write("daemon_stop")
            return 2
    while True:
        c = os.read(sig_r, 1)
        if c == b"h":
            reopen.set()
        elif c == b"q":
            break
    try:  # first thing on shutdown: stop vouching for a daemon that is leaving
        os.unlink(hup_marker)
    except OSError:
        pass
    done.set()
    reopen.set()
    skip_reporter.join(2)
    daemon.stop()
    audit.write("daemon_stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
