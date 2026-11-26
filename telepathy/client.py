"""Client side: `telepathy` (the agent) and `telepathyctl` (the human, local)."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import shutil
import socket
import sys
import time

DEFAULT_SOCKET = "/run/telepathy/telepathy.sock"
DEFAULT_ADMIN_SOCKET = "/run/telepathy/admin.sock"
MAX_REPLY = 8 * 1024 * 1024

# Exit code for "telepathy itself failed or the request was refused". The
# command's own exit code is passed through otherwise.
EXIT_REFUSED = 125


class ClientError(Exception):
    pass


def call(path: str, msg: dict, timeout: float = 10.0) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n")
        with s.makefile("rb") as f:
            line = f.readline(MAX_REPLY + 1)
    except OSError as e:
        raise ClientError(f"cannot reach telepathyd at {path}: {e.strerror or e}") from e
    finally:
        s.close()
    if not line or len(line) > MAX_REPLY:
        raise ClientError("bad reply from telepathyd")
    try:
        resp = json.loads(line)
    except ValueError as e:
        raise ClientError("bad reply from telepathyd") from e
    if not isinstance(resp, dict):
        raise ClientError("bad reply from telepathyd")
    return resp


def _say(err, text: str) -> None:
    err.write(f"telepathy: {text}\n")
    err.flush()


_ANNOUNCE = {
    "pending": "waiting for approval on your phone",
    "approved": "approved, running",
    "running": "running",
}


RESTARTED = "telepathyd restarted; nothing ran, resubmit"
CANCEL_TIMEOUT = 2.0
NO_SUCH = ("no such request: wrong id, not yours, expired and swept, "
           "or telepathyd restarted")


def cancel_message(resp: dict, rid: str) -> str:
    """One line for the outcome of a cancel call (an ok reply)."""
    state = resp["request"]["state"]
    if resp.get("changed"):
        return f"request {rid} cancelled; it will not run"
    if state == "cancelled":
        return f"request {rid} was already cancelled"
    if state == "running":
        return f"request {rid} is already running and cannot be cancelled"
    if state == "done":
        return f"request {rid} already finished; nothing to cancel"
    return f"request {rid} is already {state}; nothing to cancel"


def _interrupted(rid, sock: str, err) -> None:
    """^C: withdraw the request, best effort. Never raises and never waits long.

    Known window: a ^C before the submit reply arrives leaves no id to cancel, so
    the request (if the daemon got it) waits until it expires or is denied.
    """
    try:
        if rid is None:
            _say(err, "interrupted before the daemon confirmed the request; if it was "
                      "submitted it stays pending until it expires (10 min by default)")
            return
        try:
            resp = call(sock, {"op": "cancel", "id": rid}, timeout=CANCEL_TIMEOUT)
        except (ClientError, OSError):
            resp = None
        if resp is None:
            _say(err, f"interrupted; could not reach telepathyd to cancel request {rid}; "
                      "it may still run if it gets approved")
        elif resp.get("ok"):
            _say(err, f"interrupted; {cancel_message(resp, rid)}")
        elif resp.get("code") == "not_found":
            _say(err, f"interrupted; {NO_SUCH}")
        else:
            _say(err, f"interrupted; could not cancel request {rid}: {resp.get('error', 'failed')}")
    except (Exception, KeyboardInterrupt):  # a second ^C or a closed stderr must not escape
        pass


def run(argv, reason: str = "", sock: str = DEFAULT_SOCKET, poll: float = 1.0,
        out=None, err=None, sleep=time.sleep, cwd: str | None = None, wait: bool = True) -> int:
    """Submit a command for approval, wait, and pass its output and exit code through."""
    out = out if out is not None else sys.stdout.buffer
    err = err if err is not None else sys.stderr
    argv = list(argv)
    if not argv:
        _say(err, "no command given")
        return EXIT_REFUSED
    if not argv[0].startswith("/"):
        found = shutil.which(argv[0])
        if found is None:
            _say(err, f"command not found: {argv[0]}")
            return EXIT_REFUSED
        argv[0] = os.path.abspath(found)

    rid = None
    try:
        resp = call(sock, {"op": "submit", "argv": argv, "cwd": cwd or os.getcwd(),
                           "reason": reason})
        if not resp.get("ok"):
            _say(err, resp.get("error", "request refused"))
            return EXIT_REFUSED
        req = resp["request"]
        rid, state = req["id"], req["state"]
        _say(err, f"request {rid} [{req['short_hash']}]: {shlex.join(argv)}")
        if not wait:
            out.write(rid.encode("ascii") + b"\n")
            out.flush()
            return 0

        announced = set()
        while state not in ("done", "denied", "expired", "cancelled"):
            if state not in announced:
                announced.add(state)
                _say(err, _ANNOUNCE.get(state, state))
            sleep(poll)
            resp = call(sock, {"op": "status", "id": rid})
            if not resp.get("ok"):
                if resp.get("code") == "not_found":
                    _say(err, RESTARTED)
                else:
                    _say(err, resp.get("error", "lost track of the request"))
                return EXIT_REFUSED
            state = resp["request"]["state"]

        if state == "denied":
            _say(err, "denied")
            return EXIT_REFUSED
        if state == "cancelled":
            _say(err, "cancelled")
            return EXIT_REFUSED
        if state == "expired":
            _say(err, "expired before it could run")
            return EXIT_REFUSED

        resp = call(sock, {"op": "result", "id": rid})
        if not resp.get("ok"):
            _say(err, NO_SUCH if resp.get("code") == "not_found"
                 else resp.get("error", "result unavailable"))
            return EXIT_REFUSED
        res = resp["result"]
        out.write(base64.b64decode(res["output_b64"]))
        out.flush()
        if res.get("truncated"):
            _say(err, "output was truncated")
        if res.get("error"):
            _say(err, res["error"])
        return int(res["exit_code"])
    except ClientError as e:
        _say(err, str(e))
        return EXIT_REFUSED
    except KeyboardInterrupt:
        _interrupted(rid, sock, err)
        return 130


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="telepathy", description="Ask for a root command to be approved from your phone.")
    ap.add_argument("--socket", default=os.environ.get("TELEPATHY_SOCKET", DEFAULT_SOCKET))
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a command as root once approved")
    r.add_argument("--reason", "-r", default="", help="why (shown to the approver, marked as agent-supplied)")
    r.add_argument("--no-wait", action="store_true", help="submit, print the request id, and return")
    r.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    for name, help_ in (("status", "show a request's status"),
                        ("result", "show a request's result"),
                        ("cancel", "cancel a request that has not run yet")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("id")
    args = ap.parse_args(argv)

    if args.cmd == "run":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        return run(command, reason=args.reason, sock=args.socket, wait=not args.no_wait)
    try:
        resp = call(args.socket, {"op": args.cmd, "id": args.id})
    except ClientError as e:
        print(f"telepathy: {e}", file=sys.stderr)
        return EXIT_REFUSED
    if not resp.get("ok"):
        if resp.get("code") == "not_found":
            print(f"telepathy: {NO_SUCH}", file=sys.stderr)
        else:
            print(f"telepathy: {resp.get('error', 'failed')}", file=sys.stderr)
        return EXIT_REFUSED
    if args.cmd == "cancel":
        print(f"telepathy: {cancel_message(resp, args.id)}", file=sys.stderr)
        return 0 if resp["request"]["state"] == "cancelled" else EXIT_REFUSED
    if args.cmd == "result":
        res = resp["result"]
        sys.stdout.buffer.write(base64.b64decode(res["output_b64"]))
        sys.stdout.buffer.flush()
        return int(res["exit_code"])
    print(json.dumps(resp["request"], indent=2))
    return 0


# -- telepathyd local admin (run as root at a terminal) -------------------------


def _show(req: dict, out) -> None:
    left = req["expires_in"]
    print(f"id:      {req['id']}", file=out)
    print(f"hash:    {req['short_hash']}", file=out)
    print(f"state:   {req['state']}", file=out)
    print(f"cwd:     {req['cwd']}", file=out)
    print(f"command: {shlex.join(req['argv'])}", file=out)
    for written, real in (req.get("resolved") or {}).items():
        print(f"  note:  {written} is really {real}", file=out)
    if req["reason"]:
        print(f"reason:  {req['reason']}   (supplied by the agent, not verified)", file=out)
    print(f"expires: in {max(0, int(left))}s", file=out)


def ctl_main(argv=None, out=None, confirm=input) -> int:
    out = out if out is not None else sys.stdout
    ap = argparse.ArgumentParser(
        prog="telepathyctl", description="Approve or deny pending requests from a local terminal (root).")
    ap.add_argument("--socket", default=DEFAULT_ADMIN_SOCKET)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for name in ("show", "approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("id")
        if name == "approve":
            p.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args(argv)

    def ask(msg):
        try:
            resp = call(args.socket, msg)
        except ClientError as e:
            print(f"telepathyctl: {e}", file=sys.stderr)
            return None
        if not resp.get("ok"):
            print(f"telepathyctl: {resp.get('error', 'failed')}", file=sys.stderr)
            return None
        return resp

    if args.cmd == "list":
        resp = ask({"op": "list"})
        if resp is None:
            return 1
        for req in resp["requests"]:
            print(f"{req['id']}  {req['short_hash']}  {shlex.join(req['argv'])}", file=out)
        for sk in resp.get("skipped_prefixes") or ():
            print(f"note: protected prefix {sk['prefix']} resolves to {sk['resolved']}, too broad "
                  "to protect by itself; only the literal path is enforced", file=sys.stderr)
        return 0

    if args.cmd == "approve" and not args.yes:
        shown = ask({"op": "show", "id": args.id})
        if shown is None:
            return 1
        _show(shown["request"], out)
        if confirm("Approve this exact command? [y/N] ").strip().lower() not in ("y", "yes"):
            print("not approved", file=out)
            return 1
    resp = ask({"op": args.cmd, "id": args.id})
    if resp is None:
        return 1
    _show(resp["request"], out)
    return 0
