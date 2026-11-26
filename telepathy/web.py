"""Approval web UI.

Served only on a root-owned (0600) unix socket. The tailnet reaches it through
`tailscale serve`, which proxies requests and sets the Tailscale-User-Login
header itself (it overwrites any client-supplied value). Because no local user
can connect to the socket, that header can be trusted. Never expose this socket
any other way (not on TCP, not with looser permissions): anyone who can connect
can claim to be the approver.

The login alone is not enough. A local process (the agent) can also connect to
this machine's *own* tailnet address, and tailscaled then stamps that request
with the machine's own identity, which may be the same account as the phone. So
the request must also come from a configured approver device: the proxy records
the peer's tailnet IP in X-Forwarded-For and only its last entry (the one the
proxy appended, not anything the client sent) is trusted. This machine's own
address is never in the allowlist.

No JavaScript: the page is a static render plus two plain forms, and the CSP
forbids scripts. The command is shown argument by argument, with anything that
is not printable ASCII spelled out in red, so look-alike characters can't hide
what will actually run.
"""

from __future__ import annotations

import html
import http.server
import ipaddress
import re
import urllib.parse

from .broker import Expired, NonceMismatch, UnknownRequest
from .policy import unverified
from .request import InvalidTransition, State

MAX_BODY = 4096
_ID = r"[0-9a-f]{16}"
_VIEW = re.compile(rf"^/r/({_ID})$")
_ACT = re.compile(rf"^/r/({_ID})/(approve|deny)$")

SECURITY_HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
     "frame-ancestors 'none'; base-uri 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
]

CSS = """
:root{color-scheme:light dark}
body{font:17px/1.4 system-ui,sans-serif;margin:0 auto;padding:1rem;max-width:40rem}
h1{font-size:1.4rem;margin:.2rem 0 1rem}
.meta{opacity:.7;font-size:.9rem}
ol.argv{list-style:none;counter-reset:a -1;padding:0;margin:.5rem 0}
ol.argv li{counter-increment:a;display:flex;gap:.5rem;align-items:baseline;margin:.3rem 0}
ol.argv li::before{content:counter(a);opacity:.5;min-width:1.5rem;text-align:right;font-size:.8rem}
code{font:15px ui-monospace,monospace;white-space:pre-wrap;word-break:break-all;
border:1px solid;border-radius:.4rem;padding:.15rem .4rem;display:inline-block}
.esc{background:#c0392b;color:#fff;border-radius:.2rem;padding:0 .2rem;font-size:.85em}
.warn{border-left:4px solid #c0392b;padding:.4rem .8rem;margin:1rem 0}
.agent{border-left:4px solid #888;padding:.4rem .8rem;margin:1rem 0;white-space:pre-wrap}
form{margin:1rem 0}
button{font:inherit;font-weight:600;width:100%;padding:1rem;border-radius:.7rem;border:0;color:#fff}
.approve{background:#1e7e34}
.deny{background:#b02a37}
a{color:inherit}
"""


def _arg_html(text: str) -> tuple[str, bool]:
    """HTML-escape `text`, spelling out anything that isn't printable ASCII.

    Returns (html, flagged) where flagged means something non-ASCII or a
    control character was present.
    """
    if text == "":
        return '<span class="esc">(empty)</span>', False
    out, flagged = [], False
    for ch in text:
        o = ord(ch)
        if 0x20 <= o <= 0x7E:
            out.append(html.escape(ch))
        else:
            flagged = True
            out.append(f'<span class="esc">\\u{{{o:04X}}}</span>')
    return "".join(out), flagged


class WebApp:
    def __init__(self, daemon, approver_logins, approver_ips):
        self.daemon = daemon
        self.logins = frozenset(str(x).lower() for x in approver_logins)
        self.ips = frozenset(ipaddress.ip_address(x) for x in approver_ips)

    @staticmethod
    def _peer_ip(xff: str):
        """The proxy-appended (last) X-Forwarded-For entry, or None if unusable."""
        try:
            return ipaddress.ip_address(xff.rsplit(",", 1)[-1].strip())
        except ValueError:
            return None

    # -- entry point ------------------------------------------------------

    def handle(self, method: str, path: str, headers, body: bytes = b""):
        h = {k.lower(): v for k, v in headers.items()}
        login = h.get("tailscale-user-login", "")
        xff = h.get("x-forwarded-for", "")
        if login.lower() not in self.logins or self._peer_ip(xff) not in self.ips:
            self.daemon.broker.audit.write("web_unauthorized", login=login[:200],
                                           peer=xff[-100:], path=path[:200])
            return self._error(403, "Not authorized.")
        url = urllib.parse.urlsplit(path).path
        try:
            if method == "GET":
                if url == "/":
                    return self._index()
                m = _VIEW.match(url)
                if m:
                    return self._detail(m.group(1))
                return self._error(404, "Not found.")
            if method == "POST":
                m = _ACT.match(url)
                if m:
                    return self._act(m.group(1), m.group(2), body, login)
                return self._error(404, "Not found.")
        except UnknownRequest:
            return self._error(404, "No such request. It may have expired and been cleaned up.")
        return self._error(405, "Method not allowed.")

    # -- pages ------------------------------------------------------------

    def _page(self, status, title, body, extra=()):
        doc = ("<!doctype html><html lang=en><head><meta charset=utf-8>"
               '<meta name=viewport content="width=device-width,initial-scale=1">'
               f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
               f"<body>{body}</body></html>")
        return status, SECURITY_HEADERS + list(extra), doc.encode("utf-8")

    def _error(self, status, message, rid=None):
        back = f'<a href="/r/{rid}">Back to the request</a>' if rid else '<a href="/">Home</a>'
        return self._page(status, "telepathy", f"<h1>{html.escape(message)}</h1><p>{back}</p>")

    def _index(self):
        pending = self.daemon.broker.pending()
        if not pending:
            return self._page(200, "telepathy",
                              "<h1>telepathy</h1><p>Nothing is waiting for approval.</p>")
        items = []
        for r in pending:
            summary, _ = _arg_html(" ".join(r.argv)[:120])
            items.append(f'<li><a href="/r/{r.id}"><code>{r.short_hash}</code> {summary}</a></li>')
        return self._page(200, "telepathy",
                          f"<h1>Waiting for approval</h1><ul>{''.join(items)}</ul>")

    def _detail(self, rid):
        req = self.daemon.broker.get(rid)
        flagged = False
        items = []
        for a in req.argv:
            h, f = _arg_html(a)
            flagged |= f
            items.append(f"<li><code>{h}</code></li>")
        cwd_h, f = _arg_html(req.cwd)
        flagged |= f

        parts = []
        if req.state is State.PENDING:
            parts.append("<h1>Run this as root?</h1>")
        else:
            parts.append(f"<h1>{html.escape(req.state.value.capitalize())}</h1>")
        parts.append(f'<p class="meta">request {req.id} &middot; hash <b>{req.short_hash}</b>'
                     f" &middot; asked by uid {req.uid}</p>")
        if flagged:
            parts.append('<p class="warn">This contains non-ASCII or control characters, shown '
                         "in red. Read it carefully before approving.</p>")
        parts.append(f'<ol class="argv">{"".join(items)}</ol>')
        for written, real in (req.resolved or {}).items():
            w_h, _ = _arg_html(written)
            r_h, _ = _arg_html(real)
            parts.append(f'<p class="warn">Symlink: <code>{w_h}</code> really points to '
                         f"<code>{r_h}</code></p>")
        blocked = unverified(req.resolved) if req.state is State.PENDING else None
        if blocked:
            parts.append(f'<p class="warn">This request cannot run: {html.escape(blocked)}. '
                         "Deny it and ask the agent to submit again.</p>")
        parts.append(f"<p>Working directory: <code>{cwd_h}</code></p>")
        if req.reason:
            parts.append('<div class="agent"><b>The agent says (unverified):</b>\n'
                         f"{html.escape(req.reason)}</div>")

        if req.state is State.PENDING:
            nonce = self.daemon.broker.issue_nonce(req.id)
            left = max(0, int(self.daemon.broker.view(req)["expires_in"]))
            parts.append(f'<p class="meta">Expires in {left // 60} min {left % 60} s. '
                         f'<a href="/r/{req.id}">Reload</a></p>')
            if not blocked:
                parts.append(
                    f'<form method="post" action="/r/{req.id}/approve">'
                    f'<input type="hidden" name="nonce" value="{html.escape(nonce)}">'
                    '<button class="approve">Approve and run as root</button></form>')
            parts.append(
                f'<form method="post" action="/r/{req.id}/deny">'
                '<button class="deny">Deny</button></form>')
        else:
            if req.state is State.CANCELLED:
                parts.append("<p><b>Withdrawn by the agent (cancelled); nothing will run.</b></p>")
            line = f"<p><b>{html.escape(req.state.value)}</b>"
            if req.approver:
                line += f" by {html.escape(req.approver)}"
            if req.state is State.DONE:
                line += f", exit code {req.exit_code}"
            parts.append(line + '</p><p><a href="/">Home</a></p>')
        return self._page(200, "telepathy", "".join(parts))

    # -- actions ----------------------------------------------------------

    def _act(self, rid, action, body, login):
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        who = f"web:{login}"
        try:
            if action == "approve":
                self.daemon.approve(rid, (form.get("nonce") or [""])[0], who)
            else:
                self.daemon.deny(rid, who)
        except Expired:
            return self._error(410, "This request has expired.", rid)
        except NonceMismatch:
            return self._error(409, "This page is out of date. Reload the request and try again.", rid)
        except InvalidTransition:
            if self.daemon.broker.get(rid).state is State.CANCELLED:
                return self._error(409, "The agent withdrew this request (cancelled); "
                                        "nothing will run.", rid)
            return self._error(409, "This request was already decided or is already running.", rid)
        return 303, [("Location", f"/r/{rid}"), ("Cache-Control", "no-store")], b""


class WebHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "telepathy"
    sys_version = ""
    timeout = 10

    def address_string(self):
        return "unix"  # client_address is '' on a unix socket

    def log_message(self, *args):
        pass  # the audit log is the record

    def _send(self, status, headers, payload):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _serve(self, method):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._send(413 if length > MAX_BODY else 400, SECURITY_HEADERS,
                       b"<!doctype html><title>telepathy</title><p>Bad request size.")
            return
        body = self.rfile.read(length) if length else b""
        status, headers, payload = self.server.dispatch.handle(method, self.path, self.headers, body)
        self._send(status, headers, payload)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")
