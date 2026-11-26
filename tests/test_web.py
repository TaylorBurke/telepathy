import io
import os
import re
import shutil
import socket
import tempfile
import threading
import time
import unittest
import urllib.parse

from telepathy import client
from telepathy.audit import AuditLog
from telepathy.broker import Broker, Limits
from telepathy.config import Config
from telepathy.daemon import Daemon
from telepathy.executor import ExecResult
from telepathy.policy import Policy
from telepathy.request import State
from telepathy.web import WebApp

ME = os.getuid()
LOGIN = "me@example.com"
PHONE = "100.64.0.7"  # the approver's device
SELF = "100.64.0.1"  # this machine's own tailnet address (the agent can reach it)
ASK = ["/usr/bin/pacman", "-Syu"]


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def build(clock, logins=(LOGIN,), **cfg_kw):
    log, calls = [], []

    def stub(argv, cwd, env, timeout, max_output):
        calls.append(tuple(argv))
        return ExecResult(0, b"secret-output")

    broker = Broker(Policy.empty(), Limits(ttl=600), AuditLog(log.append), clock=clock,
                    link_trusted_uid=-1)  # runner-uid independent (root too)
    cfg = Config(allowed_uids=(ME,), approver_logins=tuple(logins),
                 approver_ips=(PHONE,) if logins else (), **cfg_kw)
    return Daemon(cfg, broker, stub, admin_uids=(ME,), poll_interval=0.005), log, calls


class WebUnit(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.d, self.log, self.calls = build(self.clock)
        self.web = WebApp(self.d, [LOGIN], [PHONE])

    def req(self, method, path, login=LOGIN, body=b"", ip=PHONE):
        headers = {} if login is None else {"Tailscale-User-Login": login}
        if ip is not None:
            headers["X-Forwarded-For"] = ip
        return self.web.handle(method, path, headers, body)

    def submit(self, argv=ASK, reason="update"):
        return self.d.broker.submit(argv, "/tmp", ME, reason)

    def page(self, rid):
        status, headers, body = self.req("GET", f"/r/{rid}")
        return status, dict(headers), body.decode()

    @staticmethod
    def nonce(text):
        return re.search(r'name="nonce" value="([^"]+)"', text).group(1)

    def post(self, rid, action, nonce=None, **kw):
        form = {} if nonce is None else {"nonce": nonce}
        return self.req("POST", f"/r/{rid}/{action}", body=urllib.parse.urlencode(form).encode(), **kw)

    # -- who may use it ---------------------------------------------------

    def test_unauthorized_logins_are_refused_and_audited(self):
        r = self.submit()
        for login in (None, "", "other@example.com", "me@example.com.evil"):
            status, _, body = self.req("GET", f"/r/{r.id}", login=login)
            self.assertEqual(status, 403, login)
            self.assertNotIn(b"pacman", body)
            self.assertEqual(self.post(r.id, "approve", "x", login=login)[0], 403)
        self.assertIn('"web_unauthorized"', "".join(self.log))
        self.assertEqual(self.d.broker.get(r.id).state, State.PENDING)

    def test_login_match_is_case_insensitive(self):
        self.assertEqual(self.req("GET", "/", login=LOGIN.upper())[0], 200)

    def test_request_must_come_from_the_approvers_device(self):
        # The agent can connect to this machine's own tailnet address and get the
        # owner's login stamped on the request, but it arrives from SELF.
        r = self.submit()
        cases = [(None, 403), ("", 403), ("garbage", 403), (SELF, 403), ("100.64.0.99", 403),
                 (f"{PHONE}, {SELF}", 403),  # the last entry is the proxy-appended one
                 (f"{SELF}, {PHONE}", 200), (PHONE, 200), (f" {PHONE} ", 200)]
        for ip, want in cases:
            self.assertEqual(self.req("GET", f"/r/{r.id}", ip=ip)[0], want, ip)
        self.assertEqual(self.post(r.id, "approve", "x", ip=SELF)[0], 403)
        self.assertEqual(self.post(r.id, "deny", ip=SELF)[0], 403)
        self.assertEqual(r.state, State.PENDING)
        self.assertIn(f'"peer":"{SELF}"', "".join(self.log))

    def test_ipv6_peers_are_compared_normalised(self):
        web = WebApp(self.d, [LOGIN], [PHONE, "fd7a:115c:a1e0::1"])
        h = {"Tailscale-User-Login": LOGIN, "X-Forwarded-For": "fd7a:115c:a1e0:0:0:0:0:1"}
        self.assertEqual(web.handle("GET", "/", h)[0], 200)
        h["X-Forwarded-For"] = "fd7a:115c:a1e0::2"
        self.assertEqual(web.handle("GET", "/", h)[0], 403)

    # -- what the approver sees -------------------------------------------

    def test_pending_page_shows_remaining_time_from_the_broker_clock(self):
        r = self.submit()
        self.assertIn("Expires in 10 min 0 s", self.page(r.id)[2])
        self.clock.t += 125
        self.assertIn("Expires in 7 min 55 s", self.page(r.id)[2])

    def test_detail_shows_where_a_symlink_really_points(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "innocent")
            os.symlink("/usr/share/doc", link)
            r = self.submit(["/usr/bin/ls", link])
            _, _, text = self.page(r.id)
        self.assertIn("Symlink:", text)
        self.assertIn("/usr/share/doc", text)
        self.assertIn("really points to", text)

    def test_detail_flags_a_symlinked_working_directory(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as td:
            cwd = os.path.join(os.path.realpath(td), "work")
            os.symlink("/usr/share/doc", cwd)
            r = self.d.broker.submit(["/usr/bin/ls", "-n"], cwd, ME, "update")
            _, _, text = self.page(r.id)
        self.assertIn("Symlink:", text)
        self.assertIn(cwd, text)
        self.assertIn("/usr/share/doc", text)

    def test_page_render_does_not_resolve_paths_again(self):
        import os, tempfile
        from unittest import mock
        from telepathy import policy as policy_mod
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "innocent")
            os.symlink("/usr/share/doc", link)
            r = self.submit(["/usr/bin/ls", link])
            os.unlink(link)
            os.symlink("/usr/share/man", link)
            with mock.patch.object(policy_mod, "resolve_path_args",
                                   side_effect=AssertionError("resolved on render")):
                _, _, text = self.page(r.id)
        self.assertIn("/usr/share/doc", text)  # the submit-time target, not the new one
        self.assertNotIn("/usr/share/man", text)

    def test_unverified_request_shows_notice_and_no_approve_button(self):
        from unittest import mock
        from telepathy import policy as policy_mod
        for key, word in ((policy_mod.TIMED_OUT_KEY, "timed out"),
                          (policy_mod.ERROR_KEY, "unexpected error")):
            with mock.patch.object(policy_mod, "resolve_path_args",
                                   return_value={key: "x"}):
                r = self.submit()
            _, _, text = self.page(r.id)
            self.assertIn("cannot run", text)
            self.assertIn(word, text)
            self.assertNotIn("Approve and run", text)
            self.assertIn("Deny", text)

    def test_normal_request_still_has_approve_button(self):
        r = self.submit()
        _, _, text = self.page(r.id)
        self.assertIn("Approve and run", text)
        self.assertNotIn("cannot run", text)

    def test_symlink_note_escapes_html_in_written_and_resolved_paths(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(os.path.realpath(td), "<i>x")
            os.symlink('/usr/share/<b>"evil"', link)
            r = self.submit(["/usr/bin/ls", link])
            _, _, text = self.page(r.id)
        self.assertIn("Symlink:", text)
        for raw in ("<i>x", '<b>"', '"evil"'):
            self.assertNotIn(raw, text)
        self.assertIn("&lt;b&gt;", text)

    def test_detail_shows_exact_command_and_security_headers(self):
        r = self.submit()
        status, headers, text = self.page(r.id)
        self.assertEqual(status, 200)
        self.assertIn("/usr/bin/pacman", text)
        self.assertIn("-Syu", text)
        self.assertIn(r.short_hash, text)
        self.assertIn("(unverified)", text)
        self.assertIn("Approve and run as root", text)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn("<script", text.lower())

    def test_html_in_arguments_and_reason_is_escaped(self):
        r = self.submit(["/usr/bin/echo", "<script>alert(1)</script>", '"><img src=x onerror=1>'],
                        reason="<b>trust me</b>")
        _, _, text = self.page(r.id)
        self.assertNotIn("<script>alert", text)
        self.assertNotIn("<img src=x", text)
        self.assertNotIn("<b>trust me", text)
        self.assertIn("&lt;script&gt;", text)

    def test_lookalike_and_control_characters_are_spelled_out(self):
        r = self.submit(["/usr/bin/echo", "раypal‮", "tab\there"])
        _, _, text = self.page(r.id)
        for needle in ("\\u{0440}", "\\u{0430}", "\\u{202E}", "\\u{0009}", "non-ASCII"):
            self.assertIn(needle, text)
        self.assertNotIn("р", text)
        self.assertNotIn("‮", text)

    def test_empty_argument_is_visible(self):
        r = self.submit(["/usr/bin/echo", ""])
        _, _, text = self.page(r.id)
        self.assertIn("(empty)", text)

    def test_index_lists_only_pending(self):
        self.assertIn("Nothing is waiting", self.req("GET", "/")[2].decode())
        r = self.submit()
        self.assertIn(r.id, self.req("GET", "/")[2].decode())
        self.d.deny(r.id, "x")
        self.assertIn("Nothing is waiting", self.req("GET", "/")[2].decode())

    def test_unknown_and_malformed_paths(self):
        for path in ("/r/0123456789abcdef", "/r/../etc/passwd", "/nope", "/r/XYZ", "/r/0123456789abcdef/x"):
            self.assertEqual(self.req("GET", path)[0], 404, path)
        self.assertEqual(self.req("POST", "/r/0123456789abcdef/approve")[0], 404)
        self.assertEqual(self.req("PUT", "/")[0], 405)

    # -- deciding ---------------------------------------------------------

    def test_approve_runs_the_command_once(self):
        r = self.submit()
        n = self.nonce(self.page(r.id)[2])
        status, headers, _ = self.post(r.id, "approve", n)
        self.assertEqual((status, dict(headers)["Location"]), (303, f"/r/{r.id}"))
        self.assertEqual(r.state, State.APPROVED)
        self.assertEqual(r.approver, f"web:{LOGIN}")
        self.d.process(r.id)  # no worker thread in unit tests
        self.assertEqual(self.calls, [tuple(ASK)])
        _, _, text = self.page(r.id)
        self.assertIn("exit code 0", text)
        self.assertNotIn("secret-output", text)  # output is never shown to the approver page
        self.assertEqual(self.post(r.id, "approve", n)[0], 409)  # no second run
        self.d.process(r.id)
        self.assertEqual(len(self.calls), 1)

    def test_wrong_missing_and_stale_nonces_do_not_approve(self):
        r = self.submit()
        first = self.nonce(self.page(r.id)[2])
        self.assertEqual(self.post(r.id, "approve", "wrong")[0], 409)
        self.assertEqual(self.post(r.id, "approve")[0], 409)
        second = self.nonce(self.page(r.id)[2])  # a reload invalidates the older page
        self.assertEqual(self.post(r.id, "approve", first)[0], 409)
        self.assertEqual(r.state, State.PENDING)
        self.assertEqual(self.post(r.id, "approve", second)[0], 303)

    def test_approve_without_ever_loading_the_page_fails(self):
        r = self.submit()
        self.assertEqual(self.post(r.id, "approve", "guess")[0], 409)
        self.assertEqual(r.state, State.PENDING)

    def test_deny_needs_no_nonce(self):
        r = self.submit()
        self.assertEqual(self.post(r.id, "deny")[0], 303)
        self.assertEqual((r.state, r.approver), (State.DENIED, f"web:{LOGIN}"))

    def test_deny_can_revoke_an_approval_before_it_runs(self):
        r = self.submit()
        self.post(r.id, "approve", self.nonce(self.page(r.id)[2]))
        self.assertEqual(self.post(r.id, "deny")[0], 303)
        self.d.process(r.id)
        self.assertEqual(self.calls, [])

    def test_cancelled_request_page_and_actions(self):
        r = self.submit()
        n = self.nonce(self.page(r.id)[2])
        self.d.broker.cancel(r.id, ME)
        status, _, text = self.page(r.id)
        self.assertEqual(status, 200)
        self.assertIn("Withdrawn by the agent (cancelled); nothing will run", text)
        self.assertNotIn("Approve and run", text)
        for action in ("approve", "deny"):
            status, _, body = self.post(r.id, action, n)
            self.assertEqual(status, 409, action)
            self.assertIn(b"withdrew this request", body)
        self.assertEqual(self.calls, [])

    def test_expired_request_cannot_be_approved(self):
        r = self.submit()
        n = self.nonce(self.page(r.id)[2])
        self.clock.t += 601
        self.assertEqual(self.post(r.id, "approve", n)[0], 410)
        self.assertEqual(self.calls, [])

    def test_decisions_are_audited_with_the_web_identity(self):
        r = self.submit()
        self.post(r.id, "approve", self.nonce(self.page(r.id)[2]))
        self.assertIn(f'"approver":"web:{LOGIN}"', "".join(self.log))


class WebSocket(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="tp", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cfg_paths = dict(socket_path=f"{self.dir}/a.sock", admin_socket_path=f"{self.dir}/b.sock",
                              web_socket_path=f"{self.dir}/w.sock")
        self.d, self.log, self.calls = build(time.time, **self.cfg_paths)
        self.d.start()
        self.addCleanup(self.d.stop)

    def http(self, raw: bytes):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(3)
        s.connect(self.cfg_paths["web_socket_path"])
        s.sendall(raw)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        headers = {k.lower(): v for k, v in (ln.split(": ", 1) for ln in lines[1:])}
        return int(lines[0].split()[1]), headers, body

    def get(self, path, login=LOGIN, peer=PHONE):
        hdr = (f"Tailscale-User-Login: {login}\r\n" if login else "") + f"X-Forwarded-For: {peer}\r\n"
        return self.http(f"GET {path} HTTP/1.0\r\n{hdr}\r\n".encode())

    def post(self, path, form, login=LOGIN):
        body = urllib.parse.urlencode(form).encode()
        head = (f"POST {path} HTTP/1.0\r\nTailscale-User-Login: {login}\r\nX-Forwarded-For: {PHONE}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n")
        return self.http(head.encode() + body)

    def test_socket_is_root_only(self):
        self.assertEqual(os.stat(self.cfg_paths["web_socket_path"]).st_mode & 0o777, 0o600)

    def test_no_web_socket_unless_approver_logins_configured(self):
        d = tempfile.mkdtemp(prefix="tp", dir="/tmp")
        self.addCleanup(shutil.rmtree, d, True)
        daemon, _, _ = build(time.time, logins=(), socket_path=f"{d}/a.sock",
                             admin_socket_path=f"{d}/b.sock", web_socket_path=f"{d}/w.sock")
        self.assertIsNone(daemon.web)
        daemon.start()
        self.addCleanup(daemon.stop)
        self.assertFalse(os.path.exists(f"{d}/w.sock"))

    def test_http_basics_over_the_socket(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Nothing is waiting", body)
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        self.assertEqual(self.get("/", login="")[0], 403)
        self.assertEqual(self.get("/", peer=SELF)[0], 403)  # right login, wrong device
        self.assertEqual(self.http(b"GET / HTTP/1.0\r\n\r\n")[0], 403)  # no identity header
        self.assertEqual(self.http(b"PUT / HTTP/1.0\r\nTailscale-User-Login: me@example.com\r\n\r\n")[0], 501)
        self.assertEqual(self.http(b"POST / HTTP/1.0\r\nTailscale-User-Login: me@example.com\r\n"
                                   b"Content-Length: 99999\r\n\r\n")[0], 413)

    def test_whole_flow_agent_asks_phone_approves(self):
        out, err = io.BytesIO(), io.StringIO()
        result = []
        t = threading.Thread(target=lambda: result.append(
            client.run(ASK, sock=self.cfg_paths["socket_path"], poll=0.02, out=out, err=err)))
        t.start()
        rid = None
        for _ in range(150):
            pending = self.d.broker.pending()
            if pending:
                rid = pending[0].id
                break
            time.sleep(0.02)
        self.assertIsNotNone(rid)
        self.assertEqual(self.calls, [])  # nothing before approval

        status, _, body = self.get(f"/r/{rid}")
        self.assertEqual(status, 200)
        nonce = re.search(rb'name="nonce" value="([^"]+)"', body).group(1).decode()
        status, headers, _ = self.post(f"/r/{rid}/approve", {"nonce": nonce})
        self.assertEqual((status, headers["location"]), (303, f"/r/{rid}"))

        t.join(5)
        self.assertEqual(result, [0])
        self.assertEqual(out.getvalue(), b"secret-output")
        self.assertEqual(self.calls, [tuple(ASK)])


if __name__ == "__main__":
    unittest.main()
