import email.message
import io
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import urllib.response
from unittest import mock

from telepathy.audit import AuditLog
from telepathy.broker import Broker, Limits
from telepathy.config import Config, ConfigError
from telepathy.daemon import Daemon, load_notifiers
from telepathy.executor import ExecResult
from telepathy.notify import NtfyNotifier, WebhookNotifier, _NoRedirect, check_https_url
from telepathy.policy import Policy

ME = os.getuid()
TOPIC = "https://ntfy.example/telepathy-secret-topic"
HOOK = "https://hooks.example/send?token=hook-secret-token"
PUBLIC = "https://box.tail1234.ts.net"
MARKER = "/usr/bin/unique-marker-xyz"
POLICY = """
[patterns]
word = '[a-z0-9]+'
[[auto]]
name = "echo"
argv = ["/usr/bin/echo", "@word..."]
"""


class FakeResponse:
    def read(self, n=-1):
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Notifier(unittest.TestCase):
    def make(self, **kw):
        self.sent = []

        def opener(req, timeout):
            self.sent.append((req, timeout))
            return FakeResponse()

        return NtfyNotifier(TOPIC, PUBLIC + "/", opener=opener, **kw)

    def test_posts_to_topic_with_link_and_no_command(self):
        n = self.make()
        n({"id": "7ccecfff4086bd1a", "short_hash": "e25d5eb1"})
        (req, timeout), = self.sent
        self.assertEqual((req.full_url, req.get_method(), timeout), (TOPIC, "POST", 5.0))
        self.assertEqual(req.get_header("Click"), f"{PUBLIC}/r/7ccecfff4086bd1a")
        self.assertEqual(req.get_header("Priority"), "high")
        self.assertIn(b"e25d5eb1", req.data)
        for h in ("Title", "Priority", "Tags", "Click"):
            req.get_header(h).encode("ascii")  # header values must be plain ASCII

    def test_errors_propagate_to_the_caller(self):
        def opener(req, timeout):
            raise urllib.error.URLError("down")

        with self.assertRaises(urllib.error.URLError):
            NtfyNotifier(TOPIC, PUBLIC, opener=opener)({"id": "a" * 16, "short_hash": "abcd1234"})

    def test_redirects_are_never_followed(self):
        r = urllib.request.Request(TOPIC, method="POST", data=b"x")
        self.assertIsNone(_NoRedirect().redirect_request(r, None, 302, "Found", {}, "https://evil.example/"))

    def test_url_validation(self):
        for bad in ("http://ntfy.example/t", "ftp://x/y", "https://", "https://user:pw@ntfy.example/t",
                    "https://ntfy.example/t#frag", "https://ntfy.example/a b", "https://ntfy.example/é",
                    "ntfy.example/t", ""):
            with self.assertRaises(ConfigError, msg=bad):
                check_https_url(bad, "x")
        with self.assertRaises(ConfigError):
            NtfyNotifier(TOPIC, "http://box.ts.net")
        self.assertEqual(check_https_url("https://ntfy.example/t", "x"), "https://ntfy.example/t")


class Webhook(unittest.TestCase):
    def make(self, opener=None):
        self.sent = []

        def record(req, timeout):
            self.sent.append((req, timeout))
            return FakeResponse()

        return WebhookNotifier(HOOK, PUBLIC + "/", opener=opener or record)

    def test_posts_json_with_link_and_no_command(self):
        self.make()({"id": "7ccecfff4086bd1a", "short_hash": "e25d5eb1"})
        (req, timeout), = self.sent
        self.assertEqual((req.full_url, req.get_method(), timeout), (HOOK, "POST", 5.0))
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(req.get_header("User-agent"), "telepathy-notify/1")
        body = json.loads(req.data)
        link = f"{PUBLIC}/r/7ccecfff4086bd1a"
        self.assertEqual(set(body), {"event", "id", "short_hash", "url", "title", "message", "text", "priority"})
        self.assertEqual(body["priority"], 8)
        self.assertEqual((body["event"], body["id"], body["short_hash"], body["url"]),
                         ("approval_needed", "7ccecfff4086bd1a", "e25d5eb1", link))
        for k in ("message", "text"):
            self.assertIn("e25d5eb1", body[k])
            self.assertIn(link, body[k])
        req.data.decode("ascii")

    def test_body_holds_only_what_it_was_given(self):
        # The daemon passes only id and short_hash; anything else is ignored.
        self.make()({"id": "a" * 16, "short_hash": "abcd1234", "argv": [MARKER]})
        self.assertNotIn(b"unique-marker", self.sent[0][0].data)

    def test_errors_propagate_and_urls_are_checked(self):
        def opener(req, timeout):
            raise urllib.error.URLError("down")

        with self.assertRaises(urllib.error.URLError):
            self.make(opener)({"id": "a" * 16, "short_hash": "abcd1234"})
        for bad in ("http://hooks.example/x", "https://u:p@hooks.example/x"):
            with self.assertRaises(ConfigError):
                WebhookNotifier(bad, PUBLIC)
        with self.assertRaises(ConfigError):
            WebhookNotifier(HOOK, "http://box.ts.net")

    def test_redirects_are_not_followed_by_default(self):
        # Drive the notifier's real opener with a fake https transport that
        # answers every request with a redirect: it must raise, not re-POST.
        calls = []

        class Redirecting(urllib.request.BaseHandler):
            handler_order = 100  # ahead of the real HTTPSHandler

            def https_open(self, req):
                calls.append(req.full_url)
                hdrs = email.message.Message()
                hdrs["Location"] = "https://evil.example/steal"
                resp = urllib.response.addinfourl(io.BytesIO(b""), hdrs, req.full_url, 302)
                resp.msg = "Found"
                return resp

        for kind in (WebhookNotifier, NtfyNotifier):
            calls.clear()
            n = kind(HOOK, PUBLIC)
            n._open.__self__.add_handler(Redirecting())
            with self.assertRaises(urllib.error.HTTPError) as cm:
                n({"id": "a" * 16, "short_hash": "abcd1234"})
            self.assertEqual((cm.exception.code, calls), (302, [HOOK]), kind.__name__)


class Loading(unittest.TestCase):
    def write(self, d, name, text):
        path = os.path.join(d, name)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, 0o600)
        return path

    def test_loads_each_configured_notifier(self):
        with tempfile.TemporaryDirectory() as d:
            nt = self.write(d, "ntfy-url", TOPIC + "\n")
            wh = self.write(d, "webhook-url", HOOK + "\n")
            base = dict(allowed_uids=(ME,), public_url=PUBLIC)
            self.assertEqual(load_notifiers(Config(**base), secure=False), [])
            both = load_notifiers(Config(ntfy_url_file=nt, webhook_url_file=wh, **base), secure=False)
            self.assertEqual([(type(n), n.url) for n in both],
                             [(NtfyNotifier, TOPIC), (WebhookNotifier, HOOK)])
            only = load_notifiers(Config(webhook_url_file=wh, **base), secure=False)
            self.assertEqual([type(n) for n in only], [WebhookNotifier])

    def test_secure_mode_checks_every_file_as_a_secret(self):
        with tempfile.TemporaryDirectory() as d:
            nt = self.write(d, "ntfy-url", TOPIC)
            wh = self.write(d, "webhook-url", HOOK)
            cfg = Config(allowed_uids=(ME,), public_url=PUBLIC, ntfy_url_file=nt, webhook_url_file=wh)
            seen = []
            with mock.patch("telepathy.daemon.require_secure_file",
                            lambda path, **kw: seen.append((path, kw))):
                load_notifiers(cfg)
            self.assertEqual(seen, [(nt, {"secret": True}), (wh, {"secret": True})])
            with mock.patch("telepathy.daemon.require_secure_file", side_effect=ConfigError("no")):
                with self.assertRaises(ConfigError):
                    load_notifiers(cfg)
            seen.clear()
            with mock.patch("telepathy.daemon.require_secure_file",
                            lambda path, **kw: seen.append(path)):
                load_notifiers(cfg, secure=False)
            self.assertEqual(seen, [])


class DaemonHook(unittest.TestCase):
    def setUp(self):
        self.log = []
        broker = Broker(Policy.from_toml(POLICY), Limits(ttl=600), AuditLog(self.log.append))
        cfg = Config(allowed_uids=(ME,))
        stub = lambda *a: ExecResult(0, b"")  # noqa: E731
        self.d = Daemon(cfg, broker, stub, admin_uids=(ME,), poll_interval=0.005)

    def submit(self, argv):
        return self.d.handle_agent({"op": "submit", "argv": argv, "cwd": "/tmp"}, ME)

    def events(self):
        return [json.loads(x)["event"] for x in self.log]

    def wait_for(self, event, timeout=3.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if event in self.events():
                return
            time.sleep(0.01)
        self.fail(f"never saw {event}: {self.events()}")

    def test_notifier_gets_only_id_and_hash_for_pending_requests(self):
        got = []
        self.d.on_pending.append(got.append)
        r = self.submit([MARKER, "--flag"])["request"]
        self.wait_for("notified")
        self.assertEqual(got, [{"id": r["id"], "short_hash": r["short_hash"]}])
        self.assertNotIn("unique-marker", json.dumps(got))

    def test_auto_approved_and_refused_requests_do_not_notify(self):
        got = []
        self.d.on_pending.append(got.append)
        self.assertTrue(self.submit(["/usr/bin/echo", "hi"])["ok"])  # auto rule
        self.assertFalse(self.submit(["/bin/sh", "-c", "id"])["ok"])  # policy deny
        self.assertFalse(self.submit("not a list")["ok"])  # invalid
        time.sleep(0.2)
        self.assertEqual(got, [])
        self.assertNotIn("notified", self.events())

    def test_failure_is_audited_without_leaking_the_url(self):
        def boom(info):
            raise urllib.error.URLError(f"cannot reach {TOPIC}")

        self.d.on_pending.append(boom)
        self.assertTrue(self.submit([MARKER])["ok"])
        self.wait_for("notify_failed")
        rec = [json.loads(x) for x in self.log if '"notify_failed"' in x][0]
        self.assertEqual(rec["error"], "URLError")
        self.assertNotIn("telepathy-secret-topic", "".join(self.log))

    def test_slow_notifier_does_not_delay_the_request(self):
        release = threading.Event()
        self.d.on_pending.append(lambda info: release.wait(5))
        t = time.monotonic()
        self.assertTrue(self.submit([MARKER])["ok"])
        self.assertLess(time.monotonic() - t, 0.5)
        release.set()

    def test_audit_names_which_notifier_without_its_url(self):
        def fake(kind, fail):
            def fn(info):
                if fail:
                    raise urllib.error.URLError(HOOK)
            fn.kind = kind
            return fn

        self.d.on_pending.extend([fake("ntfy", False), fake("webhook", True)])
        self.submit([MARKER])
        self.wait_for("notify_failed")
        self.wait_for("notified")
        recs = {json.loads(x)["event"]: json.loads(x) for x in self.log if '"notif' in x}
        self.assertEqual((recs["notified"]["via"], recs["notify_failed"]["via"]), ("ntfy", "webhook"))
        self.assertNotIn("hook-secret-token", "".join(self.log))

    def test_a_failing_notifier_does_not_stop_the_others(self):
        got = []

        def boom(info):
            raise RuntimeError("x")

        self.d.on_pending.extend([boom, got.append])
        self.submit([MARKER])
        self.wait_for("notify_failed")
        self.wait_for("notified")
        self.assertEqual(len(got), 1)


if __name__ == "__main__":
    unittest.main()
