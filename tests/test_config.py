import os
import tempfile
import unittest

from telepathy.config import Config, ConfigError, require_secure_file


class Loading(unittest.TestCase):
    def bad(self, text):
        with self.assertRaises(ConfigError):
            Config.from_toml(text)

    def test_minimal_and_defaults(self):
        c = Config.from_toml("allowed_uids = [1000]")
        self.assertEqual(c.allowed_uids, (1000,))
        self.assertEqual((c.ttl, c.max_pending, c.max_per_hour), (600.0, 5, 20))
        self.assertEqual(c.socket_path, "/run/telepathy/telepathy.sock")

    def test_overrides(self):
        c = Config.from_toml('allowed_uids = [1000, 1001]\nttl = 120\nmax_pending = 2\n'
                             'socket_path = "/run/x/a.sock"')
        self.assertEqual((c.allowed_uids, c.ttl, c.max_pending, c.socket_path),
                         ((1000, 1001), 120.0, 2, "/run/x/a.sock"))

    def test_web_settings(self):
        c = Config.from_toml("allowed_uids = [1]")
        self.assertEqual((c.approver_logins, c.approver_ips, c.web_socket_path),
                         ((), (), "/run/telepathy/web.sock"))
        c = Config.from_toml('allowed_uids = [1]\napprover_logins = ["me@example.com"]\n'
                             'approver_ips = ["100.64.0.7", "fd7a:115c:a1e0::1"]\n'
                             'web_socket_path = "/run/x/w.sock"')
        self.assertEqual((c.approver_logins, c.approver_ips, c.web_socket_path),
                         (("me@example.com",), ("100.64.0.7", "fd7a:115c:a1e0::1"), "/run/x/w.sock"))
        c = Config.from_toml("allowed_uids = [1]\napprover_logins = []\napprover_ips = []")
        self.assertEqual((c.approver_logins, c.approver_ips), ((), ()))

    def test_bad_web_settings(self):
        ips = 'approver_ips = ["100.64.0.7"]\n'
        logins = 'approver_logins = ["me@example.com"]\n'
        for bad in ('approver_logins = "me@example.com"\n' + ips, "approver_logins = [1]\n" + ips,
                    'approver_logins = [""]\n' + ips, 'approver_logins = ["a b"]\n' + ips,
                    'approver_logins = ["a\\nb"]\n' + ips, 'web_socket_path = "w.sock"',
                    logins,  # logins without a device
                    ips,  # a device without logins
                    logins + 'approver_ips = ["not-an-ip"]',
                    logins + 'approver_ips = ["100.64.0.0/10"]',  # a range is not an address
                    logins + 'approver_ips = "100.64.0.7"',
                    logins + "approver_ips = [7]"):
            self.bad("allowed_uids = [1]\n" + bad)

    def test_ntfy_settings(self):
        c = Config.from_toml("allowed_uids = [1]")
        self.assertEqual((c.ntfy_url_file, c.public_url), (None, None))
        c = Config.from_toml('allowed_uids = [1]\nntfy_url_file = "/etc/telepathy/ntfy-url"\n'
                             'public_url = "https://box.tail1234.ts.net/"')
        self.assertEqual((c.ntfy_url_file, c.public_url),
                         ("/etc/telepathy/ntfy-url", "https://box.tail1234.ts.net"))

    def test_bad_ntfy_settings(self):
        f = 'ntfy_url_file = "/etc/telepathy/ntfy-url"\n'
        u = 'public_url = "https://box.ts.net"\n'
        self.assertEqual(Config.from_toml("allowed_uids = [1]\n" + u).public_url, "https://box.ts.net")
        for bad in (f,  # a topic file needs a public_url for the notification link
                    f + 'public_url = "http://box.ts.net"', f + 'public_url = "box.ts.net"',
                    f + 'public_url = "https://box ts.net"', f + "public_url = 5",
                    'ntfy_url_file = "relative"\n' + u):
            self.bad("allowed_uids = [1]\n" + bad)

    def test_webhook_settings(self):
        c = Config.from_toml('allowed_uids = [1]\nwebhook_url_file = "/etc/telepathy/webhook-url"\n'
                             'public_url = "https://box.tail1234.ts.net"')
        self.assertEqual(c.webhook_url_file, "/etc/telepathy/webhook-url")
        self.assertIsNone(Config.from_toml("allowed_uids = [1]").webhook_url_file)
        self.bad('allowed_uids = [1]\nwebhook_url_file = "/etc/telepathy/webhook-url"')  # no public_url
        self.bad('allowed_uids = [1]\nwebhook_url_file = "rel"\npublic_url = "https://box.ts.net"')

    def test_allowed_uids_required_and_valid(self):
        self.bad("")
        self.bad("allowed_uids = []")
        self.bad('allowed_uids = ["1000"]')
        self.bad("allowed_uids = [-1]")
        self.bad("allowed_uids = [true]")
        self.bad("allowed_uids = 1000")

    def test_rejects_bad_values_and_unknown_keys(self):
        self.bad("allowed_uids = [1]\nbogus = 1")
        self.bad("allowed_uids = [1]\nttl = 0")
        self.bad('allowed_uids = [1]\nttl = "5"')
        self.bad("allowed_uids = [1]\nmax_pending = 1.5")
        self.bad("allowed_uids = [1]\nmax_output = true")
        self.bad('allowed_uids = [1]\nsocket_path = "relative.sock"')
        self.bad("allowed_uids = [")


class SecureFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        os.chmod(self.dir, 0o755)
        self.path = os.path.join(self.dir, "policy.toml")
        with open(self.path, "w") as f:
            f.write("x = 1\n")
        os.chmod(self.path, 0o644)
        self.me = os.getuid()

    def test_ok(self):
        require_secure_file(self.path, expected_uid=self.me)

    def test_wrong_owner(self):
        with self.assertRaises(ConfigError):
            require_secure_file(self.path, expected_uid=self.me + 1)

    def test_group_or_world_writable_file(self):
        for mode in (0o664, 0o646, 0o666):
            os.chmod(self.path, mode)
            with self.assertRaises(ConfigError):
                require_secure_file(self.path, expected_uid=self.me)

    def test_writable_directory(self):
        os.chmod(self.dir, 0o775)
        with self.assertRaises(ConfigError):
            require_secure_file(self.path, expected_uid=self.me)

    def test_secret_files_must_not_be_readable_by_others(self):
        require_secure_file(self.path, expected_uid=self.me)  # 0644 is fine for a normal file
        with self.assertRaises(ConfigError):
            require_secure_file(self.path, expected_uid=self.me, secret=True)
        for mode in (0o640, 0o604, 0o644):
            os.chmod(self.path, mode)
            with self.assertRaises(ConfigError):
                require_secure_file(self.path, expected_uid=self.me, secret=True)
        os.chmod(self.path, 0o600)
        require_secure_file(self.path, expected_uid=self.me, secret=True)

    def test_missing_and_not_a_file(self):
        with self.assertRaises(ConfigError):
            require_secure_file(os.path.join(self.dir, "nope"), expected_uid=self.me)
        with self.assertRaises(ConfigError):
            require_secure_file(self.dir, expected_uid=self.me)


if __name__ == "__main__":
    unittest.main()
