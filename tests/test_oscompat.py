import contextlib
import os
import socket
import sys
import time
import unittest
from unittest import mock

from telepathy import daemon, oscompat


@contextlib.contextmanager
def hidden(mod, name):
    """Remove mod.name for the block, as on a platform without it; works whether
    or not this host has it (mock's create=True + delattr fails on exit if not)."""
    missing = object()
    saved = getattr(mod, name, missing)
    if saved is not missing:
        delattr(mod, name)
    try:
        yield
    finally:
        if saved is not missing:
            setattr(mod, name, saved)


class Support(unittest.TestCase):
    def test_this_linux_host_is_supported(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux only")
        self.assertEqual(oscompat.missing_features(), [])
        oscompat.check_supported()

    def test_other_platforms_are_refused(self):
        for plat in ("darwin", "win32", "freebsd14", "cygwin"):
            with self.assertRaises(oscompat.UnsupportedPlatform, msg=plat) as cm:
                oscompat.check_supported(plat)
            self.assertIn(repr(plat), str(cm.exception))

    def test_each_missing_feature_is_refused_and_named(self):
        for mod, name in ((time, "CLOCK_BOOTTIME"), (socket, "SO_PEERCRED"), (os, "getxattr")):
            with hidden(mod, name):
                with self.assertRaises(oscompat.UnsupportedPlatform) as cm:
                    oscompat.check_supported("linux")
                self.assertIn(name, str(cm.exception))

    def test_daemon_refuses_to_start_before_reading_anything(self):
        with mock.patch.object(oscompat.sys, "platform", "darwin"), \
                mock.patch("telepathy.daemon.open", create=True, side_effect=AssertionError("read config")), \
                mock.patch("sys.stderr") as err:
            self.assertEqual(daemon.main(["--config", "/nonexistent", "--insecure-dev"]), 2)
        self.assertIn("cannot run safely", "".join(c.args[0] for c in err.write.call_args_list))


class PeerUid(unittest.TestCase):
    def test_large_uids_decode_unsigned(self):
        raw = oscompat._PEERCRED.pack(1234, 0xFFFFFFFE, 0xFFFFFFFD)
        self.assertEqual(oscompat._PEERCRED.unpack(raw), (1234, 4294967294, 4294967293))
        sock = mock.Mock()
        sock.getsockopt.return_value = raw
        self.assertEqual(oscompat.peer_uid(sock), 4294967294)

    def test_reports_our_own_uid_over_a_socketpair(self):
        if not hasattr(socket, "SO_PEERCRED"):
            self.skipTest("no SO_PEERCRED")
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b:
            self.assertEqual(oscompat.peer_uid(a), os.getuid())


if __name__ == "__main__":
    unittest.main()
