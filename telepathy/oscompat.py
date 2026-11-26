"""The operating-system-specific pieces the daemon's guarantees depend on.

Only Linux is supported. `check_supported` runs before the daemon serves
anything, so on a platform that has not been ported the daemon refuses to start
instead of running with a weaker fallback: a sleep-pausing clock (requests that
outlive their TTL), no ACL reader (every executable refused), or no peer
credentials (no caller identity at all).

The library modules keep their portable fallbacks so the unit tests can run
elsewhere; only a running daemon is gated. A port (macOS is next) adds its own
branch here and at the other platform-specific call sites, each with a test:
the clock in broker.py (`select_boottime`), the ACL check in policy.py
(`_acl_untrusted`), process tracking in executor.py and cgroup.py, and the
service files in systemd/ and install.sh.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import time

SUPPORTED = ("linux",)

# struct ucred from SO_PEERCRED: pid_t (signed), uid_t and gid_t (unsigned 32-bit).
_PEERCRED = struct.Struct("iII")


class UnsupportedPlatform(RuntimeError):
    """telepathyd has not been ported to this platform (or it lacks a feature)."""


def missing_features(platform: str | None = None) -> list[str]:
    """What this platform lacks that the daemon's guarantees need. Empty = supported."""
    platform = sys.platform if platform is None else platform
    if not platform.startswith(SUPPORTED):
        return [f"platform {platform!r} (supported: {', '.join(SUPPORTED)})"]
    missing = []
    if not hasattr(time, "CLOCK_BOOTTIME"):
        missing.append("time.CLOCK_BOOTTIME (expiry must keep counting during suspend)")
    if not hasattr(socket, "SO_PEERCRED"):
        missing.append("socket.SO_PEERCRED (caller identity on the unix sockets)")
    if not hasattr(os, "getxattr"):
        missing.append("os.getxattr (the POSIX ACL check on executables)")
    return missing


def check_supported(platform: str | None = None) -> None:
    missing = missing_features(platform)
    if missing:
        raise UnsupportedPlatform("telepathyd cannot run safely here; missing: " + "; ".join(missing))


def peer_uid(sock: socket.socket) -> int:
    """The uid of the process on the other end of a unix socket, from the kernel."""
    _pid, uid, _gid = _PEERCRED.unpack(
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size))
    return uid
