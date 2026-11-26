"""Daemon configuration: /etc/telepathy/config.toml."""

from __future__ import annotations

import ipaddress
import os
import stat
import tomllib
from dataclasses import dataclass, fields


class ConfigError(ValueError):
    """The configuration (or a file it points at) is unusable or untrusted."""


@dataclass(frozen=True)
class Config:
    socket_path: str = "/run/telepathy/telepathy.sock"
    admin_socket_path: str = "/run/telepathy/admin.sock"
    # Root-only socket for the approval page; `tailscale serve` proxies to it.
    web_socket_path: str = "/run/telepathy/web.sock"
    policy_path: str = "/etc/telepathy/policy.toml"
    audit_path: str = "/var/log/telepathy/audit.jsonl"
    # Only these local uids may submit requests. Empty means nobody (safe default).
    allowed_uids: tuple[int, ...] = ()
    # Tailscale logins allowed to approve from the web page. Empty disables the
    # page entirely (no web socket is created).
    approver_logins: tuple[str, ...] = ()
    # Tailnet IPs of the approver's device(s) (the phone). Required together with
    # approver_logins: a matching login from any other device, including this
    # machine itself, is refused.
    approver_ips: tuple[str, ...] = ()
    # Push notifications (ntfy). ntfy_url_file holds the full topic URL, which is
    # a secret, so it is a separate root-only file; public_url is the https
    # address of the approval page on your tailnet (the notification's link).
    ntfy_url_file: str | None = None
    # Generic webhook (Gotify, Slack, Mattermost, a relay of your own...): the
    # file holds the full https URL, which usually embeds a token, so it is a
    # root-only secret file like the ntfy one. Uses the same public_url.
    webhook_url_file: str | None = None
    public_url: str | None = None
    ttl: float = 600.0
    max_pending: int = 5
    max_per_hour: int = 20
    exec_timeout: float = 300.0
    max_output: int = 262144

    @classmethod
    def from_toml(cls, text: str) -> "Config":
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"invalid TOML: {e}") from e
        unknown = set(doc) - {f.name for f in fields(cls)}
        if unknown:
            raise ConfigError(f"unknown keys: {sorted(unknown)}")

        kw: dict = {}
        for name in ("socket_path", "admin_socket_path", "web_socket_path", "policy_path",
                     "audit_path", "ntfy_url_file", "webhook_url_file"):
            if name in doc:
                v = doc[name]
                if not isinstance(v, str) or not v.startswith("/") or "\0" in v:
                    raise ConfigError(f"{name} must be an absolute path")
                kw[name] = v

        if "allowed_uids" not in doc:
            raise ConfigError("allowed_uids is required (list the uids that may ask for root)")
        uids = doc["allowed_uids"]
        if (not isinstance(uids, list) or not uids
                or not all(isinstance(u, int) and not isinstance(u, bool) and u >= 0 for u in uids)):
            raise ConfigError("allowed_uids must be a non-empty list of non-negative integers")
        kw["allowed_uids"] = tuple(uids)

        if "approver_logins" in doc:
            logins = doc["approver_logins"]
            if (not isinstance(logins, list)
                    or not all(isinstance(x, str) and x and x.isprintable() and not any(c.isspace() for c in x)
                               for x in logins)):
                raise ConfigError("approver_logins must be a list of non-empty strings without whitespace")
            kw["approver_logins"] = tuple(logins)

        if "approver_ips" in doc:
            ips = doc["approver_ips"]
            if not isinstance(ips, list) or not all(isinstance(x, str) for x in ips):
                raise ConfigError("approver_ips must be a list of IP address strings")
            for x in ips:
                try:
                    ipaddress.ip_address(x)
                except ValueError as e:
                    raise ConfigError(f"approver_ips: {x!r} is not an IP address") from e
            kw["approver_ips"] = tuple(ips)
        if bool(kw.get("approver_logins")) != bool(kw.get("approver_ips")):
            raise ConfigError("approver_logins and approver_ips must be set together")

        if "public_url" in doc:
            u = doc["public_url"]
            if (not isinstance(u, str) or not u.startswith("https://") or not u.isascii()
                    or any(c.isspace() for c in u)):
                raise ConfigError("public_url must be an https:// URL")
            kw["public_url"] = u.rstrip("/")
        for name in ("ntfy_url_file", "webhook_url_file"):
            if name in kw and "public_url" not in kw:
                raise ConfigError(f"{name} needs public_url (the link in the notification)")

        for name in ("ttl", "exec_timeout"):
            if name in doc:
                v = doc[name]
                if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                    raise ConfigError(f"{name} must be a positive number")
                kw[name] = float(v)
        for name in ("max_pending", "max_per_hour", "max_output"):
            if name in doc:
                v = doc[name]
                if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                    raise ConfigError(f"{name} must be a positive integer")
                kw[name] = v
        return cls(**kw)


def require_secure_file(path: str, expected_uid: int = 0, secret: bool = False) -> None:
    """Refuse to trust a config/policy file the agent could have edited.

    The file must be a regular file owned by `expected_uid`, not writable by
    group or others, in a directory with the same properties.
    """
    try:
        st = os.stat(path)
        parent = os.stat(os.path.dirname(os.path.abspath(path)))
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror or e}") from e
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{path} is not a regular file")
    for what, s in ((path, st), (os.path.dirname(os.path.abspath(path)), parent)):
        if s.st_uid != expected_uid:
            raise ConfigError(f"{what} must be owned by uid {expected_uid}")
        if s.st_mode & 0o022:
            raise ConfigError(f"{what} must not be writable by group or others")
    if secret and st.st_mode & 0o077:
        raise ConfigError(f"{path} holds a secret and must not be accessible by group or others "
                          "(chmod 600)")
