"""Push notifications via ntfy or a generic JSON webhook.

A notification carries only the request's short hash and a link to the approval
page. It never contains the command, so nothing sensitive reaches the ntfy
server. The topic or webhook URL is a bearer secret (anyone who has it can read or send
notifications on that topic), so it lives in a root-only file, not config.toml.
Notifications are a convenience only: approving still requires the approval page,
which only accepts the approver's own device.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from .config import ConfigError

TITLE = "telepathy: approval needed"
USER_AGENT = "telepathy-notify/1"  # urllib's default is refused by some WAFs


def check_https_url(url: str, what: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.fragment or not url.isascii() or any(c.isspace() for c in url)):
        raise ConfigError(f"{what} must be a plain https:// URL")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the topic URL is a secret and must go nowhere else."""

    def redirect_request(self, *args, **kwargs):
        return None


class NtfyNotifier:
    kind = "ntfy"

    def __init__(self, url: str, public_url: str, timeout: float = 5.0, opener=None):
        self.url = check_https_url(url, "the ntfy URL")
        self.public_url = check_https_url(public_url, "public_url").rstrip("/")
        self.timeout = timeout
        self._open = opener or urllib.request.build_opener(_NoRedirect).open

    def __call__(self, info: dict) -> None:
        """info is {"id", "short_hash"}: deliberately nothing about the command."""
        body = (f"Request {info['short_hash']} is waiting for approval. "
                "Tap to review the exact command.").encode("ascii")
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Title": TITLE,
                "Priority": "high",
                "Tags": "lock",
                "Click": f"{self.public_url}/r/{info['id']}",
                "User-Agent": USER_AGENT,
            },
        )
        with self._open(req, timeout=self.timeout) as resp:
            resp.read(1024)


class WebhookNotifier:
    """POST a small JSON document to any https endpoint.

    The body carries the fields most push services read, so one shape works
    for several of them without a per-service adapter: `title` and `message`
    (Gotify, with `priority`), `text` (Slack, Mattermost, Telegram's sendMessage with chat_id in
    the URL), plus `url`, `id` and `short_hash` for anything of your own.
    Services that need another shape (Discord's `content`, Pushover's form
    fields) need a small relay. Never the command. The per-service claims
    above are from their docs, not yet tested against the real services.
    """

    kind = "webhook"

    def __init__(self, url: str, public_url: str, timeout: float = 5.0, opener=None):
        self.url = check_https_url(url, "the webhook URL")
        self.public_url = check_https_url(public_url, "public_url").rstrip("/")
        self.timeout = timeout
        self._open = opener or urllib.request.build_opener(_NoRedirect).open

    def payload(self, info: dict) -> dict:
        link = f"{self.public_url}/r/{info['id']}"
        message = f"Request {info['short_hash']} is waiting for approval. Review it: {link}"
        return {
            "event": "approval_needed",
            "id": info["id"],
            "short_hash": info["short_hash"],
            "url": link,
            "title": TITLE,
            "message": message,
            "text": f"{TITLE}. {message}",
            # Gotify defaults to 0, which its Android app shows silently; 8 and
            # up alert like ntfy's Priority: high. Other services ignore it.
            "priority": 8,
        }

    def __call__(self, info: dict) -> None:
        req = urllib.request.Request(
            self.url,
            data=json.dumps(self.payload(info), ensure_ascii=True).encode("ascii"),
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        )
        with self._open(req, timeout=self.timeout) as resp:
            resp.read(1024)
