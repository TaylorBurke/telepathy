# telepathy

Approve an AI agent's root commands from your phone.

The agent submits the exact command it wants to run as root. You get a push,
see the literal command on your phone, and approve or deny it. The approval is
single-use, bound to a hash of that exact command, and expires in minutes. No
NOPASSWD sudo, no password handed to the agent, no public inbound port.

Not related to the freedesktop.org Telepathy communications framework.

**Status: v0.1, Linux only.** It needs systemd, Python 3.11 or newer (standard
library only) and, for approving from your phone, Tailscale on the machine and
the phone. Per-command cgroups need cgroup v2 (kernel 5.14 or newer); without
them it falls back to process tracking through `/proc`. macOS is next; see the
roadmap in [DESIGN.md](DESIGN.md#roadmap), which also covers the design and
threat model.

## Using it with an agent

The agent runs `telepathy run -r "<reason>" -- <absolute path> <args...>` and
waits for your decision. A ready-made skill for Claude Code is in
[`agents/claude-code/telepathy/SKILL.md`](agents/claude-code/telepathy/SKILL.md)
(copy the folder into `~/.claude/skills/`). For other agents, the rules in that
file work as plain instructions: absolute paths, one narrow command per request,
no shells or wrappers, and never resubmit a denied command.

## Usage (development, as your own user)

    # config.toml needs allowed_uids = [<your uid>]; see telepathy/config.py
    python3 -m telepathy.daemon --config ./config.toml --insecure-dev

    # the agent asks for a command to be run as root (blocks until decided)
    bin/telepathy run -r "why" -- /usr/bin/pacman -S --needed htop

    # the human approves at a local terminal (shows the exact command first)
    sudo bin/telepathyctl list
    sudo bin/telepathyctl approve <id>

`telepathy` exits with the command's own exit code, or 125 if telepathy itself
refused or failed (denied, expired, cancelled, policy-denied, daemon unreachable).
^C withdraws the request (`telepathy cancel <id>` does the same by hand, for a
request that has not started; the queue is in memory, so a daemon restart
drops it and the client says to resubmit). A ^C in the instant before the
daemon replied to the submit cannot be cancelled; that request waits out its
expiry.
`--insecure-dev` skips the root-ownership checks and runs commands as you, so
it is for development only.

## Phone approval page

Set `approver_logins = ["you@example.com"]` and `approver_ips = ["<your phone's
tailnet IP>"]` in `/etc/telepathy/config.toml` and restart the service to enable
it (both are required; with neither set there is no web socket at all). The page
lives on a root-only unix socket, `/run/telepathy/web.sock`, and is meant to be
published to your tailnet (and nothing else) with `tailscale serve`. Tailscale
adds the logged-in user's `Tailscale-User-Login` header, and the page only
trusts it because no local user, including the agent, can connect to the
socket. Do not expose it any other way.

A matching login is not enough on its own: a local program can also connect to
this machine's own tailnet address and be stamped with the machine's identity,
which may be your account. So the request must also come from your phone's
tailnet IP (taken from the last `X-Forwarded-For` entry, the one the proxy
adds). This machine's own IP must never be in `approver_ips`.

### Setting it up

You need Tailscale on this machine and on your phone (same account), HTTPS
certificates enabled for your tailnet (<https://login.tailscale.com/admin/dns>;
this puts your machine's tailnet name in public certificate logs), and the ntfy
app on your phone. `tailscale status` shows the names and IPs.

    sudo ./install.sh --approver-login you@example.com \
        --approver-ip <your phone's tailnet IP> \
        --public-url https://<this machine>.<tailnet>.ts.net --ntfy

This writes the settings into a marked block in `/etc/telepathy/config.toml`,
creates a private random ntfy topic in `/etc/telepathy/ntfy-url` (mode 0600) and
prints its name once (subscribe to it in the ntfy app), and publishes the page
with `tailscale serve`. Re-run it any time to change the settings; the topic is
kept. Notifications go through ntfy.sh and contain only the short hash and a link
to the page, never the command, but the link does reveal your machine's tailnet
name to ntfy.sh. Tailscale must be on to open the link, not to receive the alert.

### Other push services (webhook)

Instead of ntfy, or as well, telepathy can POST a small JSON document to any
https URL. Put the full URL (it usually holds a token) in a root-only file and
point the config at it:

    sudo install -m 0600 -o root -g root /dev/null /etc/telepathy/webhook-url
    sudoedit /etc/telepathy/webhook-url    # paste the URL; keeps it out of shell history
    # then add to /etc/telepathy/config.toml (public_url must already be set,
    # e.g. by install.sh --public-url):
    #   webhook_url_file = "/etc/telepathy/webhook-url"
    sudo systemctl restart telepathyd

The body has `title` and `message` (read by Gotify), `text` (Slack,
Mattermost, Telegram's `sendMessage` with `chat_id` in the URL), and `event`,
`id`, `short_hash` and `url` for anything of your own. Like the ntfy
notification it never contains the command. Redirects are not followed. The link does reveal your machine's tailnet
name to whoever runs the webhook endpoint.
Services that want another shape (Discord's `content`, Pushover's form
fields) need a small relay in between. Not yet tested against those services.

The page shows the command one argument per line, with anything that is not
printable ASCII spelled out in red, plus the hash and a countdown. Approving
needs a one-time token issued when the page loads, so a stale tab or an old
link cannot approve. There is no JavaScript.

## Install

    PYTHONPATH=. python3 -m unittest discover -s tests   # optional, no root needed
    sudo ./install.sh

Re-running is safe. The installer puts these on the system:

| What | Where |
|------|-------|
| Program files (root-owned) | `/usr/local/lib/telepathy/` |
| Commands (symlinks) | `/usr/local/bin/telepathy`, `/usr/local/bin/telepathyctl` |
| Config and policy (created once, never overwritten) | `/etc/telepathy/config.toml`, `/etc/telepathy/policy.toml` |
| systemd unit (with `Delegate=yes`: telepathyd creates `cmd-*` child cgroups of its own cgroup, one per approved command, removed when empty) | `/etc/systemd/system/telepathyd.service` |
| Push secrets, optional (`install.sh --ntfy` creates `ntfy-url`; you create `webhook-url`; mode 0600; `--purge` removes them) | `/etc/telepathy/ntfy-url`, `/etc/telepathy/webhook-url` |
| Audit log (created by systemd) | `/var/log/telepathy/audit.jsonl` |
| Audit log rotation (weekly, 52 kept, compressed) | `/etc/logrotate.d/telepathy` |
| Sockets (while running) | `/run/telepathy/` |

`config.toml` is created with `allowed_uids` set to the user who ran `sudo`.
The policy starts empty, so every request waits for a human. Nothing is added to
sudoers, PAM or polkit.

### Audit log rotation

logrotate rotates `audit.jsonl` weekly and keeps 52 compressed copies (a year of
the only record of what ran as root). It does not use `copytruncate`, which can
drop records: the daemon reopens its log file when it gets SIGHUP, and the new
file is mode 0600. The rule is `/etc/logrotate.d/telepathy`; `create 0600 root
root` assumes the daemon runs as root (the installed unit does). Edit the rule to
change retention (`sudo ./install.sh` refreshes it, so keep local changes in a
separate file or re-apply them).

- Something must run logrotate. Most distros enable `logrotate.timer` (or
  `/etc/cron.daily/logrotate`); the installer prints a WARNING if logrotate is
  missing or nothing seems to run it, and never enables a timer itself.
- Safety: the rule calls `/usr/local/lib/telepathy/bin/telepathy-logrotate-hook`.
  Its prerotate step skips the rotation unless the unit is active and the daemon
  has written `/run/telepathy/hup-ok` (written last at start, removed first at
  stop, so it is never stale); its postrotate step sends SIGHUP to the main process
  only. Both log to the journal (`journalctl -t telepathy-logrotate`). An older
  daemon that cannot handle SIGHUP (it would be killed by it) is therefore never
  signalled, and its log is simply not rotated until you restart it.
- Upgrading: the installer restarts the daemon first, then installs the rule. With
  `--no-start` the rule is installed but rotation is skipped until you restart.
- The installer checks the rule with `logrotate -d` (a syntax check only: it runs
  no scripts and rotates nothing) and refuses to install a rule logrotate rejects.
- `sudo systemctl reload telepathyd` sends the same SIGHUP but returns before the
  reopen finishes. The result is the `audit_reopened` record in the new file. If
  reopening fails, the daemon keeps writing to the old file, retries (backoff,
  then every minute), logs to stderr, records `audit_reopen_failed` and creates
  `/run/telepathy/audit-reopen-failed` until it succeeds.
- `--purge` removes the log directory, including rotated copies; a plain
  uninstall removes only the rule and keeps the logs.

## Uninstall

    sudo ./uninstall.sh            # stop and disable the service, unpublish the phone page from
                                   # tailscale serve, remove the program files, commands and unit;
                                   # KEEPS /etc/telepathy and /var/log/telepathy
    sudo ./uninstall.sh --purge    # the same, and also delete /etc/telepathy and /var/log/telepathy

If you no longer have this checkout, do it by hand:

    sudo tailscale serve --https=443 off        # only if you set up the phone page
    sudo systemctl disable --now telepathyd.service
    sudo rm /etc/systemd/system/telepathyd.service /etc/logrotate.d/telepathy
    sudo systemctl daemon-reload
    sudo rm /usr/local/bin/telepathy /usr/local/bin/telepathyctl
    sudo rm -rf /usr/local/lib/telepathy
    # optional, removes your config, policy and audit history:
    sudo rm -rf /etc/telepathy /var/log/telepathy

`/run/telepathy` is removed by systemd when the service stops. If you run AIDE
(or similar), expect it to flag changes under `/usr/local/bin`, `/usr/local/lib`,
`/etc/systemd/system` and the new `/etc/logrotate.d/telepathy` on both install and
uninstall. Rotation also makes AIDE see `/var/log/telepathy` change weekly
(exclude it if you watch that tree). The per-command cgroups live under
`/sys/fs/cgroup/system.slice/telepathyd.service/` (a virtual filesystem AIDE does
not scan) and go away with the service.

## Tests

Python 3.11+ standard library only, no dependencies:

    PYTHONPATH=. python3 -m unittest discover -s tests   # daemon, policy, broker, client
    bats tests/                                          # installer and uninstaller (staged, no root)

## Security

See [SECURITY.md](SECURITY.md) for what telepathy defends against and how to
report a vulnerability.

## License

MIT. See [LICENSE](LICENSE).
