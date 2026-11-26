#!/usr/bin/env bash
# Install telepathy. Re-running is safe: program files are refreshed, while
# /etc/telepathy/config.toml and policy.toml are never overwritten.
#
#   sudo ./install.sh [--uid N] [--no-start]
#
# Environment: DESTDIR=/some/dir stages everything under that directory without
# root, ownership changes, or systemctl (used by the tests).
set -euo pipefail

die() { echo "install.sh: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [--uid N] [--no-start]
                         [--approver-login LOGIN --approver-ip IP --public-url URL [--ntfy]]

  --uid N                the local uid allowed to ask for root (default: the user who ran sudo)
  --no-start             install and enable the service but do not (re)start it now

Phone approval (all three of these together; re-run any time to change them):
  --approver-login LOGIN your Tailscale login, e.g. you@example.com
  --approver-ip IP       your phone's tailnet IP (see `tailscale status`)
  --public-url URL       this machine's tailnet address, e.g. https://box.tailXXXX.ts.net
  --ntfy                 also create a private ntfy topic (/etc/telepathy/ntfy-url, mode 0600)
                         and print its name so you can subscribe to it in the ntfy app

These write a marked block into /etc/telepathy/config.toml and publish the
approval page to your tailnet with `tailscale serve` (HTTPS certificates must be
enabled for your tailnet).

Installs to /usr/local/lib/telepathy, /usr/local/bin, /etc/telepathy and
/etc/systemd/system/telepathyd.service and /etc/logrotate.d/telepathy. See README.md for the full list and
for how to uninstall.
EOF
}

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESTDIR="${DESTDIR:-}"
ALLOWED_UID="${SUDO_UID:-}"
NO_START=0
APPROVER_LOGIN=""
APPROVER_IP=""
PUBLIC_URL=""
WANT_NTFY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --uid) [ $# -ge 2 ] || die "--uid needs a value"; ALLOWED_UID="$2"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --approver-login) [ $# -ge 2 ] || die "--approver-login needs a value"; APPROVER_LOGIN="$2"; shift 2 ;;
    --approver-ip) [ $# -ge 2 ] || die "--approver-ip needs a value"; APPROVER_IP="$2"; shift 2 ;;
    --public-url) [ $# -ge 2 ] || die "--public-url needs a value"; PUBLIC_URL="$2"; shift 2 ;;
    --ntfy) WANT_NTFY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
  die "must run as root: sudo ./install.sh"
fi
[[ "$ALLOWED_UID" =~ ^[0-9]+$ ]] || die "cannot tell which user may ask for root; pass --uid N (yours is $(id -u))"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "Python 3.11 or newer is required (tomllib)"

PHONE_SETUP=0
if [ -n "$APPROVER_LOGIN$APPROVER_IP$PUBLIC_URL" ]; then
  if [ -z "$APPROVER_LOGIN" ] || [ -z "$APPROVER_IP" ] || [ -z "$PUBLIC_URL" ]; then
    die "--approver-login, --approver-ip and --public-url must be given together"
  fi
  [[ "$APPROVER_LOGIN" =~ ^[^[:space:]\"\\]+$ ]] || die "--approver-login must not contain spaces, quotes or backslashes"
  python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$APPROVER_IP" 2>/dev/null \
    || die "--approver-ip must be a single IP address (see: tailscale status)"
  [[ "$PUBLIC_URL" =~ ^https://[A-Za-z0-9.:-]+/?$ ]] || die "--public-url must look like https://box.tailXXXX.ts.net"
  PUBLIC_URL="${PUBLIC_URL%/}"
  PHONE_SETUP=1
elif [ "$WANT_NTFY" -eq 1 ]; then
  die "--ntfy needs --approver-login, --approver-ip and --public-url"
fi

LIB="$DESTDIR/usr/local/lib/telepathy"
BIN="$DESTDIR/usr/local/bin"
ETC="$DESTDIR/etc/telepathy"
UNIT="$DESTDIR/etc/systemd/system/telepathyd.service"
LOGROTATE="$DESTDIR/etc/logrotate.d/telepathy"

OWN=()
[ -z "$DESTDIR" ] && OWN=(-o root -g root)

TMP="$(mktemp -d)"
lr_dir=""  # the logrotate check dir, see install_logrotate
trap 'rm -rf "$TMP" ${lr_dir:+"$lr_dir"}' EXIT

echo "Installing program files to ${LIB#"$DESTDIR"}"
install -d -m 0755 "${OWN[@]}" "$LIB" "$LIB/telepathy" "$LIB/bin" "$BIN" "$ETC" "$(dirname "$UNIT")" "$(dirname "$LOGROTATE")"
# Replace the package wholesale so a removed module can't linger.
find "$LIB/telepathy" -maxdepth 1 \( -name '*.py' -o -name __pycache__ \) -exec rm -rf {} +
install -m 0644 "${OWN[@]}" "$SRC"/telepathy/*.py "$LIB/telepathy/"
install -m 0755 "${OWN[@]}" "$SRC/bin/telepathy" "$SRC/bin/telepathyctl" "$SRC/bin/telepathyd" "$SRC/bin/telepathy-logrotate-hook" "$LIB/bin/"
ln -sfn ../lib/telepathy/bin/telepathy "$BIN/telepathy"
ln -sfn ../lib/telepathy/bin/telepathyctl "$BIN/telepathyctl"

if [ -e "$ETC/config.toml" ]; then
  echo "Keeping existing ${ETC#"$DESTDIR"}/config.toml"
else
  sed "s/@UID@/$ALLOWED_UID/" "$SRC/etc/config.toml" > "$TMP/config.toml"
  install -m 0644 "${OWN[@]}" "$TMP/config.toml" "$ETC/config.toml"
  echo "Created ${ETC#"$DESTDIR"}/config.toml (allowed_uids = [$ALLOWED_UID])"
fi
if [ -e "$ETC/policy.toml" ]; then
  echo "Keeping existing ${ETC#"$DESTDIR"}/policy.toml"
else
  install -m 0644 "${OWN[@]}" "$SRC/etc/policy.toml" "$ETC/policy.toml"
  echo "Created ${ETC#"$DESTDIR"}/policy.toml (empty: everything asks a human)"
fi
if [ "$PHONE_SETUP" -eq 1 ]; then
  BEGIN='# >>> telepathy phone setup (written by install.sh; re-run it to change) >>>'
  END='# <<< telepathy phone setup <<<'
  NTFY_FILE="$ETC/ntfy-url"
  if [ "$WANT_NTFY" -eq 1 ]; then
    if [ -e "$NTFY_FILE" ]; then
      echo "Keeping existing ntfy topic (${NTFY_FILE#"$DESTDIR"})"
    else
      TOPIC="telepathy-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      ( umask 077; printf 'https://ntfy.sh/%s\n' "$TOPIC" > "$TMP/ntfy-url" )
      install -m 0600 "${OWN[@]}" "$TMP/ntfy-url" "$NTFY_FILE"
      echo "Created a private ntfy topic. In the ntfy app, subscribe to:  $TOPIC"
    fi
  fi
  # Drop any previous block, then append the current one.
  awk -v b="$BEGIN" -v e="$END" '$0 == b {skip = 1; next} $0 == e {skip = 0; next} !skip' \
    "$ETC/config.toml" > "$TMP/config.new"
  {
    echo "$BEGIN"
    echo "approver_logins = [\"$APPROVER_LOGIN\"]"
    echo "approver_ips = [\"$APPROVER_IP\"]"
    echo "public_url = \"$PUBLIC_URL\""
    [ "$WANT_NTFY" -eq 1 ] && echo "ntfy_url_file = \"${NTFY_FILE#"$DESTDIR"}\""
    echo "$END"
  } >> "$TMP/config.new"
  install -m 0644 "${OWN[@]}" "$TMP/config.new" "$ETC/config.toml"
  echo "Wrote the phone approval settings to ${ETC#"$DESTDIR"}/config.toml"
fi
install -m 0644 "${OWN[@]}" "$SRC/systemd/telepathyd.service" "$UNIT"

# Audit log rotation (the daemon reopens the file on SIGHUP). Program-owned, so
# it is refreshed on every run, like the unit. Validated with logrotate -d (a
# syntax check only). Installed only after the daemon has been restarted (or
# when nothing is started), and its postrotate only signals a daemon that has
# written its hup-ok marker, so a still-running older daemon (no SIGHUP
# handler) is never sent a HUP that would kill it.
install_logrotate() {
  if command -v logrotate >/dev/null; then
    # Check a copy whose log path points into $TMP: logrotate -d still stats the
    # log, and on a deployed host /var/log/telepathy is root-only, so an
    # unprivileged (DESTDIR/test) run would fail on "Permission denied".
    # The checked log lives in a fixed-template dir (only [A-Za-z0-9._/-], so
    # logrotate's own parsing cannot split or glob it), rewritten literally.
    lr_dir="$(mktemp -d /tmp/telepathy-lrcheck.XXXXXX)"
    python3 -I -c '
import sys
src, dst, log = sys.argv[1:]
head = "/var/log/telepathy/audit.jsonl {"
lines = open(src).read().split("\n")
if lines.count(head) != 1:
    sys.exit("etc/logrotate.telepathy must have exactly one line \"" + head + "\"")
open(dst, "w").write("\n".join(log + " {" if l == head else l for l in lines))
' "$SRC/etc/logrotate.telepathy" "$TMP/logrotate.telepathy" "$lr_dir/audit.jsonl" \
      || { rm -rf "$lr_dir"; die "cannot prepare etc/logrotate.telepathy for its syntax check; not installed"; }
    chmod 0644 "$TMP/logrotate.telepathy"
    lr_rc=0
    logrotate -d -s "$TMP/logrotate.state" "$TMP/logrotate.telepathy" >"$TMP/logrotate.out" 2>&1 || lr_rc=$?
    rm -rf "$lr_dir"
    if [ "$lr_rc" -ne 0 ] || grep -qi error "$TMP/logrotate.out"; then
      cat "$TMP/logrotate.out" >&2
      die "logrotate rejected etc/logrotate.telepathy (exit $lr_rc); not installed"
    fi
  fi
  install -m 0644 "${OWN[@]}" "$SRC/etc/logrotate.telepathy" "$LOGROTATE"
  echo "Installed ${LOGROTATE#"$DESTDIR"} (audit log: weekly, 52 kept)"
  if ! command -v logrotate >/dev/null; then
    echo "WARNING: logrotate is not installed, so the audit log will NOT be rotated until you install it." >&2
  elif [ -z "$DESTDIR" ] && ! systemctl is-enabled --quiet logrotate.timer 2>/dev/null \
       && ! [ -e /etc/cron.daily/logrotate ]; then
    echo "WARNING: nothing seems to run logrotate (logrotate.timer is not enabled and there is no" >&2
    echo "         /etc/cron.daily/logrotate). Enable it yourself: sudo systemctl enable --now logrotate.timer" >&2
  fi
}

# Refuse to (re)start a daemon whose kept config/policy no longer parse.
python3 -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from telepathy.config import Config
from telepathy.policy import Policy
Config.from_toml(open(sys.argv[2], encoding="utf-8").read())
Policy.from_toml(open(sys.argv[3], encoding="utf-8").read())
' "$LIB" "$ETC/config.toml" "$ETC/policy.toml" \
  || die "config.toml or policy.toml is invalid (see the error above); fix it and re-run"

if [ -n "$DESTDIR" ]; then
  install_logrotate
  echo "DESTDIR is set: skipped systemctl. Staged under $DESTDIR"
  exit 0
fi

systemctl daemon-reload
systemctl enable telepathyd.service
if [ "$NO_START" -eq 1 ]; then
  install_logrotate
  echo "Enabled but not started (--no-start). Start it with: sudo systemctl start telepathyd"
  exit 0
fi
systemctl restart telepathyd.service

for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -S /run/telepathy/admin.sock ] && break
  sleep 0.5
done
if ! "$BIN/telepathyctl" list >/dev/null 2>&1; then
  journalctl -u telepathyd.service -n 20 --no-pager >&2 || true
  die "the daemon did not come up; see the log above"
fi

install_logrotate

if [ "$PHONE_SETUP" -eq 1 ]; then
  command -v tailscale >/dev/null || die "tailscale is not installed; the approval page was not published"
  echo "Publishing the approval page to your tailnet (tailscale serve, HTTPS 443)..."
  tailscale serve --bg --https=443 unix:/run/telepathy/web.sock \
    || die "tailscale serve failed. If it mentions HTTPS, enable HTTPS certificates at https://login.tailscale.com/admin/dns and re-run."
  tailscale serve status || true
fi

cat <<EOF

telepathy is running.
  Agent:   telepathy run -r "why" -- /usr/bin/pacman -S --needed htop
  Human:   sudo telepathyctl list ; sudo telepathyctl approve <id>
  Audit:   /var/log/telepathy/audit.jsonl
  Remove:  sudo $SRC/uninstall.sh   (see README.md)
EOF
