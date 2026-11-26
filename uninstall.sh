#!/usr/bin/env bash
# Remove telepathy. Your config, policy and audit log are KEPT unless --purge.
#
#   sudo ./uninstall.sh [--purge]
#
# Environment: DESTDIR=/some/dir operates on a staged tree (used by the tests).
set -euo pipefail

die() { echo "uninstall.sh: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo ./uninstall.sh [--purge]

  --purge   also delete /etc/telepathy (config, policy) and /var/log/telepathy (audit log)
EOF
}

DESTDIR="${DESTDIR:-}"
PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
  die "must run as root: sudo ./uninstall.sh"
fi

LIB="$DESTDIR/usr/local/lib/telepathy"
BIN="$DESTDIR/usr/local/bin"
ETC="$DESTDIR/etc/telepathy"
LOGS="$DESTDIR/var/log/telepathy"
UNIT="$DESTDIR/etc/systemd/system/telepathyd.service"
LOGROTATE="$DESTDIR/etc/logrotate.d/telepathy"

if [ -z "$DESTDIR" ]; then
  # Stop it first so nothing runs from the files we are about to remove.
  systemctl disable --now telepathyd.service 2>/dev/null || true
  # Unpublish the approval page, but only if the published entry is ours.
  if command -v tailscale >/dev/null && tailscale serve status 2>/dev/null | grep -q '/run/telepathy/web.sock'; then
    tailscale serve --https=443 off && echo "Removed the telepathy page from tailscale serve."
  fi
fi
rm -f -- "$UNIT" "$LOGROTATE"
if [ -z "$DESTDIR" ]; then
  systemctl daemon-reload
  systemctl reset-failed telepathyd.service 2>/dev/null || true
fi

# Only remove the commands if they still point at our files.
for name in telepathy telepathyctl; do
  if [ -L "$BIN/$name" ] && [ "$(readlink "$BIN/$name")" = "../lib/telepathy/bin/$name" ]; then
    rm -f -- "$BIN/$name"
  elif [ -e "$BIN/$name" ] || [ -L "$BIN/$name" ]; then
    echo "Left ${BIN#"$DESTDIR"}/$name alone: it is not the telepathy symlink" >&2
  fi
done

rm -rf -- "${LIB:?}"
echo "Removed the service, commands, log rotation rule and program files."

if [ "$PURGE" -eq 1 ]; then
  rm -rf -- "${ETC:?}" "${LOGS:?}"
  echo "Purged ${ETC#"$DESTDIR"} and ${LOGS#"$DESTDIR"}."
else
  for kept in "$ETC" "$LOGS"; do
    [ -e "$kept" ] && echo "Kept ${kept#"$DESTDIR"} (use --purge to delete it)"
  done
fi
exit 0
