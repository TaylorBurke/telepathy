#!/usr/bin/env bats
# Installer tests run against a staging directory (DESTDIR), so they need no
# root and never touch the real system or systemctl.

setup() {
  REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  export DESTDIR="$BATS_TEST_TMPDIR/root"
  export SUDO_UID=1234
  LIB="$DESTDIR/usr/local/lib/telepathy"
  BIN="$DESTDIR/usr/local/bin"
  ETC="$DESTDIR/etc/telepathy"
  UNIT="$DESTDIR/etc/systemd/system/telepathyd.service"
}

install_it() { run bash "$REPO/install.sh" "$@"; }

@test "install lays out program files, commands, config, policy and unit" {
  install_it
  [ "$status" -eq 0 ]
  for f in request policy broker audit config executor daemon client web; do
    [ -f "$LIB/telepathy/$f.py" ]
  done
  [ -x "$LIB/bin/telepathy" ] && [ -x "$LIB/bin/telepathyctl" ] && [ -x "$LIB/bin/telepathyd" ]
  [ "$(readlink "$BIN/telepathy")" = "../lib/telepathy/bin/telepathy" ]
  [ "$(readlink "$BIN/telepathyctl")" = "../lib/telepathy/bin/telepathyctl" ]
  [ -f "$ETC/config.toml" ] && [ -f "$ETC/policy.toml" ] && [ -f "$UNIT" ]
}

@test "program files are mode 0644/0755 and not group/world writable" {
  install_it
  [ "$(stat -c %a "$LIB/telepathy/daemon.py")" = "644" ]
  [ "$(stat -c %a "$LIB/bin/telepathyd")" = "755" ]
  [ "$(stat -c %a "$LIB")" = "755" ]
}

@test "config gets the sudo user's uid and installed config+policy validate" {
  install_it
  grep -qx 'allowed_uids = \[1234\]' "$ETC/config.toml"
  run python3 -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from telepathy.config import Config
from telepathy.policy import Policy
c = Config.from_toml(open(sys.argv[2]).read())
p = Policy.from_toml(open(sys.argv[3]).read())
assert c.allowed_uids == (1234,) and p.rules == ()
' "$LIB" "$ETC/config.toml" "$ETC/policy.toml"
  [ "$status" -eq 0 ]
}

@test "--uid overrides SUDO_UID; missing or bad uid is refused" {
  install_it --uid 4321
  [ "$status" -eq 0 ]
  grep -qx 'allowed_uids = \[4321\]' "$ETC/config.toml"

  rm -rf "$DESTDIR"; unset SUDO_UID
  install_it
  [ "$status" -ne 0 ]
  [[ "$output" == *"--uid"* ]]
  install_it --uid abc
  [ "$status" -ne 0 ]
  [ ! -e "$ETC/config.toml" ]
}

@test "unit file runs the daemon isolated and adds no sandbox that would break approved commands" {
  install_it
  grep -q '^ExecStart=/usr/bin/python3 -I /usr/local/lib/telepathy/bin/telepathyd ' "$UNIT"
  grep -q '^NoNewPrivileges=yes' "$UNIT"
  grep -q '^Restart=on-failure' "$UNIT"
  run bash -c "grep -v '^#' '$UNIT' | grep -E 'ProtectHome|ProtectSystem|PrivateTmp|CapabilityBoundingSet|ReadOnlyPaths'"
  [ "$status" -ne 0 ]
}

@test "installed scripts run under python -I (sys.path trick works from the install dir)" {
  install_it
  run python3 -I "$LIB/bin/telepathyd" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"telepathyd"* ]]
  run python3 -I "$LIB/bin/telepathy" --help
  [ "$status" -eq 0 ]
  run python3 -I "$LIB/bin/telepathyctl" --help
  [ "$status" -eq 0 ]
}

@test "re-running keeps edited config and policy but refreshes code and drops stale modules" {
  install_it
  echo '# my edit' >> "$ETC/config.toml"
  echo '# my policy edit' >> "$ETC/policy.toml"
  echo 'tampered = True' > "$LIB/telepathy/daemon.py"
  echo 'x = 1' > "$LIB/telepathy/stale.py"
  install_it
  [ "$status" -eq 0 ]
  grep -q '# my edit' "$ETC/config.toml"
  grep -q '# my policy edit' "$ETC/policy.toml"
  cmp "$LIB/telepathy/daemon.py" "$REPO/telepathy/daemon.py"
  [ ! -e "$LIB/telepathy/stale.py" ]
  [[ "$output" == *"Keeping existing"* ]]
}

@test "a kept config that no longer parses stops the install" {
  install_it
  echo 'this is = = not toml' > "$ETC/config.toml"
  install_it
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid"* ]]
}

@test "uninstall removes program files, commands and unit but keeps config and logs" {
  install_it
  mkdir -p "$DESTDIR/var/log/telepathy"
  echo '{}' > "$DESTDIR/var/log/telepathy/audit.jsonl"
  run bash "$REPO/uninstall.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$LIB" ] && [ ! -e "$UNIT" ]
  [ ! -L "$BIN/telepathy" ] && [ ! -L "$BIN/telepathyctl" ]
  [ -f "$ETC/config.toml" ] && [ -f "$ETC/policy.toml" ]
  [ -f "$DESTDIR/var/log/telepathy/audit.jsonl" ]
  [[ "$output" == *"--purge"* ]]
}

@test "uninstall --purge also removes config, policy and logs" {
  install_it
  mkdir -p "$DESTDIR/var/log/telepathy"
  run bash "$REPO/uninstall.sh" --purge
  [ "$status" -eq 0 ]
  [ ! -e "$ETC" ] && [ ! -e "$DESTDIR/var/log/telepathy" ] && [ ! -e "$LIB" ]
}

@test "uninstall leaves a same-named command it did not install" {
  install_it
  rm "$BIN/telepathy"
  echo 'not ours' > "$BIN/telepathy"
  run bash "$REPO/uninstall.sh"
  [ "$status" -eq 0 ]
  [ -f "$BIN/telepathy" ] && grep -q 'not ours' "$BIN/telepathy"
  [[ "$output" == *"alone"* ]]
}

@test "uninstall on a system without telepathy is a clean no-op" {
  run bash "$REPO/uninstall.sh"
  [ "$status" -eq 0 ]
  run bash "$REPO/uninstall.sh" --purge
  [ "$status" -eq 0 ]
}

@test "uninstall then install again works" {
  install_it
  run bash "$REPO/uninstall.sh" --purge
  install_it
  [ "$status" -eq 0 ]
  [ -f "$LIB/telepathy/daemon.py" ]
}

@test "unknown options are rejected" {
  run bash "$REPO/install.sh" --bogus
  [ "$status" -ne 0 ]
  run bash "$REPO/uninstall.sh" --bogus
  [ "$status" -ne 0 ]
}

PHONE=(--approver-login me@example.com --approver-ip 100.64.0.7 --public-url https://box.tail1234.ts.net)

# Parse the installed config with the installed code and assert on it.
config_check() {
  python3 -I -c '
import sys
sys.path.insert(0, sys.argv[1])
from telepathy.config import Config
c = Config.from_toml(open(sys.argv[2]).read())
exec(sys.argv[3])
' "$LIB" "$ETC/config.toml" "$1"
}

@test "phone flags write a config block that the daemon's own parser accepts" {
  install_it "${PHONE[@]}"
  [ "$status" -eq 0 ]
  config_check 'assert c.approver_logins == ("me@example.com",) and c.approver_ips == ("100.64.0.7",) and c.public_url == "https://box.tail1234.ts.net" and c.ntfy_url_file is None'
  [ ! -e "$ETC/ntfy-url" ]
}

@test "re-running with new phone settings replaces the block and keeps other edits" {
  install_it "${PHONE[@]}"
  sed -i 's/^ttl = .*//; $a ttl = 120' "$ETC/config.toml" 2>/dev/null || true
  install_it --approver-login me@example.com --approver-ip 100.99.1.2 --public-url https://box.tail1234.ts.net/
  [ "$status" -eq 0 ]
  [ "$(grep -c '^approver_ips' "$ETC/config.toml")" = "1" ]
  [ "$(grep -c '^approver_logins' "$ETC/config.toml")" = "1" ]
  grep -qx 'approver_ips = \["100.99.1.2"\]' "$ETC/config.toml"
  grep -qx 'public_url = "https://box.tail1234.ts.net"' "$ETC/config.toml"  # trailing slash dropped
  config_check 'assert c.ttl == 120.0'
}

@test "a plain re-run after phone setup leaves the phone settings alone" {
  install_it "${PHONE[@]}"
  install_it
  [ "$status" -eq 0 ]
  config_check 'assert c.approver_ips == ("100.64.0.7",)'
}

@test "phone flags are validated and must be given together" {
  for args in "--approver-login me@example.com" "--approver-ip 100.64.0.7" "--public-url https://box.ts.net" \
              "--ntfy" \
              "--approver-login me@example.com --approver-ip 300.1.1.1 --public-url https://box.ts.net" \
              "--approver-login me@example.com --approver-ip 100.64.0.0/10 --public-url https://box.ts.net" \
              "--approver-login me@example.com --approver-ip 100.64.0.7 --public-url http://box.ts.net" \
              "--approver-login me@example.com --approver-ip 100.64.0.7 --public-url https://box.ts.net/x" \
              "--approver-login a\"b --approver-ip 100.64.0.7 --public-url https://box.ts.net" \
              "--approver-login a-b-c --approver-ip"; do
    rm -rf "$DESTDIR"
    run bash -c "bash '$REPO/install.sh' $args"
    [ "$status" -ne 0 ] || { echo "accepted: $args"; return 1; }
    [ ! -e "$ETC/config.toml" ]  # nothing is written when the arguments are bad
  done
}

@test "--ntfy creates a private random topic once and wires it into the config" {
  install_it "${PHONE[@]}" --ntfy
  [ "$status" -eq 0 ]
  [[ "$output" =~ subscribe\ to:\ +telepathy-[0-9a-f]{32} ]]
  [ "$(stat -c %a "$ETC/ntfy-url")" = "600" ]
  grep -Eqx 'https://ntfy\.sh/telepathy-[0-9a-f]{32}' "$ETC/ntfy-url"
  config_check 'assert c.ntfy_url_file == "/etc/telepathy/ntfy-url"'
  first="$(cat "$ETC/ntfy-url")"
  install_it "${PHONE[@]}" --ntfy
  [ "$status" -eq 0 ]
  [ "$(cat "$ETC/ntfy-url")" = "$first" ]
  [[ "$output" == *"Keeping existing ntfy topic"* ]]
  # the secret topic is never printed on a re-run
  [[ "$output" != *"${first##*/}"* ]]
}

@test "uninstall keeps the ntfy topic unless --purge" {
  install_it "${PHONE[@]}" --ntfy
  run bash "$REPO/uninstall.sh"
  [ "$status" -eq 0 ]
  [ -f "$ETC/ntfy-url" ]
  run bash "$REPO/uninstall.sh" --purge
  [ ! -e "$ETC/ntfy-url" ]
}

@test "shellcheck is clean on every shell script (skipped only if shellcheck is not installed)" {
  command -v shellcheck >/dev/null || skip "shellcheck not installed"
  # discover scripts by shebang so newly added ones are covered automatically
  scripts=()
  while IFS= read -r f; do
    if head -n1 "$REPO/$f" 2>/dev/null | grep -Eq '^#!.*\b(ba|da|k)?sh\b'; then
      scripts+=("$REPO/$f")
    fi
  done < <(cd "$REPO" && find . -type f -not -path './.git/*' -not -name '*.py' -not -name '*.md' | sed 's|^\./||' | sort)
  # the installer, uninstaller and hook must always be among them
  [[ " ${scripts[*]} " == *" $REPO/install.sh "* ]]
  [[ " ${scripts[*]} " == *" $REPO/uninstall.sh "* ]]
  [[ " ${scripts[*]} " == *" $REPO/bin/telepathy-logrotate-hook "* ]]
  run shellcheck "${scripts[@]}"
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "install lays down the logrotate rule; uninstall removes it but keeps logs" {
  install_it
  R="$DESTDIR/etc/logrotate.d/telepathy"
  [ -f "$R" ] && [ "$(stat -c %a "$R")" = "644" ]
  grep -q 'create 0600 root root' "$R"
  ! grep -q '^[^#]*copytruncate' "$R"
  grep -q 'telepathy-logrotate-hook' "$R"
  [ -x "$LIB/bin/telepathy-logrotate-hook" ]
  mkdir -p "$DESTDIR/var/log/telepathy"
  echo '{}' > "$DESTDIR/var/log/telepathy/audit.jsonl"
  install_it
  [ "$status" -eq 0 ]
  run bash "$REPO/uninstall.sh"
  [ "$status" -eq 0 ]
  [ ! -e "$R" ]
  [ -f "$DESTDIR/var/log/telepathy/audit.jsonl" ]
}

@test "the logrotate syntax check runs on a copy pointed into a temp dir, never the real log" {
  # A stand-in logrotate that keeps the config it was given.
  fake="$BATS_TEST_TMPDIR/fakebin"; mkdir -p "$fake"
  printf '#!/bin/sh\nfor a; do last="$a"; done\ncp "$last" "%s/checked.conf"\n' \
    "$BATS_TEST_TMPDIR" > "$fake/logrotate"
  chmod +x "$fake/logrotate"
  TMPDIR="$BATS_TEST_TMPDIR/odd dir & [x]*"; mkdir -p "$TMPDIR"; export TMPDIR
  PATH="$fake:$PATH" install_it
  [ "$status" -eq 0 ]
  C="$BATS_TEST_TMPDIR/checked.conf"
  [ -f "$C" ]
  ! grep -q '/var/log/telepathy' "$C"
  grep -q '^/tmp/telepathy-lrcheck\.[A-Za-z0-9]*/audit.jsonl {$' "$C"
  checked_dir="$(dirname "$(head -n1 <(grep '^/tmp/telepathy-lrcheck' "$C"))")"
  [ ! -e "$checked_dir" ]  # cleaned up
  # The installed rule itself still names the real log.
  grep -q '^/var/log/telepathy/audit.jsonl {$' "$DESTDIR/etc/logrotate.d/telepathy"
}

@test "install refuses a logrotate rule whose log line it cannot find" {
  command -v logrotate >/dev/null || skip "logrotate not installed"
  copy="$BATS_TEST_TMPDIR/repo"
  cp -r "$REPO" "$copy"
  sed -i 's#^/var/log/telepathy/audit.jsonl {#/var/log/elsewhere/audit.jsonl {#' "$copy/etc/logrotate.telepathy"
  run bash "$copy/install.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cannot prepare etc/logrotate.telepathy"* ]]
  [ ! -e "$DESTDIR/etc/logrotate.d/telepathy" ]
}
