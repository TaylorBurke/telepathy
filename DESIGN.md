# telepathy: design

Let an AI agent work unattended on this machine and still get root commands
done, with a human approving each one from their phone. The agent never holds a
password or a standing privilege.

## Goals

- Agent asks for root; the human sees the **literal command** on their phone
  and approves or denies it.
- Approval is **single-use, hash-bound, and short-lived**. It cannot be replayed
  or applied to a different command.
- No inbound exposure to the public internet. No NOPASSWD sudo anywhere.
- The agent never sees the approval channel's secrets or any password.
- Routine, boring commands can be pre-allowed by a narrow policy so the phone is
  only pinged for the unusual ones.

## Non-goals

- Not a general remote shell. Not a replacement for sudo when the human is at
  the machine (use a local terminal then).
- Not a defence against a fully compromised user account. The threat model is a
  *misled or injected agent*, not a root-level attacker.

## Components

```
agent (normal user)            telepathyd (root, systemd)           phone
     |                                  |                                |
     |-- telepathy run -- cmd --------->|  unix socket, SO_PEERCRED      |
     |   (blocks, polls)                |  stores request {argv, cwd,    |
     |                                  |  sha256, expires_at}           |
     |                                  |-- push: "request #id" -------->|  (no command text)
     |                                  |                                |
     |                                  |<-- tailnet HTTPS: GET /r/<id> -|  shows exact argv
     |                                  |<-- POST /r/<id>/approve -------|  (Face ID device, nonce)
     |                                  |  re-hash, check, run once      |
     |<-- exit code + output -----------|                                |
```

1. **`telepathy` (client CLI, runs as the agent's user).** `telepathy run --
   <argv...>` submits a request over a unix socket and blocks until it is
   approved, denied, or expired, then prints the command's output and exits
   with its exit code. `telepathy status <id>` for non-blocking use, `telepathy cancel <id>` to withdraw.
2. **`telepathyd` (root, systemd system service).** Owns the request queue,
   policy, approval web endpoint, and execution. Python 3 standard library only.
3. **Push (ntfy).** Outbound-only notification that carries *only* a request id
   and a generic title, never the command, so nothing sensitive reaches a third
   party. Tapping it opens the approval page. A generic JSON webhook (same
   rules: id, short hash and link only, secret URL in a root-only file, no
   redirects) covers other push services; both can be enabled at once.
4. **Approval page (Tailscale only).** `tailscale serve` exposes the daemon's
   local HTTPS listener to the tailnet. The daemon accepts approvals only when
   the Tailscale identity headers name the owner's phone node.

## Request lifecycle and invariants

- A request is `argv` (a list, never a shell string), an absolute `cwd`, a
  minimal fixed environment, and a human-readable `reason` supplied by the agent.
- `hash = sha256(canonical_json({argv, cwd, env, uid}))`. The approval page
  shows the argv and the first 8 hex chars of the hash.
- **Single use:** state machine `pending -> approved -> running -> done` plus
  `denied`, `expired` and `cancelled`. Any other transition is rejected. A request runs at
  most once.
- **Cancel:** `telepathy cancel <id>` (agent socket op `cancel`) withdraws a
  request that has not started: `pending` or `approved` becomes `cancelled`
  (terminal; audit `cancelled` with `by` and `was`), which frees its
  `max_pending` slot and makes a later approve or run fail. Only the submitting
  uid, or root, may cancel; anyone else gets the same `not_found` as for an
  unknown id. Cancelling a `running`, `done`, `denied`, `expired` or already
  cancelled request changes nothing and the reply says so (`cancelled`/`changed`
  flags); a running command is never killed. Cancel and `begin_run` serialise
  on the broker lock, so a request is either cancelled before it starts or it
  runs. `telepathy run` cancels on ^C, best effort: 2 s timeout, any failure
  (daemon gone, a second ^C) is reported and swallowed, exit code 130.
  Known window: a ^C that lands before the submit reply arrives leaves the client
  with no id, so it cannot cancel; the request (if the daemon received it) stays
  pending until it expires, and the client says so. Closing it would need a
  client-chosen request token in the protocol, judged not worth it. Only the
  broker decides who may cancel, under its lock, so the owner check and the state
  change cannot be separated. `run_refused` is audited if anything but an
  approved request is ever handed to `begin_run`.
- **Restarts lose the queue, by design.** Requests live in memory only; a
  restart drops pending and approved-not-run ones and nothing runs. Persisting
  them was rejected: a resumed approval would outlive the process whose state
  the approver saw, for little gain. A waiting client that gets `not_found`
  says "telepathyd restarted; nothing ran, resubmit".
- **Expiry:** default 10 minutes from submission; configurable; never extended.
  Expiry, TTL and rate windows use `CLOCK_BOOTTIME`, so stepping the wall
  clock (NTP, manual change) cannot extend or shorten a request and time spent
  suspended still counts (plain `time.monotonic` pauses in suspend); wall
  time is only used for the audit log's `ts`. The API exposes `expires_in`, not
  an absolute time.
- **Re-verify at run time:** the daemon recomputes the hash from the stored
  fields immediately before exec and refuses on mismatch. It also re-resolves
  the symlinks in the path arguments and refuses (audit `symlink_changed_at_run`)
  if any resolved target differs from the one frozen at submit and shown to the
  approver, and re-evaluates the deny rules, because the agent controls symlinks
  and a link that was harmless at approval may now point elsewhere. This narrows but
  cannot close the race: a link can still be retargeted between that last check
  and the exec itself. The approval step, not this check, is the guarantee.
- **Deny rules re-checked after the freeze:** `evaluate` and the freeze
  are separate filesystem passes, so `check_guarded` then re-runs every
  filesystem-dependent deny rule (`Policy.check_targets`): the executable
  checks on argv[0]'s frozen target (or argv[0] itself when nothing was
  frozen), the protected prefixes on each frozen target, and evaluate's
  protected-path check on each argument again, from the frozen cwd when the cwd
  was frozen. A frozen cwd that cannot be resolved is denied. The cwd itself and
  the "mentions telepathy" text rule are not re-checked (evaluate covers them as
  written). Whatever the approver is shown, and whatever `begin_run` compares
  against, was checked.
- **Symlinks:** protected-path checks run on each path argument both as written
  and with symlinks resolved (`realpath`, including symlinked parent
  directories, and `..` applied after links as the kernel does). Each protected prefix is also resolved, at every evaluation, so a prefix that is
  itself a link on this host (a relocated `/etc/sudoers.d`) protects its real
  target too, unless the resolved form is `/` or a strict ancestor of the literal one (a link to `/etc` would deny a whole shared tree); those are skipped, the literal prefix still applies, and everything else, however shallow, stays enforced. The daemon resolves the skipped set once at start, reports it (stderr and a `protected_prefix_skipped` audit record) and seeds a cache with that same set. Each later evaluation compares its own resolution with the cache and, on a difference (a link repointed), commits it and queues one `protected_prefix_skipped` or `protected_prefix_unskipped` event on a bounded queue (oldest dropped, counted in a `protected_prefix_events_dropped` record). Queueing happens under a small lock that never covers I/O, so events are ordered by commit; an observation resolved before a newer committed one is ignored, and a prefix whose resolution fails keeps its previous state (the literal prefix is enforced regardless). A daemon reporter thread drains the queue and writes audit and stderr with bounded retries, so the evaluating thread (a limited `check_guarded` worker, off the broker lock) never does that I/O and the policy decision cannot be affected. The cache is module-level state in `policy.py` (one policy per daemon process). The admin `list` response carries the cached set (no filesystem access) and `telepathyctl list` prints it to stderr, keeping stdout parseable. A path that cannot be resolved is denied. The approval page and `telepathyctl` show the resolved path
  for arguments that cross a symlink *not owned by root* (the agent's links);
  system links such as `/bin` stay quiet so the warning means something. A
  root-owned link counts as a system link only when the directory holding it is
  root-owned with no other-write, no non-root group-write and no named-ACL write
  grant, and so is every ancestor up to `/` (an agent-writable ancestor can rename
  the tree; anything that cannot be inspected is reported). The broker takes the
  trusted uid as `link_trusted_uid`, separate from `Policy.trusted_uid`, so tests can
  say "no link is root's" without breaking the executable check; a root-made link in an
  agent-writable directory is reported like the agent's own. The
  resolution is computed **once, at submit**, under a 5 s time limit, and stored on
  the request (outside the hash): page renders, `status` and `list` only read it,
  so a hung mount cannot stall handler threads and the shown value cannot change
  on reload. If it times out, the request is still shown but is refused at run
  time as never verified; the page says so and offers only Deny. An unexpected resolver error is handled the same way, under its own reason. A request that was never frozen is refused too (fail closed).
  **Filesystem checks never run under the broker lock.** `policy.evaluate` and the
  resolution run together in one guarded worker thread (`check_guarded`), so a hung
  mount stalls only the request being checked; the lock is taken only to enqueue
  (submit) or to re-validate state and move to RUNNING (`begin_run`). A worker that
  hangs cannot be killed, so at most 8 run at once and each keeps its slot until the
  thread really finishes. With no free slot a check fails closed at once (`check_busy`)
  rather than spawning more threads. Submit checks also take a per-uid and a
  total quota (see known limitations).
  - *Submit time:* if `evaluate` times out, raises, or no slot is free, the submit is
    denied and audited as `check_timeout`, `check_error` or `check_busy` (not as a
    policy verdict). If only the resolution times out, the decision stands and the
    request is shown but refused at run time as never verified (above).
  - *Run time:* a pre-check off the worker filters out transient failures first
    (audited as `run_unverified` with `stage: precheck`; see known limitations);
    then the same check runs again outside the lock. A real policy deny, a
    crash of the evaluator (`policy_error_at_run`) or a resolved target that changed
    is terminal. A timeout or no free worker slot is transient: the attempt is
    refused (`run_unverified`, "path check timed out; try again"), the request stays
    approved with its original expiry, and the daemon retries with exponential
    backoff (2, 4, 8, 16 s) for at most 5 attempts in all or until it expires. After
    the cap it is denied (`run_unverified_gave_up`). Pending retry timers are
    cancelled on shutdown. The state is re-validated under the lock after each
    check, so a cancel, expiry or a concurrent `begin_run` that landed meanwhile wins.
  - *Limits and TTL:* a submit holds a `max_pending` slot while it is being checked
    (up to the 5 s limit) and gives it back as soon as the check returns, so only
    enqueued requests count afterwards. The approval TTL starts when the request is
    enqueued, so check time does not use it up. A submit denied because the check
    itself failed (timeout, busy, error) gives its hourly rate-limit token back.
  The comparison is exact dict equality over only the links *not owned by root*
  (the same set the page shows): retargeting a root-owned system link is outside
  it, being root's own act.
- **Display is authoritative:** the page renders `argv` from the stored request,
  never the agent's `reason`. `reason` is shown separately and visually marked as
  agent-supplied.
- **Approval nonce:** each approve POST must include a per-request nonce issued
  on page load, so a stale tab or forwarded link cannot approve.
- **Rate limit and cap:** max pending requests, max requests per hour, so a
  looping agent can't flood the phone.
- **Audit log:** append-only JSONL under `/var/log/telepathy/` recording
  submit, decision, who approved (tailnet identity), exec start/finish, exit
  code. Output is stored by length and hash, not content, unless enabled.
  Rotation: logrotate (weekly, 52 kept, no `copytruncate`) plus SIGHUP, on which the
  daemon opens the new file and closes the old fd while holding the lock every
  write takes, so each record goes whole to one file. A failed reopen keeps the old
  file, retries and is reported loudly (stderr, `audit_reopen_failed`, a flag file).
  The daemon installs the SIGHUP handler before serving and writes a `hup-ok`
  marker that the logrotate rule checks, so an older daemon is never sent a HUP.
- **Timeout kill and detached descendants (cgroups):** the unit has
  `Delegate=yes`, so telepathyd owns its cgroup v2 directory. At start it probes
  that it can create a `cmd-*` child with `cgroup.kill` (kernel >= 5.14); if so,
  each command runs in its own `cmd-<pid>-<n>/`: the executor starts a tiny exec
  helper (`_exec_helper.py`, stdlib only, `python3 -I`) that writes itself into
  the child's `cgroup.procs` and then execs the argv, so the command is in the
  cgroup from its first instruction (no `preexec_fn`, unsafe in a threaded
  process). A failed join or exec is reported on a close-on-exec pipe with the
  same 126/127 mapping as before, and the command is then never run. A timeout
  writes `cgroup.kill`, which SIGKILLs every member at once (setsid, double fork
  and fork bombs included) and waits until the cgroup is empty; no `/proc`
  polling. After a normal exit, leftovers keep running (by design, as before);
  their directory is removed once empty, after each command and at start-up.
  The daemon itself stays in its cgroup root (no controllers are enabled in
  `cgroup.subtree_control`, so the no-internal-processes rule does not apply).
  An approved command runs as root and could move itself out on purpose;
  approval remains the guarantee. The tests run the real cgroup path
  unprivileged inside `systemd-run --user --scope -p Delegate=yes`.
- **Fallback without cgroups:** the executor starts each command in
  its own session. While it runs, the tracker (every 0.25s) walks direct
  children from the command's pid using `/proc/<pid>/task/*/children`, so the
  cost is proportional to the live tree, not to all of `/proc`. Where that file
  does not exist it falls back to a full `/proc` listing at a coarser 1s
  interval. Tracked entries are pid plus start time; each scan keeps an old
  entry only if the pid still has that start time and is not a zombie, so
  finished processes are pruned and a recycled pid is not followed; before each
  signal the starttime is re-checked, after opening a pidfd where the kernel has
  one (this narrows the pid-reuse window, which matters because the daemon runs
  as root; without pidfd a tiny check-then-kill window remains). The process
  group always gets SIGKILL, even with no tracked pid alive. On timeout it repeatedly
  rescans and SIGSTOPs the process group and tracked pids until the set is
  stable (a stopped process cannot fork), then SIGKILLs them, at most 20
  passes. If `/proc` is unavailable only the group is killed and the result's
  error says descendants may survive; likewise if the tree is still alive after
  the passes. This covers `setsid` children and double-forks seen before the
  intermediate parent exited. Residual limitation: a process that double-forks
  and orphans itself entirely between two scans (under 0.25s) is never seen and
  survives; a daemon that outlives a command that exited normally is left alone
  by design (only the timeout path kills). The cgroup path above closes this
  where it is available.

## Policy

`/etc/telepathy/policy.toml`, root-owned, not writable by the agent or by
anything telepathyd can run.

- **`deny`** always wins: shells and interpreters as the executable
  (`sh`, `bash`, `python`, `perl`, ...; matched on the basename of argv[0] both
  as written and after resolving symlinks, so `ln -s /bin/bash /tmp/foo` does not
  slip through; on a host whose coreutils are busybox links this also denies
  them), `sudo`/`su`, anything that edits
  `/etc/telepathy`, `/etc/sudoers*`, the daemon itself, or its units.
- **Trusted executable:** the file argv[0] *resolves to* must be owned by root and
  not writable by others (group-write is tolerated only for group 0), in
  directories that are too, so a *copy* of a shell in an agent-writable place is
  denied. This judges the resolved file, not the path as written: an agent-owned
  link to a root-owned binary passes this check (the page and `telepathyctl` show
  where it points), and retargeting it before exec is the residual race described
  under "Re-verify at run time", closed by comparing resolved targets at run time. Owner and mode
  bits plus POSIX ACLs: the file and each directory above it are refused if the
  `system.posix_acl_access` xattr (read with `os.getxattr`, parsed with `struct`)
  grants write to a named user other than root or a named group other than 0
  (the mask is ignored on purpose, since a chmod can loosen it); a malformed ACL
  or an unexpected read error (including ENOSYS/EPERM from FUSE or other odd filesystems, by design) is refused, no ACL (ENODATA/ENOTSUP) is fine. The
  executable must also be a regular file. Immutable flags are not consulted: they
  can only make a file harder to change, so ignoring them never trusts anything
  wrongly, and reading them needs an ioctl on an opened file. The gap between the lstat and the xattr read is the same
  swap-before-exec race. A file that does not
  exist yet passes on its own; its directories are still checked, and the check
  is repeated just before running.
- **`auto`** exact-match rules for routine commands that never need a human,
  e.g. `pacman -S --needed <pkg>` where each package is validated against a
  pattern and the repo db. Starts empty; grows one rule at a time.
- **`ask`** is everything else: goes to the phone.

Policy changes are made by the human at a local terminal, never through
telepathy.

## Authentication of the approver (v1 and v2)

- **v1:** tailnet-only listener, identity taken from Tailscale's headers and
  checked against an allowlisted user *and* device. The phone's own lock screen
  (Face ID) gates access. Per-request nonce on approve.
- **v2:** WebAuthn/passkey assertion on the approve POST, so approval needs a
  fresh Face ID, not just an unlocked phone. Needs an HTTPS origin, which
  `tailscale serve` provides.

## Threat model notes

- **Prompt injection of the agent** is the main case. Mitigations: the human
  sees the literal argv, approval is hash-bound and single-use, policy denies
  interpreters, nothing is pre-approved beyond the `auto` list.
- **Approval fatigue** is the main residual risk. Keep `ask` rare by growing the
  `auto` list sensibly, and keep the argv display large and unambiguous.
- **Push topic leakage:** the ntfy topic is a bearer secret but carries no
  command text; the approval itself requires tailnet identity, so a leaked
  topic can at worst spam notifications.
- **Webhook URL leakage:** a webhook URL is usually a credential for the push
  service itself (a Telegram URL holds the bot token, a Slack or Mattermost URL
  lets anyone post as the integration). Leaking it never lets anyone approve a
  request, but it exposes that service account, so treat it like a password.
- **The agent is not trusted with secrets:** the ntfy topic and any tokens live
  in root-only config (`/etc/telepathy/config.toml`, mode 0600).

## Deployment

- Program files live root-owned in `/usr/local/lib/telepathy`; the unit runs
  `python3 -I` on them, so no `PYTHON*` env var or user site-packages can inject
  code into the root process. Config and policy must be root-owned and not
  group/world-writable (the daemon refuses to start otherwise).
- **No extra systemd sandboxing, on purpose.** Approved commands are children of
  the service and inherit its sandbox, so `ProtectSystem`, `ProtectHome`,
  `PrivateTmp`, capability or address-family limits would break the commands the
  human approves (package installs, service restarts, anything under `/home` or
  `/tmp`). Only `NoNewPrivileges` is set. `systemd-analyze security` therefore
  scores the unit as exposed; the controls are the approval step, the policy,
  and the root-owned files, not confinement of approved commands. If a class of
  command is ever routine enough to confine, run it from a separate, sandboxed
  unit rather than weakening this one.
- **Unsupported platforms refuse to start.** `oscompat.check_supported` runs
  first, even with `--insecure-dev`, and stops the daemon unless the platform is
  Linux with `CLOCK_BOOTTIME`, `SO_PEERCRED` and `os.getxattr`, so a port can
  never silently run on a weaker fallback. The library modules keep their
  portable fallbacks so the unit tests run anywhere.
- `install.sh` is re-run safe and never overwrites config or policy;
  `uninstall.sh` keeps them (and the audit log) unless `--purge`.

### Known limitations (path checks)

- The pool of 8 check workers is shared, with a submit quota: submit-time
  checks may hold at most 6 slots in all, so at least 2 stay free for run-time
  checks of approved requests (not capped per uid: a human or an auto rule
  already allowed them). When `allowed_uids` lists several uids, each uid may
  hold at most 3, so one agent's paths on a hung mount only make *its own*
  further submits fail closed (`check_busy`). Agents sharing one uid (the usual
  single-user host) share its quota and can still starve each other's submits,
  and several uids together can still fill the 6 submit slots.
- The daemon runs requests from one serial worker. Each approved request is first
  pre-checked in its own thread (`Broker.precheck`, the same guarded check, no
  state change), and a timeout or busy result there is retried with the usual
  backoff and shares the attempt cap, so a hung path no longer reaches the worker.
  The worker's `begin_run` still checks again right before exec and alone
  decides. Requests reach the worker in pre-check completion order. A mount that
  hangs between the pre-check and `begin_run` can still block the worker once,
  for up to the 5 s limit.

## Approval page trust model

- The page is served on a **root-only unix socket**, never TCP. `tailscale serve`
  (root) proxies tailnet requests to it and sets `Tailscale-User-Login`. A local
  TCP port would let any local process, including the agent, forge that header
  and approve its own request, so the socket's `0600` mode is a security
  boundary and is covered by a test.
- Only a request that matches a login in `approver_logins` **and** comes from a
  device in `approver_ips` may view or decide; everything else gets a 403 and an
  audit record. The device check exists because a local process can connect to
  this machine's own tailnet address and tailscaled stamps it with the machine's
  own identity, which may be the same account as the phone. The source is the
  last `X-Forwarded-For` entry (appended by the proxy; earlier entries are
  client-controlled and ignored), and this machine's own IP is never allowed.
  With either list empty, no web socket exists.
- The command is rendered one argument per line; non-printable-ASCII characters
  are spelled out (`\u{0440}`) so look-alikes and bidi controls can't disguise
  it. The agent's `reason` is shown separately and marked unverified. Command
  output is never shown on the page.
- Approve needs the per-page nonce (a reload invalidates older pages); deny does
  not, and can also revoke an approval that has not started running. CSP
  forbids scripts, framing and cross-origin form posts.
- Still open: approval is bound to the phone's device and unlocked screen, not
  to a fresh biometric check per approval (the passkey work on the roadmap).
  Assumptions about Tailscale worth re-checking whenever it changes: that
  `tailscale serve` appends the peer's address as the last `X-Forwarded-For`
  entry, that a request from this machine to its own tailnet address arrives
  from this machine's IP, and that the `unix:` target works on your version.

## Roadmap

Built (v0.1, Linux with systemd): request model and policy, daemon, client and
admin CLIs, audit log and rate limits, executor with per-command cgroups,
installer and unit, the approval page behind `tailscale serve`, and ntfy or
webhook push.

Next:

1. **macOS (v0.2).** Each platform-specific piece gets a branch in
   `telepathy/oscompat.py` and its call site. Same trust model: `tailscale serve` to a root-only unix
   socket appears to be supported there. Needs macOS versions of peer
   credentials, the ACL checks, a sleep-counting clock, process tracking without
   `/proc` or cgroups, a launchd job instead of the systemd unit, newsyslog
   instead of logrotate, and a bundled Python.
2. **Passkey approval.** A WebAuthn assertion on each approve, so approval needs
   a fresh biometric check, not just an unlocked phone.
3. **Native Windows (later).** `tailscale serve` cannot target a unix socket on
   Windows, so the page would sit on a localhost TCP port where any local
   program could forge the identity header. Windows therefore needs passkey
   approval first, plus owner/ACL checks built on SIDs, a Windows deny list,
   and a decision on how to show a command line that is one string, not argv.

## Prerequisites on the human's side

- Tailscale on this machine and on the phone (one account, one tailnet).
- The ntfy app (iOS or Android) subscribed to a random private topic, or a
  self-hosted ntfy, or any push service reachable through the webhook.
