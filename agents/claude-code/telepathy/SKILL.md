---
name: telepathy
description: Run a command as root while the user is away from the machine, by asking for approval on their phone with `telepathy run`. Use ONLY when you need root (sudo, pacman, apt, systemctl, etc.) AND the user is away, for example when the session has remote control enabled (env CLAUDE_CODE_BRIDGE_SESSION_ID is non-empty). When the user is at the machine, ask them to run the command in their own terminal instead.
---

# telepathy: root commands approved from the user's phone

`telepathyd` runs one exact command as root after the user approves that exact
command on their phone. No password is typed and nothing is handed to you.

## When to use it

Check once, with no side effects: `[ -n "$CLAUDE_CODE_BRIDGE_SESSION_ID" ] && echo away || echo here`.

- **away** (remote control on): use telepathy for every command that needs root. Nobody is at the keyboard to type a password.
- **here**: do not use telepathy. Tell the user the exact command and why, and let them run it in their own terminal. Never ask for, read or handle their password.
- If the signal is unclear (variable unset but the user says they are away), use telepathy only if the user says so explicitly.

## How to run a command

1. Use an absolute path for the executable: `telepathy run -r "<reason>" -- /usr/bin/pacman -S --needed htop`.
2. The reason is shown to the user marked as agent-supplied and unverified: keep it short and factual (one line, say what and why, no persuasion).
3. A request lives about 10 minutes by default. Run it in the background (or with `--no-wait`, then `telepathy status <id>` / `telepathy result <id>`), and tell the user: "Waiting for your approval on the phone: <command> (hash <short hash>)". The short hash is printed in brackets on the first line of `telepathy run`; it is what the user should see on the approval page.
4. Check the background output when notified; do not busy-loop.

## Outcomes

- Exit 0: it ran; the command's own output follows. Otherwise telepathy passes on the command's own exit code, except 125 (below), which means telepathy itself refused or failed.
- Exit 125 with `denied`: the user said no. Stop. Report it and ask what to do. Never resubmit the same or a reworded command to get around a denial.
- Exit 125 with `expired before it could run`: nobody approved in time. Report it and ask; resubmit only if the user says so.
- Exit 125 with a policy reason (refused as a shell, interpreter, wrapper, protected path, symlink problem, and so on): the command is blocked by design. Do not try to disguise it (no `sh -c`, `env`, `xargs`, symlinks, relative paths). Tell the user and propose a different approach.
- Exit 130: interrupted; the request is cancelled. If you abandon a pending request yourself, run `telepathy cancel <id>`.
- "cannot reach telepathyd": the service is down. Report it; do not try to start it with sudo.

## Rules

- One request per root action, kept as narrow as possible (named package, named unit, exact path). Do not batch unrelated actions into one script.
- Never submit shells, interpreters, `sudo`, `su`, `env`, `xargs`, `timeout`, or anything mentioning telepathy itself; the daemon denies these and trying counts as evasion.
- Do not read or print anything under `/etc/telepathy/` (the push topic or webhook URL is a secret), the approval link, or the audit log.
- Unless the user has added `[[auto]]` rules, every request goes to the phone. Never edit `/etc/telepathy/policy.toml` or ask the user to add rules; that is their call.
- Prefer a non-root way when one exists (user-level install, `--user` units) so the user is not interrupted for nothing.
- Package installs run install scripts as root: tell the user which package and why before submitting.
