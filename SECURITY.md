# Security

telepathy runs commands as root, so its bugs matter. Please report them
privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the **Security** tab of this
repository, then **Report a vulnerability**. Please do not open a public issue
for anything that could let a command run without the approver's consent.

Useful to include: the version or commit, your distribution and kernel, the
relevant config and policy (with secrets such as the ntfy topic removed), and
the smallest steps that reproduce it.

## What telepathy is meant to stop

The threat model is a **misled or prompt-injected agent** running as an
ordinary user. In scope, for example:

- running anything as root without a matching approval, or running something
  other than the command the approver saw (argv, working directory, or a
  symlink target that changed after approval);
- reusing an approval, approving an expired, cancelled or denied request, or
  approving from anything other than the configured approver device;
- the agent reaching the approval page's socket, forging the identity headers,
  or reading the secrets in `/etc/telepathy`;
- getting past the built-in deny rules (shells, interpreters, wrappers,
  protected paths) by aliasing, symlinks or path tricks;
- a request that hides its real command on the approval page (look-alike
  characters, bidi controls, truncation);
- a timed-out command or its descendants surviving the kill where cgroups are
  available.

## Out of scope

- An attacker who already has root, or who controls the approver's unlocked
  phone or Tailscale account.
- Whatever an approved command does. Approval is the guarantee; check what you
  approve, and remember that a package install runs its scripts as root.
- Commands allowed by `[[auto]]` rules you wrote yourself.
- Denial of service by an allowed local user, within the documented rate limits
  and quotas.

The design, its invariants and the known residual races are in
[DESIGN.md](DESIGN.md).
