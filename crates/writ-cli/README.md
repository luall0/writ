# writ-cli

The `writ` binary, for both sides.

## What it does

- **The agent's side** (`agent`): `writ request` (a new session key, the ticket submitted, the
  decision awaited) and `writ wait`; session files in `~/.writ/sessions/<lease>/` (`session`),
  the daemon's signing key among them (`signing_key.pub`).
- **The approver's side** (`approver`): `writ ls`, `writ sign` (the trusted display, narrowing
  flags, a signature by the approval key through the approver's agent), `writ refuse`,
  `writ revoke`. `approver/signer` runs `ssh-keygen -Y sign` with only the approval key's
  public half; `approver/narrowing` checks a narrowing never widens (a convenience).
- **The trusted display** (`display`): agent-written text escaped and behind a gutter, so it
  can never pass for a line `writ` wrote.
- **Talking to the daemon** (`client`, `https`): over SSH with the pinned host key, or HTTPS
  with the pinned certificate; never the user's `~/.ssh`, config or agent.

## Scope

- A client: every check it makes is a convenience; the daemon checks again (hard rule 1).
- Never touches personal keys: only the dedicated approval key, through the agent.

## Depends on

`writ-core`, `writ-crypto`, `writ-proto`. Never on the daemon's crates (checked).

## Docs

[Clients](../../docs/architecture/clients.md),
[Approvals](../../docs/architecture/approvals.md#writ-sign-the-trusted-display).
