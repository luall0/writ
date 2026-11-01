# writ-sign

The `writ-sign` shim: git's `gpg.ssh.program` on agent hosts.

## What it does

- `-Y sign`: sends the object git wants signed to the daemon (`writ-sign git <repo>` over the
  gateway, with the session certificate), with the parent commits and trees the daemon needs
  to compute the paths it touches (`evidence`), and writes the armored signature where git
  expects it, after checking it is one.
- Everything else (`-Y verify`, `-Y find-principals`, …): the real `ssh-keygen`.
- The daemon is `git config writ.url`, the repo `writ.repo`, reached with the SSH command git
  itself uses (`GIT_SSH_COMMAND`, then `core.sshCommand`); never a plain `ssh`, which would
  offer the user's own keys.
- The daemon's words reach the agent escaped; when ssh itself fails, the session certificate
  says whether there is no lease, an expired one, or one the daemon refused (`diagnose`).

## Scope

- A client: the daemon decides whether to sign. No key ever lives on the agent host.
- Wired by `writ init`.

## Depends on

`writ-core` (text escaping, timestamps), `writ-crypto` (reading the certificate),
`writ-proto` (the request body). Never on the daemon's crates (checked).

## Docs

[Clients](../../docs/architecture/clients.md#repo-setup-on-an-agent-host),
[Flows](../../docs/flows.md) § 2.
