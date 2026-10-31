# writ-sign

The `writ-sign` shim: git's `gpg.ssh.program` on agent hosts.

## What it does

- `-Y sign`: sends the object git wants signed to the daemon (`writ-sign git` over the
  gateway, with the session certificate) and writes the armored signature where git expects
  it, after checking it is one.
- Everything else (`-Y verify`, `-Y find-principals`, …): the real `ssh-keygen`.
- The daemon is `git config writ.url`, reached with the SSH command git itself uses
  (`GIT_SSH_COMMAND`, then `core.sshCommand`); never a plain `ssh`, which would offer the
  user's own keys.

## Scope

- A client: the daemon decides whether to sign. No key ever lives on the agent host.
- Wired by `writ init` (M3).

## Depends on

No crate of the workspace (`anyhow` only).

## Docs

[Clients](../../docs/architecture/clients.md#repo-setup-on-an-agent-host),
[Flows](../../docs/flows.md) § 2.
