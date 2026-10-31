# writ-integration

Test-only: the crates and the binaries working together, with the real local tools and no
external service. Nothing depends on this crate (checked).

## What it does

- **The harness** (`src/`): a check that `git` and OpenSSH are recent enough, the workspace
  binaries, a throwaway `ssh-agent` (standing in for the approver's Secretive), a fake
  Telegram Bot API, waits with deadlines, the real `writd` on a temporary configuration (its
  ports read from its own log) with the `writ` CLI for both sides, and the gateway in-process.
- **The scenarios** (`tests/`): each milestone's acceptance items, end to end through the
  binaries: `ticket_flow` (M2), `gateway_git` (the gateway with real git and ssh), `interop`
  (`writ-crypto` against `ssh-keygen` and `ssh-agent`).

## Scope

- Local only: the real `git`, `ssh`, `ssh-keygen`, `ssh-agent`, `nc`, and the workspace
  binaries (`make test` builds them first). Docker and real forges are the end-to-end level
  (`make e2e`, from M4).
- Never the user's `~/.ssh`, git configuration or agent; what needs a human (Touch ID) is in
  the manual checks.

## Docs

[Testing](../../docs/testing.md), [manual checks](../../docs/guides/manual-checks.md).
