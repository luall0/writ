# writ-gateway

The daemon's front door: an SSH server (russh) for agents and the approval API, and the
approval API over HTTPS.

## What it does

- **Connections** (`lib`, `handler`): accepted from a platform `Transport`, the caller attested
  by a `CallerAttestor`; authentication by role (a session certificate for a lease, a plain
  session key for ticket submission, a reader key on the approval listener); one routing
  function decides who may run what (`handler::route`).
- **Limits** (`limits`): connections per listener and per source, the authentication
  deadline, channels per connection, body deadlines, coalesced denials before
  authentication; the listener's allowed sources.
- **The agent and approval commands** (`api`): the same over SSH and HTTPS (`https`).
- **Lease holders' commands** (`exec`): `git upload-pack` / `receive-pack` on the lease's repos
  (`exec/git`, with a clean environment) and `writ-sign` (`exec/sign`).
- **The pre-receive check** (`hook`): git's hook (`hook/client`, run by git as
  `writd hook pre-receive`) asks the daemon (`hook/server`) about the ref updates.
- Open sessions dropped when their lease ends.

Every refusal it makes on its own is logged before the client is told.

## Scope

- Transport, protocol and dispatch. Lease decisions are the approval service's (and
  `writ-core`'s); the gateway never decides policy itself.
- Until M3 and M4: signing uses a key in memory, and pushes are checked only against the
  repo's protected refs.

## Depends on

`writ-approval`, `writ-core`, `writ-crypto`, `writ-platform` (the traits), `writ-proto`.

## Docs

[Gateway, mirrors and upstream](../../docs/architecture/gateway.md),
[Identity](../../docs/architecture/identity.md).
