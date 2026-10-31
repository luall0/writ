# writ-approval

The approval service: tickets from submission to decision, and the leases they become.

## What it does

`Service`, shared by the gateway and the daemon's timers, grouped by caller:

- **The agent** (`service/agent`): `submit` (a ticket file and the session key it came with)
  and `wait` (the decision, with the lease and its certificate once signed).
- **The approver** (`service/approver`): `list`, `show`, `approve` (an SSHSIG by a key in
  `approvers`, namespace `writ-approval`, over the canonical bytes of the ticket or a
  narrowing of it), `refuse`, `revoke`.
- **The gateway** (`service/gateway`): `authorize` (a session certificate → its single active
  lease, checked for the operation), and `gateway_denied` (what the gateway turned away on its
  own).
- **Time** (`service/sweep`): expiry, exhaustion, ended sessions.

Every change writes its audit line first; every denial writes one too. Errors are
`ServiceError`; the gateway turns them into the wire `ApiError`.

With the `testing` feature: `testing`, a service on the platform fakes and the approver's
signatures, for every crate's tests.

## Scope

- It gathers facts, verifies signatures, applies decisions and logs them. The decisions
  themselves are `writ-core`'s.
- Not here: the network (the gateway), configuration files and keys (`writd`). Admin changes
  and unsealing come in M5.

## Depends on

`writ-core`, `writ-crypto`, `writ-platform` (the traits only), `writ-proto`, `writ-store`.

## Docs

[Approvals](../../docs/architecture/approvals.md), [Flows](../../docs/flows.md) § 1 and § 5,
[Policy, state and audit](../../docs/architecture/policy-and-state.md).
