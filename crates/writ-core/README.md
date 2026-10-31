# writ-core

The lease model and every policy decision, as pure functions.

## What it does

- **Configuration** (`config`): the repo registry (hard per-repo limits) and the templates
  (what a ticket may ask for), parsed from YAML with errors that name the field (`yaml`).
- **Tickets** (`ticket`): what the agent asks for (`TicketRequest`) and the complete ticket the
  daemon builds from it (`Ticket`), whose canonical bytes an approval signs (`canonical`).
- **Fit and submission** (`fit`): whether a ticket fits a template and the registry.
- **Narrowing** (`narrow`): what an approver may narrow when signing, never widen.
- **Lifecycle** (`lease`): ticket and lease states, approvals, amendments.
- **Caller facts** (`caller`): what is known about a caller, and the lease's caller constraint.
- **Decisions** (`policy`): sign, push, fetch, with a `DenyCode` and a reason on every denial.
- **Signed documents** (`signed`): refusals and revocations.
- **Validated values** (`names`, `pattern`, `units`) and **safe display of agent text** (`text`).

## Scope

- **Pure**: no I/O, no clock, no randomness, no threads. Time comes in as `now`, ids from
  bytes the caller drew. Every decision is testable as a plain function.
- Not here: storage (`writ-store`), signatures and certificates (`writ-crypto`), the network
  (`writ-gateway`), anything platform-specific (`writ-platform`).

## Depends on

No other crate of the workspace (checked by `tool/check-deps.py`).

## Docs

[Lease model](../../docs/lease-model.md),
[Policy, state and audit](../../docs/architecture/policy-and-state.md),
[Flows](../../docs/flows.md).
