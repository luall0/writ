# writ-store

The daemon's state on disk: the lease store and ledger (SQLite), and the audit log (JSONL).

## What it does

- **Tickets and leases** (`store`): every ticket and where it stands, the lease it became, its
  certificate, its counters; state changes are compare-and-set and go through `writ-core`'s
  lifecycle first.
- **The ledger** (`store/ledger`): every commit signed under a lease, for which repo, with
  which key.
- **Strict decoding** (`store/rows`): a row that doesn't decode is an error (fail closed).
- **The schema** (`store/schema`): creation and migrations.
- **The audit log** (`audit`): append-only, one synced line per event; no field can hold a
  secret.

With the `testing` feature: an in-memory store, a breakable audit log (`AuditBreaker`) and the
secret scan used by every crate's tests (`looks_secret`).

## Scope

- Storage only: it records decisions, it never makes one.
- Not here: deciding what to log (the approval service and the gateway), notifications.

## Depends on

`writ-core`.

## Docs

[Policy, state and audit](../../docs/architecture/policy-and-state.md).
