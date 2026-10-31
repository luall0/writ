# writ-proto

The messages between the clients (`writ`, `writ-sign`, approver apps) and the daemon.

## What it does

- **Commands** (`command`): every command as an SSH exec line (`writ approve <id>`) and, for
  the approval API, an HTTPS route (`POST /v1/tickets/<id>/approve`), parsed strictly.
- **The envelope** (`envelope`): one JSON reply, `{"ok": …}` or `{"error": {"message",
  "reasons"}}`, and request bodies.
- **Messages** (`messages`): each command's reply and body (`Submitted`, `Decision`, `Shown`,
  `ApproveRequest`, …). Tickets travel as their canonical bytes in a string, so a client can
  decode and sign exactly them.
- The protocol constants: the SSH users (`LEASE_USER`, `CLIENT_USER`), `MAX_BODY`.

## Scope

- Message shapes and parsing only: no transport, no policy, no I/O.
- Shared by clients and the daemon, so it depends on nothing a client must not see.

## Depends on

`writ-core` (ids, states, units) only.

## Docs

[Clients](../../docs/architecture/clients.md),
[Approvals](../../docs/architecture/approvals.md),
[Gateway](../../docs/architecture/gateway.md).
