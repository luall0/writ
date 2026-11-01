# writ-git

Git objects as the daemon reads them from bytes an agent sent: nothing here trusts the agent,
runs `git` or touches a file (M3). Mirrors, quarantine and the upstream pusher join it in M4.

## What it does

- **Object ids** (`object`): computed from an object's bytes, SHA-1 with collision detection
  (git's `sha1dc` algorithm, `sha1-checked`) or SHA-256; never the sender's word.
- **Commits** (`commit`): the bytes git asks to sign, parsed strictly (only the layout git
  writes; a signature already in it, an unknown header, more than 100 parents refused); what
  kind of object a signing request carries.
- **Trailers** (`trailers`): found the way git finds them (`git interpret-trailers --parse`).
- **Trees** (`tree`) and **touched paths** (`paths`): the paths a commit touches, computed from
  the parent commits and trees `writ-sign` sends, each checked against its id; bounded walk.
- **The signed commit** (`signed`): the commit git writes once the signature is in it, and its
  id, which the ledger records.

Tested against the real `git` (`tests/real_git.rs`): parsing, touched paths against
`git diff-tree`, signed ids against the commits git writes (SHA-1 and SHA-256), trailers
against `git interpret-trailers`.

## Scope

- Pure: no I/O, no clock. Decisions are `writ-core`'s.

## Depends on

`writ-core` (ids and object kinds).

## Docs

[Flows](../../docs/flows.md) § 2, [Lease model](../../docs/lease-model.md#rules),
[Gateway](../../docs/architecture/gateway.md).
