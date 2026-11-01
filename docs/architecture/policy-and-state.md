# Policy, state and audit

Code: decisions in `crates/writ-core` (pure), storage in `crates/writ-store`.

## Policy engine

Every request → find the single lease matching the caller's certificate → allow / deny
+ notify. It's the only place where decisions are made.

- **Fail closed**: no matching lease, more than one, a sealed daemon, an unreadable config or
  any internal error → deny.
- The decision itself is a pure function in `writ-core` (request facts + lease + registry +
  template + counters → decision with a reason); the daemon gathers the facts and applies the
  result. Keeping it pure keeps it exhaustively testable.
- Denials carry a reason the agent can read and a hint (e.g. submit an amendment), see
  [Flows](../flows.md#6-out-of-ticket-request).
- The constraints it checks, and how much each can be trusted, are listed in
  [Lease model](../lease-model.md#constraints-and-how-much-to-trust-them).

### The decisions (`writ_core::policy`)

| Function | Input facts | Checks, in order |
|---|---|---|
| `resolve_lease` | Certificate key id, serial, session key fingerprint | Exactly one lease matches all three |
| `decide_sign` | Repo, object kind, committer email, `Writ:` trailers, touched paths | Common checks, then: a commit (no tag, tree, blob or other object), committer email in the lease, the trailer if the repo's `ticket_link` is `trailer`, `paths_check`, `max_signatures`, rate |
| `decide_push` | Repo, push mode, ref updates (old, new, fast-forward), new commits with their ledger entries, pack size | Common checks, then: push mode allowed by registry and template (`direct_ssh` never here), each ref valid, not protected, a branch, within the lease's branches, no force push or deletion unless allowed; every new commit in the ledger for this lease and repo; size; `max_pushes`; rate |
| `decide_fetch` | Repo | Common checks, rate |

The **common checks** come first in every decision: the lease is active and before
`expires_at`, not exhausted; the caller satisfies the lease's caller constraint
([platform](platform.md#caller-facts-and-the-policy)); the operation and the repo are in the
lease; the template and the repo still exist and the lease still fits its template under the
current config. Counts and rate come last, so an out-of-scope request gets the out-of-scope
reason.

Each denial has a code (`DenyCode`). Out-of-scope codes (operation, repo, push mode, object
type, committer, ticket link, paths, ref, protected ref, force push, unsigned commit, size)
are **violations** and trigger the lease's `on_violation`; running out of time, counts or
rate, a wrong caller or a config change are not.

Around them: `fit::submit` (a request → a complete ticket fitting one template, or every
reason why not), `fit::fits` (a ticket within its template and the registry, used at
submission, at approval and on every request), `narrow::check` (signed ⊆ submitted),
`lease::activate` / `lease::apply_amendment` / `lease::refuse` (the lifecycle, after the
approval service verified the SSHSIG), `lease::due_transition` (expired or exhausted now).

The daemon takes counts through the store's atomic `consume` after a decision allows, so two
concurrent requests can't both take the last signature.

A signature (`Service::sign`, from the gateway's `writ-sign git <repo>`) runs under the
service's state lock: the single active lease, `decide_sign`, the signature through the
`Signer`, then the `sign` audit line (lease, certificate, repo, commit, committer, warnings),
`consume` and the ledger entry. The signature leaves the daemon only after all three; a
signer or audit-log failure signs nothing, counts nothing and records nothing. A violation
under `on_violation: revoke_lease` revokes the lease (a `revoke` line with the violation as
its reason).

## Lease store + ledger (SQLite)

- Leases and their state ([lifecycle](../lease-model.md#lifecycle))
- **Ledger**: every commit hash signed, with lease ID, repo, key ID, timestamp. Used at push
  time to check that every pushed commit was signed under this lease, for this repo.

Active leases persist across restarts and are reloaded after unsealing ([Q8](../decisions.md)).

Tables (`writ_store::Store`, schema version in `PRAGMA user_version`, now 2; an older one is migrated in one transaction, a newer one is refused):

| Table | Holds |
|---|---|
| `tickets` | One row per ticket: its canonical bytes (as submitted, then as signed), state, feedback, approval (approver fingerprint, namespace, SSHSIG), the session public key it was submitted with (schema 2). A lease is the row of its first ticket, with the certificate serial, the `signatures` and `pushes` counters, and `current_ticket`: the row whose terms are in force (itself, or the last applied amendment), and the certificate issued for it (schema 2) |
| `ops` | One row per allowed operation of a lease, for `max_ops_per_minute` (window: the last 60 s) |
| `ledger` | `(commit, lease, repo)` → signer key id, time. The commit is the id of the commit git writes with the daemon's signature in it (`writ_git::signed`), never the unsigned bytes' id. Signing the same commit again for the same lease and repo keeps the first entry |

- Stored tickets are decoded strictly (canonical bytes only), and an approval must be complete
  and under `writ-approval`: a record edited by hand fails closed.
- State changes are compare-and-set (`… WHERE state = <expected>`) and follow the lifecycle;
  applying an amendment updates the amendment and its lease in one transaction.
- `consume` raises a counter only while it is under the limit and the lease is active, and
  records the operation, in one transaction.
- WAL journal, `synchronous = FULL`, foreign keys on, a 5 s busy timeout.

## Audit log

Append-only JSONL, one line per event: grants, signatures, pushes, denials, revocations, admin
changes, seal/unseal. Each entry carries the lease ID, the session certificate serial, the
approver key fingerprint when relevant, and in local mode the **full process chain** of the
caller ([Identity](identity.md#local-mode-process-chain-checks)).

```json
{"time":"2026-10-31T14:05:09Z","event":"sign","result":"allowed","lease":"wrt_01JD8X","cert":1842,"repo":"omega-code","commit":"9e1c2f…","committer":"user+agent@…","process_chain":["/Applications/Omega Code.app/…/omega","/usr/local/bin/claude","/usr/bin/git","/usr/local/bin/writ-sign"]}
```

Fields (`writ_store::AuditEvent`, empty ones left out): `time`, `event` (`submit`, `grant`,
`refuse`, `amend`, `revoke`, `expire`, `exhaust`, `close`, `connect` (a session certificate presented to the gateway, or a caller turned away), `command` (an exec request the gateway doesn't serve for this caller), `sign`, `push`, `fetch`, `admin`,
`seal`, `unseal`), `result` (`allowed`, `denied`, `done`), `lease`, `ticket`, `cert`,
`approver`, `repo`, `commit`, `refs`, `committer`, `code`, `reason`, `warnings`,
`source_addr`, `process_chain`.

- Allowed **and** denied operations are logged, including what the gateway turns away on its
  own (a caller the attestor can't attest, a command it doesn't serve, an unknown repo, a ref
  update or a signature it refuses).
- A grant is logged **before** it is made: the line is written (and synced), then the state
  changes. If the change then fails, a `denied` line with the reason follows. So nothing is
  granted, applied, submitted or refused without its line; when the log can't be written,
  those are refused.
- A **reduction of privilege** (revocation, withdrawal, expiry, exhaustion, an ended session)
  never waits for the log: the certificate goes on the deny list first, the line is written
  first when the log can take it, and otherwise kept in memory (up to 10,000 lines) and
  written, in order, as soon as it can, with an error in the daemon's log meanwhile.
- A request about a ticket that doesn't exist (approve, refuse, revoke) is logged as denied
  (`no such ticket`).
- Secrets never reach the log: no key material, passphrases, tokens or full signatures. No
  field of `AuditEvent` can hold one (an approval is logged by its approver's fingerprint).
- The file is only ever opened for appending; each event is one write followed by a sync. If
  the last line was cut by a crash, or a write failed part way (a full disk), the next event
  starts on a new line and nothing is rewritten.
- Characters a terminal could act on (C1 controls, bidi, zero-width, tags: the same set as
  `writ sign` escapes) are written as JSON `\u` escapes, so `cat` on the log is safe; the
  text reads back the same.
- The log and `leases.db` are created `0600`, whatever the umask.
- The ledger and the audit log must survive an incident for review: back them up
  ([Deployment](deployment.md)).
