# Policy, state and audit

Code: decisions in `crates/writ-core` (pure), storage in `crates/writ-store`.

## Policy engine

Every request → find the single active lease matching the caller's certificate → allow / deny
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

## Lease store + ledger (SQLite)

- Leases and their state ([lifecycle](../lease-model.md#lifecycle))
- **Ledger**: every commit hash signed, with lease ID, key ID, timestamp. Used at push time to
  check that every pushed commit was signed under this lease.

Active leases persist across restarts and are reloaded after unsealing ([Q8](../decisions.md)).

## Audit log

Append-only JSONL, one line per event: grants, signatures, pushes, denials, revocations, admin
changes, seal/unseal. Each entry carries the lease ID, the session certificate serial, the
approver key fingerprint when relevant, and in local mode the **full process chain** of the
caller ([Identity](identity.md#local-mode-process-chain-checks)).

```json
{"time":"2026-10-31T14:05:09Z","event":"sign","result":"allowed","lease":"wrt_01JD8X","cert":1842,"repo":"omega-code","commit":"9e1c2f…","committer":"user+agent@…","process_chain":["/Applications/Omega Code.app/…/omega","/usr/local/bin/claude","/usr/bin/git","/usr/local/bin/writ-sign"]}
```

- Allowed **and** denied operations are logged.
- Secrets never reach the log: no key material, passphrases, tokens or full signatures.
- The ledger and the audit log must survive an incident for review: back them up
  ([Deployment](deployment.md)).
