# History

What was built, in the order it was built: one page each, with what was planned, what was
done, the decisions and the numbers.

The milestones M0 to M10 of the [roadmap](../roadmap.md) come first: when one is done, its
section moves from the roadmap to a page here (`m<N>-<slug>.md`), its checklist ticked with a
note under each item saying how it was verified, and a row is added below. After v1, work
starts in the [backlog](../backlog/README.md) and its pages move here when done, ending with a
"What was done" section.

| # | Item | What it brought |
|---|---|---|
| 1 | [M0 — Protocol spike](m0-protocol-spike.md) | Go for the stack: certificate-only SSH gateway (TCP and Unix socket), git fetch/push checked by the daemon in git's quarantine, daemon-signed commits through `writ-sign`, agent-held approval keys; local mode's signer chosen (CryptoKit Secure Enclave key under a `_writd` user) |
| 2 | [M1 — Lease model and policy core](m1-lease-model-and-policy-core.md) | `writ-core`: the lease model and every policy decision as pure functions, canonical ticket bytes pinned by fixtures, property-tested narrowing and template fit; `writ-store`: SQLite leases and ledger with atomic counters, append-only JSONL audit log |
| 3 | [M2 — Ticket flow](m2-ticket-flow.md) | The platform traits (portable implementations, fakes, contract suites); the approval service; the approval API over SSH and HTTPS, each optional (Q29); `writ request`, `wait`, `ls`, `sign` (trusted display, narrowing), `refuse`, `revoke`; certificates issued on approval, revocation dropping open sessions; signed or open refusals; Telegram notifications |
