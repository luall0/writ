# History

What was built, in the order it was built: one page each, with what was planned, what was
done, the decisions and the numbers.

The milestones M0 to M10 of the [roadmap](../roadmap.md) (with M2.5, M2.6, M4.5, M7.5) come first: when one is done, its
section moves from the roadmap to a page here (`m<N>-<slug>.md`), its checklist ticked with a
note under each item saying how it was verified, and a row is added below. After v1, work
starts in the [backlog](../backlog/README.md) and its pages move here when done, ending with a
"What was done" section.

| # | Item | What it brought |
|---|---|---|
| 1 | [M0 — Protocol spike](m0-protocol-spike.md) | Go for the stack: certificate-only SSH gateway (TCP and Unix socket), git fetch/push checked by the daemon in git's quarantine, daemon-signed commits through `writ-sign`, agent-held approval keys; local mode's signer chosen (CryptoKit Secure Enclave key under a `_writd` user) |
| 2 | [M1 — Lease model and policy core](m1-lease-model-and-policy-core.md) | `writ-core`: the lease model and every policy decision as pure functions, canonical ticket bytes pinned by fixtures, property-tested narrowing and template fit; `writ-store`: SQLite leases and ledger with atomic counters, append-only JSONL audit log |
| 3 | [M2 — Ticket flow](m2-ticket-flow.md) | The platform traits (portable implementations, fakes, contract suites); the approval service; the approval API over SSH and HTTPS, each optional (Q29); `writ request`, `wait`, `ls`, `sign` (trusted display, narrowing), `refuse`, `revoke`; certificates issued on approval, revocation dropping open sessions; signed or open refusals; Telegram notifications |
| 4 | [M2.5 — Code quality checkup](m2.5-code-quality-checkup.md) | The review after M2 and its fixes (pre-receive input limit, audit before change, gateway denials logged, `writ-sign` never a plain `ssh`, repo scope on fetch); one module per interface and per concern; typed errors, `tracing`, test kits; [code conventions](../conventions.md); hardened tests (no sleeps, exact codes, both sides of limits, seeded proptest); `crates/writ-integration` |
| 5 | [M2.6 — Security checkup](m2.6-security-checkup.md) | The security review after M2.5 and its fixes (no daemon exit on accept errors, revocation re-checked at push and kept across restarts and log failures, reader keys for the approval API, `allow` lists and bounds on every listener, authority files checked, a bounded trusted display, Unicode from categories, hardened YAML, explicit SSH and key types); [security conventions](../security.md); `make ci` with `cargo deny`, CI and a pre-push hook; the guarantee registry; tests that assert exact errors |
