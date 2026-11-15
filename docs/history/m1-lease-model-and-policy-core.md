# M1 — Lease model and policy core

The [lease model](../lease-model.md) as code in `writ-core`, plus `writ-store`. No network.

- Types for the repo registry, templates, tickets and leases; YAML config loading with
  errors that name the field.
- Canonical encoding of a ticket (the bytes an approval signs), pinned by fixtures.
- Template fit (which template, or why none), narrowing check (signed ⊆ submitted, strict),
  lifecycle state machine, amendments replacing a scope.
- Policy decisions as pure functions: sign request, push (refs, protected refs, force push,
  ledger, size), fetch, limits and rate.
- `CallerFacts` and the lease's caller constraint
  ([Platform interfaces](../architecture/platform.md#caller-facts-and-the-policy)): checked
  purely, missing facts deny.
- SQLite lease store + ledger, JSONL audit log
  ([Policy, state and audit](../architecture/policy-and-state.md)).

**Status:** done on 2026-10-31. Nothing calls this code from the network yet: `writd` wires
it in M2 (tickets, approvals), M3 (signing) and M4 (pushing).

Acceptance checklist, all must pass:
- [x] Table-driven tests for every row of
      [Constraints](../lease-model.md#constraints-and-how-much-to-trust-them) checked by the daemon.
  *`crates/writ-core/tests/constraints.rs`, one table per row: TTL, counts and rate; repo;
  destination ref and protected refs (protected refs win even over a `*` lease); force push
  (non-fast-forward, deletion, creation); pushed commits against the ledger (missing, another
  lease, this lease for another repo); committer identity and object type; the `Writ:`
  trailer; caller = lease holder (`resolve_lease`); origin host advisory; process tree; files
  vs `expected_paths` (`warn`, `deny`, none). Every case asserts the exact `DenyCode`. The
  `direct_ssh` rows (repo through a deploy key, push host through `session-bind`) are checked
  from M10 (since dropped: [why](../backlog/parked/direct-ssh-push-mode.md)); the plan check is in the backlog.*
- [x] Property tests: a narrowed ticket never grants anything the submitted one did not; no
      ticket outside every template is ever accepted; ambiguity (two matching leases) denies.
  *`crates/writ-core/tests/properties.rs` (proptest, 1,024 cases each), checked through the
  real decisions with random and boundary-aimed sign, push and fetch requests, usage, time and
  caller facts: `a_narrowed_ticket_never_grants_more`,
  `no_ticket_outside_every_template_is_accepted` (whatever a ticket allows, its template's
  largest ticket allows), `a_ticket_beyond_its_template_never_fits`, `ambiguity_denies`, plus
  `counters_never_exceed_limits` (counts and the sliding rate window). Checked against
  mutants: removing each narrowing rule (repos, operations, branches, force push, emails,
  expected paths emptied or added, every limit, expiry, subject), a fit rule, the ambiguity
  check, a count or the rate (off by one) each makes a property fail.*
- [x] A lease with a caller constraint denies when the facts lack a process chain, and when
      the chain doesn't contain the required ancestor (executable and generation).
  *`constraints.rs` `process_tree`: no chain (TCP), an empty chain, not in the tree, a reused
  pid (other generation), same pid with another executable, same executable with another
  pid; `process_tree_with_code_identity`: unsigned or other-team processes refused.*
- [x] Canonical encoding fixtures stable across runs; any field change changes the bytes.
  *`crates/writ-core/tests/canonical.rs`: `tests/fixtures/ticket-full.json` (every optional
  field set, a title with quotes, non-ASCII and an escape sequence) and `ticket-minimal.json`
  match byte for byte and decode back; changing each of 33 fields gives 33 distinct byte
  strings; 13 non-canonical variants (whitespace, key order, unsorted or duplicate set, unknown
  or missing field, other kind, size as text, offset timestamp, escaped `/`, `\u` escape) are
  refused by `Ticket::from_canonical`.*
- [x] Leases and ledger survive a reopen of the database; the audit log is append-only and
      holds no secret.
  *`crates/writ-store/tests/store.rs` `leases_and_ledger_survive_a_reopen` (an active lease
  with usage, ledger entries, a pending and a refused ticket, read back from a reopened file);
  `tampered_records_fail_closed` (a ticket widened by hand in SQLite, an unknown state, another
  namespace, a missing signature: refused). `tests/audit.rs`: `the_log_only_grows` across a
  reopen, `a_cut_line_is_kept_and_the_next_event_starts_a_new_line`, and
  `the_log_holds_no_secret`, which scans every line of a full lifecycle (submit to unseal) for
  key material, SSH signatures and tokens.*

## What was done

- `writ-core` (pure, about 3,100 lines with its unit tests):
  - `names`, `units`, `pattern`: validated repo, template and key names, emails, ticket ids
    (`wrt_` + ULID, built from parts the daemon supplies: this crate reads no clock and no
    randomness), commit ids, fingerprints; UTC timestamps with one text form; durations and
    sizes; ref names checked like `git check-ref-format`; branch and ref patterns with exact
    coverage; path globs.
  - `config`: `PolicyConfig::from_yaml` with every error naming its field, and the
    cross-checks (template repos registered, `commit_sign` needs emails and a key, branches
    with signing or pushing, `direct_ssh` settings only with that mode…).
  - `ticket`: `TicketRequest` (what the agent writes), `Ticket` and its canonical bytes.
  - `fit`: `submit` (template choice, defaults, links to the amended lease and the revised
    ticket) and `fits`; `narrow::check`; `lease`: states, transitions, `activate`,
    `apply_amendment`, `refuse`, `due_transition`; `caller::check`.
  - `policy`: `resolve_lease`, `decide_sign`, `decide_push`, `decide_fetch`, `DenyCode` with
    the violation rule, denials with the amendment hint.
- `writ-store` (about 850 lines): `Store` (SQLite, compare-and-set transitions, atomic
  `consume`, ledger, strict decoding) and `AuditLog` (append-only JSONL).
- `make check` and `make test` pass: 99 tests and one opt-in (83 new; about 3,900 lines of
  tests), about 11 s in all. Tests: 13 unit,
  20 constraint tables, 16 lifecycle and narrowing, 6 properties, 5 canonical, 3 config, 5
  guarantee tests at the policy level (`crates/writ-core/tests/guarantees.rs`, one per
  guarantee M1 can reach), 10 store, 5 audit.

## Decisions

All in the [decision log](../decisions.md):

- Canonical encoding: compact JSON, fixed field order, `kind` first, strict decoding.
- Templates cap committer emails, the signing key and force push; every limit is required.
- `expires_at` fixed at submission; pending tickets expire.
- Amendments apply in place (the lease keeps its id, certificate and counters); revisions
  name the refused ticket (`revises`).
- A lease that allows `fetch` is never exhausted (found by a property test, below).
- The ledger records the repo; a push needs an entry for the same lease and repo.
- A lease must still fit its template under the current config; deleting a branch is a force
  push; only branches can be pushed.
- Branch and ref patterns: an exact name or a prefix with one trailing `*`.
- Crates: `rusqlite`, `serde-saphyr` (with `serde_path_to_error`), `proptest`, `jiff`,
  `globset` ([Stack](../stack.md)); `serde_yaml` is deprecated.

## Findings

- **The narrowing property found a real hole** in the first exhaustion rule ("exhausted when
  its counted operations are used up"): a `[fetch, push]` lease with every push used was
  exhausted, but the same ticket narrowed to `[fetch]` was not, so the narrowed lease could
  still fetch. Fixed by never exhausting a lease that allows `fetch`.
- **Random requests make weak properties.** At first the property generators almost never
  produced a request that passed every other check, so removing a narrowing rule went
  unnoticed. The fix: biased tickets (most fit a template), "signed" tickets that change one
  or two fields, probe requests built from the two tickets' own repos, branches, emails, paths
  and limits, and a policy for the properties where the template allows what only the
  narrowing check should refuse. Each property was then checked against mutants.
- `serde-saphyr`'s errors combined with `serde_path_to_error` name the exact field, unknown
  ones included (`templates.feature-branch.max_tll: unknown field`), with line and column.
- Clippy refuses a type with interior mutability as a set key, so `PathPattern` holds only its
  text and a `PathSet` is compiled per decision.
- Carried over: the `UnwrapErr(SysRng)` panic noted in M0 is in `writ-crypto` and untouched
  here; revisit in M2, where certificates are issued on a real path.
