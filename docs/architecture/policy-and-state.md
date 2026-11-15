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
| `decide_sign` | Repo, object kind, committer and author emails and names, `Writ:` trailers, touched paths | Common checks, then: a commit (no tag, tree, blob or other object) in the repo's `object_format`, committer email in the lease, author email in the lease's committer emails (`author`), both names the lease's `committer_name` when it has one (`committer_name`, `author_name`), the trailer if the repo's `ticket_link` is `trailer`, `paths_check` and the expected paths of the repo's terms, the repo's `max_signatures`, rate |
| `decide_push` | Repo, push mode, ref updates (old, new, fast-forward, a twin ignoring case), new commits with their ledger entries and the digest of the paths each touches (computed again from the objects git verified), pack size | Common checks, then: push mode allowed by registry and template (`direct_ssh` never here), each ref valid, updated once (ignoring case), without a twin ignoring case in the repo, not protected, a branch, within the repo's branches in the lease, no force push or deletion unless the repo's terms allow it; every new commit in the ledger for this lease and repo, touching the paths signing saw (when it saw them); size (the smaller of the repo's `max_push_size` and its template's); the repo's `max_pushes`; rate |
| `decide_fetch` | Repo | Common checks, rate (`Service::fetch` then takes one operation of the rate window under the same lock) |

The **common checks** come first in every decision: the lease is active and before
`expires_at`, not exhausted; the caller satisfies the lease's caller constraint
([platform](platform.md#caller-facts-and-the-policy)); the operation is in the lease (in
some repo: otherwise `operation`), the repo is in it (`repo`), and the operation is in that
repo's terms (`operation`, "… not allowed in repo X"); every template and the repo still exist
and the lease still fits its templates under the current config. Each decision then reads the
repo's terms only. Counts and rate come last, so an out-of-scope request gets the out-of-scope
reason; one exception, a signature's path check comes after them (a request at its limit
costs no path match under the lock), so a path refusal there is reported as the count or the
rate, and `on_violation` doesn't fire.

Each denial has a code (`DenyCode`). Out-of-scope codes (operation, repo, push mode, object
type, committer, author, ticket link, paths, ref, protected ref, force push, unsigned
commit, paths changed since signing, size) are **violations** and trigger the lease's `on_violation`; running out of time, counts or
rate, a wrong caller or a config change are not.

Around them: `fit::submit` (a request → a complete ticket, each repo fitting a template and
the lease-wide terms the strictest of them, or every reason why not), `fit::fits` (a ticket
within its templates and the registry, used at
submission, at approval and on every request), `narrow::check` (signed ⊆ submitted),
`lease::activate` / `lease::apply_amendment` / `lease::refuse` (the lifecycle, after the
approval service verified the SSHSIG), `lease::due_transition` (expired or exhausted now).

The daemon takes counts through the store's atomic `consume` after a decision allows, so two
concurrent requests can't both take the last signature.

A signature (`Service::sign`, from the gateway's `writ-sign git <repo>`) runs in three
phases, so the `Signer` never runs under the service's state lock (a slow or hung device
would hold up every approval, wait, refusal and revocation):

1. **Under the lock**: the single active lease, `decide_sign`, then `consume` (the count and
   the rate slot taken). A denial is logged there, and a violation's certificate goes on the
   deny list before the lock is released.
2. **Without the lock**: the signature, through the signer's queue and its deadline
   ([the queue](signer.md#the-queue-in-front-of-a-backend)). No other lock is held either:
   an OpenPGP key's creation time is copied out first, so an admin change that replaces the
   OpenPGP keys never waits for a signature.
3. **Under the lock again**: the lease still the one the decision was made on (same terms:
   an amendment approved meanwhile discards the signature), active, not past `expires_at`,
   its certificate not on the deny list, and still fitting the template in force (a policy
   tightened meanwhile by a signed change discards it, code `config`); then the signed commit's id, the `sign` audit line
   (lease, certificate, repo, commit, committer, warnings) and the ledger entry. Only then
   does the signature leave the daemon; otherwise it is discarded and the denial logged
   ("… (while the commit was being signed); the signature was discarded").

Each call writes one `sign` line. A slot taken is never given back: a signature that fails
(the signer, the audit log, the ledger) or is discarded still used its count and rate slot,
so a failure can't be retried past the limits, and a crash between phases uses a slot and
grants nothing. While a signature is in flight its lease is not marked exhausted by the
sweep (its own slot would make its last check refuse it): the last phase marks it once the
signature is settled. A violation under `on_violation: revoke_lease` revokes the lease (a
`revoke` line with the violation as its reason). A revocation the daemon decides (a
violation, an ended session, a removed approver) that the store can't record keeps its
certificate on the deny list, and each sweep (every request runs one first) records it again
until the store takes it.

`decide_sign` checks the count and the rate before the commit's paths: a request refused for
them never pays for the path match. `recheck_sign` is the same decision without the count,
the rate and the lease's exhaustion, for a signature's last phase (the slot the first phase
took fills them), against the policy in force then (the review after M7.6, A-7). That match is bounded by the ticket: at most 100
`expected_paths` patterns, 16 KiB of them in all, 16 wildcards (`*`, `?`, `[`, `{`) each.

## Lease store + ledger (SQLite)

- Leases and their state ([lifecycle](../lease-model.md#lifecycle))
- **Ledger**: every commit hash signed, with lease ID, repo, key ID, timestamp. Used at push
  time to check that every pushed commit was signed under this lease, for this repo.

Active leases persist across restarts and are reloaded after unsealing ([Q8](../decisions.md)).

Tables (`writ_store::Store`). The state carries its version: `PRAGMA user_version` (the
state version, `STATE_VERSION`, now 12: M6.2's policy shape, the token changes' counts of M7.7,
the record of migrations of M7.9.6) and `formats.ticket_kind` (the ticket format it stores,
`writ-ticket/3`). A new database gets the whole schema at once. **An older state is migrated
in steps** (M7.9.6), by `writd run` only, before anything reads it (`Store::open_migrating`):
the whole database is first copied into `<state_dir>/backups/state-v<N>-<time>.db`
(`VACUUM INTO`, a new file made `0600` in a `0700` directory, a suffix added rather than a
copy written over), then one step per version runs in its own transaction and is recorded
in `migrations` (from, to, when, the copy); the start logs it and writes one `migrate` audit
line. A step that fails is rolled back and stops the start, naming it
(`StoreError::Migration`), the copy untouched. Every other open refuses an older state with the
way to migrate it (`Older`); a state newer than the binary, or older than the first step
(version 11), is refused by every open (`OtherVersion`), and so is another ticket format
(`OtherTicketFormat`): never a silent mix. `writd check-upgrade` reads the version and runs the
steps on a copy (`Store::version_at`, `Store::copy_state`), never on the state.

| Table | Holds |
|---|---|
| `tickets` | One row per ticket: its canonical bytes (as submitted, then as signed), state, feedback, approval (approver fingerprint, namespace, SSHSIG), the session public key it was submitted with, the source it came from (`source`: an IPv4 address, an IPv6 /64 or `local`; what `max_active_per_source` and `writ sign`'s other leases are counted by) and the lease it renews (`renews`). A lease is the row of its first ticket, with the certificate serial, `current_ticket` (the row whose terms are in force: itself, or the last applied amendment), the certificate issued for it, and the closing summary (`summary`) |
| `usage` | `(lease, repo)` → the `signatures` and `pushes` counters of that lease in that repo (M6.1.5, version 9: each repo counted against its own terms; a repo with nothing used yet has no row) |
| `formats` | One row: the ticket format the state holds |
| `token_versions` | A credential id (ASCII lowercase: one count per token file, on a file system that folds case) → how many token changes (`writ-token/3`) were applied for it (version 11, the review after M7.6, A-6). Never deleted, not even when the id leaves the policy and its token file goes: a change names the count it replaces, so it applies once. An id never given a token has no row (count 0) |
| `ops` | One row per allowed operation of a lease, for `max_ops_per_minute` (window: the last 60 s). The daemon's timer sweep deletes rows an hour past the window (`Store::prune_ops`): a clock set back by up to an hour still counts what it must |
| `ledger` | `(commit, lease, repo)` → signer key id, time, the digest of the paths the commit touched as signing computed them (`writ_git::paths::digest`; none when unknown, schema 4). The commit is the id of the commit git writes with the daemon's signature in it (`writ_git::signed`), never the unsigned bytes' id. Signing the same commit again for the same lease and repo keeps the first entry. Under `ticket_link: notes` (schema 5), each entry's `note`: none (not asked for), `pending` once upstream took the commit (with `note_credential`, the credential of that push, which pushes the note), `written` once the note is upstream; a written note stays written |

- Stored tickets are decoded strictly (canonical bytes only), and an approval must be complete
  and under `writ-approval`: a record edited by hand fails closed.
- State changes are compare-and-set (`… WHERE state = <expected>`) and follow the lifecycle;
  applying an amendment updates the amendment and its lease in one transaction, and so does
  granting a renewal (the new lease active, the renewed one `renewed`).
- A lease's chain (`Store::predecessors`: the lease it renews, then that one's…, at most
  10,000) is one recursive query: a push under a renewal accepts the commits its predecessors
  signed, and notes are marked for them too.
- `consume(lease, repo, counter, max)` raises the repo's counter only while it is under the
  limit and the lease is active, and records the operation, in one transaction; `usage`
  returns each repo's counters and the lease's operations in the rate window.
- WAL journal, `synchronous = FULL`, foreign keys on, a 5 s busy timeout.

## Audit log

Append-only JSONL, one line per event: grants, signatures, pushes, denials, revocations, admin
changes, seal/unseal. Each entry carries the lease ID, the session certificate serial, the
approver key fingerprint when relevant, and in local mode the **full process chain** of the
caller ([Identity](identity.md#local-mode-process-chain-checks)).

```json
{"time":"2026-10-31T14:05:09Z","event":"sign","result":"allowed","lease":"wrt_01JD8X","cert":1842,"repo":"omega-code","commit":"9e1c2f…","committer":"user+agent@…","process_chain":["/Applications/Omega Code.app/…/omega","/usr/local/bin/claude","/usr/bin/git","/usr/local/bin/writ-sign"]}
```

Fields (`writ_store::AuditEvent`, empty ones left out): `time`, `event` (`submit`, `grant`
(a renewal's grant names the lease it renews in `reason`), `refuse`, `amend`, `renew` (a lease
ended by its renewal's grant), `dry_run` (a ticket checked as a submission, nothing stored: allowed with the template it fits, or denied with the reasons), `policy` (what a ticket for a repo may ask was read: allowed with the repo, denied for a repo not in the registry), `revoke`, `expire`, `exhaust`, `close` (done: the agent closed
its lease, or added its summary to one that had ended: `reason` says `already <state>`), `connect` (a session certificate presented to the gateway, or a caller turned away), `command` (an exec request the gateway doesn't serve for this caller), `sign`, `push`, `fetch`, `prove` (an agent
signing key's [proof for a remote](approvals.md#proving-a-signing-key-to-a-remote)), `notes`
(a lease's [notes](gateway.md#notes) pushed upstream, or not, one line per lease and push of
the notes ref), `admin`, `seal`, `unseal`, `key` (a key made on the host by `writd recover`,
with its public half), `scan` (a [host key scan](approvals.md#the-daemons-checks): allowed
with the host and port (`<host>:<port>: scanning`) and the approver who signed it, written
before the daemon connects out; then done with the fingerprints read, or denied with why:
the document refused, the host not reached), `check` (an [upstream check](approvals.md#the-daemons-checks):
allowed with each step, or denied with the step that failed and what upstream said)), `result` (`allowed`, `denied`, `done`), `lease`,
`ticket`, `cert`, `approver`, `repo`, `commit`, `refs`, `committer`, `key` (a proof's key, the
credential that pushed notes, a key made), `namespace`, `message_sha256` (a proof's namespace and the
digest of its message, never the message), `count` (how many notes a `notes` line is about, or
how many denials or connections a coalesced line counts),
`code`, `reason`, `warnings`, `source_addr`, `process_chain`.

- `seal` (done): the daemon started sealed. `unseal`: allowed (the approver who signed, or
  "the development keystore, open at start"), or denied with the reason (a signature for
  another boot or daemon, a key not in `approvers`, a wrong passphrase, a keystore that
  doesn't open); never the passphrase. While sealed, a refused request is a `command` line
  (denied, `daemon sealed`), coalesced per source like the other denials before a lease.
- Every text field is cut to 2,048 characters (`…`) when the line is written
  (`writ_store::MAX_FIELD_CHARS`), so what a request carries can't make a line large.
- A lease's denials past 60 lines a minute are counted, not written one by one: the count is
  a line of its own when the minute is over (`writ_approval` `service/coalesced.rs`); so are
  its allowed connections (`connect`), on a budget of their own. Denials before
  authentication are coalesced the same way, per source, by the gateway.
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
