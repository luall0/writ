# M3 — Signed commits

[Flows § 2](../flows.md#2-signed-commit): commits signed by the daemon under a lease.

- The gateway's `sign` command: parse the commit bytes, check lease, limits, rate, committer
  email, object type (commits only, no tags: [Q11](../decisions.md)), `ticket_link: trailer`,
  `paths_check` against `expected_paths`; sign through the `Signer`; append to the ledger.
- `writ-sign` shim; `writ init` writes the remote, signing config and `core.sshCommand`
  ([repo setup](../architecture/clients.md#repo-setup-on-an-agent-host)).
- Added during the milestone, after a discussion with the user: `writ init` in wrapper mode
  by default (the operator's own git untouched), each repo's `object_format` in the
  registry, an [operator guide](../operators/good-practice.md), and "remote" in place of "forge" in
  the docs.

**Status:** done on 2026-11-01, in five `feat:` steps, two `docs:` commits, and a test fix
found on the way.

## What was done

**Step 1, `writ-git`** (new, pure): git objects from an agent's bytes. Object ids computed,
never taken: SHA-1 with collision detection (`sha1-checked`, git's `sha1dc` algorithm) or
SHA-256. Commits parsed strictly (only the layout git writes; a signature already in it, an
unknown header or more than 100 parents refused). Trailers found the way git finds them.
Trees parsed strictly, and the paths a commit touches computed from **evidence**: the parent
commits and trees `writ-sign` sends, each read only by the id computed from its bytes, in a
walk bounded to 1,000,000 entries, 100,000 paths and 256 levels. The id of the commit git
writes once the signature is in it (`gpgsig` header, as `do_sign_commit` builds it), which is
what the ledger records. Tested against the real `git` in SHA-1 and SHA-256 repositories.

**Step 2, `writ-signer`** (new): the `Signer` trait (`list_keys`, `sign` returning an
SSH-encoded signature, `capabilities`), `sshsig` over any backend, the software backend
(Ed25519 and P-256, wiped on drop, never printed), the contract suite every backend runs and
a signer that fails on demand (feature `testing`).

**Step 3, signing in the daemon.** `Service::sign`: under the state lock, the single active
lease, the policy's `decide_sign`, the signature through the `Signer` with the template's
`signing_key`, then the `sign` audit line, `consume` and the ledger entry; the signature
leaves only after all three. `on_violation: revoke_lease` applied. The service refuses to
start when a template's signing key isn't in the signer; the dev keystore makes one key per
template key id. The gateway's `writ-sign git <repo>` takes a framed `writ-sign/1` body (the
object, then evidence; 16 MiB, 100,000 objects), decoded and parsed off the async threads.
The grant carries the lease's signing public key (`signing_key.pub` in the session).
`writ-sign` gathers the evidence (`git cat-file --batch`, `diff-tree`, `ls-tree`), reads the
repo from `writ.repo`, prints what the daemon and ssh say escaped, and on ssh's own failure
explains from the session certificate (no lease, expired, refused).

**Step 4, `writ init`.** Wrapper mode by default: only `<git common dir>/writ/config` is
written; the agent runs any git command through `writ git …` (or a program through
`writ exec -- …`), the settings passed through the environment (`GIT_CONFIG_COUNT`,
`GIT_SSH_COMMAND`), so the operator's git in the same clone keeps their key, email and
remotes. `--whole-repo` writes the settings in the repo's config for a clone dedicated to an
agent, recording what they replace; `--undo` takes either back exactly. Both modes share one
set of settings (`commit.gpgSign`, `tag.gpgSign = false`, the session's SSH command with
`BatchMode`, the lease's email…).

**Step 5, `object_format`.** Each repo in the registry names its object format (`sha1`, the
default, or `sha256`); a commit is signed only in its repo's format
(`DenyCode::ObjectFormat`). The M4 roadmap gained a push-time check of the touched paths on
the objects git verified in the quarantine.

**Docs**: this page, the [operator guide](../operators/good-practice.md), the M6 note (one skill,
always `writ git`), and a separate commit replacing "forge" with "remote" (or GitHub,
Codeberg, Forgejo, GitLab…) outside the history pages.

**Numbers**: 87 files changed by the five steps, about 6,300 lines added (1,650 in the two new
crates). New tests: 21 in `writ-git` (5 against the real `git`), 4 in `writ-signer`, 3 for
the body format, 9 for `Service::sign`, 1 in the gateway, 5 in `writ-sign`, 6 in `writ-cli`
(settings, environment, endpoints, `-C`), 1 for the dev keystore, 3 more in `writ-core`
(object kinds and formats), 10 integration scenarios (`signed_commits.rs`, `writ_init.rs`).

## Decisions

Each has its row in the [decision log](../decisions.md) (2026-11-01):

- **Touched paths from evidence checked by its ids**: the daemon has no copy of the agent's
  repository when it signs (the commit isn't written yet), and paths the client would list
  itself could say anything. The client can leave objects out, never change one. A merge
  touches what differs from every parent (what the merge itself changed, like `git diff-tree
  -c`).
- **The ledger holds the signed commit's id**: the unsigned bytes' id is also the id of the
  same commit made without a signature.
- **The sign command names the repo** (`writ.repo`): the policy needs it, the ledger records it.
- **One call, one line**: `Service::sign` decides, signs and records under one lock, and logs
  once (no separate per-command `authorize` line for signing).
- **`writ-sign` explains refused sessions locally**: the gateway refuses ended leases'
  certificates during authentication, where SSH carries no reason; accepting them to explain
  would widen what an ended lease reaches.
- **`on_violation: revoke_lease` applied** now that a decision can find a violation.
- **Wrapper mode by default** (with the user): `core.sshCommand` and the signing settings cover
  a whole repo, so writing them took the operator's `origin` and signing over. Worktrees were
  set aside (they don't share ignored files), and so was a temporary overwrite of the config
  (shared state, an undo an agent can forget). Every git command goes through `writ git`,
  since rebase, cherry-pick and amend make commits too. The operator protects their own keys
  (user presence); deny lists in agents' configs are guardrails.
- **SHA-1 allowed by default, the format explicit per repo** (with the user): SHA-1 off by
  default would be switched on for nearly every repo (GitHub has only SHA-1 repositories); the
  risk is bounded (collision detection, the lease's other checks, M4's push-time check).
- **"Remote", not "forge"** (the user's wording).

## Findings

- **git folds identical `--trailer`s into one** (`trailer.ifExists = addIfDifferentNeighbor`):
  the "two trailers" test writes them in the message.
- **A disconnect overtakes a channel's last messages in russh**: revoking a lease for a
  violation dropped the session before the agent got the reason. The requesting connection
  now ends by itself (refused by the deny list meanwhile); the others are dropped at once.
- **A failed audit log at the allow step left no denial line**: the denial is now kept and
  written when the log works again, like every other denial.
- **The tree walk ran on an async worker**: moved, with the decoding, into the blocking task.
- **A flaky test from M2.6**: the accept-retry test counted log lines through a scoped
  `tracing` subscriber, and another test running the same line on another thread could leave
  it cached as unheard (about one run in eight). Fixed in its own commit: the warn-once
  decision is a small type the test checks directly.
- **A global pre-commit check refuses home-directory paths** (`/home/<user>`): test paths
  use `/opt/agent`.

## The security checklist, for M3

1. **Inputs**: new ones (the sign command's repo, the `writ-sign/1` body, the commit, the
   evidence objects, `object_format` in the registry) are in the
   [inventory](../security.md#untrusted-inputs) with their bounds, strict parsers and hostile
   tests (`refuses_anything_else` ×3, `refuses_malformed_trees`,
   `evidence_is_only_what_its_bytes_hash_to`, `a_shared_subtree_cannot_blow_up_the_walk`,
   `depth_is_bounded_on_both_sides`, `bounds_on_both_sides`,
   `a_sign_request_that_isnt_one_is_refused_and_logged`).
2. **Authority**: no new way to grant; signing goes through the policy within the lease and its
   template, and the key is the template's. `writ init`'s settings are a client convenience.
3. **Fail closed**: unknown paths deny under `deny`; a malformed body, commit or tree, an
   unknown or other object format, a missing signing key, a signer or audit failure deny;
   non-commits are refused after the lease checks; an unwired repo refuses `writ git`.
4. **Audit**: one `sign` line per decision, allowed lines before the signature leaves;
   gateway refusals logged; a violation's revocation logged with its reason.
5. **Revocation**: a violation revokes the lease (deny list first); every signature re-checks
   the lease and the deny list under the lock.
6. **Secrets**: signing keys stay in the `Signer` (no key in `Debug` or errors, tested); the
   agent gets the public key only; `writ init`'s record holds no key.
7. **Display**: the daemon's and ssh's words escaped by `writ-sign`; denial paths may hold
   anything.
8. **Dependencies**: `sha1-checked` 0.10 (RustCrypto, `std` only), row in
   [stack.md](../stack.md); `cargo deny` passes.
9. **Guarantees**: three new guarantees (commits only, in their repo's format, with their
   trailer; paths with `deny`; the ledger holds the signed commit) and new tests on four
   existing ones.
10. **Threat model**: one new residual risk (SHA-1 repositories, the default: the touched
    paths rest on SHA-1 ids with collision detection, checked again at push from M4), and the
    operator's own credentials stated as outside what Writ guarantees; both with the user.

## Acceptance

- [x] In a repo wired by `writ init`, `git commit -S` works without any prompt and
      `git verify-commit` passes with the agent key in `allowed_signers`.
  *Both modes, with the real `writd`, `writ request` and `writ sign --yes`, stdin closed and
  `BatchMode`: in wrapper mode (`wrapper_mode_signs_through_writ_git_and_leaves_the_operator_s_git_alone`)
  `writ git commit` is signed by the daemon and verifies with `signing_key.pub`, while the
  operator's plain `git commit -S` in the same clone is signed with the operator's key and
  their `origin` push works; `writ git rebase` signs the rewritten commits again. In
  `--whole-repo` (`whole_repo_mode_wires_a_dedicated_clone_and_undo_restores_it`) plain
  `git commit` is signed (`commit.gpgSign`). `--undo` leaves the config as it was. Ed25519
  and P-256 signing keys: `*_commits_signed_by_the_daemon_verify_and_are_in_the_ledger`.*
- [x] Denied cases each fail with the reason printed in the agent's terminal: no lease,
      expired, over `max_signatures`, over the rate, wrong committer email, a tag, a missing or
      wrong `Writ:` trailer, paths outside `expected_paths` with `paths_check: deny`.
  *Each through real `git`, `ssh` and `writ-sign`, asserting git's exit status (128), the reason
  in its stderr and the audit line's code: `what_the_commit_says_is_checked` (committer, missing,
  another lease's and two trailers, a tag), `paths_outside_the_ticket_are_refused_with_paths_check_deny`,
  `signatures_stop_at_the_lease_s_count_and_rate`, `no_lease_an_expired_or_a_revoked_one_says_why`
  (no certificate, one past its end, a revoked lease: explained by `writ-sign`, since the gateway
  refuses those during authentication). The same cases with exact `DenyCode`s on the fake clock,
  expiry to the second: `crates/writ-approval/tests/sign.rs`.*
- [x] `paths_check: warn` signs and records the warning for the activity report.
  *`whole_repo_mode_wires_a_dedicated_clone_and_undo_restores_it`: a commit touching `README`
  outside `src/**` is signed, its `sign` line carries `warnings: ["files outside
  expected_paths: README"]`; unknown paths give "paths not checked"
  (`paths_outside_the_ticket_warn_or_deny`).*
- [x] Every signed commit is in the ledger with its lease and key.
  *Read from the daemon's `leases.db` in the end-to-end scenarios (every commit, lease, repo
  `demo`, key `agent-01`, in order; the rebase's two new ones too) and the in-process ones;
  the id is the commit git wrote, not the unsigned bytes'
  (`a_commit_is_signed_counted_and_recorded_as_git_writes_it`,
  `the_signed_id_is_the_commit_git_writes`).*

`make ci` passes on macOS after every commit. No manual check is new: the only human step is
the ticket's approval, M2's [Secretive check](../guides/manual-checks.md); its optional step
5b signs a commit by hand.

## The review after M3

A security and code-quality review of the whole milestone (`6daf751..568c055`), on
2026-11-01, read by hand; its most serious finding was reproduced with a harness against
`writ-git` before it was fixed. Every finding below was fixed in seven `M3 review step` commits
and this page, except F5 (signing outside the lock), which became [M3.5](../roadmap.md#m35--signing-outside-the-lock),
and one question settled with the user (Q34, step 10). `make ci` passed after each step.

| # | Severity | Finding | Fix | Verified by |
|---|---|---|---|---|
| F1 | High | The touched-paths walk was bounded in entries, paths and depth but not in bytes: one long directory name over many files made it hold the name once per file (1 MB sent → 200 MB held, measured; a 16 MiB request → hundreds of GB). And the gateway decoded and walked a request before any lease check | Step 1: no path over 4,096 bytes, 64 MiB of paths in all, one error per bound. Step 3: `Service::may_sign` (active lease, `commit_sign`, the repo) before the body is read | `long_names_cannot_blow_up_the_walk`, `path_length_is_bounded_on_both_sides`, `path_bytes_are_bounded_on_both_sides`, `paths_are_bounded_on_both_sides`, `entries_are_bounded_on_both_sides`; `a_lease_that_cannot_sign_is_refused_before_its_request_is_read`, and garbage for a repo outside the lease refused with the lease's reason (`a_sign_request_that_isnt_one_is_refused_and_logged`) |
| F2 | Medium | A committer email as large as the request was logged and repeated in the denial; the paths shown had no bound; denied requests don't count against the rate | Step 4: every audit text field cut to 2,048 characters when written; agent values shown cut to 256 characters. Step 10 (Q34, with the user): a lease's denials past 60 lines a minute counted, the count logged when the minute is over | `every_text_in_a_line_is_bounded_on_both_sides`, `agent_text_stays_short_in_denials_warnings_and_the_log` (a 1 MiB email, a 4,000-byte path), `a_lease_s_denials_are_counted_past_sixty_lines_a_minute` (both sides of the budget and of the window) |
| F3 | Medium | A merge touched "what differs from every parent": a merge whose tree is its second parent's touched nothing, so a merge could bring in any file unchecked; and each commit is checked only against its own (agent-chosen) parent | Step 1, with the user: a merge is compared with its first parent; `writ-sign` sends that parent only. A made-up unsigned parent is stopped at push (an M4 acceptance case now) | `a_merge_is_checked_against_its_first_parent`; `touched_paths_are_git_s` against `git diff-tree <merge>^1 <merge>` |
| F4 | Low/Medium | A violation released the lock before revoking: another request could slip in, and a revocation failing early left the certificate accepted | Step 5: the certificate on the deny list before the lock is released | `a_violation_bars_the_certificate_even_when_its_revocation_fails` (step 8: the revocation's lease lookup made to fail with a `StoreBreaker`; the test fails without the fix); a request waiting on the lock during a violation: M3.5's blocking signer |
| F5 | Low | The signer runs under the service's state lock | [M3.5](../roadmap.md#m35--signing-outside-the-lock): three phases and a `QueuedSigner` | — |
| F6 | Low | A push certificate or garbage counted as an object-type violation, revoking a lease under `revoke_lease` | Step 5: only a tag is a violation; anything else is `invalid` | `committer_identity_and_object`, `signatures_only_for_allowed_committer_identities`, `only_what_the_lease_allows_is_signed` |
| F7 | Low | A tree entry read as `.git` by some filesystem was accepted | Step 2: refused as git's `verify_path` reads it, and the gateway refuses the commit whatever `paths_check` says; M4 sets `receive.fsck.hasDotgit = error` (git only warns: checked with git 2.54) | `refuses_malformed_trees` (every spelling), `a_dot_git_entry_is_refused_whatever_paths_check_says` |
| F8 | Low | `writ git` / `writ exec` pass the wiring to every git their process runs, in any repository | Step 6: the operator guide and `clients.md` say so. Step 9: `writ init` records the repo's git common dir (`writ.gitdir`), and `writ-sign` refuses a commit made in any other repository | `wrapper_mode_signs_through_writ_git_and_leaves_the_operator_s_git_alone` (a commit `writ exec` makes in another clone is refused, nothing signed), `the_same_directory_through_a_link`, `writes_exactly_the_documented_config` |
| Q1–Q2 | Low | Two `Option`s and a namespace field the service had to trust agreed with the gateway's parsing | Step 5: `SignObject`; the service builds the policy's request from the commit; the namespace is always `git` there | The sign suite, rewritten on `SignObject` |
| Q3 | Low | One allocation per byte of every object id | Step 1: one per id | The `writ-git` suite |
| Q4 | Low | The signer was built in `main.rs`, not `platform.rs` (hard rule 4) | Step 7 | `make ci` |
| Q5 | Low | ssh's exit 255 read as "refused" even when the daemon was down; the lease id unescaped | Step 6 | `a_valid_certificate_says_both_causes`, `no_lease_an_expired_or_a_revoked_one_says_why` |
| Q6 | Low | `writ init --undo` ignored every `--unset-all` failure | Step 6: only "not set" passes | `whole_repo_mode_wires_a_dedicated_clone_and_undo_restores_it` (a locked config changes nothing) |
| Q7–Q8 | Low | Idents not checked as their error said; a signature without its last newline | Step 2 | `refuses_anything_else` (times, zones), `a_signature_must_end_its_last_line` |
| Q9 | Low | `writ-sign` read every tree before checking the budget | Step 1: stops at the budget | `reading_stops_at_the_budget_on_both_sides` |

**Docs drift** found by the review and fixed with each step: the security inventory (walk and
body bounds), the threat model (the paths guarantee and its tests, three residual risks: the
signer under the lock until M3.5, a hidden `.git` entry until M4; a denial flood, settled by
step 10), the lease model (merges, violations), the decision log (one row per step, Q34), flows § 2,
gateway, clients, platform, the operator guide, the roadmap (M3.5, and M4's ledger schema,
`hasDotgit`, mirror `object_format`, the made-up parent). The classes of mistake behind the
findings became general rules in the [security conventions](../security.md) (and its
checklist), the [code conventions](../conventions.md) and the [test rules](../testing.md#hardened-tests).

### The security checklist, for the review

1. **Inputs**: evidence bounded in path length and bytes; trees refuse `.git`; idents checked;
   the sign body read only for a lease that may sign; every new bound tested on both sides.
2. **Authority**: nothing new grants.
3. **Fail closed**: a walk past a bound, a `.git` entry, a malformed ident, an unterminated
   signature, an internal mismatch, an unexpected git failure in `--undo`: each denies or stops.
4. **Audit**: every line bounded; a lease's denials past 60 a minute counted, the count a
   line (Q34); allowed signatures still one line.
5. **Revocation**: a violation's certificate on the deny list before the lock is released.
6. **Secrets**: not touched.
7. **Display**: denials show cut values; `writ-sign`'s diagnosis escaped.
8. **Dependencies**: none added.
9. **Guarantees**: the paths guarantee stated against the first parent with six new tests;
   new tests on "no signature outside an active lease", "everything logged" and the
   commit-only guarantee.
10. **Threat model**: three residual risks added (above), each with its milestone; no
    guarantee weakened.
