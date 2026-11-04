# M6 — Agent skill, amendments, renewals and close

The workflow the agent follows ([Clients](../architecture/clients.md#client-list),
[Flows § 6 and § 6b](../flows.md#6-out-of-ticket-request)), and the first real task through
Writ. Replanned with the user before building (commit `a169fee`; the decision log's M6 rows),
M6.1 (multi-repo workspaces) split off.

**Status:** done (2026-11-04). Every acceptance item a test can reach passes in `make ci` and
`make e2e`. The first two need a real agent and Touch ID: run by the user on a throwaway
GitHub repository against the development daemon, following
[manual checks with a real agent](../guides/manual-checks-e2e.md), both passed (the first on
its second try, after the fixes below; both with the template's committer name).

## What was planned

**The skill and its installer**

- `skill/writ/SKILL.md`: think through the scope, estimate the work, write and submit the
  ticket, wait, revise on refusal, amend on an out-of-ticket denial, renew when time runs out,
  close with a summary. One skill for both wirings (`writ git …` always), built into the
  `writ` binary.
- `writ init` installs the skill for the agents asked for, in as few folders as possible
  (Claude Code, `.agents/skills`, OpenCode only without the two others, Cursor), asked on a
  terminal or answered by `--agents`, `--skill-dir`, `--global`; excluded from git; undone by
  `--undo` (the timings file kept); refused without a terminal and without flags.
  `--agents-md` appends a pointer to `AGENTS.md` / `CLAUDE.md`.
- Adaptive timings: `timings.md` beside the fixed `SKILL.md`, appended to by `writ close` and
  compacted with fixed rules, its limits in its front matter (`writ timings`).
- `writ mark <phase>`, and `writ check <file>` (asked by the user while building).

**The lease model**

- The ticket (`writ-ticket/1`) gains `ticket.renews` and `ticket.estimate`; the state records
  its version and `writd` refuses another one.
- Amendments: the original lease runs while pending; the amendment's end is capped at the
  lease's ([M3.6](m3.6-review-after-m3.5.md)).
- Renewals (`renews: <id>`): signed like any ticket, from the lease's session key, for a lease
  active or ended within `renew_grace`; same template, scope the same or narrower; a lease of
  its own that ends the renewed one and may push the commits it signed; `max_renewals`.
- The estimate (`coding`, `checks`, `ci`): agent-written, shown, never read by the policy.

**Closing and the report**: `writ close` and the activity report (commits, pushes, branches,
denials, time used vs granted, paths vs `expected_paths`, the estimate vs the real time per
phase, the agent's marks).

**Each agent on its own lease**: the session chosen by `WRIT_SESSION`, then the repo's pinned
lease (`writ init --lease`), then `current`, a chosen session that is unknown or ended refused;
a whole-repo clone's signing settings following its lease (the [M5.6 review](m5.6-review-after-m5.5.md)'s
L19); the source's other active leases on the approver's screen; `max_active_per_source`.

## What was done

- **Versions** (`writ-core`, `writ-store`): `ticket.renews` and `ticket.estimate` in
  `writ-ticket/1` (the canonical fixtures regenerated: nothing was deployed). The state
  carries its version (`STATE_VERSION` 7, the ticket format in `formats`) and refuses another
  at open, naming both, without writing over it: one schema, no migration chain.
- **Renewals**: a ticket from the lease's session, same template, scope the same or narrower,
  `on_violation` as strict, for a lease active or ended within `renew_grace` (`writd.yaml`,
  24 h by default, 0 s to 7 d); checked at submission and again at signing. Signed, it is a
  lease of its own (a new certificate for the same session key), and the renewed lease is
  `renewed` in the same change, its certificate barred. A push under the renewal accepts its
  predecessors' commits, the chain followed back in the ledger. `max_renewals` per template.
  The `renew` audit event, and the `grant` line naming the lease renewed.
- **Amendments end with their lease**: capped at submission, refused at signing otherwise.
- **`max_active_per_source`** (`writd.yaml`, no limit by default), checked at submission and
  at signing; an amendment adds no lease, a renewal replaces its lease. The source a ticket
  came from (an IPv4 address, an IPv6 /64; an IPv4 address seen as IPv6 the same) is a column
  of the state, not part of the signed ticket.
- **`writ sign`** shows the source's other active leases (at most 10 and a count, the
  overlapping ones first, flagged `OVERLAP`, one row above saying what it means), a renewal's
  original ticket and its chain (renewals so far, time used, what changed), and the estimate
  beside the TTL asked; every new row within the trusted display's 78 columns.
- **`writ close`** (as user `writ` with the lease's session key, on the agents' listener; it
  works on a lease that already ended) and **`writ report`** (approval API): the activity
  report from the state and the audit log, read without the state lock (at most 100,000 lines
  of the chain), the phases derived from the daemon's timestamps and labeled approximate. The
  closing summary is bounded (4,000 characters, 100 lines, not blank). The `close` event.
- **The client**: the session chosen as `WRIT_SESSION`, then `writ init --lease`, then
  `current`, an unknown or ended one refused with its reason; `writ request` prints the
  `export WRIT_SESSION=…` line and warns when it moves `current` away from another active
  lease of the home. `writ-sign` refuses a `WRIT_SESSION` other than the session `writ.session`
  names, and asks the daemon in the format of the session's lease, whichever way git called
  it, so a whole-repo clone follows its lease with no change to its config. `writ init` reads
  previous values with `git config --get-all -z` and computes its settings once.
- **The skill** (`skill/writ/SKILL.md`, built in) and its installer (`writ-cli`'s `skill`
  module): Claude Code, `.agents/skills`, OpenCode (only without the two others), Cursor,
  `--skill-dir`, `--global`, `--agents-md`; each installed folder in `.git/info/exclude`; a
  `SKILL.md` that isn't Writ's never written over; `--undo` exact, the timings kept.
- **Timings** (`writ-cli`'s `timings` module): `writ close` records each run and compacts
  with fixed rules within `max_lines`, `max_bytes`, `keep_runs`, `max_notes`; `writ timings`
  prints or sets them; `writ mark` records the agent's phase ends in the session; `writ check`
  checks a ticket file with the daemon's own text checks (`fit::check_request`), or the timings
  file for every line `writ close` would drop or rewrite (exit 3).
- **Tests**: `writ-core` (`lifecycle.rs`: renewals, `renew_grace` and `max_renewals` on both
  sides, amendments' end, the estimate, `writ check`'s ticket checks), `writ-store` (the state
  version, renewal chains, close), `writ-approval` (`leases.rs`, `sign.rs`: the source's
  leases, `max_active_per_source`, renewals pushing, the report against the audit log),
  `writ-cli` and `writ-sign` units (the skill, the prompt, timings, sessions), integration
  (`leases.rs`: two agents in one home, pinned clones, renewals, the skill installed and
  undone, a whole-repo clone following its lease's format), end-to-end scenario 20
  (`sessions_and_renewals`).
- **After the first commit**, two display fixes found by CI and `make e2e`: overlapping leases
  listed first, so never the one left in "and N more" (`6311702`; the test failed 7 runs in 8
  without it), and the `OVERLAP` flag within 78 columns (`c1d3b64`; the width test now covers
  every section M6 added at its widest).
- **Docs**: [lease model](../lease-model.md), [flows](../flows.md),
  [clients](../architecture/clients.md), [approvals](../architecture/approvals.md),
  [policy and state](../architecture/policy-and-state.md), the operator pages (`writd.yaml`,
  `policy.yaml`, the ticket, the clients, good practice) and their templates,
  [security](../security.md) (three new untrusted inputs), the [threat model](../threat-model.md),
  [testing](../testing.md) and [end-to-end](../end-to-end.md) registries, the decision log
  (seven M6 rows, four more after the first real run).

## After the first real run

The first try at acceptance item 1 (OpenCode on a throwaway GitHub repository, the prompt
not naming Writ) went through but showed what the agent couldn't know. It wrote the whole
change first and asked for a ticket at commit time: the skill said to use it "before any git
commit, push or fetch". Its first ticket asked for `main`, rejected (`agent/*` only). Its
commit was refused three times, each teaching one rule: the committer email, the author
email (`writ init` had suggested `--email` before any lease, and the user's own email was
set over the lease's), the `Writ:` trailer. Nothing was pushed: the prompt didn't ask for it.
Fixed with the user:

- **`writ policy [<repo>]`**: what a ticket for the repo may ask, from the daemon's policy in
  force (each template that allows it, the repo's protected refs and ticket link, `min_ttl`,
  `renew_grace`, `max_active_per_source`), only that repo; on the agents' listener with any
  key, counted against the submission rates, logged (`policy`). `writ_proto::Command::Policy`,
  `RepoPolicy`; `Service::repo_policy`.
- **`writ request --dry-run`**: every check a submission gets (`Service::admit`, the code
  `submit` now shares), nothing stored, nobody notified, logged (`dry_run`).
  `Command::DryRun`, `Checked`; `Service::dry_run`.
- **The skill**: read at the start of any task that changes files (its description, and the
  `AGENTS.md` pointer `--agents-md` writes), no edit before the lease, `writ policy` first, a
  branch of its own within the template's patterns, `push` unless told not to, the committer
  email from the policy, `writ request --dry-run` before submitting, `--no-wait` and `writ wait`
  when the shell can't block, what to do when an email is refused.
- **`writ init`** before any lease says the committer email will be the lease's and points at
  `writ policy`, rather than suggesting `--email`.
- Tests: `writ-approval`'s `tests/policy.rs` (one repo and nothing else, an unknown repo
  refused, a dry run with a submission's exact reasons that stores and notifies nothing, the
  rate), `writ-proto`'s command lines, `writ-cli`'s display (escaped), integration
  (`writ_policy_and_a_dry_run_tell_the_agent_what_fits_before_it_asks`), and end-to-end
  scenario 20 (`writ policy`, `writ policy --url`, `writ request --dry-run`, in the registry).
- Docs: [clients](../architecture/clients.md#what-the-agent-reads-before-it-asks), the
  [gateway](../architecture/gateway.md)'s commands, [flows](../flows.md), the audit events
  ([policy and state](../architecture/policy-and-state.md)), the operator pages (the clients,
  `writd.yaml`'s submission rates), [security](../security.md) (two inputs), the
  [threat model](../threat-model.md) (a residual risk: anyone the agents' listener lets in
  reads what a ticket for a repo may ask, accepted with the user), three rows of the decision
  log.

The security checklist for these changes: **inputs** two (the policy read's repo name, the
dry run's ticket), bounded and tested with hostile input; **authority** none granted (both
read); **fail closed** an unknown repo refused, a dry run refused wherever a submission would
be; **audit** `policy` and `dry_run` lines, refusals over the rate counted like a
submission's; **revocation** not touched; **secrets** none in either reply (tested: no
upstream, credential or signing key); **display** the policy escaped (tested); **dependencies**
none; **guarantees** none weakened; **threat model** the row above.

## A template's committer name

Asked by the user after the first real task, whose commit carried the operator's own git name
with the agent's email. A template may set `committer_name`; unset, the name isn't checked.

- **The policy** (`writ-core`): `CommitterName` (1 to 100 characters, nothing hidden, no `<`
  or `>`, no character git strips at either end, so the name git writes is exactly it);
  `Template::committer_name`; copied into each lease that signs as `scope.committer_name` (a
  ticket can't ask for one); `fits` refuses a lease whose name isn't its template's (a renamed
  template no longer fits its leases); a narrowing or a renewal can't change it;
  `decide_sign` compares the commit's author and committer names exactly (`committer_name`,
  `author_name`, violations, with a hint instead of the amendment one); with an OpenPGP key,
  its user id for each email must be `<name> <email>`, checked at start.
- **The format**: `writ-ticket/2` and state version 8 (the M6 rule: a format change bumps
  both); fixtures regenerated, the full one with a non-ASCII name.
- **`writ-git`** reads the names (bytes before ` <`; not UTF-8 is none, never guessed).
- **The client**: `user.name` set from the lease (`writ git`, a whole-repo clone); `writ
  init`, `writ request`, `writ sign` (a scope row) and `writ policy` show it.
- **Tests**: `writ-core`'s `tests/committer_name.rs` (the name's bounds, the lease, `fits`,
  narrowing and renewal, every signature with each wrong name as committer and as author, no
  check without one, the OpenPGP user id), `writ-git`'s name parsing, the display's width
  with a 100-character name, integration
  (`a_template_s_committer_name_is_set_on_commits_and_any_other_refused`), end-to-end
  scenario 18 (the `openpgp` template names its commits "Writ agent": set over the agent's own
  git name, still verified on Forgejo, another name refused); the configuration registry row.
- **Docs**: the operator reference and the policy template, the [lease model](../lease-model.md),
  [policy and state](../architecture/policy-and-state.md), [clients](../architecture/clients.md),
  the client settings, [security](../security.md) (the commit's names), the
  [threat model](../threat-model.md) (the identity guarantee widened to names, and a residual
  risk: without `committer_name`, the name is the agent's to choose), the skill, the decision
  log.

The security checklist: **inputs** the commit's names (agent input, compared exactly, not
UTF-8 refused when a name is required) and the policy's name (bounded, refused naming its
field); **authority** nothing granted, a check added; **fail closed** a renamed template
refuses its leases, a name that isn't UTF-8 is refused; **audit** the two denial codes;
**revocation** not touched; **secrets** not touched; **display** the name through the bounded
display (tested at its widest); **dependencies** none; **guarantees** the identity guarantee
covers names, with its tests; **threat model** the rows above.

## Decisions

In the [decision log](../decisions.md), 2026-11-02 and 2026-11-04: each agent on its own lease
and `max_active_per_source`; more time is a renewal, never an amendment (option B of three);
the skill installed by `writ init`; adaptive timings beside a fixed skill; the estimate
display-only; one ticket format and a versioned state; `writ check`; `writ-sign` following the
session's lease's format; `writ close` with the session key on an ended lease; M6.1 split off.

## The security checklist, for M6

1. **Inputs:** `ticket.renews` and `ticket.estimate` (bounded, 30 days per phase; a renewal
   checked at submission and at signing), the closing summary (4,000 characters, 100 lines,
   only from the lease's own session), the timings file and `writ check`'s file (client-side,
   bounded, hostile-input tests); all in the inventory.
2. **Authority:** a renewal is an approver-signed ticket within its lease and its template;
   nothing grants by flag; `max_active_per_source` only refuses.
3. **Fail closed:** an unknown or ended `WRIT_SESSION` or pinned lease is refused, never
   replaced by `current`; a chain that doesn't start with the renewed lease is an internal
   denial; a state of another version is refused.
4. **Audit:** `renew` (the renewed lease's end), `grant` naming the lease renewed, `close`
   (done or denied); coalesced lines carry their `count`.
5. **Revocation:** a renewal bars the renewed lease's certificate in the same change; closing
   bars an active lease's; the deny list at start includes `renewed` leases.
6. **Secrets:** not touched (no key or token in any new field, file or reply).
7. **Display:** the renewal, the source's other leases, the estimate and the report go through
   the bounded, escaped display, before the enforced terms, each row within 78 columns.
8. **Dependencies:** `tempfile` as a dev-dependency of `writ-sign` (already in the tree).
9. **Guarantees:** "only commits signed under the same lease reach upstream" now includes the
   leases it renews (decided with the user); "leases bounded in time" now covers amendments and
   renewals; their tests in the registry.
10. **Threat model:** renewal chains, the source as a network address, and the agent-editable
    skill and timings files added as residual risks.

## Acceptance

- [x] A real feature on a personal repo goes from prompt to pushed branch through Writ, with
      exactly one Touch ID (the ticket), while I'm away.
      *By the user, 2026-11-04, after the fixes of "After the first real run": OpenCode on a
      throwaway GitHub repository (`writ init demo --agents opencode`, no `AGENTS.md` line,
      the prompt not naming Writ), asked for a TypeScript Express server (`GET /health`, an
      `X-Request-Id` middleware, Jest and supertest tests) pushed for review. The audit log:
      `policy`, `dry_run` and `submit` before any file was written, one `grant` (the one
      signature: no refusal, revocation or amendment), a fetch, one `sign` and one `push`
      (`agent/express-health-server`, a branch of its own), `close`; no denial. The commit (9
      files, `Writ:` trailer, by `agent@writ.invalid`) verifies with the lease's signing key
      and is on GitHub; the timings file took the run (2m53s used of 1h, estimate 30m) and a
      note. Run again with the template's `committer_name` (check 1 and step 7 of
      [the guide](../guides/manual-checks-e2e.md)): the commits carry the name over the
      operator's own, and another name is refused (`committer_name`, `author_name`).*
- [x] A refusal round-trip, an amendment round-trip and a renewal both work from the agent's
      side using only the skill.
      *By the user, 2026-11-04: check 2 of [the guide](../guides/manual-checks-e2e.md), a real
      agent asked for two branches and a fix pushed after a slow "CI", the prompt not naming
      Writ: its first ticket refused and revised (`ticket.revises`), the revision signed
      narrowed to one branch and 20 minutes, the out-of-ticket push amended
      (`ticket.amends`), the expired lease renewed (`ticket.renews`) and the commit the first
      lease signed pushed by the renewal, every commit named after the template. The same
      round trips run scripted in
      `tickets_are_requested_signed_refused_revised_amended_and_revoked` and
      `a_lease_is_renewed_closed_and_learned_from` (`make e2e`).*
- [x] The activity report matches the audit log for that lease; `timings.md` takes the run
      and stays within its limits, whatever the number of runs.
      *`the_report_matches_the_audit_log_phase_by_phase` (every signature and push the log
      holds, the phases to the second), `closing_ends_the_lease_and_reports_what_it_did`,
      `a_run_is_recorded_and_read_back`, `the_file_stays_within_its_limits_whatever_the_number_of_runs`;
      end to end in `a_lease_is_renewed_closed_and_learned_from`.*
- [x] An amendment applied minutes before the lease ends doesn't move its end: `writ ls`, the
      lease and the certificate all end at the original time.
      *`an_amendment_minutes_before_the_end_keeps_the_end` (ten minutes before the end, a 4 h
      amendment: its `expires_at` and `writ ls`'s are the lease's), `an_amendment_ends_with_its_lease`;
      an amendment keeps the lease's certificate, whose `valid_before` is the lease's end.*
- [x] A renewal of an expired lease within `renew_grace` pushes the commits signed under the
      lease it renews; one second past `renew_grace`, from another session key, of a revoked,
      closed or already renewed lease, or wider than its lease, it is refused with its reason;
      `max_renewals` holds on both sides; the renewed lease's certificate is refused once the
      renewal is signed.
      *`a_renewal_ends_its_lease_and_pushes_what_that_lease_signed`,
      `a_renewal_is_refused_past_its_grace_or_from_another_session` (59 s taken, 60 s
      refused), `renew_grace_holds_on_both_sides`,
      `only_an_active_expired_or_used_up_lease_of_the_same_session_is_renewed`,
      `a_renewal_stays_within_its_lease`, `max_renewals_holds_on_both_sides`,
      `a_renewal_is_checked_again_when_it_is_signed`; with the real daemon,
      `a_renewal_pushes_what_its_lease_signed_and_holds_to_every_bound` (the renewed lease's
      certificate refused by SSH, the commit pushed by the renewal).*
- [x] Two agents on one host and one Writ home, each with its `WRIT_SESSION`: every signature
      and push lands under its own lease in the ledger, whichever lease `current` points at.
      A `WRIT_SESSION` naming an unknown or ended lease is refused with its reason, and
      nothing goes out under `current`.
      *`two_agents_in_one_home_each_keep_their_own_lease` (the ledger and the push line per
      lease; an unknown and a closed lease refused, HEAD unchanged).*
- [x] A whole-repo clone wired under an SSH lease, then used under an OpenPGP lease: commits
      are signed in the new lease's format; `writ init --undo` restores every value it
      changed, one spanning several lines included.
      *`a_whole_repo_clone_follows_its_lease_s_format_and_undo_is_exact` (an SSH then a PGP
      signature in the same clone; a two-line `user.email` back byte for byte).*
- [x] `writ init --lease`: a pinned repo uses its lease in both wirings; in a whole-repo clone
      pinned to one lease, `writ-sign` refuses a commit with `WRIT_SESSION` naming another,
      with its reason.
      *`a_pinned_repo_uses_its_lease_in_both_wirings`,
      `writ_session_must_name_the_session_the_settings_are_for`.*
- [x] `writ init` installs the skill where each agent finds it, once for OpenCode, excluded
      from git; `--undo` removes exactly what it added, the timings file aside; without a
      terminal and without `--agents` or `--skill-dir` it refuses before wiring anything.
      *`writ_init_installs_the_skill_where_each_agent_looks_and_undo_removes_it`,
      `opencode_gets_its_own_folder_only_without_the_folders_it_reads`,
      `the_skill_is_installed_once_excluded_and_never_over_someone_else_s`,
      `the_prompt_s_answer_picks_the_agents`.*
- [x] `writ sign` lists the source's other active leases and flags an overlap; 11 of them
      show 10 and the count; a lease from another source isn't listed.
      *`writ_sign_sees_the_source_s_other_active_leases` (11 leases: 10 and 1 more, the
      overlapping one first; another source's and an ended one not listed),
      `branch_patterns_intersect_when_a_branch_matches_both`; the width test over every M6
      section.*
- [x] `max_active_per_source`: one below the limit a submission is accepted, at the limit it
      is refused with its code; a lease granted between submission and signature makes the
      signature refused; a lease ending frees its slot; an amendment or a renewal doesn't
      count twice.
      *`max_active_per_source_counts_the_active_leases_of_one_source`,
      `a_lease_granted_meanwhile_makes_the_signature_refused`,
      `max_active_per_source_and_renew_grace_are_bounded_on_both_sides`; with the real daemon,
      `max_active_per_source_holds_at_submission_and_at_signing`.*
- [x] Every new command, flag, key and variable (`writ close`, `writ report`, `writ check`,
      `writ timings`, `writ mark`,
      `writ init --lease`, `--agents`, `--skill-dir`, `--global`, `--agents-md`,
      `WRIT_SESSION`, `max_active_per_source`, `renew_grace`, `max_renewals`,
      `ticket.renews`, `ticket.estimate`) is used for real by end-to-end scenarios, with its
      rows in the registries (rules 18 and 19).
      *Scenario 20 (`sessions_and_renewals`) and the rows in the
      [coverage registry](../end-to-end.md#coverage-every-command-and-flag) and the
      [configuration registry](../testing.md#configuration-coverage-every-key); `make check`
      and `make test` check both. After the first real run, `writ policy`, `writ policy
      --url` and `writ request --dry-run` too, in the same scenario, and
      `templates.<name>.committer_name` in scenario 18. `make check`, `make test` (795 tests)
      and `make e2e` (25 scenarios) passed with them, here and in the user's run.*
