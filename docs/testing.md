# Testing

Run everything with `make test`; lint, format, dependency directions and source rules with
`make check`. Writ is a security boundary: a missing deny is a bug as serious as a crash, and
a test that passes by luck is no test at all.

## Three levels

| Level | What it tests | Needs | Runs in |
|---|---|---|---|
| **Unit** | One crate alone: its unit tests (`#[cfg(test)]`) and its `tests/`, on the platform fakes (`writ_platform::testing`) and the test kits (`writ_approval::testing`) | nothing | `make test` |
| **Integration** | The crates and the binaries together (`crates/writ-integration`): the real `writd`, `writ` and `writ-sign`, the real `git` and OpenSSH, a throwaway `ssh-agent` standing in for the approver's, a fake Telegram Bot API; temporary `HOME` and git config | the local tools only (checked at start: `git` ≥ 2.47, OpenSSH ≥ 8.9, `nc`); upstream is a test remote, an SSH server in the test process (`writ_integration::remote`) that can also misbehave (never answer, flood), and the same repositories over HTTPS with a token (`writ_integration::https_remote`: `git http-backend` behind TLS, which can also hang, flood, redirect, or print the token back) | `make test` |
| **End to end** | The documented paths themselves ([end-to-end](end-to-end.md)): the real Linux binaries in their own containers (`writd`, an agent host with the approver), a real Forgejo, the operator setup with the operator guide's commands, every command and flag of `writ`, `writd` and `writ-sign` used by a scenario (`crates/writ-e2e`); a throwaway GitHub repo by hand ([manual checks](guides/manual-checks.md#a-throwaway-github-repo-m4)) | Docker | `make e2e`, and CI's `e2e` job |

Each milestone's acceptance items become integration scenarios, and what a person or an
agent reaches through a binary becomes an end-to-end scenario too: every command and flag has
one ([the rule and its registry](end-to-end.md#coverage-every-command-and-flag), checked by
`make check` and `make test`; [adding a scenario](end-to-end.md#adding-a-scenario)).
Every configuration key is set by an integration test or an end-to-end scenario that checks
its effect ([the rule and its registry](#configuration-coverage-every-key)).
What needs a human stays manual: the approver's real agent (`make test-agent`, Touch ID) and
the [manual checks](guides/manual-checks.md).

## Hardened tests

These rules hold for every test, at every level.

- **Deterministic.** A test checks the same thing every run, whatever the machine's speed:
  - **No waiting on time.** Never `sleep` and then assert. Wait for a signal: a condvar
    (`RecordingNotifier::wait_for`, `FakeTelegram::wait_for`), a channel, a broadcast
    (`Service::subscribe_revocations`), a process's exit, a log line. Only what gives no
    signal (another process's socket appearing) is polled, through one helper
    (`writ_platform::testing::eventually`) with a deadline (`WAIT_LIMIT`) that fails the test.
    A deadline bounds how long a test looks; it never decides what the test checks. "Still
    pending after 50 ms" is fine because pending is the only possible outcome, not because
    50 ms is enough.
  - **No real clock** where the code takes one: the service runs on `FakeClock`, moved by
    hand. (The gateway tests use the system clock, because russh checks certificate validity
    against it itself; nothing in them waits on time.)
  - **No order it doesn't control**: ordered collections, ordered delivery (the notification
    worker delivers in order, so "a rejected ticket never notifies" is checked by the next
    notification being the valid ticket's).
  - **No fixed ports**: bind port 0 and read the port back (the daemon logs the ports it bound;
    the fixture reads them).
  - **No unseeded randomness** in what a test asserts. Generated keys and ids are fine
    (nothing depends on their value); property tests are seeded (below).
- **Adversarial.** A test tries to break the check, not to exercise it:
  - every denial asserts **its exact code or error variant** (`DenyCode::ProtectedRef`,
    `RefusalCode::Signature`, `LifecycleError::SessionKeyChanged`), or an exit status's exact
    code, never just `is_err()` or `!success()`. Where the error really is opaque (a TLS or
    SSH library's failure), the assertion says so in a `// any error: <why>` comment, and
    `tool/check-rules.py` refuses a bare one;
  - no sleep: a poll for something that gives no signal says what it polls in a
    `// poll: <why>` comment (checked by `tool/check-rules.py`);
  - every limit is tested **on both sides**: one below allowed, at the limit denied (counts,
    sizes, expiry to the second, input lengths);
  - every allowed case next to its denials passes, so the denial is the check's doing and not
    a broken fixture;
  - hostile input is tried where input is untrusted: escape sequences and bidi controls in
    every agent-written field, cut-short and oversized input, path-like names;
  - a limit that is costly to reach is tested on both sides with a small limit passed in (the
    mechanism), plus one test at the real limit or past it with the input it guards against
    (`writ_git::paths`: `path_bytes_are_bounded_on_both_sides` with a 7-byte budget,
    `long_names_cannot_blow_up_the_walk` at the real one);
  - an ordering that matters (the deny list before the lock is released, the audit line
    before the change) has a test that makes the step after it fail (`FailingSigner`,
    `AuditBreaker`, `StoreBreaker`) and checks what is left; a fix's test is seen to fail
    without the fix before it is committed.
- **Fixtures are shared, not copied**: the test kits and the integration harness hold the
  service setup, the approver's signatures, the agent, the daemon. A fixture edited for a test
  asserts the edit applied, so a drifted fixture fails instead of weakening the test.

## Property tests

`proptest` runs in two passes, both in `make test`:

1. **Fixed seed**: the same inputs every run, plus every case in the regressions files
   (`crates/writ-core/tests/properties.proptest-regressions`,
   `crates/writ-approval/tests/sign_phases.proptest-regressions`: each failure ever found).
2. **Random seed**: new inputs each run. The seed is printed
   (`proptest seed: … (replay with WRIT_PROPTEST_SEED=…)`), so a failure is replayed exactly
   with `make test-props SEED=<seed>`; the failing case is also saved to the regressions file,
   which is committed, so the fixed pass checks it from then on.

| Area | What to test |
|---|---|
| `writ-core` | Table-driven tests for every policy decision (allowed and denied, with the reason). Property tests (`proptest`): narrowing never widens; a ticket outside every template is never accepted; two matching leases deny; counters never exceed limits. Canonical encoding pinned by fixtures in `crates/writ-core/tests/fixtures/`. Lifecycle: every transition allowed by the [state diagram](lease-model.md#lifecycle), every other one refused. |
| `writ-crypto` | SSHSIG round trips for each algorithm; signatures from real `ssh-keygen`, directly and through a throwaway `ssh-agent`, verify (`crates/writ-integration/tests/interop.rs`) (opt-in: a key in your own agent, `make test-agent KEY=<.pub>`; never a stored fixture of a real key); wrong namespace, wrong bytes, unknown key refused. Certificates: expiry, serial, key ID = lease ID, revocation. |
| `writ-store` | Leases and ledger across a database reopen; the audit log only grows and never contains a secret (scan entries for key material, passphrases, tokens). |
| `writ-git` | Against the real `git` (`tests/real_git.rs`, SHA-1 and SHA-256 repositories): commits it writes parse (merges, another encoding); touched paths equal `git diff-tree` (changes, added and removed directories, a file becoming a directory, a mode change, an empty commit, a root commit, a merge against its first parent, with a resolved conflict); the signed commit's id is the one git writes; trailers equal `git interpret-trailers --parse`. Hostile evidence: objects swapped or mislabeled, malformed trees, `.git` entries as every filesystem reads them, a merge bringing in another parent's file, shared subtrees and long names (bounded walk), every bound of the walk on both sides (entries, paths, depth, path length, path bytes). M4: quarantine (a pack's new commits found exactly; size bound enforced; quarantine removed on every path). |
| `writ-gateway` | In-process server with a temporary CA and temporary repositories, driven by real `git` and `ssh`: fetch, push, sign, lease commands, each denial with its message. |
| `writ-signer` | The software backend against the `Signer` contract suite (`writ_signer::contract`, shared, so later backends run the same ones), alone and behind a `QueuedSigner` (the decorator section: `Busy` at once when full, `Timeout` from a backend held stuck by a `GatedSigner`, keys listed meanwhile, an abandoned job never signed); keys it refuses; nothing of a key in `Debug` or errors. M5: sealed keystore unreadable without the passphrase. |
| `writ-approval` | The approval service on the platform fakes (`RecordingNotifier`, `FakeWatcher`) and a manual clock: rejection before the approver, approval and certificate, every approval that must be refused (unknown key, other namespace, other bytes, widening, non-canonical bytes), proofs (`tests/prove.rs`: only with the approver's signature over exactly the document, never in `git` or a `writ…` namespace, over 4 KiB, for a key no template signs with, nor passed off as a ticket approval; none handed out when the signer or the audit log fails), narrowing, refusal and revision, revocation, `decisions: signed` and `open`, expiry, session binding, deny list across a restart, audit log without secrets; faults in the middle of an operation (a failing signer, audit log or lease lookup: `FailingSigner`, `AuditBreaker`, `StoreBreaker`); what happens while a signature is in flight (a revocation, an expiry, a violation, an amendment, the last slot; the service answering meanwhile), the signer held at a `GatedSigner` and released on a signal. Property test (`tests/sign_phases.rs`): concurrent signature requests driven a phase at a time, with the clock moving and a revocation at any point; never more signatures than `max_signatures` or the rate, none after a revocation, none discarded without a reason, each logged and in the ledger. |
| `writ-platform*` | One contract suite per interface (`Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock`, `Notifier`), run by every implementation, portable or platform-only. Fakes for each, used by the core crates' tests, so the core is tested without any real platform. Platform-only suites run on their OS (`cfg`-gated). |
| Clients | `writ sign`'s display neutralizes control sequences; `writ-sign` forwards verify calls to `ssh-keygen`, prints denial reasons escaped and explains a refused session from its certificate; `writ init` writes exactly the documented config (`writes_exactly_the_documented_config`), in wrapper mode through the environment after the caller's own entries; in `writ_init.rs`, the operator's git (key, email, remotes) untouched beside `writ git`, a commit `writ exec` makes in another clone refused, a rebase signed again, `--undo` restoring the config exactly. |
| Integration | `crates/writ-integration`: each milestone's acceptance scenarios with the real binaries and local tools. |
| End to end | `crates/writ-e2e`, run by `make e2e` against Forgejo in Docker: the scenarios and the coverage registry of [end-to-end](end-to-end.md). Not part of `make test` (needs Docker); CI runs it as a job of its own. |

The integration scenarios (`crates/writ-integration/tests/`) run the real `git` and `ssh`
against an in-process gateway (`gateway_git.rs`; `signed_commits.rs` for signing, every
denial with the reason git prints), the real `writd` in repos wired by `writ init`
(`writ_init.rs`), the real `writd` binary with the real `writ`
CLI, approver signatures from `ssh-keygen` through a throwaway `ssh-agent` and a fake
Telegram Bot API (`ticket_flow.rs`), and the OpenSSH tools against `writ-crypto`
(`interop.rs`). They run the binaries as they ship: `make test` builds them first on their
own (`-p writd -p writ-cli -p writ-sign`, in `target/bins`, `writd` with the `dev-keystore`
feature the tests need) and names the directory in `WRIT_BIN_DIR`, so no `testing` feature
of another crate is compiled into the `writd` under test (`tool/check-features.py` checks the
shipped graph in `make check`).

`make ci` (`make check` then `make test`) is the one definition of green: GitHub Actions runs
it on Linux for every push and pull request (`.github/workflows/ci.yml`, no third-party
action), and on the Mac, where macOS-only code is tested, the `pre-push` hook (`make hooks`)
allows a push only of a tree `make ci` passed on. The hook doesn't run CI itself: git runs it
with the connection to the remote already open, and a hook as long as `make ci` made the
remote close it. Instead, `make ci` on a clean working tree (no change, no untracked file,
the same tree at the start and the end) stamps HEAD's tree in `.git/writ-ci-ok`
(`tool/ci-stamp.sh`), and the hook refuses any pushed commit whose tree isn't the stamped one.
`make push` does both: `make ci` unless the tree is already stamped, then `git push`.
`make hooks` installs stubs in `.git/hooks` rather than setting a local `core.hooksPath`,
which would turn off a global one.
The gateway's own tests (`crates/writ-gateway/tests/`) run on the fakes only: an in-memory
transport, a fake attestor, an in-process SSH client and an in-process HTTPS client pinning
the certificate. The end-to-end tests approve over SSH in one scenario and over HTTPS in the
others.

Every crate is testable without network or Docker. Tests never touch the
user's real `~/.ssh`, git config or ssh-agent (except `make test-agent`, run by hand): they set `HOME`, `GIT_CONFIG_GLOBAL` and
`GIT_CONFIG_NOSYSTEM`, and use generated keys.

## Configuration coverage: every key

Every key of `writd.yaml`, `policy.yaml` and the ticket file, and every environment variable a
binary reads, is set by a test that checks its effect: an integration test
(`crates/writ-integration/tests/`, the real binaries, or the in-process gateway and mirrors
for the mirror bounds) or an end-to-end scenario. A parser's unit test doesn't count: it shows
the key is read, not that it does anything. A key whose effect comes with a later milestone
names it (`planned: M10`); one this build refuses at start names the test that shows the
refusal. Hard rule 19; the [conventions](conventions.md#configuration-keys) say what else a
key change touches.

Checked: `make test` fails when a key the parsers take has no row here (or on its
[operator reference](operators/README.md) page), or a row names a key they don't take
(`writd`'s `every_writd_yaml_key_is_in_the_operator_reference`, `writ-core`'s
`every_policy_key_is_in_the_operator_reference` and `every_ticket_key_is_in_the_operator_reference`);
`make check` fails when a named test isn't one of the integration or end-to-end crate's, or a
planned milestone is done, or a `WRIT_*` variable a binary reads has no `env:` row
(`tool/check-config.py`).

| Key | Tested by |
|---|---|
| `writd.yaml: state_dir` | `a_restarted_daemon_keeps_leases_mirrors_and_ledger`, `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `whole_repo_mode_wires_a_dedicated_clone_and_undo_restores_it` |
| `writd.yaml: policy` | `writd_signing_keys_prints_the_key_a_lease_signs_with`, `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd.yaml: approvers` | `only_a_key_in_approvers_can_sign`, `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd.yaml: readers` | `every_client_setting_works_as_a_flag`, `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says` |
| `writd.yaml: decisions` | `decisions_open_takes_unsigned_refusals_and_signed_does_not`, `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `writd.yaml: max_pending` | `max_pending_caps_the_tickets_waiting_on_both_sides` |
| `writd.yaml: submissions.per_source` | `submission_rates_per_source_and_in_all_are_the_operator_s` |
| `writd.yaml: submissions.in_all` | `submission_rates_per_source_and_in_all_are_the_operator_s` |
| `writd.yaml: sign_requests.per_lease` | `sign_requests_per_lease_bounds_the_requests_held_at_once` |
| `writd.yaml: keystore.dev` | `writd_signing_keys_prints_the_key_a_lease_signs_with`, `the_operator_sets_the_daemon_up_from_nothing_as_the_guide_says`, `a_repo_behind_https_is_fetched_and_pushed_with_a_token_nobody_else_sees` |
| `writd.yaml: keystore.sealed.dir` | `writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest` |
| `writd.yaml: keystore.sealed.boot` | `writd_init_makes_a_sealed_keystore_that_reveals_no_key_at_rest` |
| `writd.yaml: mirrors.known_hosts` | `another_host_key_or_an_unpinned_host_is_refused`, `a_stopped_a_changed_and_a_closed_upstream_are_refused_with_their_reasons` |
| `writd.yaml: mirrors.ca_certs` | `a_certificate_from_a_ca_the_daemon_does_not_trust_is_refused_before_any_token`, `the_operator_s_cas_are_the_only_ones_git_is_given`, `a_certificate_the_system_trusts_is_refused_when_the_operator_named_their_cas` |
| `writd.yaml: mirrors.git` | `mirrors_git_and_ssh_are_the_programs_named` |
| `writd.yaml: mirrors.ssh` | `mirrors_git_and_ssh_are_the_programs_named` |
| `writd.yaml: mirrors.fresh_for` | `a_sync_mirrors_branches_and_tags_only_and_follows_upstream`, `concurrent_syncs_of_a_stale_mirror_fetch_once`, `upstream_moved_the_push_is_refused_then_fetch_rebase_re_sign_and_push_again` |
| `writd.yaml: mirrors.sync_every` | `mirrors_sync_every_syncs_without_any_client` |
| `writd.yaml: mirrors.timeout` | `an_upstream_that_never_answers_is_cut_at_the_deadline`, `a_mirror_held_past_its_deadline_is_busy_never_waited_on_forever` |
| `writd.yaml: mirrors.max_fetch` | `a_sync_past_the_byte_cap_is_refused_on_both_sides` |
| `writd.yaml: transports.agents` | `listeners_take_only_the_sources_they_allow`, `rejected_signed_narrowed_and_refused_tickets_end_to_end` |
| `writd.yaml: transports.approvals.ssh` | `listeners_take_only_the_sources_they_allow`, `https_approval_clients_check_the_pin_and_both_transports_cannot_be_disabled` |
| `writd.yaml: transports.approvals.https` | `listeners_take_only_the_sources_they_allow`, `https_approval_clients_check_the_pin_and_both_transports_cannot_be_disabled`, `revocation_and_expiry_drop_sessions_and_refuse_the_certificate` |
| `writd.yaml: <listener>.tcp` | `listeners_take_only_the_sources_they_allow`, `rejected_signed_narrowed_and_refused_tickets_end_to_end` |
| `writd.yaml: <listener>.unix` | `what_this_build_does_not_have_is_refused_at_start` (refused); planned: M7 |
| `writd.yaml: <listener>.allow` | `listeners_take_only_the_sources_they_allow` |
| `writd.yaml: attestor` | `what_this_build_does_not_have_is_refused_at_start`, `the_origin_hint_is_shown_and_a_caller_constraint_is_checked`; the value macos_process_chain planned: M7 |
| `writd.yaml: session_watcher` | `what_this_build_does_not_have_is_refused_at_start`, `the_origin_hint_is_shown_and_a_caller_constraint_is_checked`; the value macos planned: M7 |
| `writd.yaml: notifiers[].telegram.token.boot` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `while_sealed_every_request_fails_closed_with_daemon_sealed_and_is_logged` |
| `writd.yaml: notifiers[].telegram.token.sealed` | planned: M5 |
| `writd.yaml: notifiers[].telegram.chat_id` | `rejected_signed_narrowed_and_refused_tickets_end_to_end` |
| `writd.yaml: notifiers[].telegram.api_base` | `rejected_signed_narrowed_and_refused_tickets_end_to_end` |
| `policy.yaml: repos.<name>.upstream` | `a_push_reaches_upstream_with_the_daemon_s_credential_only`, `a_push_reaches_an_https_upstream_with_the_token_which_the_agent_never_sees` |
| `policy.yaml: repos.<name>.upstream_credential` | `a_push_reaches_upstream_with_the_daemon_s_credential_only`, `a_credential_the_remote_does_not_take_is_refused`, `an_https_upstream_syncs_with_the_token_which_nothing_else_holds` |
| `policy.yaml: repos.<name>.protected_refs` | `fetch_and_push_through_the_gateway`, `every_push_denial_leaves_forgejo_and_the_mirror_unchanged` |
| `policy.yaml: repos.<name>.push_modes` | `push_modes_without_gateway_refuse_a_gateway_push`; the value proxy planned: M9, the value direct_ssh planned: M10 |
| `policy.yaml: repos.<name>.notes_ref` | `a_push_leaves_a_note_per_commit_upstream_the_commits_untouched`, `notes_go_under_refs_notes_writ_when_the_repo_says_so` |
| `policy.yaml: repos.<name>.ticket_link` | `ticket_link_trailer_is_required_only_when_the_repo_asks`, `what_the_commit_says_is_checked`, `a_push_leaves_a_note_per_commit_upstream_the_commits_untouched`, `a_repo_without_notes_gets_none` |
| `policy.yaml: repos.<name>.object_format` | `an_upstream_in_another_object_format_is_refused`, `a_sync_mirrors_branches_and_tags_only_and_follows_upstream` |
| `policy.yaml: repos.<name>.direct_ssh.hosts` | planned: M10 |
| `policy.yaml: repos.<name>.direct_ssh.allow_account_wide` | planned: M10 |
| `policy.yaml: templates.<name>.repos` | `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `policy.yaml: templates.<name>.operations` | `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `policy.yaml: templates.<name>.branches` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `policy.yaml: templates.<name>.push_modes` | `push_modes_without_gateway_refuse_a_gateway_push` |
| `policy.yaml: templates.<name>.force_push` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `policy.yaml: templates.<name>.committer_emails` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `what_the_commit_says_is_checked` |
| `policy.yaml: templates.<name>.signing_key` | `ed25519_commits_signed_by_the_daemon_verify_and_are_in_the_ledger`, `p256_commits_signed_by_the_daemon_verify_and_are_in_the_ledger`, `commits_are_verified_once_the_signing_key_is_registered_and_proven` |
| `policy.yaml: templates.<name>.max_ttl` | `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `policy.yaml: templates.<name>.max_signatures` | `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `policy.yaml: templates.<name>.max_pushes` | `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `policy.yaml: templates.<name>.max_ops_per_minute` | `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `policy.yaml: templates.<name>.max_push_size` | `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `policy.yaml: templates.<name>.paths_check` | `paths_check_off_signs_any_path_without_a_warning`, `paths_outside_the_ticket_are_refused_with_paths_check_deny` |
| `policy.yaml: templates.<name>.require_expected_paths` | `require_expected_paths_rejects_a_ticket_without_them` |
| `ticket: template` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked`, `commits_are_verified_once_the_signing_key_is_registered_and_proven` |
| `ticket: origin_hint` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked` |
| `ticket: caller.descends_from.executable` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked` (shown, and never granted without a session watcher); the operation-time check planned: M7 |
| `ticket: caller.descends_from.pid` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked` (shown, and never granted without a session watcher); the operation-time check planned: M7 |
| `ticket: caller.descends_from.generation` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked` (shown, and never granted without a session watcher); the operation-time check planned: M7 |
| `ticket: caller.descends_from.code_identity.signing_id` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked` (shown, and never granted without a session watcher); the operation-time check planned: M7 |
| `ticket: caller.descends_from.code_identity.team_id` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked` (shown, and never granted without a session watcher); the operation-time check planned: M7 |
| `ticket: scope.repos` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `ticket: scope.operations` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `a_fetch_goes_through_the_policy_and_counts_against_the_rate` |
| `ticket: scope.branches` | `a_branch_outside_the_lease_is_refused`, `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `ticket: scope.force_push` | `a_force_push_or_a_deletion_is_refused_without_force_push`, `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `ticket: scope.committer_emails` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `ticket: ticket.title` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `ticket: ticket.task` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `ticket: ticket.plan` | `the_origin_hint_is_shown_and_a_caller_constraint_is_checked` |
| `ticket: ticket.expected_paths` | `paths_outside_the_ticket_are_refused_with_paths_check_deny`, `require_expected_paths_rejects_a_ticket_without_them` |
| `ticket: ticket.amends` | `tickets_are_requested_signed_refused_revised_amended_and_revoked` |
| `ticket: ticket.revises` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `decisions_open_takes_unsigned_refusals_and_signed_does_not` |
| `ticket: limits.ttl` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `a_ticket_left_unsigned_expires` |
| `ticket: limits.max_signatures` | `signatures_stop_at_the_lease_s_count_and_rate`, `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `ticket: limits.max_pushes` | `a_ticket_past_its_template_is_rejected_with_each_reason`, `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `ticket: limits.max_ops_per_minute` | `signatures_stop_at_the_lease_s_count_and_rate`, `a_fetch_goes_through_the_policy_and_counts_against_the_rate` |
| `ticket: limits.max_push_size` | `a_pack_over_max_push_size_is_refused`, `a_ticket_past_its_template_is_rejected_with_each_reason` |
| `ticket: on_violation` | `a_violation_revokes_a_lease_that_asks_for_it`, `the_approver_narrows_every_term_and_the_lease_holds_to_them` |
| `env: WRIT_HOME` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `every_client_setting_works_as_a_flag` |
| `env: WRIT_KNOWN_HOSTS` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `every_client_setting_works_as_a_flag` |
| `env: WRIT_TLS_PINS` | `revocation_and_expiry_drop_sessions_and_refuse_the_certificate`, `every_client_setting_works_as_a_flag` |
| `env: WRIT_READER` | `every_client_setting_works_as_a_flag` |
| `env: WRIT_URL` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `every_client_setting_works_as_a_flag` |
| `env: WRIT_APPROVAL_URL` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `every_client_setting_works_as_a_flag` |
| `env: WRIT_APPROVAL_KEY` | `rejected_signed_narrowed_and_refused_tickets_end_to_end`, `every_client_setting_works_as_a_flag` |
| `env: WRIT_APPROVAL_AGENT` | `decisions_open_takes_unsigned_refusals_and_signed_does_not`, `every_client_setting_works_as_a_flag` |
| `env: WRIT_SSH_KEYGEN` | `writ_ssh_keygen_names_the_program_the_approver_signs_with` |
| `env: WRIT_LOG` | `mirrors_sync_every_syncs_without_any_client` |

## Guarantee tests

Each line of [What Writ guarantees](threat-model.md#what-writ-guarantees) names the tests that
try to break it (the guarantee registry), wherever they live: `writ-core/tests/guarantees.rs`
at the policy level, then the service, the gateway and the integration scenarios.
`tool/check-guarantees.py` (in `make check`) fails if a named test doesn't exist or is
`#[ignore]`d, or if a guarantee has neither a test nor the milestone that brings one
(`planned: M7.5`). When a guarantee is added, its tests come in the same change.
