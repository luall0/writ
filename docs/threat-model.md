# Threat model

What Writ defends against, what it protects, and what it explicitly does not guarantee. Every
guarantee below must be covered by at least one test that tries to break it
([Testing](testing.md#guarantee-tests)).

## Actors

| Actor | Description | Design target? |
|---|---|---|
| **Sloppy agent** | Does what it's asked but may commit/push to the wrong place, loop, push too much | ✅ Primary |
| **Prompt-injected agent** | Steered by malicious content (repo file, issue, web page, dependency) into abusing its access. It also **writes its own ticket**, so it can ask for more than the task needs with a convincing plan | ✅ Primary: templates cap any ticket, whatever its wording |
| **Malware on an agent host** | Code running next to the agent, can read the session key | ⚠️ Bounded by the active leases on that host |
| **Network attacker** | Between agent hosts, daemon, remotes, approvers | ✅ Authenticated transports only |
| **Compromised approver key or Mac** | Can sign approvals | ⚠️ Bounded by templates (can't widen scope) |
| **Attacker on the daemon host** | Root or access to the Docker volumes | ❌ v1 with software keys; mitigated by YubiKey/TPM later |
| **Me** | Approves, reviews, revokes | Trusted |

## Assets

| Asset | Where | Notes |
|---|---|---|
| My personal keys | Secretive (Secure Enclave) | **Never touched by Writ** |
| Agent signing keys | Signer backend | Software (v1), YubiKey / SE / TPM later. Each declared in the signed policy's `keys` with its format (SSH or OpenPGP), algorithm, hash and backend, checked against its backend wherever a policy is read ([M5.5](history/m5.5-signature-formats-and-key-algorithms.md), [M6.2](history/m6.2-managing-the-daemon-from-the-cli.md)) |
| OpenPGP certificates | Daemon: made from the key, its creation time and the policy's user ids; beside the key (`signing/<id>.asc`), with each grant | Bind an email to an agent key, which remotes then trust as the account's. A user id only through a signed policy change; the certificate is public |
| Upstream remote credentials | Daemon: SSH keys behind the signer interface; HTTPS tokens sealed in the keystore (`tokens/<id>.age`), added from the approver's machine (`writ admin token`) | SSH keys on my remote accounts: **account-wide access**, not per repo; tokens as narrow as the remote allows (GitHub: one repository). Agents never see them; a token reaches only the daemon's own git, for one operation |
| Repo mirrors | Daemon host | Personal projects only for now |
| Session keys + certificates | Agent hosts | Short-lived, one per lease |
| Approver keys | Secretive (v1), YubiKey, own SE app later | Sign approvals, admin changes and unsealing; listed in the daemon's `approvers` file |
| Keystore passphrase (v1) | My head / password manager | Needed with an approver signature to unseal |
| Leases, ledger, audit log | Daemon (SQLite + JSONL) | Must survive an incident for review |
| Notifier credentials (Telegram bot token) | Daemon, a `0600` file (from M5: the boot tier or the sealed keystore, the operator's choice) | Lets anyone send messages as the bot. Never in an error, `Debug` output or log line |

## Trust boundaries

### 1. Agent ↔ daemon: session certificate
The gateway only accepts SSH certificates issued by the daemon for an active lease.
**Possession of the session key = identity.** Anything on the agent host that can read the key
can use it, but only within the lease (repo, ops, branches, time, count).

**An agent host's reach is every active lease on it.** The daemon knows a caller by its session
key, not by which process on the host holds it: an agent (prompt-injected, or malware beside it)
that can read another agent's session files can act under that lease. In local mode the caller
constraint ties a lease to one agent session's process tree, so another agent is refused. The
agent's ticket names the session's process by its pid alone (`writ run` writes it); the daemon
fills in its executable, generation and code identity from the kernel's chain of the
submission, and refuses a pid the submission doesn't descend from. A template with
`require_session` refuses an unbound ticket, so an injected agent can't drop the binding to
escape it, and the approver can't drop it when signing. In detached mode only the OS keeps
agents apart (one user, container or VM each).
`max_active_per_source` (`1` for a host meant for one agent) caps the leases one source holds,
and `writ sign` shows the approver the source's other active leases, an overlap flagged
([M6](history/m6-agent-skill-amendments-renewals-and-close.md)). `WRIT_SESSION` keeps agents
that share a Writ home on their own leases, but it is a client setting: it doesn't keep one
agent out of another's session files.

Mitigations: short TTL, one key per lease, revocation list. Later: non-exportable session
keys ([M8.5](roadmap.md#m85--non-exportable-session-keys): Secure Enclave, TPM) and
source-address pinning ([backlog](backlog/README.md#source-address-pinning)).

Local mode adds kernel peer checks (process tree) on the Unix socket.

See [Identity](architecture/identity.md).

### 2. Policy: strong, because the daemon is the git server
The daemon receives the actual objects and refs:
- repo = endpoint on the daemon (not inferred from a working directory)
- destination ref = what the push asks for, checked before anything reaches upstream
- content = the pack in quarantine; every new commit must be in the ledger for this lease
- the commit bytes it signs are parsed by the daemon itself

See [Gateway](architecture/gateway.md) and [Policy, state and audit](architecture/policy-and-state.md).

### 3. Signer: depends on the backend
| Backend | Key extraction possible by |
|---|---|
| Software (v1) | Root on the daemon host while unsealed (keys in memory); the keys volume alone is encrypted |
| YubiKey PIV | Nobody (physical theft of the key still allows signing until revoked) |
| Secure Enclave | Nobody |
| TPM | Nobody (bound to that machine) |

See [Signer and sealing](architecture/signer.md).

### 4. Approvals: approver signatures
Approvals are SSHSIGs (namespace `writ-approval`) by registered approver keys over the
**exact lease content**, sent over the approval listener (SSH or HTTPS), whose SSH host key or TLS certificate the
client pins ([Q29](decisions.md)), and which lets in only the keys in its `readers` file. A notification click alone is never an approval. Admin changes
(approvers, templates, repo registry) and unsealing require a signed approval too.

With Secretive, the Touch ID prompt doesn't show what is signed: `writ sign` on the Mac is the
trusted display. Malware on the Mac could show one lease and get another signed, so the
approver key's worth is bounded by templates.

See [Approvals](architecture/approvals.md).

### 5. Daemon host: the crown jewel
It holds agent keys, upstream credentials and mirrors. Hardening: dedicated host or VM,
container running as non-root, minimal exposed ports (gateway + approval API), backups of
ledger and audit log, YubiKey backend as soon as practical.

See [Deployment](architecture/deployment.md).

### 5b. Files that grant authority
`approvers` (who may sign), `readers` (who may use the approval API), the policy (repos and
templates) and `writd.yaml` decide who may do what. Whoever can write one becomes an
approver at the next start, which would bypass signed admin changes. The daemon refuses each
unless it is a regular file (no link followed, never a FIFO) owned by the daemon's user and
not writable by group or others; secrets (a bot token, a wrapped key) must also be readable
by nobody else. From M5, `approvers`, `readers` and the policy change only through signed
admin changes: the daemon's state holds the versions in force, each bound to the keystore by
a MAC keyed by a sealed secret (a version altered, replaced or swapped for another one without
the passphrase stops the unseal), and writes them back to the files, where a hand edit is never
applied ([M5](history/m5-sealed-start-and-signed-admin-changes.md)). Only the operator, on the
host and with the passphrase, puts them under the MAC again (`writd recover`, which shows the
versions it would seal and seals them only on an explicit yes). `writd.yaml` stays a
host file: it can't make anyone an approver. Since M6.2 it holds no key declaration and no
upstream host key either: both are in the signed policy (`keys`, `upstream_hosts`), so whoever
writes `writd.yaml` can no longer change a key's declared hash or algorithm, nor pin a host key
of their own for an upstream (and so receive its pushes); a `writd.yaml` that still holds
`signing_keys` or `mirrors.known_hosts` stops the start. A token's declaration names the one
host it may be sent to, and a repo using it must have its `https://` upstream there.

### 6. Local mode: the daemon vs my own user
In local mode, agents run as my user. A daemon running as my user can't keep its keys from
them: they could read its files, use a Secure Enclave key blob, or attach to the process. So
the local daemon runs as a dedicated user, `_writd` on the Mac, `writd` on Linux: my user can't
read its files, use its key blob or attach to it (checked in the M0 spike on the Mac, by
end-to-end scenario 24 on Linux). Root stays out of scope, so my user must not have
passwordless `sudo`.

On Linux the daemon must read my user's processes (their executables and namespaces), which
the kernel allows only with `CAP_SYS_PTRACE`. That capability is held by one small helper
alone, `writd proc-reader`: it answers one pid at a time with what that process's `exe` and
`ns/*` links say, under its own seccomp filter, which lets it read and write its socket,
`readlink`, manage its memory and exit, and kills it on anything else: it can't `open` a file,
so not `/proc/<pid>/mem`, nor trace, signal or start a process. `writd` itself drops every
capability before it reads a secret, so a compromised `writd` can ask the reader for links and
nothing else, and can't attach to it. **Residual risk:** an exploited reader could still
`readlink` any process's links: the names of its working directory, root and open files.

See [macOS Secure Enclave](architecture/macos-secure-enclave.md) and
[platform](architecture/platform.md#the-linux-process-chain-and-session-watcher).

### 7. Daemon ↔ upstream: an authenticated host, bounded input
Upstream is the operator's remote, trusted to hold the repository but not to behave: it can be
compromised, and the network to it can be hostile. The daemon talks to it only over ssh to a
host key the operator pinned (nothing learned on first use), authenticating with a key that
stays in the signer (a one-operation agent socket); or over HTTPS to a certificate from the
system's CAs or the operator's (`mirrors.ca_certs`), with no redirect, reaching nothing but
the registry's host (a one-operation proxy), authenticating with a token handed to its own git
for that operation alone (a one-operation credential socket). It treats what comes back as
untrusted input: every object checked by `fsck` with the checks Writ relies on at error level, branches
and tags only (and a repo's notes ref, fetched only when the daemon's notes push meets one that
moved: the same checks and bounds), all or none, the registry's object format, bounded in bytes and time
([Gateway](architecture/gateway.md#repo-mirrors)). What a compromised remote can still do is
serve agents bad content on its branches (which they would fetch from it anyway) and refuse
service; it can't reach the daemon's keys, its other mirrors, or a lease. An HTTPS remote
receives its token (that is how it authenticates): what it prints back is taken out of the
errors agents see.

A repo can be reached through a **proxy** of the policy (M7.2: SOCKS5, Tor among them, or HTTP
CONNECT), for remotes that answer only from some addresses or inside some network. The proxy
is no more trusted than the network: it carries a tunnel the daemon asked for, to the
registry's host and port, by name (the proxy resolves it; the daemon never does), and what goes
through is SSH with the pinned host key or TLS with a verified certificate, so it sees
ciphertext and can only refuse service. Its answers are untrusted input, read field by field
and bounded; what it says reaches an agent's terminal with its password taken out. The proxy
is named by a signed policy change, never by the daemon's host; its password is a secret of
the keystore, sent only to it, in clear for SOCKS5 and plain HTTP (residual risk below).

Two operations reach out at an approver's request (M6.2): a host key scan, only on an
approver's signed `writ-scan/1` naming this daemon and a one-use nonce (a reader key alone
can't make the daemon open a connection anywhere), which reads the keys a host offers and
pins nothing; and an upstream check, with a reader key, only of a repo the signed policy
already names, with its credential, pushing nothing. Both bounded in number, time and size,
logged, and what comes back shown escaped. A scan's answer is only as good as the network
between the daemon and the host: the approver compares the keys with the ones the remote
publishes before a second signed change pins them.

## What Writ guarantees

Each guarantee names the tests that try to break it (the guarantee registry). `make check`
fails if a named test doesn't exist or is ignored, or if a guarantee has no test without a
milestone that brings it (`tool/check-guarantees.py`). A new guarantee comes with its tests,
in the same change ([security conventions](security.md#guarantees-and-their-tests)).

Since M3 the daemon signs a commit only through the policy (`writ_core::policy::decide_sign`,
called by `Service::sign`); since M4 it takes a push into its mirror only through the policy
too (`decide_push`, called by `Service::push` on what git verified in the quarantine).

| Guarantee | Tests that try to break it |
|---|---|
| ✅ Agents never get remote credentials or signing keys | `no_key_in_debug_or_errors`, `clients_never_see_an_internal_cause`, `errors_and_debug_never_contain_the_token`, `the_audit_log_holds_every_decision_and_no_secret`, `the_log_holds_no_secret`, `a_push_reaches_an_https_upstream_with_the_token_which_the_agent_never_sees`, `an_https_upstream_syncs_with_the_token_which_nothing_else_holds`, `a_token_upstream_refuses_fails_the_sync_without_showing_it`, `a_hostile_upstream_printing_the_token_back_has_it_taken_out`, `a_token_is_one_word_of_printable_ascii_and_never_printed`, `a_declared_token_is_the_operator_s_never_made` |
| ✅ An HTTPS upstream's token goes only to the registry's host, over TLS it verified, for one operation | `a_certificate_from_a_ca_the_daemon_does_not_trust_is_refused_before_any_token`, `the_operator_s_cas_are_the_only_ones_git_is_given`, `a_redirect_is_refused_and_the_token_never_follows_it`, `it_tunnels_only_to_upstream`, `only_a_request_for_this_upstream_over_https_is_answered`, `the_socket_answers_this_upstream_a_bounded_number_of_times`, `git_reaches_nothing_but_the_one_transport_allowed`, `https_urls_are_read_strictly` |
| ✅ Behind a proxy (M7.2), the daemon reaches upstream only through it, to the registry's host and port, asked by name (never resolved by the daemon), with what goes through still authenticated end to end; its password goes to that proxy alone, is never shown (what a proxy prints back is taken out), and is needed before anything is sent | `an_ssh_upstream_behind_a_proxy_is_synced_and_written_through_it_by_a_name_it_alone_resolves`, `an_https_upstream_behind_a_proxy_is_synced_through_it`, `the_host_key_scan_goes_through_the_proxy_which_resolves_the_name`, `a_missing_proxy_password_refuses_every_operation_until_it_is_added`, `every_way_a_proxy_refuses_or_fails_refuses_the_sync_with_its_reason`, `socks5_sends_the_name_for_the_proxy_to_resolve`, `no_message_holds_the_password`, `behind_a_proxy_ssh_connects_through_the_daemon_s_tunnel_only`, `it_tunnels_only_to_upstream` |
| ✅ No signature or push outside an active, approver-signed lease | `no_signature_or_push_outside_an_active_approver_signed_lease`, `a_ticket_outside_every_template_is_rejected_before_reaching_the_approver`, `a_narrowed_ticket_never_grants_more`, `a_lease_revoked_while_the_pack_comes_in_moves_no_ref`, `an_expired_or_revoked_lease_signs_nothing`, `a_lease_that_cannot_sign_is_refused_before_its_request_is_read`, `no_lease_an_expired_or_a_revoked_one_says_why` |
| ✅ Pushes only to allowed repos and refs, no force push unless allowed | `pushes_only_to_allowed_repos_and_refs_no_force_push_unless_allowed`, `destination_ref_and_protected_refs`, `fetch_and_push_through_the_gateway`, `git_runs_only_on_the_lease_repos_and_every_refusal_is_logged`, `a_branch_outside_the_lease_is_refused`, `a_force_push_or_a_deletion_is_refused_without_force_push`, `a_ref_that_differs_only_in_case_from_one_the_repo_has_is_refused`, `refs_that_differ_only_in_case_are_refused`, `an_agent_pushing_a_notes_ref_is_refused` |
| ✅ A fetch gets only what the mirror's refs reach: `upload-pack` speaks protocol v0 whatever the client asks (nothing is taken from the client's environment), where a reachable commit may be asked for by its id and any other object is refused | `upload_pack_serves_what_refs_reach_and_nothing_else`, `a_fetch_by_id_gets_only_what_refs_reach_whatever_the_protocol_asked`, `every_protocol_version_a_client_asks_for_works_served_in_v0` (and end-to-end scenario 19) |
| ✅ Only commits signed under the same lease (or a lease it renews, each renewal signed by the approver) reach upstream, with the paths checked at signing | `a_renewal_ends_its_lease_and_pushes_what_that_lease_signed`, `a_renewal_pushes_what_its_lease_signed_and_holds_to_every_bound`, `pushed_commits_signed_under_this_lease`, `only_commits_signed_under_the_same_lease_reach_upstream`, `malformed_objects_never_land`, `a_commit_not_signed_under_this_lease_is_refused`, `a_commit_whose_paths_changed_since_signing_is_refused`, `a_pushed_commit_s_paths_must_be_the_ones_checked_at_signing`, `unsigning_gives_back_the_commit_that_was_signed` |
| ✅ Signatures only for allowed committer and author identities (their emails, and their names when the template sets `committer_name`) | `signatures_only_for_allowed_committer_identities`, `committer_identity_and_object`, `only_what_the_lease_allows_is_signed`, `what_the_commit_says_is_checked`, `every_signature_carries_the_name_as_author_and_committer`, `a_lease_fits_only_with_the_template_s_name`, `a_template_s_committer_name_is_set_on_commits_and_any_other_refused` |
| ✅ Signatures only for commits, in their repo's object format, linked to their lease (`Writ:` trailer) where the repo asks | `a_commit_is_signed_only_in_its_repo_s_object_format`, `only_what_the_lease_allows_is_signed`, `what_the_commit_says_is_checked`, `a_sign_request_that_isnt_one_is_refused_and_logged`, `trailers_are_git_s` |
| ✅ With `paths_check: deny`, no signature for a commit touching paths outside `expected_paths` (compared with its first parent, a merge too), or whose paths are unknown; the trees are read as git reads them (a mode git doesn't write, which git reads by its type bits, is refused whatever `paths_check` says, and never lands in a mirror); the walk that finds them is bounded whatever the trees | `paths_outside_the_ticket_warn_or_deny`, `a_directory_with_a_non_standard_mode_cannot_hide_its_files`, `a_mode_git_reads_as_a_directory_is_refused_not_read_as_a_file`, `only_the_modes_git_writes_are_read`, `a_directory_with_a_non_standard_mode_hides_nothing`, `a_non_standard_mode_is_refused_whatever_paths_check_says`, `malformed_objects_never_land`, `malformed_or_dangerous_objects_from_upstream_never_land`, `paths_outside_the_ticket_are_refused_with_paths_check_deny`, `evidence_is_only_what_its_bytes_hash_to`, `touched_paths_are_git_s`, `a_merge_is_checked_against_its_first_parent`, `a_shared_subtree_cannot_blow_up_the_walk`, `long_names_cannot_blow_up_the_walk`, `path_length_is_bounded_on_both_sides`, `path_bytes_are_bounded_on_both_sides`, `paths_are_bounded_on_both_sides`, `entries_are_bounded_on_both_sides` |
| ✅ The ledger holds the commit as signed: the same commit without its signature has another id | `a_commit_is_signed_counted_and_recorded_as_git_writes_it`, `the_signed_id_is_the_commit_git_writes`, `ed25519_commits_signed_by_the_daemon_verify_and_are_in_the_ledger` |
| ✅ Leases bounded in time, count and rate (counts per repository, each within its own template's: no lease-wide cap, so a lease's total is the sum over its repositories, which the approver sees and signs; time, rate and renewals the strictest of its templates'); revocable instantly; an amendment never moves a lease's end; a renewal only within `renew_grace` and `max_renewals`, the renewed lease ended | `an_amendment_ends_with_its_lease`, `an_amendment_minutes_before_the_end_keeps_the_end`, `renew_grace_holds_on_both_sides`, `max_renewals_holds_on_both_sides`, `a_renewal_is_checked_again_when_it_is_signed`, `a_renewal_is_refused_past_its_grace_or_from_another_session`, `leases_bounded_in_time_count_and_rate`, `counters_never_exceed_limits`, `signatures_stop_at_the_count_and_the_rate`, `signatures_stop_at_the_lease_s_count_and_rate`, `a_fetch_goes_through_the_policy_and_counts_against_the_rate`, `count_and_rate_hold_whatever_the_phases_interleaving`, `a_violation_revokes_only_a_lease_that_asks_for_it`, `a_violation_bars_the_certificate_even_when_its_revocation_fails`, `a_revocation_completes_while_a_signature_is_in_flight`, `a_violation_while_a_signature_is_in_flight_discards_it`, `a_lease_that_expires_while_signing_discards_the_signature`, `a_lease_amended_while_signing_discards_the_signature`, `the_last_signature_in_flight_is_not_refused_as_used_up`, `counters_are_per_repository`, `a_repository_used_up_leaves_the_others_their_signatures`, `revocation_and_expiry_drop_sessions_and_refuse_the_certificate`, `a_revocation_never_waits_for_the_audit_log`, `a_revocation_completes_at_once_with_fetches_and_pushes_in_flight`, `a_restart_watches_bound_sessions_again`, `a_lease_revoked_while_the_pack_comes_in_moves_no_ref`, `a_policy_change_and_a_revocation_complete_while_an_openpgp_signature_is_in_flight`, `a_template_tightened_while_signing_discards_the_signature`, `a_violation_bars_the_certificate_even_when_its_revocation_fails` |
| ✅ Everything logged (a lease's denials and allowed connections past 60 a minute counted), every line bounded | `every_text_in_a_line_is_bounded_on_both_sides`, `a_lease_s_denials_are_counted_past_sixty_lines_a_minute`, `a_lease_s_connections_are_counted_past_sixty_lines_a_minute`, `agent_text_stays_short_in_denials_warnings_and_the_log`, `the_audit_log_holds_every_decision_and_no_secret`, `nothing_is_granted_without_its_audit_line`, `a_failing_signer_or_audit_log_signs_nothing_and_keeps_the_slot`, `a_sign_request_that_isnt_one_is_refused_and_logged`, `an_unknown_ticket_is_logged_as_denied`, `git_runs_only_on_the_lease_repos_and_every_refusal_is_logged` |
| ✅ Only reader keys reach the approval API | `only_reader_keys_reach_the_approval_api`, `only_a_reader_key_gets_through_mutual_tls`, `https_turns_away_a_key_not_in_readers` |
| ✅ Writ never uses personal keys: only the approval key, in its agent | `writ_sign_never_signs_with_a_private_key_file` |
| ✅ An agent signing key signs nothing but commits under a lease and the proofs an approver signed, never in `git` or Writ's own namespaces | `a_proof_needs_an_approver_signature_over_exactly_that_document`, `a_proof_in_git_or_writ_s_namespaces_or_over_4_kib_is_refused`, `a_proof_and_a_ticket_approval_never_pass_for_each_other`, `a_proof_for_a_key_no_template_signs_with_is_refused`, `a_proof_the_signer_or_the_audit_log_fails_is_never_handed_out`, `a_hostile_proof_sent_over_the_wire_is_refused_and_logged`, `a_proof_follows_the_policy_in_force_not_the_one_at_start` |
| ✅ The approver sees what gets signed, whatever the agent wrote (and, for a renewal, the chain's original ticket; the source's other active leases) | `writ_sign_sees_the_source_s_other_active_leases`, `a_hostile_ticket_shows_nothing_a_terminal_would_act_on`, `agent_text_cannot_push_the_enforced_terms_off_the_screen`, `no_row_is_wider_than_the_terminal_and_long_agent_text_cannot_forge_a_row` |
| ✅ The keys directory alone reveals no key: every secret but the boot tier's is its own age file, unwrapped only after an unseal | `the_keys_directory_alone_reveals_no_key`, `a_replaced_or_foreign_file_is_refused_by_name` |
| ✅ While sealed, nothing is served: every request but `info` and `unseal` fails closed with "daemon sealed", and is logged | `while_sealed_every_request_fails_closed_with_daemon_sealed`, `while_sealed_every_request_fails_closed_with_daemon_sealed_and_is_logged`, `a_restart_keeps_active_leases_working_after_unseal` |
| ✅ Unsealing and admin changes need an approver signature (and, to unseal, the passphrase); a signed change applies once, on the daemon it names, to the version it names; a hand edit or a version altered at rest is never in force; removing an approver revokes the leases it signed | `an_unseal_needs_an_approver_signature_over_this_daemon_and_this_boot`, `unsealing_needs_both_the_passphrase_and_an_approver_signature`, `an_unsigned_wrongly_signed_or_stale_change_is_refused_and_logged`, `a_signed_change_applies_at_once_and_is_written_back_to_its_file`, `a_hand_edited_file_is_set_aside_at_the_next_start_and_never_applied`, `versions_whose_mac_is_not_the_keystore_s_keep_the_daemon_sealed`, `a_version_altered_at_rest_keeps_the_daemon_sealed_and_writd_recover_needs_the_passphrase`, `a_change_replayed_after_the_text_came_back_never_applies_again`, `removing_an_approver_revokes_the_leases_it_signed` |
| ✅ A token reaches the daemon only from an approver, encrypted to the keystore (never in clear on its disk), never replayed and never taken from a change signed for another daemon; a key a signed policy change names is created in the keystore and used at once | `a_signed_token_against_the_file_in_force_is_logged_and_a_replay_is_stale`, `an_unsigned_wrongly_signed_or_malformed_token_is_refused_and_logged`, `a_sealed_service_takes_no_token`, `a_token_added_from_the_mac_is_used_at_once_and_never_in_clear_on_disk`, `a_policy_naming_new_keys_creates_them_and_uses_them_at_once`, `the_software_backend_passes_the_contract_behind_a_queue` |
| ✅ A `writd` process that holds a secret leaves no core dump and takes no debugger, or doesn't run (a debug build started traced aside, with a warning); never through a setting of the whole system | `the_linux_hardening_passes_the_contract_and_does_what_it_says`, `a_traced_start_is_refused_in_a_release_build_and_a_warning_in_a_debug_one`, `the_macos_hardening_passes_the_contract_and_does_what_it_says`, `a_traced_process_is_refused_in_release_and_skipped_in_debug_never_killed`, `a_refused_step_stops_the_process_and_a_warning_does_not`, `no_hardening_refuses_every_step` |
| ✅ A key signs in the format it is declared with, and only with a combination its backend can do: a request in the other format is denied, a declaration the backend, the format or the hash refuses stops the start, never adjusted | `an_openpgp_lease_signs_in_openpgp_only_and_gpg_verifies_its_commits`, `a_hash_set_is_checked_never_adjusted`, `each_refused_key_declaration_stops_the_start_with_its_reason`, `a_key_held_otherwise_than_declared_is_refused_by_recover_and_stops_the_start`, `a_pair_a_key_does_not_sign_with_is_refused_by_name` |
| ✅ An OpenPGP key certifies an email only through a signed policy change; an OpenPGP proof never signs a commit- or tag-shaped message | `a_user_id_needs_an_approver_s_signature_and_a_signed_one_is_certified_and_logged`, `an_openpgp_key_proves_itself_in_openpgp_never_over_a_commit_shaped_message`, `a_template_signs_only_with_a_declared_signing_key_carrying_its_emails` |
| ✅ RSA signs in constant time (AWS-LC), never through the `rsa` crate; nothing under RSA 3072, no SHA-1, no `ssh-rsa` | `rsa_signs_with_each_sha2_in_constant_time_code_and_is_stored_as_pkcs8`, `rsa_under_3072_bits_is_refused`, `a_signature_of_the_wrong_size_or_pair_is_refused` |
| ✅ Every block `writd`, `writ` and `writ-sign` free is zeroed first, whatever code freed it (a library's copy of a secret too); `realloc` never frees an old block unwiped; the zeroing survives the optimizer | `every_block_freed_is_zero_whatever_its_size`, `every_block_freed_is_zero_whatever_its_alignment`, `a_vec_grown_many_times_leaves_no_copy_behind`, `strings_and_zeroed_blocks_too`, `blocks_freed_from_many_threads_are_all_zero`, `realloc_moves_through_a_wiped_free`, `the_checker_sees_a_block_left_unwiped`, `the_zeroing_survives_optimization_and_only_thanks_to_the_barrier`, `the_global_allocator_wipes_every_block_freed` |
| ✅ Keys and upstream host pins change only by a signed policy change (M6.2): `writd.yaml` declares none (its old keys stop the start); a key is made by the change that declares it, of the kind its use and URL take (a token for its host only), and a key the policy no longer declares is deleted for good once the change applies (out of its signer and the keystore, its public half in the `admin` line), never while anything uses it | `the_keys_writd_yaml_held_are_refused_naming_the_policy`, `a_repo_s_credential_is_declared_for_its_url_and_its_host_pinned`, `a_removed_key_is_deleted_for_good_and_what_something_uses_is_never_removed`, `an_entry_something_uses_is_never_removed_and_one_nothing_uses_is`, `set_changes_only_the_fields_named_and_a_change_made_in_between_refuses_it` |
| ✅ The daemon reaches a host it has no pin for only on an approver's signature (M6.2): a host key scan needs a signed `writ-scan/1` naming this daemon and a nonce it handed out, used once, for 5 minutes (a reader key alone, a replayed nonce, another daemon's document refused); a scan pins nothing; an upstream check reaches only a repo the policy names, pushing nothing; both bounded and logged, what comes back escaped | `a_scan_runs_only_on_an_approver_s_signature_over_this_daemon_and_a_fresh_nonce`, `nonces_and_scans_are_bounded`, `a_check_reaches_only_a_registered_repo_within_its_rate`, `a_host_is_scanned_on_a_signature_pinned_once_compared_and_a_repo_checked` |
| ✅ Hardware backends: keys non-exportable (the Secure Enclave, M7.5: the key is made by the device, and the keystore holds only its blob, usable by that Mac's Secure Enclave alone) | `secure_enclave_keys_sign_commits_git_verifies_and_push_upstream`, `the_secure_enclave_passes_the_contract_alone_and_behind_a_queue`, `a_device_passes_the_contract_alone_and_behind_a_queue` |
| ✅ A device backend run through a helper (the Secure Enclave, M7.5) gets only the blobs it made, as the daemon kept them for each key (a frame with a digest over the key's public point, checked first): a corrupted, cut, bare or other key's blob never reaches it; and a helper that dies, stays silent or lies costs one job, never the daemon nor another key | `stored_bytes_not_framed_for_the_key_never_reach_the_helper`, `a_framed_blob_the_helper_refuses_or_reads_as_another_key_is_unusable`, `every_way_a_helper_fails_to_sign_is_refused_and_the_next_job_served`, `a_helper_that_dies_on_a_blob_at_start_costs_that_key_alone`, `a_key_the_helper_makes_must_prove_its_point`, `a_stuck_device_never_holds_up_a_software_key` |

## What Writ does NOT guarantee

- ❌ That signed content is good (that's review; see the future
  [LLM task-conformance check](backlog/llm-task-conformance.md))
- ❌ That a note on the remote (`ticket_link: notes`) is the daemon's: notes commits are
  unsigned, and anyone who can push to the remote can write or rewrite one. A note is a
  readable copy of the link; the daemon's ledger is the reference
  ([notes](architecture/gateway.md#notes))
- ❌ Protection of software keys against a compromised daemon host (v1)
- ❌ That an OpenPGP signature's time is true: it is the daemon's clock, shown by remotes,
  never checked by Writ
- ❌ That a user id removed from the policy stops being trusted: remotes keep the
  certificate they imported; remove the key there too (OpenPGP revocation certificates are
  not made in v1)
- ❌ Protection against an attacker who controls an agent host during a lease, beyond the
  scope of the leases active on that host
- ❌ Protection of the operator's own credentials from an agent running as the operator:
  Writ guards what goes through the daemon. The operator's signing and push keys stay theirs
  by needing their presence (Touch ID, a security key), and no credential helper or token
  should answer silently ([operators' good practice](operators/good-practice.md#protect-your-own-credentials))

## Residual risks (v1)

| Risk | Accepted because | Mitigation path |
|---|---|---|
| Software keys extractable on daemon host | Personal use, homelab | YubiKey / TPM backend |
| A keystore copied to another Mac (a backup restored) hands that Mac's Secure Enclave blobs another Secure Enclave made: well-formed and framed, so the digest passes. Whether a foreign blob is refused cleanly or can panic the firmware like a corrupted one is not known (not tried: no second Mac, and the real device is never fed what it didn't make) | Restoring a keystore onto another Mac is not a supported path: its Secure Enclave keys are lost with the Mac (the recovery guide makes new ones); a software key moves with the keystore | Bind each frame to the device that made it (a MAC keyed in that Secure Enclave, M7.6) |
| A corrupted Secure Enclave blob can make the Secure Enclave's firmware panic, and the Mac with it (M7.5, found on the real device). Someone who can write the daemon's files (root, or `_writd`) could craft one that passes the frame's digest and stop the Mac at each daemon start | The daemon never hands the device a blob whose frame doesn't check against the key's kept public half (sealed blobs are also authenticated by age); a writer of the daemon's files can stop the daemon anyway, and root is out of scope | The boot tier's blob behind a MAC keyed in hardware (M7.6) |
| A signed policy change that no longer declares a key deletes it for good (M6.2): a mistaken removal loses it (an upstream key is made and registered again; a signing key's commits stay verifiable from its public half in the audit log, but it signs nothing more) | Every change needs an approver's signature over the whole new text shown as a diff; `writ admin key remove` asks for the id to be typed again and refuses while anything uses the key; a key is never deleted before the change is in force | The keystore's backup |
| SHA-1 repositories are the default (`object_format: sha1`, as on GitHub and most remotes): there, the paths a commit touches are read from objects the agent sends, identified by SHA-1 | Each object's id is computed with collision detection (git's own `sha1dc` algorithm), which refuses the known attack constructions; a new chosen-prefix collision would cost a lot and only change what the path check sees, within the lease (the signature's other checks don't use these objects); the ledger's commit id includes the daemon's signature, which the agent can't predict; git and the remote rest on the same ids. A push is refused unless the paths are the same when computed again from the objects git verified in the quarantine (M4), so a forged tree never reaches the mirror or upstream through `gateway` (nor `proxy`, M9) | `object_format: sha256` where the remote supports it |
| A signature that fails, times out or is discarded (its lease revoked, expired or amended while it was being signed) still uses its count and rate slot; a crash between the phases uses one too | It errs toward less: no privilege is added, a failure can't be retried past the limits, and a stuck device holds up only commit signing (16 waiting at most, 10 s each), never approvals or revocations | A new lease, or an amendment raising `max_signatures` |
| A push that left for upstream before a revocation still lands: the lease is checked again right before the upstream push starts, but a push on its way can't be called back | The window is one upstream push (bounded by `mirrors.timeout`), for a push the policy already accepted under the lease; it reaches only what the lease allowed | — |
| Session key theft on an agent host | Bounded by lease scope and TTL | Non-exportable session keys (M8.5), source-address pinning (backlog) |
| In detached mode, agents on one host as one user can use each other's leases: the daemon can't tell processes on a remote host apart, and non-exportable session keys don't help (same user, same session agent) | Every lease is still bounded by its template and was signed by the approver; the approver sees the source's other active leases | One OS user, container or VM per agent ([good practice](operators/good-practice.md#more-isolation)); `max_active_per_source: 1`; local mode's caller constraint |
| A source is a network address (an IPv4 address, an IPv6 /64): hosts behind one NAT or proxy count as one source for `max_active_per_source` and `writ sign`'s list, and one host with several addresses as several | The list is context for the approver, never a grant; the limit errs toward refusing (one shared address) or is no worse than without it | Per-host agent keys registered with the daemon (backlog) |
| A chain of renewals keeps one piece of work going past a template's `max_ttl`, and a renewal may push the commits its predecessors signed | Each renewal is a ticket the approver signs, shown with the chain's original ticket and the time used so far; its scope is the renewed lease's or narrower; the renewed lease ends when it is signed; within `renew_grace` only; `max_renewals` caps a chain | `max_renewals` on templates; a short `renew_grace` |
| The skill, its timings file and `writ init`'s records (a repository's `.git/writ/config`, a workspace's `.writ-workspace`) live on the agent host: the agent (or a prompt injection) can rewrite them, and the timings file steers how big its tickets are | All client-side and untrusted: the daemon never reads them, templates cap every ticket, the approver sees each one; `SKILL.md` is replaced by each `writ init`, and `writ close` rewrites what it can't parse in the timings file; a record is read bounded, and `writ init --undo` removes only what is still Writ's (a skill file with its mark, empty folders on the way to one, its own pointer and exclude lines) and takes back only repositories whose own record names the workspace | Review tickets as usual; `writ init` again restores the skill |
| Without a template's `committer_name`, the name on a signed commit is whatever the agent's git says: an agent (or a prompt injection) can sign, with an allowed email, a commit that names someone else ("Alice (reviewed)") | The email is always checked, and remotes verify by email and key; the ledger and the audit log name the lease | Set `committer_name` on templates whose commits people read on a remote |
| Anyone the agents' listener lets in can read what a ticket for a repo they name may ask (`writ policy`: the templates' operations, branch patterns, committer emails and limits for it, its protected refs), and check tickets against the templates without submitting them (`writ request --dry-run`): a prompt-injected agent learns the most it could ask for without a round trip | A rejection already says which branch, email or limit a ticket is past; both only read and grant nothing; only the repos named are shown, never their upstream, their credential, a signing key (only its id, which agents get with each grant anyway) or another repo; both count against the submission rates and are logged (`policy`, `dry_run`); the approver still reads and signs every ticket | Templates no larger than the work needs; `transports.agents.allow` |
| Daemon is a single point of failure | Fail closed is the right behavior | Local mode as fallback |
| Upstream keys have account-wide access | Remotes don't scope personal SSH keys per repo | Repo registry + `protected_refs` enforced by the daemon; keys on YubiKey; deploy keys or bot accounts later |
| An HTTPS upstream's token leaves the daemon's memory for each operation: its own git (and git's `remote-https`) holds it, through pipes, while the operation runs; a token can't stay in a signer, since it doesn't sign | Only the daemon's user reaches those processes and the private socket directory (boundary 5); one operation, then the socket is gone; never a command line, an environment, a URL or a file; the token as narrow as the remote allows | Prefer `ssh://` upstreams (the key never leaves the signer); M5's process hardening; per-operation tokens where a remote issues them (GitHub App installation tokens, backlog) |
| A proxy's password (M7.2) crosses the network to the proxy in clear: SOCKS5 (RFC 1929) and HTTP Basic send it so, and anyone on that path can reuse it to use the proxy | It opens a proxy, not a remote: what goes through stays authenticated end to end (the pinned host key, the verified certificate), so the password buys a path, never a repository; the operator chooses the proxy and the network to it; a proxy restricted by the daemon's address needs none | A proxy on the daemon's host or a trusted network; a TLS link to the proxy ([backlog](backlog/README.md#a-tls-link-to-an-upstream-proxy)) |
| A proxy (M7.2) sees which upstream host the daemon reaches, when, and how much, and can refuse or slow every operation through it | It is the network path the operator chose for that remote; the tunnel's content is encrypted end to end, and a refusal or a stall fails the operation with its reason (bounded by `connect_timeout` and `mirrors.timeout`), never a fallback to a direct connection | A proxy the operator runs; Tor for what the remote learns of the daemon |
| An HTTPS upstream is authenticated by the system's CAs unless the operator narrows them (`mirrors.ca_certs`, then the only ones: the system's CA directory isn't given to git either): any public CA, or one compromised, could vouch for a remote and receive the token | The web PKI is how HTTPS remotes identify themselves (and the operator's own `git push` trusts it already); no redirect is followed; git reaches only the registry's host through the daemon's proxy, so a MITM needs a bad certificate for that very host | `mirrors.ca_certs` with only the remote's CA; certificate pinning (open question Q37); `ssh://` upstreams with a pinned host key |
| The boot tier (the SSH host key, the TLS key, the notification token with `token: boot`) is readable at rest: a copy of it, plus an intercepted `writ unseal`, lets an impostor pose as the daemon and receive the passphrase, which then opens a copy of the keys directory | A sealed daemon must authenticate itself before any human input, so without hardware what it uses can be rebuilt from its disk; the boot tier can live apart from the keys directory (another volume, a Docker secret); the unseal signature is bound to one daemon and one boot, so it can't be replayed; with `token: boot`, an "unsealed" message comes only from the real daemon | A transport key in hardware (M7.5 in local mode; YubiKey or TPM later); the approval API reached only over a trusted network ([good practice](operators/good-practice.md)) |
| With `token: boot`, whoever holds the boot tier can send messages as the notification bot | A notification never grants anything; the operator chooses it, knowing this | `token: sealed` |
| Memory locking is best effort (M5): without an unlimited lock limit or `CAP_IPC_LOCK` on Linux, and always on macOS (no call locks a whole process), a page of a secret can reach swap; the daemon starts anyway with a warning (Linux). Writ never changes a setting of the whole system to get it. (No core dump and no debugger attach are required: a release build that can't apply them, or started traced, doesn't start; a debug build started traced keeps running, with a warning) | Each failure says how to fix it, and the operator guide shows how to check each step; macOS encrypts swap | Set the host up as the operator guide says (M8's compose file does) |
| After unseal the daemon keeps the keystore's identity in memory (M5), to seal the keys a policy change creates and open the tokens `writ admin token` brings: whoever reads its memory once can also open, from a copy of the keys directory, the secrets added afterwards | Every secret the identity opens is already in the daemon's memory once unsealed; it is wiped on drop and never printed; reading the daemon's memory takes its user's account (or root), and process hardening (M5) refuses a debugger and core dumps | Hardware recipients (M7.6): each secret unwrapped by the device only when used, no identity held |
| The keystore's passphrase passes, in `writ unseal`'s request, through buffers Writ doesn't own: the SSH library's channel buffers, or hyper's and rustls's on HTTPS, on both sides, held while the request is handled | Writ wipes its own copies (the request body as it is read, every buffer it grows into, the decoded passphrase, the typed one), and every buffer the libraries free is zeroed by the wiping allocator ([M5.7](history/m5.7-memory-wiped-on-free.md)); the request goes only over the pinned, authenticated channel, to a reader key; reading another process's live memory takes its user's account | Hardware recipients (M7.6): no passphrase to send |
| With `unseal: auto` (M7.6, opt-in): anyone who can restart the daemon, or who takes the whole machine with its hardware, gets a running daemon without the approver | Only with every key and secret in hardware (the notification token and transport keys aside), so no copy of the disk opens anything; leases still need the approver's signature and fit their templates; the start is logged and notified; `writd recover` needs the offline recovery identity | Keep the sealed start (the default) |
| The authority files' state put back whole from an older copy (the policy, approvers and readers of that time) is accepted: every version in it carries a valid MAC | It is what restoring a backup is; anyone able to put the state back can also stop the daemon; the audit log keeps every change, and the files are written back with what is in force, so the change is visible | A hardware monotonic counter (a TPM's) in the head's MAC, with M7.6's hardware |
| Libraries hold copies of secrets while their call runs: age's encryption buffer (the plaintext of a key sealed at runtime: a policy change, `writ admin token` on the approver's Mac, `writd init`'s data key), bech32's checksum work and age's parse (the keystore identity's encoding at unseal); and what never goes through the heap: the stack and registers, git's own processes (an HTTPS token), the kernel's socket buffers | Since [M5.7](history/m5.7-memory-wiped-on-free.md) every block is zeroed when it is freed, whatever library made it (the wiping allocator of `writd`, `writ` and `writ-sign`), so such a copy lives only while its call runs; Writ wipes every copy it owns (the identity's text and 5-bit groups, the PEM bodies, the request bodies, each sized up front); a live copy is in the daemon's memory, or the approver's `writ`, which only their user can read | Hardware recipients (M7.6): no identity, and keys made in the device |
| RSA keys sign through AWS-LC (C and assembly, `aws-lc-rs`): a flaw there is in the signing path of an RSA key ([M5.5](history/m5.5-signature-formats-and-key-algorithms.md)) | Only RSA keys use it, and only an operator who declares one; it signs in constant time, which the pure-Rust `rsa` crate (banned: Marvin) doesn't, and agents can ask for signatures and time them | Ed25519 or ECDSA keys (pure Rust); hardware backends |
| Local mode on Linux (M7.1): the daemon's process reader holds `CAP_SYS_PTRACE`. Its seccomp filter leaves it `readlink` (and its socket, memory and exit), so an exploited reader could learn the names behind any process's links (its working directory, root, open files), never their contents or any process's memory | The kernel shows another user's executables and namespaces to that capability alone, and the daemon must see the agents' processes; the reader is a few lines that read a pid and answer two links, and `writd`, which handles every untrusted input, holds no capability and can't attach to it | A kernel interface that names a process's executable without the capability (none in Linux 6.x) |
| Restart needs a human (sealed start) | Keeps keys encrypted at rest | [Hardware-wrapped secrets](roadmap.md#m76--hardware-wrapped-secrets) (M7.6) |
| `writd` running as my user while developing (M0–M6) | Test keys and test repos only | A daemon isolated from my user (M7), Secure Enclave keys (M7.5) |
| `direct_ssh` repos: refs and content unchecked | Opt-in per repo, deploy key required by default | Prefer `proxy` (same checks as `gateway`, no mirror) |
| With `decisions: open`, any reader can refuse pending tickets or revoke leases without a signature, and an unsigned refusal's feedback reaches the agent (a way to steer it) | Opt-in (the default is `signed`); only keys in `readers` reach the approval API; never a grant; unsigned feedback is labeled as such for the agent and in the revision | Keep `decisions: signed` |
| Any caller from an address in the agents' `allow` list can submit tickets (a new agent has no identity yet) | The list is required; submissions are bounded (2 waiting per session key, 10 a minute per address or IPv6 /64 and 60 a minute from all sources together by default, both set by the operator in `writd.yaml` (`submissions`), `max_pending` in all, at least `min_ttl` each, 5 minutes by default; every refusal over a rate is counted in the log), notifications are bounded and coalesced, and nothing is granted without the approver's signature. The caps for all sources together (`max_pending`, `submissions.in_all`) mean a few allowed sources can delay everyone's submissions for a while; they can't get anything granted | Per-host agent keys registered with the daemon (backlog) |
| An operator who lowers `min_ttl` lets submitters renew their waiting slots sooner: the approver's notifications are then bounded by the `submissions` rates alone (60 a minute from all sources by default), not by `max_pending` over 5 minutes (about 4 a minute) | `min_ttl` defaults to 5 minutes and can't go under 10 seconds; it is the operator's choice in `writd.yaml`, next to the rates that still bound it, and the reference says what it trades | — |
| A denial before authentication (a source not allowed, no free connection slot, a key not in `readers`, a refused certificate) is coalesced: one audit line per source (an IPv6 /64) and minute, at most 60 lines a minute in all, with the count of the others | Every denial is still counted; a flood can't fill the disk and turn the audit log into a way to block revocations | — |
| Without an `allow` list on the approval listener, anyone who reaches it can hold its connection slots (256, 16 per source or IPv6 /64, 20 s each without authenticating), delaying a revocation through the API | A denial of service only; nothing is granted or read without a reader key; the agents' listener has its required `allow` list | Set `allow` on the approval listeners (the approver's Mac); firewall them |
| In local mode every caller on the Unix socket shares one submission rate (10 a minute by default, `submissions.per_source`) | Local agents are the user's own; the caps bound a runaway one | Per-process rates from the attestor's facts (M7) |
| Notifications go through a third party (Telegram): ticket ids, template names and revisions leave the network | No agent-written text is sent (no title: it could carry links, and it is the agent's words); nothing in a notification grants anything; the token is sent in clear only to a server on this machine | Another `Notifier` (self-hosted, native macOS) |
| On the approver's Mac, `writ` hands rustls a copy of the reader key (PKCS#8) for its client certificate, and ring keeps its own key for the life of the process (the copies Writ makes, and rcgen's, are wiped; rustls's is zeroed by the wiping allocator when it drops it, M5.7) | The reader key only reaches the approval API (reads, and unsigned refusals and revocations under `decisions: open`), never grants; `writ` lives for one command; reading another process's freed memory takes the user's account, which holds the approval key's agent anyway | A reader key in a hardware or agent-held backend (backlog); rustls and ring wiping keys upstream |
| The HTTPS approval API's TLS key (`tls-01`, P-256) is in the boot tier, readable at a sealed start (the boot tier's row above), and in the daemon's memory while it runs, in its own software `Signer` (wiped on drop; rustls holds no key and asks the `Signer` for each handshake signature) | The key only authenticates the daemon to approver clients, which pin its certificate, and grants nothing | Process hardening (M5, best effort); M7.5: the TLS key in the Secure Enclave, a config choice |
