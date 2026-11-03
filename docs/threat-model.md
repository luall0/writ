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
| Agent signing keys | Signer backend | Software (v1), YubiKey / SE / TPM later |
| Upstream remote credentials | Daemon: SSH keys behind the signer interface; HTTPS tokens in the keystore (a `0600` file until M5) | SSH keys on my remote accounts: **account-wide access**, not per repo; tokens as narrow as the remote allows (GitHub: one repository). Agents never see them; a token reaches only the daemon's own git, for one operation |
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
constraint ties a lease to one agent session's process tree, so another agent is refused; in
detached mode only the OS keeps agents apart (one user, container or VM each). M6 adds
`max_active_per_source` (`1` for a host meant for one agent) and shows the approver the host's
other active leases ([M6](roadmap.md#m6--agent-skill-amendments-and-close)).

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
applied ([M5](roadmap.md#m5--sealed-start-and-signed-admin-changes)). `writd.yaml` stays a
host file: it can't make anyone an approver.

### 6. Local mode: the daemon vs my own user
In local mode, agents run as my user. A daemon running as my user can't keep its keys from
them: they could read its files, use a Secure Enclave key blob, or attach to the process. So
the local daemon runs as a dedicated macOS user, `_writd`: my user can't read its files, use
its key blob or attach to it (checked in the M0 spike). Root stays out of scope, so my user
must not have passwordless `sudo`.

See [macOS Secure Enclave](architecture/macos-secure-enclave.md).

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
| ✅ Agents never get remote credentials or signing keys | `no_key_in_debug_or_errors`, `clients_never_see_an_internal_cause`, `errors_and_debug_never_contain_the_token`, `the_audit_log_holds_every_decision_and_no_secret`, `the_log_holds_no_secret`, `a_push_reaches_an_https_upstream_with_the_token_which_the_agent_never_sees`, `an_https_upstream_syncs_with_the_token_which_nothing_else_holds`, `a_token_upstream_refuses_fails_the_sync_without_showing_it`, `a_hostile_upstream_printing_the_token_back_has_it_taken_out`, `a_token_is_one_word_of_printable_ascii_and_never_printed`, `https_repos_take_the_operator_s_token_and_ssh_repos_a_generated_key` |
| ✅ An HTTPS upstream's token goes only to the registry's host, over TLS it verified, for one operation | `a_certificate_from_a_ca_the_daemon_does_not_trust_is_refused_before_any_token`, `the_operator_s_cas_are_the_only_ones_git_is_given`, `a_redirect_is_refused_and_the_token_never_follows_it`, `it_tunnels_only_to_upstream`, `only_a_request_for_this_upstream_over_https_is_answered`, `the_socket_answers_this_upstream_a_bounded_number_of_times`, `git_reaches_nothing_but_the_one_transport_allowed`, `https_urls_are_read_strictly` |
| ✅ No signature or push outside an active, approver-signed lease | `no_signature_or_push_outside_an_active_approver_signed_lease`, `a_ticket_outside_every_template_is_rejected_before_reaching_the_approver`, `a_narrowed_ticket_never_grants_more`, `a_lease_revoked_while_the_pack_comes_in_moves_no_ref`, `an_expired_or_revoked_lease_signs_nothing`, `a_lease_that_cannot_sign_is_refused_before_its_request_is_read`, `no_lease_an_expired_or_a_revoked_one_says_why` |
| ✅ Pushes only to allowed repos and refs, no force push unless allowed | `pushes_only_to_allowed_repos_and_refs_no_force_push_unless_allowed`, `destination_ref_and_protected_refs`, `fetch_and_push_through_the_gateway`, `git_runs_only_on_the_lease_repos_and_every_refusal_is_logged`, `a_branch_outside_the_lease_is_refused`, `a_force_push_or_a_deletion_is_refused_without_force_push`, `a_ref_that_differs_only_in_case_from_one_the_repo_has_is_refused`, `refs_that_differ_only_in_case_are_refused`, `an_agent_pushing_a_notes_ref_is_refused` |
| ✅ Only commits signed under the same lease reach upstream, with the paths checked at signing | `only_commits_signed_under_the_same_lease_reach_upstream`, `malformed_objects_never_land`, `a_commit_not_signed_under_this_lease_is_refused`, `a_commit_whose_paths_changed_since_signing_is_refused`, `a_pushed_commit_s_paths_must_be_the_ones_checked_at_signing`, `unsigning_gives_back_the_commit_that_was_signed` |
| ✅ Signatures only for allowed committer identities | `signatures_only_for_allowed_committer_identities`, `committer_identity_and_object`, `only_what_the_lease_allows_is_signed`, `what_the_commit_says_is_checked` |
| ✅ Signatures only for commits, in their repo's object format, linked to their lease (`Writ:` trailer) where the repo asks | `a_commit_is_signed_only_in_its_repo_s_object_format`, `only_what_the_lease_allows_is_signed`, `what_the_commit_says_is_checked`, `a_sign_request_that_isnt_one_is_refused_and_logged`, `trailers_are_git_s` |
| ✅ With `paths_check: deny`, no signature for a commit touching paths outside `expected_paths` (compared with its first parent, a merge too), or whose paths are unknown; the walk that finds them is bounded whatever the trees | `paths_outside_the_ticket_warn_or_deny`, `paths_outside_the_ticket_are_refused_with_paths_check_deny`, `evidence_is_only_what_its_bytes_hash_to`, `touched_paths_are_git_s`, `a_merge_is_checked_against_its_first_parent`, `a_shared_subtree_cannot_blow_up_the_walk`, `long_names_cannot_blow_up_the_walk`, `path_length_is_bounded_on_both_sides`, `path_bytes_are_bounded_on_both_sides`, `paths_are_bounded_on_both_sides`, `entries_are_bounded_on_both_sides` |
| ✅ The ledger holds the commit as signed: the same commit without its signature has another id | `a_commit_is_signed_counted_and_recorded_as_git_writes_it`, `the_signed_id_is_the_commit_git_writes`, `ed25519_commits_signed_by_the_daemon_verify_and_are_in_the_ledger` |
| ✅ Leases bounded in time, count and rate; revocable instantly | `leases_bounded_in_time_count_and_rate`, `counters_never_exceed_limits`, `signatures_stop_at_the_count_and_the_rate`, `signatures_stop_at_the_lease_s_count_and_rate`, `a_fetch_goes_through_the_policy_and_counts_against_the_rate`, `count_and_rate_hold_whatever_the_phases_interleaving`, `a_violation_revokes_only_a_lease_that_asks_for_it`, `a_violation_bars_the_certificate_even_when_its_revocation_fails`, `a_revocation_completes_while_a_signature_is_in_flight`, `a_violation_while_a_signature_is_in_flight_discards_it`, `a_lease_that_expires_while_signing_discards_the_signature`, `a_lease_amended_while_signing_discards_the_signature`, `the_last_signature_in_flight_is_not_refused_as_used_up`, `revocation_and_expiry_drop_sessions_and_refuse_the_certificate`, `a_revocation_never_waits_for_the_audit_log`, `a_revocation_completes_at_once_with_fetches_and_pushes_in_flight`, `a_restart_watches_bound_sessions_again`, `a_lease_revoked_while_the_pack_comes_in_moves_no_ref` |
| ✅ Everything logged (a lease's denials and allowed connections past 60 a minute counted), every line bounded | `every_text_in_a_line_is_bounded_on_both_sides`, `a_lease_s_denials_are_counted_past_sixty_lines_a_minute`, `a_lease_s_connections_are_counted_past_sixty_lines_a_minute`, `agent_text_stays_short_in_denials_warnings_and_the_log`, `the_audit_log_holds_every_decision_and_no_secret`, `nothing_is_granted_without_its_audit_line`, `a_failing_signer_or_audit_log_signs_nothing_and_keeps_the_slot`, `a_sign_request_that_isnt_one_is_refused_and_logged`, `an_unknown_ticket_is_logged_as_denied`, `git_runs_only_on_the_lease_repos_and_every_refusal_is_logged` |
| ✅ Only reader keys reach the approval API | `only_reader_keys_reach_the_approval_api`, `only_a_reader_key_gets_through_mutual_tls`, `https_turns_away_a_key_not_in_readers` |
| ✅ Writ never uses personal keys: only the approval key, in its agent | `writ_sign_never_signs_with_a_private_key_file` |
| ✅ An agent signing key signs nothing but commits under a lease and the proofs an approver signed, never in `git` or Writ's own namespaces | `a_proof_needs_an_approver_signature_over_exactly_that_document`, `a_proof_in_git_or_writ_s_namespaces_or_over_4_kib_is_refused`, `a_proof_and_a_ticket_approval_never_pass_for_each_other`, `a_proof_for_a_key_no_template_signs_with_is_refused`, `a_proof_the_signer_or_the_audit_log_fails_is_never_handed_out`, `a_hostile_proof_sent_over_the_wire_is_refused_and_logged` |
| ✅ The approver sees what gets signed, whatever the agent wrote | `a_hostile_ticket_shows_nothing_a_terminal_would_act_on`, `agent_text_cannot_push_the_enforced_terms_off_the_screen` |
| ✅ The keys directory alone reveals no key: every secret but the boot tier's is its own age file, unwrapped only after an unseal | `the_keys_directory_alone_reveals_no_key`, `a_replaced_or_foreign_file_is_refused_by_name` |
| ✅ While sealed, nothing is served: every request but `info` and `unseal` fails closed with "daemon sealed", and is logged | `while_sealed_every_request_fails_closed_with_daemon_sealed`, `while_sealed_every_request_fails_closed_with_daemon_sealed_and_is_logged`, `a_restart_keeps_active_leases_working_after_unseal` |
| ✅ Unsealing and admin changes need an approver signature (and, to unseal, the passphrase); a hand edit or a version altered at rest is never in force | `an_unseal_needs_an_approver_signature_over_this_daemon_and_this_boot`, `unsealing_needs_both_the_passphrase_and_an_approver_signature`, `an_unsigned_wrongly_signed_or_stale_change_is_refused_and_logged`, `a_signed_change_applies_at_once_and_is_written_back_to_its_file`, `a_hand_edited_file_is_set_aside_at_the_next_start_and_never_applied`, `versions_whose_mac_is_not_the_keystore_s_keep_the_daemon_sealed`, `a_version_altered_at_rest_keeps_the_daemon_sealed_and_writd_recover_needs_the_passphrase` |
| ✅ A token reaches the daemon only from an approver, encrypted to the keystore (never in clear on its disk), and never replayed; a key a signed policy change names is created in the keystore and used at once | `a_signed_token_against_the_file_in_force_is_logged_and_a_replay_is_stale`, `an_unsigned_wrongly_signed_or_malformed_token_is_refused_and_logged`, `a_sealed_service_takes_no_token`, `a_token_added_from_the_mac_is_used_at_once_and_never_in_clear_on_disk`, `a_policy_naming_new_keys_creates_them_and_uses_them_at_once`, `the_software_backend_passes_the_contract_behind_a_queue` |
| ✅ Hardware backends: keys non-exportable | planned: M7.5 |

## What Writ does NOT guarantee

- ❌ That signed content is good (that's review; see the future
  [LLM task-conformance check](backlog/llm-task-conformance.md))
- ❌ That a note on the remote (`ticket_link: notes`) is the daemon's: notes commits are
  unsigned, and anyone who can push to the remote can write or rewrite one. A note is a
  readable copy of the link; the daemon's ledger is the reference
  ([notes](architecture/gateway.md#notes))
- ❌ Protection of software keys against a compromised daemon host (v1)
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
| SHA-1 repositories are the default (`object_format: sha1`, as on GitHub and most remotes): there, the paths a commit touches are read from objects the agent sends, identified by SHA-1 | Each object's id is computed with collision detection (git's own `sha1dc` algorithm), which refuses the known attack constructions; a new chosen-prefix collision would cost a lot and only change what the path check sees, within the lease (the signature's other checks don't use these objects); the ledger's commit id includes the daemon's signature, which the agent can't predict; git and the remote rest on the same ids. A push is refused unless the paths are the same when computed again from the objects git verified in the quarantine (M4), so a forged tree never reaches the mirror or upstream through `gateway` (nor `proxy`, M9) | `object_format: sha256` where the remote supports it |
| A signature that fails, times out or is discarded (its lease revoked, expired or amended while it was being signed) still uses its count and rate slot; a crash between the phases uses one too | It errs toward less: no privilege is added, a failure can't be retried past the limits, and a stuck device holds up only commit signing (16 waiting at most, 10 s each), never approvals or revocations | A new lease, or an amendment raising `max_signatures` |
| A push that left for upstream before a revocation still lands: the lease is checked again right before the upstream push starts, but a push on its way can't be called back | The window is one upstream push (bounded by `mirrors.timeout`), for a push the policy already accepted under the lease; it reaches only what the lease allowed | — |
| Session key theft on an agent host | Bounded by lease scope and TTL | Non-exportable session keys (M8.5), source-address pinning (backlog) |
| In detached mode, agents on one host as one user can use each other's leases: the daemon can't tell processes on a remote host apart, and non-exportable session keys don't help (same user, same session agent) | Every lease is still bounded by its template and was signed by the approver; the approver sees the host's other active leases (M6) | One OS user, container or VM per agent ([good practice](operators/good-practice.md#more-isolation)); `max_active_per_source: 1` (M6); local mode's caller constraint |
| Daemon is a single point of failure | Fail closed is the right behavior | Local mode as fallback |
| Upstream keys have account-wide access | Remotes don't scope personal SSH keys per repo | Repo registry + `protected_refs` enforced by the daemon; keys on YubiKey; deploy keys or bot accounts later |
| An HTTPS upstream's token leaves the daemon's memory for each operation: its own git (and git's `remote-https`) holds it, through pipes, while the operation runs; a token can't stay in a signer, since it doesn't sign | Only the daemon's user reaches those processes and the private socket directory (boundary 5); one operation, then the socket is gone; never a command line, an environment, a URL or a file; the token as narrow as the remote allows | Prefer `ssh://` upstreams (the key never leaves the signer); M5's process hardening; per-operation tokens where a remote issues them (GitHub App installation tokens, backlog) |
| An HTTPS upstream is authenticated by the system's CAs unless the operator narrows them (`mirrors.ca_certs`, then the only ones: the system's CA directory isn't given to git either): any public CA, or one compromised, could vouch for a remote and receive the token | The web PKI is how HTTPS remotes identify themselves (and the operator's own `git push` trusts it already); no redirect is followed; git reaches only the registry's host through the daemon's proxy, so a MITM needs a bad certificate for that very host | `mirrors.ca_certs` with only the remote's CA; certificate pinning (open question Q37); `ssh://` upstreams with a pinned host key |
| The boot tier (the SSH host key, the TLS key, the notification token with `token: boot`) is readable at rest: a copy of it, plus an intercepted `writ unseal`, lets an impostor pose as the daemon and receive the passphrase, which then opens a copy of the keys directory | A sealed daemon must authenticate itself before any human input, so without hardware what it uses can be rebuilt from its disk; the boot tier can live apart from the keys directory (another volume, a Docker secret); the unseal signature is bound to one daemon and one boot, so it can't be replayed; with `token: boot`, an "unsealed" message comes only from the real daemon | A transport key in hardware (M7.5 in local mode; YubiKey or TPM later); the approval API reached only over a trusted network ([good practice](operators/good-practice.md)) |
| With `token: boot`, whoever holds the boot tier can send messages as the notification bot | A notification never grants anything; the operator chooses it, knowing this | `token: sealed` |
| Process hardening is best effort (M5): where a platform or the host's limits don't allow one step (memory locking without an unlimited lock limit or `CAP_IPC_LOCK`; macOS has no call to lock everything), the daemon starts anyway with a warning | Each failure says how to fix it, and the operator guide shows how to check each step; macOS encrypts swap | Set the host up as the operator guide says (M8's compose file does) |
| After unseal the daemon keeps the keystore's identity in memory (M5), to seal the keys a policy change creates and open the tokens `writ admin token` brings: whoever reads its memory once can also open, from a copy of the keys directory, the secrets added afterwards | Every secret the identity opens is already in the daemon's memory once unsealed; it is wiped on drop and never printed; reading the daemon's memory takes its user's account (or root), and process hardening (M5) refuses a debugger and core dumps | Hardware recipients (M7.6): each secret unwrapped by the device only when used, no identity held |
| The keystore's passphrase passes, in `writ unseal`'s request, through buffers Writ doesn't wipe: the SSH library's channel buffers, or hyper's and rustls's on HTTPS, on both sides | Writ wipes its own copies (the request body, the decoded passphrase, the typed one); the request goes only over the pinned, authenticated channel, to a reader key; reading another process's freed memory takes its user's account | Hardware recipients (M7.6): no passphrase to send |
| With `unseal: auto` (M7.6, opt-in): anyone who can restart the daemon, or who takes the whole machine with its hardware, gets a running daemon without the approver | Only with every key and secret in hardware (the notification token and transport keys aside), so no copy of the disk opens anything; leases still need the approver's signature and fit their templates; the start is logged and notified; `writd recover` needs the offline recovery identity | Keep the sealed start (the default) |
| The authority files' state put back whole from an older copy (the policy, approvers and readers of that time) is accepted: every version in it carries a valid MAC | It is what restoring a backup is; anyone able to put the state back can also stop the daemon; the audit log keeps every change, and the files are written back with what is in force, so the change is visible | A hardware monotonic counter (a TPM's) in the head's MAC, with M7.6's hardware |
| Restart needs a human (sealed start) | Keeps keys encrypted at rest | [Hardware-wrapped secrets](roadmap.md#m76--hardware-wrapped-secrets) (M7.6) |
| `writd` running as my user while developing (M0–M6) | Test keys and test repos only | A daemon isolated from my user (M7), Secure Enclave keys (M7.5) |
| `direct_ssh` repos: refs and content unchecked | Opt-in per repo, deploy key required by default | Prefer `proxy` (same checks as `gateway`, no mirror) |
| With `decisions: open`, any reader can refuse pending tickets or revoke leases without a signature, and an unsigned refusal's feedback reaches the agent (a way to steer it) | Opt-in (the default is `signed`); only keys in `readers` reach the approval API; never a grant; unsigned feedback is labeled as such for the agent and in the revision | Keep `decisions: signed` |
| Any caller from an address in the agents' `allow` list can submit tickets (a new agent has no identity yet) | The list is required; submissions are bounded (2 waiting per session key, 10 a minute per address or IPv6 /64 and 60 a minute from all sources together by default, both set by the operator in `writd.yaml` (`submissions`), `max_pending` in all, at least 5 minutes each; every refusal over a rate is counted in the log), notifications are bounded and coalesced, and nothing is granted without the approver's signature. The caps for all sources together (`max_pending`, `submissions.in_all`) mean a few allowed sources can delay everyone's submissions for a while; they can't get anything granted | Per-host agent keys registered with the daemon (backlog) |
| A denial before authentication (a source not allowed, no free connection slot, a key not in `readers`, a refused certificate) is coalesced: one audit line per source (an IPv6 /64) and minute, at most 60 lines a minute in all, with the count of the others | Every denial is still counted; a flood can't fill the disk and turn the audit log into a way to block revocations | — |
| Without an `allow` list on the approval listener, anyone who reaches it can hold its connection slots (256, 16 per source or IPv6 /64, 20 s each without authenticating), delaying a revocation through the API | A denial of service only; nothing is granted or read without a reader key; the agents' listener has its required `allow` list | Set `allow` on the approval listeners (the approver's Mac); firewall them |
| In local mode every caller on the Unix socket shares one submission rate (10 a minute by default, `submissions.per_source`) | Local agents are the user's own; the caps bound a runaway one | Per-process rates from the attestor's facts (M7) |
| Notifications go through a third party (Telegram): ticket ids, template names and revisions leave the network | No agent-written text is sent (no title: it could carry links, and it is the agent's words); nothing in a notification grants anything; the token is sent in clear only to a server on this machine | Another `Notifier` (self-hosted, native macOS) |
| On the approver's Mac, `writ` hands rustls a copy of the reader key (PKCS#8) for its client certificate: rustls drops it unwiped once loaded, and ring keeps its own key for the life of the process (the copies Writ makes, and rcgen's, are wiped) | The reader key only reaches the approval API (reads, and unsigned refusals and revocations under `decisions: open`), never grants; `writ` lives for one command; reading another process's freed memory takes the user's account, which holds the approval key's agent anyway | A reader key in a hardware or agent-held backend (backlog); rustls and ring wiping keys upstream |
| The HTTPS approval API's TLS key (`tls-01`, P-256) is in the boot tier, readable at a sealed start (the boot tier's row above), and in the daemon's memory while it runs, in its own software `Signer` (wiped on drop; rustls holds no key and asks the `Signer` for each handshake signature) | The key only authenticates the daemon to approver clients, which pin its certificate, and grants nothing | Process hardening (M5, best effort); M7.5: the TLS key in the Secure Enclave, a config choice |
