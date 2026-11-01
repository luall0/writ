# Threat model

What Writ defends against, what it protects, and what it explicitly does not guarantee. Every
guarantee below must be covered by at least one test that tries to break it
([Testing](testing.md#guarantee-tests)).

## Actors

| Actor | Description | Design target? |
|---|---|---|
| **Sloppy agent** | Does what it's asked but may commit/push to the wrong place, loop, push too much | ✅ Primary |
| **Prompt-injected agent** | Steered by malicious content (repo file, issue, web page, dependency) into abusing its access. It also **writes its own ticket**, so it can ask for more than the task needs with a convincing plan | ✅ Primary: templates cap any ticket, whatever its wording |
| **Malware on an agent host** | Code running next to the agent, can read the session key | ⚠️ Bounded by the lease |
| **Network attacker** | Between agent hosts, daemon, forges, approvers | ✅ Authenticated transports only |
| **Compromised approver key or Mac** | Can sign approvals | ⚠️ Bounded by templates (can't widen scope) |
| **Attacker on the daemon host** | Root or access to the Docker volumes | ❌ v1 with software keys; mitigated by YubiKey/TPM later |
| **Me** | Approves, reviews, revokes | Trusted |

## Assets

| Asset | Where | Notes |
|---|---|---|
| My personal keys | Secretive (Secure Enclave) | **Never touched by Writ** |
| Agent signing keys | Signer backend | Software (v1), YubiKey / SE / TPM later |
| Upstream forge credentials | Daemon, behind the signer interface | SSH keys on my forge accounts: **account-wide access**, not per repo. Agents never see them |
| Repo mirrors | Daemon host | Personal projects only for now |
| Session keys + certificates | Agent hosts | Short-lived, one per lease |
| Approver keys | Secretive (v1), YubiKey, own SE app later | Sign approvals, admin changes and unsealing; listed in the daemon's `approvers` file |
| Keystore passphrase (v1) | My head / password manager | Needed with an approver signature to unseal |
| Leases, ledger, audit log | Daemon (SQLite + JSONL) | Must survive an incident for review |
| Notifier credentials (Telegram bot token) | Daemon, a `0600` file (sealed keystore from M5) | Lets anyone send messages as the bot. Never in an error, `Debug` output or log line |

## Trust boundaries

### 1. Agent ↔ daemon: session certificate
The gateway only accepts SSH certificates issued by the daemon for an active lease.
**Possession of the session key = identity.** Anything on the agent host that can read the key
can use it, but only within the lease (repo, ops, branches, time, count).

Mitigations: short TTL, one key per lease, revocation list, Secure Enclave-held session key on
Macs, optional source-address pinning.

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
by nobody else. From M5, changes to them go through signed admin changes.

### 6. Local mode: the daemon vs my own user
In local mode, agents run as my user. A daemon running as my user can't keep its keys from
them: they could read its files, use a Secure Enclave key blob, or attach to the process. So
the local daemon runs as a dedicated macOS user, `_writd`: my user can't read its files, use
its key blob or attach to it (checked in the M0 spike). Root stays out of scope, so my user
must not have passwordless `sudo`.

See [macOS Secure Enclave](architecture/macos-secure-enclave.md).

## What Writ guarantees

Each guarantee names the tests that try to break it (the guarantee registry). `make check`
fails if a named test doesn't exist or is ignored, or if a guarantee has no test without a
milestone that brings it (`tool/check-guarantees.py`). A new guarantee comes with its tests,
in the same change (the security conventions, `docs/security.md`).

| Guarantee | Tests that try to break it |
|---|---|
| ✅ Agents never get forge credentials or signing keys | `clients_never_see_an_internal_cause`, `errors_and_debug_never_contain_the_token`, `the_audit_log_holds_every_decision_and_no_secret`, `the_log_holds_no_secret` |
| ✅ No signature or push outside an active, approver-signed lease | `no_signature_or_push_outside_an_active_approver_signed_lease`, `a_ticket_outside_every_template_is_rejected_before_reaching_the_approver`, `a_narrowed_ticket_never_grants_more`, `a_lease_revoked_while_the_pack_comes_in_moves_no_ref` |
| ✅ Pushes only to allowed repos and refs, no force push unless allowed | `pushes_only_to_allowed_repos_and_refs_no_force_push_unless_allowed`, `destination_ref_and_protected_refs`, `fetch_and_push_through_the_gateway`, `git_runs_only_on_the_lease_repos_and_every_refusal_is_logged` |
| ✅ Only commits signed under the same lease reach upstream | `only_commits_signed_under_the_same_lease_reach_upstream`, `malformed_objects_never_land` |
| ✅ Signatures only for allowed committer identities | `signatures_only_for_allowed_committer_identities`, `committer_identity_and_object` |
| ✅ Leases bounded in time, count and rate; revocable instantly | `leases_bounded_in_time_count_and_rate`, `counters_never_exceed_limits`, `revocation_and_expiry_drop_sessions_and_refuse_the_certificate`, `a_revocation_never_waits_for_the_audit_log`, `a_restart_watches_bound_sessions_again`, `a_lease_revoked_while_the_pack_comes_in_moves_no_ref` |
| ✅ Everything logged | `the_audit_log_holds_every_decision_and_no_secret`, `nothing_is_granted_without_its_audit_line`, `an_unknown_ticket_is_logged_as_denied`, `git_runs_only_on_the_lease_repos_and_every_refusal_is_logged` |
| ✅ Only reader keys reach the approval API | `only_reader_keys_reach_the_approval_api`, `only_a_reader_key_gets_through_mutual_tls`, `https_turns_away_a_key_not_in_readers` |
| ✅ Writ never uses personal keys: only the approval key, in its agent | `writ_sign_never_signs_with_a_private_key_file` |
| ✅ The approver sees what gets signed, whatever the agent wrote | `a_hostile_ticket_shows_nothing_a_terminal_would_act_on`, `agent_text_cannot_push_the_enforced_terms_off_the_screen` |
| ✅ Hardware backends: keys non-exportable | planned: M7.5 |

## What Writ does NOT guarantee

- ❌ That signed content is good (that's review; see the future
  [LLM task-conformance check](backlog/llm-task-conformance.md))
- ❌ Protection of software keys against a compromised daemon host (v1)
- ❌ Protection against an attacker who controls an agent host during a lease, beyond the
  lease scope

## Residual risks (v1)

| Risk | Accepted because | Mitigation path |
|---|---|---|
| Software keys extractable on daemon host | Personal use, homelab | YubiKey / TPM backend |
| Session key theft on an agent host | Bounded by lease scope and TTL | SE-held session keys, source pinning |
| Daemon is a single point of failure | Fail closed is the right behavior | Local mode as fallback |
| Upstream keys have account-wide access | Forges don't scope personal SSH keys per repo | Repo registry + `protected_refs` enforced by the daemon; keys on YubiKey; deploy keys or bot accounts later |
| Restart needs a human (sealed start) | Keeps keys encrypted at rest | Hardware unseal recipients later |
| `writd` running as my user while developing (M0–M6) | Test keys and test repos only | A daemon isolated from my user (M7), Secure Enclave keys (M7.5) |
| `direct_ssh` repos: refs and content unchecked | Opt-in per repo, deploy key required by default | Prefer `proxy` (same checks as `gateway`, no mirror) |
| With `decisions: open`, any reader can refuse pending tickets or revoke leases without a signature, and an unsigned refusal's feedback reaches the agent (a way to steer it) | Opt-in (the default is `signed`); only keys in `readers` reach the approval API; never a grant; unsigned feedback is labeled as such for the agent and in the revision | Keep `decisions: signed` |
| Any caller from an address in the agents' `allow` list can submit tickets (a new agent has no identity yet) | The list is required; submissions are bounded (2 waiting per session key, 10 a minute per address, `max_pending` in all, at least 5 minutes each), notifications are bounded and coalesced, and nothing is granted without the approver's signature | Per-host agent keys registered with the daemon (backlog) |
| A denial before authentication (a source not allowed, no free connection slot, a key not in `readers`, a refused certificate) is coalesced: one audit line per source and minute, with the count of the others | Every denial is still counted; a flood can't fill the disk and turn the audit log into a way to block revocations | — |
| Notifications go through a third party (Telegram): ticket ids, template names and revisions leave the network | No agent-written text is sent (no title: it could carry links, and it is the agent's words); nothing in a notification grants anything; the token is sent in clear only to a server on this machine | Another `Notifier` (self-hosted, native macOS) |
| The HTTPS approval API's TLS private key sits in rustls's memory for the daemon's life, not zeroized (rustls and ring don't wipe keys) | The daemon holds it in no other copy; the key only authenticates the daemon to approver clients, which pin it, and grants nothing | M5: the TLS key behind the `Signer` (software backend, wiped on drop) and process hardening (no core dumps, no debugger attach, secrets locked out of swap); M7.5: the TLS key in the Secure Enclave, a config choice |
