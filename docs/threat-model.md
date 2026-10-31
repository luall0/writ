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
**exact lease content**. A notification click alone is never an approval. Admin changes
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

### 6. Local mode: the daemon vs my own user
In local mode, agents run as my user. A daemon running as my user can't keep its keys from
them: they could read its files, use a Secure Enclave key blob, or attach to the process. So
the local daemon runs as a dedicated macOS user, `_writd`: my user can't read its files, use
its key blob or attach to it (checked in the M0 spike). Root stays out of scope, so my user
must not have passwordless `sudo`.

See [macOS Secure Enclave](architecture/macos-secure-enclave.md).

## What Writ guarantees

- ✅ Agents never get forge credentials or signing keys
- ✅ No signature or push outside an active, approver-signed lease
- ✅ Pushes only to allowed repos and refs, no force push unless allowed
- ✅ Only commits signed under the same lease reach upstream
- ✅ Signatures only for allowed committer identities
- ✅ Leases bounded in time, count and rate; revocable instantly
- ✅ Everything logged
- ✅ Hardware backends: keys non-exportable

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
