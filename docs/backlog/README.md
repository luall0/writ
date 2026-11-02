# Backlog

Ideas and new requirements for Writ, not built yet, and not part of the
[roadmap](../roadmap.md) to v1. What was built, in order, is in the
[history](../history/README.md).

## How it works

1. **An idea** is a few lines below, under its area: what and why. Anyone adds one.
2. **Specified:** before building it, it gets its own page in this folder (the template
   below), written up to its plan, and its row links there.
3. **In progress:** the user picked it. Each commit of its plan leaves Writ working.
4. **Done:** the page moves to `docs/history/` (`git mv`) with a "What was done" section
   (what shipped, decisions, numbers), it is added at the end of the
   [history](../history/README.md), and its row and section leave this page. Links to its
   old path are updated in the same change.
5. **Parked:** looked at and set aside for now. Its page moves to (or is written in)
   [`parked/`](#parked) with why it is a no-go and what would reopen it, and its row moves to
   the parked table below. Reopening it moves the page back here.

Sizes are rough: **S** a day or less, **M** a few days, **L** a week or more. Nothing here is
a promise or an order: the user picks what comes next.

### Page template

```markdown
# <Title>

**Status:** idea | specified | in progress. **Area:** … **Kind:** feature | improvement | fix | hardening.

## Problem
What hurts today, and for whom.

## Proposal
What the user (or the agent) sees and does.

## Scope and non-goals
What is left out (see the product's non-goals).

## Design
Which crates own it; changes to the lease model, the protocol or the threat model.

## Threat model impact
New assets, actors or guarantees; what a compromised agent could do with it.

## Open questions
To decide before building.

## Acceptance
How we know it is done, including the guarantee tests it adds.

## Plan
The commits, each leaving Writ working. Added when the idea is picked.
```

## Index

| Idea | Area | Kind | Size | Status |
|---|---|---|---|---|
| [LLM task-conformance check](llm-task-conformance.md) | Policy | feature | L | idea, sketched |
| [HTTP credential proxy (v2)](http-credential-proxy.md) | Credentials | feature | L | idea, sketched |
| [Multi-user daemon](multi-user.md) | Identity, Approvals, Upstream | feature | L | specified up to its open questions; picked as [M11](../roadmap.md#m11--multi-user-daemon) |
| [YubiKey PIV signer backend](#yubikey-piv-signer-backend) | Signers | feature | M | idea |
| [TPM signer backend](#tpm-signer-backend) | Signers | feature | M | idea |
| [Cloud KMS signer backend](#cloud-kms-signer-backend) | Signers | feature | M | idea |
| [Signature formats and key algorithms](signature-formats-and-key-algorithms.md) | Signers, Clients | feature | L | specified; picked as [M5.5](../roadmap.md#m55--signature-formats-and-key-algorithms) |
| [x509 commit signatures](#x509-commit-signatures) | Signers | feature | M | idea |
| [Developer ID signed binaries](#developer-id-signed-binaries) | Packaging | improvement | S | idea |
| [Hardware-wrapped secrets](hardware-wrapped-secrets.md) | Sealing, Credentials | feature | M | specified; picked as [M7.6](../roadmap.md#m76--hardware-wrapped-secrets) |
| [Own Mac approver app](#own-mac-approver-app) | Approvals | feature | L | idea |
| [iPhone approver app](#iphone-approver-app) | Approvals | feature | L | idea |
| [Non-exportable session keys](non-exportable-session-keys.md) | Identity | hardening | M | specified; picked as [M8.5](../roadmap.md#m85--non-exportable-session-keys) |
| [Local mode on Linux](#local-mode-on-linux) | Identity | feature | M | idea |
| [Source-address pinning](#source-address-pinning) | Identity | hardening | S | idea |
| [Narrower upstream credentials](#narrower-upstream-credentials) | Upstream | hardening | M | idea |
| [Omega Code plugin](#omega-code-plugin) | Clients | feature | M | idea |

## Signers

### YubiKey PIV signer backend

Agent keys and upstream credentials on a YubiKey (P-256, P-384, ed25519 on recent firmware),
touch policy `never`, USB passthrough to the container. Removes the main v1 residual risk:
software keys extractable on the daemon host ([Signer](../architecture/signer.md)). Built in
[M7.5](../roadmap.md#m75--secure-enclave-signer-on-the-mac) instead if the M0 spike falls back
to Plan D for local mode. The Secure Enclave signer itself is on the roadmap (M7.5).

### TPM signer backend

Same, on the server's TPM 2.0 (P-256), keys bound to that machine.

### Cloud KMS signer backend

Agent signing keys and `ssh://` upstream credentials in a cloud key service (AWS KMS, Google
Cloud KMS, Azure Key Vault or Managed HSM, HashiCorp Vault Transit…), for a daemon on a VPS or
a server with no YubiKey, TPM or Secure Enclave: the private key never leaves the provider's
HSM, the daemon only asks it for signatures ([Signer](../architecture/signer.md)).

- **Algorithms:** P-256 on all of them, Ed25519 on some; the backend's `capabilities` say
  which, and the daemon refuses to start on a template whose key the service can't hold.
- **It moves the secret, it doesn't remove it:** the daemon still needs a credential for the
  service. Best is a workload identity (instance role, OIDC federation) with nothing on disk;
  otherwise it sits in the sealed keystore like a token. Root on the host can sign while the
  daemon holds it, but can never copy the key, and the provider's own audit log and
  revocation add a second record and a kill switch outside the host.
- **Network on the signing path:** one round trip per signature (tens of ms) and a new
  availability dependency. An unreachable service fails closed behind the signer queue's
  timeout; no fallback to a software key.
- **Signs only:** an `https://` repo's token still lives in the keystore, and unsealing is
  unchanged (a KMS that can decrypt is one more recipient of
  [hardware-wrapped secrets](hardware-wrapped-secrets.md)).
- One implementation per provider behind a Cargo feature in `writ-signer`, each passing the
  `Signer` contract suite (against the provider's emulator or a local Vault where one exists);
  no provider SDK in the core. The threat model gains a trusted third party (the provider and
  the account holding the keys).

### x509 commit signatures

Git's third signature format (`gpg.format = x509`, `gpgsm`: a CMS signature with an X.509
certificate), after SSH and OpenPGP ([M5.5](../roadmap.md#m55--signature-formats-and-key-algorithms)
leaves the seam: one encoder per format, `format` an open enum). To settle: where the
certificate comes from (a CA the operator runs, an S/MIME certificate from a public CA, which
GitHub shows as verified, or self-made), its renewal, which remotes verify it, and
`writ-sign` as `gpg.x509.program`.

### Developer ID signed binaries

Pay for the Apple Developer Program only to sign `writd`, `writ` and `writ-sign` with a
Developer ID certificate and notarize them, instead of the self-signed certificate M7
plans. What it brings: binaries that install on any Mac without Gatekeeper warnings or a
self-signed certificate to trust, and a code identity anchored in Apple (team ID) for the
process chain's `CodeIdentity`. Not a security gain for this Mac: Plan B's isolation comes
from the `_writd` user, not from the signature. Not coupled with the keychain signer, which is
[parked](parked/keychain-secure-enclave-signer.md). Worth it once Writ runs on Macs other than
mine.

## Approvals

### Own Mac approver app

A Secure Enclave approver app that shows the ticket in its own UI and signs the same SSHSIG
format: the Touch ID prompt finally shows what is signed. Adding it is adding a key to
`approvers` ([Approvals](../architecture/approvals.md)).

### iPhone approver app

Same, on the iPhone (Secure Enclave + Face ID), to approve away from the Mac.

## Identity

### Local mode on Linux

`writ-platform-linux`: a `CallerAttestor` from `SO_PEERCRED` and `/proc` (executable path,
start time as the pid's generation) and a pidfd `SessionWatcher`, so leases bound to a session
work for agents on a Linux workstation too. Only implementations and a config preset
([Platform interfaces](../architecture/platform.md)).

### Source-address pinning

Bind a session certificate to the source address it was requested from (SSH certificate
`source-address` option): a stolen session key is useless from another host.

## Upstream

### Narrower upstream credentials

Deploy keys or bot accounts so upstream credentials stop having account-wide access, and the
repo registry is no longer the only per-repo boundary
([residual risks](../threat-model.md#residual-risks-v1)).

## Clients

### Omega Code plugin

Request the lease automatically when an agent tab opens, bind it to that tab's session (process
chain in local mode), and wire the repo's git config ([Q10](../decisions.md)).

## Parked

Looked at and set aside: each page says why it is a no-go for now and what would reopen it.

| Idea | Area | Kind | Parked on | Why |
|---|---|---|---|---|
| [Keychain Secure Enclave signer with a paid Apple account](parked/keychain-secure-enclave-signer.md) | Signers | feature | 2026-11-02 | Plan B under `_writd` already meets every goal, and a launchd daemon can't use the data protection keychain (TN3137) |
