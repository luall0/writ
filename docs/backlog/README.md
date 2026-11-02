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
| [Keychain Secure Enclave signer with a paid Apple account](#keychain-secure-enclave-signer-with-a-paid-apple-account) | Signers | feature | M | idea, spiked |
| [Hardware unseal recipients](#hardware-unseal-recipients) | Sealing | feature | M | idea |
| [Own Mac approver app](#own-mac-approver-app) | Approvals | feature | L | idea |
| [iPhone approver app](#iphone-approver-app) | Approvals | feature | L | idea |
| [Secure Enclave session keys](#secure-enclave-session-keys) | Identity | hardening | M | idea |
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

### Keychain Secure Enclave signer with a paid Apple account

The `se-keychain` backend of [macOS Secure Enclave](../architecture/macos-secure-enclave.md):
a Secure Enclave key in the data protection keychain under a keychain access group, once the
Apple Developer Program is paid. The M0 spike built it with a free Personal Team (the Xcode
project is archived in commit `3485f40`, `spikes/secure-enclave/keychain-app/`); what it found:

- Works: the capability, launching with the profile, key creation and signing with no
  prompt (6–7 ms); code without the entitlement is refused (`-34018`), an ad-hoc binary
  claiming it is killed at launch.
- **Isolation is by team, not by daemon:** other code, reusing the profile and signed with my
  Apple Development identity, used the key without a prompt. Anything running as my user can
  sign with my team (identity in the login keychain, Xcode's account session), so the design
  must keep the signing identity out of the agents' reach (build elsewhere, or remove it from
  this Mac after signing) and drop `get-task-allow` (no debugger attach).
- A Personal Team profile lasts 7 days; a paid account's lasts years, which is what makes
  removing the identity from this Mac practical.
- The paid team ID likely differs from the Personal Team's: the access group changes, so the
  keys are created again (agent keys re-registered on remotes and in `allowed_signers`).

Most of what it needs (SSHSIG conversion, the `Signer` contract suite, key creation) comes
with the CryptoKit backend in [M7.5](../roadmap.md#m75--secure-enclave-signer-on-the-mac).

## Sealing

### Hardware unseal recipients

Wrap the keystore's data key to age plugin recipients (Secure Enclave, YubiKey) so unsealing
needs no passphrase, plus a recovery recipient (offline YubiKey or paper key) so one lost
device doesn't lose everything ([Startup and sealing](../architecture/signer.md#startup-and-sealing)).

## Approvals

### Own Mac approver app

A Secure Enclave approver app that shows the ticket in its own UI and signs the same SSHSIG
format: the Touch ID prompt finally shows what is signed. Adding it is adding a key to
`approvers` ([Approvals](../architecture/approvals.md)).

### iPhone approver app

Same, on the iPhone (Secure Enclave + Face ID), to approve away from the Mac.

## Identity

### Secure Enclave session keys

The optional session agent holds the session key in the Mac's Secure Enclave (no Touch ID),
so malware on the agent host can use it during the lease but never copy it
([Identity](../architecture/identity.md)).

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
