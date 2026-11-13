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
| [x509 commit signatures](#x509-commit-signatures) | Signers | feature | M | idea |
| [Developer ID signed binaries](#developer-id-signed-binaries) | Packaging | improvement | S | idea |
| [Hardware-wrapped secrets](hardware-wrapped-secrets.md) | Sealing, Credentials | feature | M | in progress as [M7.6](../roadmap.md#m76--hardware-wrapped-secrets) |
| [SSH host key behind the `Signer`](#ssh-host-key-behind-the-signer) | Signers | hardening | M | idea; waits for a signer hook in russh (left out of M7.6) |
| [Own Mac approver app](#own-mac-approver-app) | Approvals | feature | L | idea |
| [iPhone approver app](#iphone-approver-app) | Approvals | feature | L | idea |
| [Non-exportable session keys](non-exportable-session-keys.md) | Identity | hardening | M | specified; picked as [M8.5](../roadmap.md#m85--non-exportable-session-keys) |
| [Local mode on Linux](#local-mode-on-linux) | Identity | feature | M | picked as [M7.1](../history/m7.1-local-mode-on-linux.md) |
| [Source-address pinning](#source-address-pinning) | Identity | hardening | S | idea |
| [Narrower upstream credentials](#narrower-upstream-credentials) | Upstream | hardening | M | idea |
| [A TLS link to an upstream proxy](#a-tls-link-to-an-upstream-proxy) | Upstream | hardening | S | idea |
| [A proxy program](#a-proxy-program) | Upstream | feature | M | idea |
| [Omega Code plugin](#omega-code-plugin) | Clients | feature | M | idea |
| [One program, several repositories](#one-program-several-repositories) | Clients | feature | M | idea (left out of [M6.1](../history/m6.1-multi-repo-workspaces.md)) |
| [Submodules](#submodules) | Clients, Gateway | feature | M | idea (left out of [M6.1](../history/m6.1-multi-repo-workspaces.md)) |
| [Per-repository tickets](per-repository-tickets.md) | Lease model, Approvals, Clients | feature | L | done in [M6.1.5](../history/m6.1.5-per-repository-tickets.md) |
| [A signing key per repository in one lease](#a-signing-key-per-repository-in-one-lease) | Signers, Clients | feature | M | idea (left out of [M6.1.5](../history/m6.1.5-per-repository-tickets.md)) |
| [Managing the daemon from the CLI](daemon-management-from-the-cli.md) | Administration, Signers, Upstream, Clients | improvement | L | done in [M6.2](../history/m6.2-managing-the-daemon-from-the-cli.md) |
| [Pending hand edits](#pending-hand-edits) | Administration | improvement | M | idea |
| [Old upstream histories](#old-upstream-histories) | Upstream | improvement | M | idea; lowest priority, waits for a real repository that needs it |

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

### SSH host key behind the `Signer`

The gateway's SSH host key (the boot tier's `host`) on a hardware backend like the TLS key
(M7.5), so a copy of the boot tier reveals no key at all. Left out of
[M7.6](../roadmap.md#m76--hardware-wrapped-secrets) with the user: russh 0.65 signs its host
key proofs in the key exchange with an in-memory `PrivateKey` (`server::Config::keys`) and has
no hook for an external signer. Reopens when russh grows one (an issue or a pull request
upstream; a patched copy carried in the tree was ruled out: a fork on the security path that
every upgrade must re-apply). Then: an adapter over the `Signer` (as `writ_signer::tls` does
for rustls), `writd init --host-key-backend`, and a live rotation re-pinning `known_hosts` as
`writ admin tls rotate` re-pins the TLS certificate.

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
([Platform interfaces](../architecture/platform.md)). Picked: the plan is
[M7.1](../history/m7.1-local-mode-on-linux.md).

### Source-address pinning

Bind a session certificate to the source address it was requested from (SSH certificate
`source-address` option): a stolen session key is useless from another host.

## Upstream

### Narrower upstream credentials

Deploy keys or bot accounts so upstream credentials stop having account-wide access, and the
repo registry is no longer the only per-repo boundary
([residual risks](../threat-model.md#residual-risks-v1)).

### A TLS link to an upstream proxy

Since [M7.2](../roadmap.md#m72--upstream-proxies), a repo's upstream can be reached through a
SOCKS5 or HTTP CONNECT proxy, the link to the proxy in clear: its password crosses the network
to it as both protocols send it. An `https://` proxy (CONNECT inside TLS, the proxy's
certificate verified against the system's CAs or a pinned one) would keep the password off the
wire for a proxy reached over an untrusted network.

### A proxy program

M7.2's proxies are protocols the daemon speaks itself. Some networks need a program in between
(an SSH bastion with `ssh -W`, a corporate client, `nc` variants), what OpenSSH's
`ProxyCommand` runs. A program the daemon runs per connection, with `%h` and `%p`, named in
`writd.yaml` (a host's setting, read at start, like `mirrors.ssh`) and only *referenced* by
name from the signed policy: a signed change must never choose a program the daemon runs.

### Old upstream histories

**Lowest priority: left alone until a real repository needs it.** Since M5.6 (S1), a tree is
read only with the five modes git writes, and `badFilemode` is an `fsck` error for every git
the daemon runs, syncs included ([decision log](../decisions.md), 2026-11-03). An upstream
whose history holds a mode only old tools wrote (`100664`, `100600`, `40755`…: git before mid
2005, some early converters) can't be mirrored at all: the sync's `fsck` refuses the whole
fetch. Writ can't rewrite those trees (rule 7, every hash would change); only the repository's
owner can (`git filter-repo`). Ways to serve them, in order of preference
([Q40](../decisions.md#open-questions)):

1. **Read modes exactly as git does, proved against git itself**: copy git's `canon_mode`
   (directory, file, link or submodule from the type bits), with a test that writes one tree
   holding every mode string Writ accepts (a bounded length, zero-padded forms included) and
   checks that `git ls-tree` and `writ_git::tree` read every entry alike. Upstream trees then
   read as git reads them; agent pushes stay strict (an agent's git never writes these modes).
2. **A narrow exception per repo**, as a stopgap: the registry lists the exact tree ids
   accepted despite their mode (git's `fsck.skipList`), approved with the policy's signature
   and audited; a new key with its five steps (rule 19).
3. **git computes the changed paths** (`git diff-tree`), one reader of trees only: the
   biggest change (a git process per check, every option pinned, signing's path check no
   longer pure Rust).

## Clients

### Omega Code plugin

Request the lease automatically when an agent tab opens, bind it to that tab's session (process
chain in local mode), and wire the repo's git config ([Q10](../decisions.md)).

### One program, several repositories

`writ exec -- <program>` passes one repository's settings to everything the program runs, and
`writ-sign` refuses a commit made in any other repository. A program that runs git in several
repositories of a workspace at once (a script looping over them) would need each git to get
its own repository's settings: a generated configuration with one `includeIf "gitdir:…"`
section per wired repository (through `GIT_CONFIG_GLOBAL`, including the user's own global
configuration), and `writ-sign` choosing the repository by the git directory it runs in.

### Submodules

A submodule is a repository inside another, and a commit in the parent records which commit
of the child it points to. Supporting them means wiring the child as its own repository (its
registry name), signing the parent's commits that move a pointer like any other, and fetching
the child through the daemon too (`git submodule update` reaches the child's own remote).

### A signing key per repository in one lease

Since M6.1.5 a ticket's repositories may fit different templates, but they must name the
same signing key: the session holds one (`signing_key.pub` or `.asc`), and `writ-sign` and
the wiring use it for every repository. The committer email is common to the lease for the
same reason (`common.committer_emails`); with this idea it moves to each repository's block. When the templates name different keys (or formats), the
agent asks one lease per repository instead. Letting one lease hold one key per repository
means the grant writing a key per repository in the session, the wiring pointing each
repository at its own, `writ-sign` asking the format per repository, and the approver seeing
each key.

## Administration

### Pending hand edits

Editing the policy, `approvers` or `readers` on the daemon host, then applying it with one
signature, instead of copying it to the Mac for `writ admin apply` ([sealing](../operators/sealing.md#changing-the-policy-the-approvers-or-the-readers)).
Today a hand edit is set aside at the next unseal (`<file>.unapplied-<time>`) and never
applied.

- **Flow:** edit the file on the host; nothing happens. From the Mac, `writ admin apply
  <target> --host` (name to settle): a new approval-API command has the daemon read its own
  file now (`read_authority`: regular file, owned by its user, no link, bounded, UTF-8
  without control characters) and return it; `writ` shows the diff against the version in
  force, saying it comes from the host file; one signature, an ordinary `writ-admin/2` over
  exactly that text naming the version in force, applied through the existing path.
- **The signature covers what was shown, not the file:** an edit made between the diff and
  the signature is not applied (set aside when the text in force is written back).
- **At unseal:** a file that differs is left in place as pending (a log line, an audit line,
  a notification; `writ info` says the host file differs) instead of being set aside. A
  change applied meanwhile by `writ admin apply` sets it aside as today, since it was made
  against an older version.
- **No file watcher:** the operator knows they edited it; watching would need a new platform
  seam for little gain.
- **Guarantee unchanged:** nothing is in force without an approver's signature over its whole
  text (the threat model's wording becomes "a hand edit is never in force unsigned"). New: the
  host file read on request is an untrusted input (an inventory row in
  [security](../security.md), its bounds, a hostile-input test). Whoever can write it can
  prepare a change and hope it is signed unread; the operator starts the apply and sees the
  whole diff. [`writd recover`](../operators/recovery.md) stays the locked-out path.
- **Open question:** at unseal, leave the hand edit in place (found where it was made) or
  move it to `<file>.pending` and write the version in force back (the host file always shows
  what is in force).
- **Rejected alternative:** an "unsecure" mode reading these files unsigned. Whoever can write
  them becomes an approver, or points an upstream at their server and receives its token;
  before M7 that is any agent running as the operator's user, and host access without the
  passphrase would win everything at the next unseal. It breaks the hard rules on failing
  closed and on signed admin changes.

## Parked

Looked at and set aside: each page says why it is a no-go for now and what would reopen it.

| Idea | Area | Kind | Parked on | Why |
|---|---|---|---|---|
| [Keychain Secure Enclave signer with a paid Apple account](parked/keychain-secure-enclave-signer.md) | Signers | feature | 2026-11-02 | Plan B under `_writd` already meets every goal, and a launchd daemon can't use the data protection keychain (TN3137) |
