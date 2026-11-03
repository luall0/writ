# Roadmap

The milestones to [Scope v1](product.md#scope-v1). Work **strictly in order**: each milestone
ends with everything built so far working, tested, and committed. When a milestone is done,
its section moves to [`history/`](history/README.md) with notes on what was done (see
[AGENTS.md](../AGENTS.md#project-status)).

Order rationale: prove the risky protocol pieces first (M0), then build the policy as a pure
library (M1), then add one end-to-end capability per milestone (ticket → signing → pushing).
Writ guards real credentials, so it is used only on **test repos and test remote accounts**
until sealing and signed admin changes exist (M5); the first real task goes through Writ in M6.

The core is platform-agnostic from the start ([Platform interfaces](architecture/platform.md)):
M1 brings the caller facts into the policy, M2 puts every platform seam behind its interface
with one portable implementation each. During M0–M6 `writd` runs natively on the Mac over TCP.
Local mode (M7) and detached mode (M8) are then implementations and configuration plugged into
an unchanged core.

| # | Milestone | What it brings |
|---|---|---|
| M0 | [Protocol spike](history/m0-protocol-spike.md) ✅ | Go for the gateway (certificates, git, daemon-signed commits, agent-held approval keys); local mode's signer: CryptoKit Secure Enclave key under a `_writd` user |
| M1 | [Lease model and policy core](history/m1-lease-model-and-policy-core.md) ✅ | `writ-core`: tickets, templates, registry, narrowing, lifecycle, decisions; store and audit log |
| M2 | [Ticket flow](history/m2-ticket-flow.md) ✅ | `writ request` / `sign` / `refuse` / `revoke` / `ls`, certificates, the approval API over SSH and HTTPS, notifications (Telegram) |
| M2.5 | [Code quality checkup](history/m2.5-code-quality-checkup.md) ✅ | The review after M2 and its fixes; module layout and conventions ([conventions.md](conventions.md)); hardened tests and the integration test crate |
| M2.6 | [Security checkup](history/m2.6-security-checkup.md) ✅ | The security review after M2.5 and its fixes; the [security conventions](security.md), their checks in `make check`, CI |
| M3 | [Signed commits](history/m3-signed-commits.md) ✅ | `writ-sign`, the sign command through the `Signer`, touched paths from checked evidence, the ledger, `writ init` (wrapper mode), `object_format`; the review after M3 and its fixes |
| M3.5 | [Signing outside the lock](history/m3.5-signing-outside-the-lock.md) ✅ | `Service::sign` in three phases (the signer never runs under the state lock), the `QueuedSigner` in front of a backend |
| M3.6 | [Review after M3.5](history/m3.6-review-after-m3.5.md) ✅ | The security and code quality review after M3.5 and its fixes: sign requests bounded in time and number, `ops` pruned, the reader key's copies wiped, submission rates for all sources set by the operator with every refusal counted, a panicking signer logged once |
| M4 | [Gateway push and fetch](history/m4-gateway-push-and-fetch.md) ✅ | Mirrors synced as untrusted input, every push check in the quarantine, upstream over SSH before the mirror moves, `make e2e` |
| M4.1 | [Real end-to-end scenarios](history/m4.1-real-end-to-end-scenarios.md) ✅ | The operator's and the agent's paths run for real in containers against Forgejo, in CI: every command and flag in a scenario, the guides' commands the ones the pipeline runs, heavy concurrency; `writ prove-key` and verified commits on the account |
| M4.5 | [HTTPS upstream](history/m4.5-https-upstream.md) ✅ | Upstream over HTTPS with a token: the daemon's own credential helper fed by a one-operation socket, a one-operation proxy capping bytes and reaching only the registry's host, the certificate verified, no redirect |
| M4.6 | [Review after M4.5](history/m4.6-review-after-m4.5.md) ✅ | The security and code quality review after M4.5 and its fixes: a push's mirror never held by a client, the mirror lock with a deadline, `mirrors.ca_certs` the only trust, GnuTLS's certificate refusal read, the ledger before a push's walk, `mirrors.git`, `writ-mirror` split by concern |
| M4.7 | [Ticket link in git notes](history/m4.7-ticket-link-in-git-notes.md) ✅ | `ticket_link: notes`: each pushed commit's lease in a git note (`refs/notes/commits`, or `refs/notes/writ`), written and pushed by the daemon after the branch, merged with the remote's, the commit untouched |
| M5 | [Sealed start and admin changes](#m5--sealed-start-and-signed-admin-changes) | Encrypted keystore (one age file per secret, a boot tier for the transport keys), `writd init`, `writ unseal`, signed admin changes to approvers, readers, templates and registry applied live, `writ admin token`, process hardening |
| M5.5 | [Signature formats and key algorithms](#m55--signature-formats-and-key-algorithms) | OpenPGP commit signatures beside SSH; each signing key declared with its format, algorithm (Ed25519, P-256, P-384, RSA 3072/4096) and hash, checked against its backend at start; `writd keys create` |
| M6 | [Agent skill, amendments, close](#m6--agent-skill-amendments-and-close) | The Writ skill, amendments, activity report, each agent on its own lease, the host's other leases on the approver's screen: first real task end to end |
| M7 | [Local mode on the Mac](#m7--local-mode-on-the-mac) | macOS implementations plugged in: Unix socket, process chain, revoke on exit, a daemon isolated from my user, launchd, `writ try` |
| M7.5 | [Secure Enclave signer](#m75--secure-enclave-signer-on-the-mac) | The non-exportable local-mode signer the M0 spike picked |
| M7.6 | [Hardware-wrapped secrets](#m76--hardware-wrapped-secrets) | Each secret unwrapped by a hardware key only when used: the common unwrap interface, the Secure Enclave as its first recipient, unsealing with no passphrase |
| M8 | [Detached deployment](#m8--detached-deployment) | Docker image on the homelab, agents on other hosts |
| M8.5 | [Non-exportable session keys](#m85--non-exportable-session-keys) | The session key in the agent host's hardware (Secure Enclave, TPM) when it has some, detected on first use, switched with `writ session-key` |
| M9 | [`proxy` push mode](#m9--proxy-push-mode) | Relayed pushes with the same checks, no mirror |
| M10 | [`direct_ssh` push mode](#m10--direct_ssh-push-mode) | Lent per-lease ssh-agent socket with a deploy key |
| M11 | [Multi-user daemon](#m11--multi-user-daemon) (after v1) | Several people on one daemon: users with their own approvers, readers, templates and upstream credentials, admins for admin changes and unsealing |

M10 completes v1. M11 is the first idea picked from the [backlog](backlog/README.md) after
it; new work after M11 comes from there too.

## M0 — Protocol spike (go/no-go)

**Done.** Moved to [history/m0-protocol-spike.md](history/m0-protocol-spike.md): the gateway
stack is a go, and local mode's signer is a CryptoKit Secure Enclave key under a dedicated
`_writd` user.

## M1 — Lease model and policy core

**Done.** Moved to [history/m1-lease-model-and-policy-core.md](history/m1-lease-model-and-policy-core.md):
`writ-core` (tickets, templates, registry, canonical encoding, fit, narrowing, lifecycle,
caller checks, decisions) and `writ-store` (leases, ledger, audit log).

## M2 — Ticket flow: request, sign, refuse, revoke

**Done.** Moved to [history/m2-ticket-flow.md](history/m2-ticket-flow.md): the platform
traits with their portable implementations, fakes and contract suites; the approval service;
the approval API over SSH and HTTPS (each optional); `writ request` / `wait` / `ls` / `sign` /
`refuse` / `revoke`; certificates and revocation; Telegram notifications.

## M2.5 — Code quality checkup

**Done.** Moved to [history/m2.5-code-quality-checkup.md](history/m2.5-code-quality-checkup.md):
the review after M2 and its fixes (the pre-receive input limit, audit before change, gateway
denials logged, `writ-sign` without a plain `ssh`), the module layout and the
[code conventions](conventions.md), hardened tests and `crates/writ-integration`.

## M2.6 — Security checkup

**Done.** Moved to [history/m2.6-security-checkup.md](history/m2.6-security-checkup.md): the
security review after M2.5 and its fixes (availability, revocation, reader keys, `allow`
lists and bounds, authority files, the bounded trusted display, core hardening, explicit
crypto and SSH, supply chain and CI), the [security conventions](security.md) and their
checks in `make check`, the guarantee registry.

## M3 — Signed commits

**Done.** Moved to [history/m3-signed-commits.md](history/m3-signed-commits.md): `writ-git`
(commits, trailers, touched paths from evidence checked by its ids, the signed commit's id),
`writ-signer` (the `Signer` trait, the software backend, its contract suite), `Service::sign`
(policy, signature, audit line, counter and ledger under one lock; `on_violation` applied),
`writ-sign git <repo>`, `writ init` (wrapper mode by default: `writ git`, `writ exec`;
`--whole-repo`; `--undo`), `object_format` per repo, the operator guide.

## M3.5 — Signing outside the lock

**Done.** Moved to [history/m3.5-signing-outside-the-lock.md](history/m3.5-signing-outside-the-lock.md):
`Service::sign` in three phases (decide and take the slot, sign without the lock, check again
and record), a lease with a signature in flight not marked exhausted until it is settled, the
`QueuedSigner` in front of the agent keys' backend, the property test over interleavings.

## M3.6 — Review after M3.5

**Done.** Moved to [history/m3.6-review-after-m3.5.md](history/m3.6-review-after-m3.5.md):
the review after M3.5 and its fixes; what it found for M4 and M6 is in their sections below.

## M4 — Gateway push and fetch

**Done.** Moved to [history/m4-gateway-push-and-fetch.md](history/m4-gateway-push-and-fetch.md):
`writ-mirror` (the daemon's hardened git, mirrors synced from upstream as untrusted input,
upstream over OpenSSH with pinned host keys and a one-operation agent socket), fetches through
`decide_fetch` and the rate, every push check on what git verified in the quarantine (the
ledger, the paths again, case twins), accepted pushes upstream before the mirror moves,
`writ init`'s `origin` rewrite, a lease's connections coalesced, `make e2e` against Forgejo.
The throwaway GitHub repo check is left for the user
([manual checks](guides/manual-checks.md#a-throwaway-github-repo-m4)).

## M4.5 — HTTPS upstream

**Done.** Moved to [history/m4.5-https-upstream.md](history/m4.5-https-upstream.md): an
`https://` upstream reached with a token from the keystore (`<keys>/tokens/<id>` until M5),
handed to the daemon's own git for one operation by its credential helper
(`writd upstream-credential`) and a one-operation socket; git reaching only the registry's
host through a one-operation SOCKS5 proxy that caps what upstream sends; the certificate
verified (`mirrors.ca_certs` or the system's), no redirect; the token taken out of upstream's
words; scenario 13 against Forgejo behind a TLS front.

## M4.6 — Review after M4.5

**Done.** Moved to [history/m4.6-review-after-m4.5.md](history/m4.6-review-after-m4.5.md):
the review after M4.5 and its fixes (a push's mirror released at receive-pack's exit, at once
on a refusal and 10 s after an acceptance at the latest; `Mirrors::lock` with a deadline;
`mirrors.ca_certs` the only trust, the system's CA directory too, with an end-to-end scenario;
GnuTLS's certificate refusal recognized; the ledger read before a push's objects are walked;
`mirrors.git`; one `MirrorError` per cause; the arithmetic lint in `writ-mirror` and
`writ-gateway`; `mirror.rs` split by concern), and the review loop's.

## M4.7 — Ticket link in git notes

**Done.** Moved to [history/m4.7-ticket-link-in-git-notes.md](history/m4.7-ticket-link-in-git-notes.md):
`ticket_link: notes`, each pushed commit's lease in a git note (`refs/notes/commits` by
default, `refs/notes/writ` with `notes_ref: writ`), written by the daemon from its ledger and
pushed after the branch by a notes job under the mirror lock (merged with `cat_sort_uniq` when
the remote's ref moved, one retry, the notes waiting for the next push otherwise); unsigned
notes commits; the commits untouched.

## M5 — Sealed start and signed admin changes

[Signer and sealing](architecture/signer.md#startup-and-sealing),
[Flows § 7](flows.md#7-daemon-startup-sealed). From here, Writ may hold real credentials.
Settled with the user before building (the [decision log](decisions.md) has the rows).

**The keystore.**
- age keystore with a random data key: the data key is an age X25519 **identity**, wrapped
  with the passphrase (age scrypt), and **each secret is its own age file** encrypted to that
  identity's recipient: the CA key, the agent signing keys, the upstream credentials, the
  HTTPS upstreams' tokens, the authority MAC key (below), and the notification token when the
  operator seals it. Reading a secret goes through one seam (which identity unwraps this
  file), so hardware recipients ([M7.6](#m76--hardware-wrapped-secrets)) plug in with no
  format change and no migration. Public halves sit beside, in clear, so the commands that
  print a key need no unseal.
- **The boot tier.** A sealed daemon must still prove who it is to the client that brings the
  passphrase, so the keys that authenticate it are readable at a sealed start: the SSH host
  key and the HTTPS approval API's TLS key (with its certificate), in their own directory
  (`keystore.boot`, mode 0700, files 0600), which can live on another volume or a Docker
  secret than the keys directory. Nothing else is. Without hardware this can't be avoided:
  what a daemon uses before any human input can be rebuilt from its disk, so a copy of the
  boot keys plus an intercepted unseal gives the passphrase away (the threat model's residual
  risk; closed by a transport key in hardware, M7.5 in local mode).
- **The notification token, the operator's choice** (`notifiers[].telegram.token`: `{ boot: <file> }` or
  `{ sealed: <id> }`, required, no default): `boot` sends "writd restarted, sealed" at once, and
  "unsealed" only from the real daemon (no such message after a `writ unseal` that said it
  worked means something answered in its place), but whoever holds the boot keys can send
  as the bot; `sealed` sends nothing until unsealed. Both are written up in the operator
  guides.
- `writd init <writd.yaml>` (on the daemon host, as the daemon's user, once): asks for the
  passphrase twice, makes the identity, the boot keys (the TLS certificate signed through the
  `Signer`), the CA and every key the policy names; copies the authority files as their first
  versions in force; prints the host key, the TLS fingerprint, the upstream keys and the
  signing keys. It refuses an existing keystore.

**Sealed start and unseal.**
- `writd run` starts sealed: the listeners are up, every request but the unseal fails closed
  with "daemon sealed" (logged, coalesced per source like the other denials before a lease),
  and nothing of the keystore but the boot tier is read.
- `writ unseal` (on the Mac) asks for the passphrase (no echo) and signs a `writ-unseal/1`
  document with the approval key: it names the daemon's host key fingerprint and a random
  nonce drawn at each sealed start (`writ info` shows it), so an unseal signature is good for
  one daemon and one boot only. The daemon checks the signature first (only an approver can
  make it spend scrypt's second), then unwraps the identity, decrypts every secret, checks the
  authority versions (below), builds what the sealed start couldn't, reloads the active
  leases, logs `unseal`. A wrong passphrase or signature is refused and logged; either alone
  never unseals.
- The development keystore (`keystore: { dev: … }`, still refused by release builds) starts
  unsealed, for the integration tests.

**Signed admin changes.**
- After `writd init`, the policy (repo registry and templates), `approvers` and `readers`
  change only through `writ admin apply <policy|approvers|readers> <file>`: `writ` fetches the
  version in force (`writ admin show <target>`), shows the diff (agent-free text, neutralized
  all the same), and signs a `writ-admin/1` document: the target, the hash of the version in
  force, the full new text. The daemon checks it is unsealed, the signer is an approver in
  force, the version in force is still that one (no replay, no lost update), and the new text
  passes every startup check (approvers not empty, one key one purpose, the policy valid);
  then stores the version with its signed document, logs `admin` (target, both hashes, the
  signer), and **applies it live**: approvers and templates swap in the service (leases are
  re-checked against the current templates on each use already, and a tightened one is
  denied until amended), readers swap in the gateway (re-checked at each command), and a
  registry change reopens only the mirrors whose entry changed.
- **The daemon's state holds the versions in force**, each bound to the keystore by a MAC
  whose key is a sealed secret: at unseal every version is checked, and one altered, replaced
  or swapped for another version by anyone without the passphrase stops the unseal. The whole
  state put back from an older copy carries a valid MAC: that is a restored backup, which
  only a hardware counter could tell apart.
- **The files stay in sync:** after each applied change the daemon writes the text in force
  back to the file `writd.yaml` names, so the host shows what is in force. A hand edit is
  never applied: at start, a file that differs is moved aside to `<file>.unapplied-<time>`
  (the edit kept), the text in force written back, and both logged. `writd.yaml` itself stays
  a host file (listeners, `decisions`, mirrors): it can't make anyone an approver.
- **Keys:** a signed policy change that names a new agent signing key or `ssh://` upstream
  credential makes the daemon create it (Ed25519, encrypted to the recipient with its public
  half beside it), and hand it to its signer live through **`Signer::add_key`**: the
  interface's verb for a key made outside the backend (the software backend takes it by move;
  `QueuedSigner` passes it through its worker, in order with the signatures queued before,
  then refreshes its key list; a backend that can't take one answers `Unsupported`, the
  default). The reply (`AdminApplied`) and the `admin` audit line give each created key's
  public key to register. A key the keystore already holds (made by a change that failed
  after) is loaded, not made again. No key is ever made on a plain start (M5.5 adds declared
  algorithms and `writd keys create`; M7.5 a verb for keys a device makes itself).
- **The identity stays open:** after unseal the daemon keeps the keystore's identity in memory
  (wiped on drop), behind the one seam (`SecretFiles`), so a secret added later is opened as a
  start opens it. Every secret it opens is in memory already once unsealed; what it adds is in
  the threat model (closed by M7.6's hardware recipients).
- **Tokens:** `writ admin token <id>` fetches the keystore's public recipient (`writ info`),
  reads the token on the Mac (no echo; one line of stdin when it isn't a terminal), encrypts
  it there, and signs a `writ-token/1` document `{id, previous, sealed}`: the armored age
  ciphertext, and the digest of the `tokens/<id>.age` it replaces (`none` for a first one), so
  a replay or a lost update is refused as an admin change's is. The id must be one an
  `https://` repo or a sealed notifier (`token.sealed`) uses. The daemon checks the
  ciphertext opens to a token, writes `tokens/<id>.age`, logs `admin` (the id and both
  digests, never the token), and uses it at once: the mirrors of the repos that use it
  reopen, the notifier starts or takes the new token. The plaintext never touches the daemon
  host's disk. An `https://` repo without its token doesn't stop the unseal: its syncs and
  pushes are refused with "add it with `writ admin token <id>`"; a sealed notifier without
  its token stays off, with a warning. The development keystore refuses `writ admin token`
  (its tokens are files the operator writes). This changes in
  [M7.6](#m76--hardware-wrapped-secrets): the token is wrapped to the daemon host's hardware
  recipient and unwrapped there only when used.
- **Recovery, when every approver or reader key is lost, or to apply a file edited on the
  host:** `writd recover <writd.yaml> <policy|approvers|readers> <file>`, run on the host as
  the daemon's user with the daemon stopped, asks for the keystore passphrase, checks the file
  like an admin change, puts it in force as a new version (its own MAC, the reason "recovered
  on the host") and logs it (`admin`, no approver). It needs both the host and the
  passphrase, which together open every secret already: it gives an attacker nothing new.
  The operator guide also says to enroll a second approver key from the start (a YubiKey,
  `sk-ssh-ed25519`) and a second reader key.

**The TLS key behind the `Signer`.** Like every other key: under a key id (`tls-01`, P-256)
in the boot tier, its own `Signer` queue; the self-signed certificate is made by signing
through the `Signer`, and rustls signs handshakes through a small adapter (its signing-key
trait asking the `Signer`, which returns the raw signature; the adapter DER-encodes it).
The software backend (the `p256` crate, wiped on drop) is the default; a hardware backend is
a config choice (M7.5). Handshake signatures run off the async threads if the backend is
slow.

**Process hardening, best effort.** For every secret the daemon holds in memory: no core
dumps (`RLIMIT_CORE` 0; Linux: not dumpable), no debugger attach (Linux: not dumpable, which
also closes `/proc/<pid>/mem`; macOS: `PT_DENY_ATTACH`), memory locked out of swap (Linux:
`mlockall` only when the lock limit is unlimited or the daemon has `CAP_IPC_LOCK`: a partial
lock would make an allocation fail, and the daemon abort, once the limit is reached; macOS has
no call to lock everything, and encrypts swap). OS calls, so behind a platform interface with
its contract suite (hard rule 4), in new `writ-platform-linux` and `writ-platform-macos`
crates, applied at startup before any secret is read. Each one that can't be applied is a
startup warning saying how to fix it, never a stop; the operator guide lists how to check each
on the host, and the threat model says what is left without it.

**Tests.** The end-to-end pipeline moves to the sealed keystore (the operator path for real:
`writd init`, `writ unseal`, admin changes, tokens, recovery, hardening checked in the
containers); the integration tests keep the development keystore for most scenarios, plus
dedicated ones on the sealed keystore.

Steps (one commit each, `make ci` green):
1. The keystore format: the identity, one age file per secret behind the one seam, the boot
   tier, `writd init`, `keystore: { sealed: … }` in `writd.yaml`.
2. The TLS key behind the `Signer`: the certificate signed through it, the rustls adapter.
3. The sealed start and `writ unseal`; the notification token's two modes; leases reloaded.
4. Admin changes: the versions in force and their MAC, `writ-admin/1`, `writ admin show` and
   `apply`, applied live, the files written back, `writd recover`.
5. Keys and tokens through admin changes: keys made by a policy change, `writ admin token`.
6. Process hardening: the interface, its contract suite, the two platform crates.
7. The end-to-end pipeline on the sealed keystore, with the new scenarios.
8. Docs: architecture pages, operator guides, threat model, history.

Acceptance:
- [ ] While sealed, every request fails closed with "daemon sealed", and is logged.
- [ ] Unsealing needs both the right passphrase and a valid approver signature over this
      boot's `writ-unseal/1`; either alone, or a signature from an earlier boot or for
      another daemon, fails and is logged.
- [ ] The keys directory alone reveals no key (checked by inspecting it at rest); the boot
      directory holds only the host key, the TLS key and certificate, and the notification
      token when the operator chose `boot`.
- [ ] Each secret is its own age file; a test adds a second recipient (a fake) for one secret
      and reads it back with no change to the keystore code.
- [ ] A restart keeps active leases working after unseal; their certificates still expire on time.
- [ ] An unsigned or wrongly signed admin change is refused, so is one made against a version
      no longer in force; a signed one applies live and is logged; a hand-edited authority
      file is never applied (set aside, the text in force written back); a version altered
      at rest stops the unseal.
- [ ] A policy change naming a new signing key or upstream credential creates it, gives its
      public key, and signs or reaches upstream with it at once (`Signer::add_key`, passing the
      contract suite); `writ admin token` adds a token that never appears in clear on the
      daemon host and is used at once; a replayed or stale `writ-token/1` is refused; an
      `https://` repo without its token is refused with the reason, the daemon unsealed.
- [ ] `writd recover` replaces the policy, approvers or readers only with the passphrase,
      checked like an admin change, and is logged; without the passphrase it changes nothing.
- [ ] The TLS key is only in the boot tier and the `Signer`: no PEM key file, no copy outside
      the `Signer`; HTTPS approvals work as in M2, with the certificate pinned from
      `writd tls-fingerprint`.
- [ ] Where the platform allows it, the running daemon leaves no core dump when it crashes,
      refuses a debugger attaching to it (`lldb -p`, `gdb -p` as the same user), and its
      memory is locked (checked on macOS and on Linux); each one it can't apply is a startup
      warning with the fix.

## M5.5 — Signature formats and key algorithms

[The backlog page](backlog/signature-formats-and-key-algorithms.md) holds the design. Writ
signs in SSH only, with the Ed25519 keys the development keystore generates; many people keep
an OpenPGP key for commits, separate from their SSH keys, and the goal is as many of git's
formats as possible. After M5, because a key's UIDs are bound by a signed admin change and its
certificate lives in M5's keystore.

- **The `Signer` seam first** (hard rule 4): `sign` takes the hash to use (a message, or a
  digest already computed), `Capabilities` lists the (algorithm, hash) pairs a backend
  supports; the contract suite and the [signer page](architecture/signer.md) before any
  backend changes.
- **Keys declared:** `signing_keys.<id>` in `writd.yaml` (`format: ssh | openpgp`,
  `algorithm: ed25519 | p256 | p384 | rsa3072 | rsa4096`, `hash` optional, `backend`), the
  OpenPGP UIDs in `policy.yaml` (a signed admin change). One format per key.
- **Refused, never adjusted:** the daemon refuses to start, naming the key and the reason, on
  a format, algorithm, hash or backend that don't go together, a declared key missing from the
  keystore or held with another algorithm or format, an OpenPGP key without a UID for an email
  its templates allow, a template naming an undeclared key. `hash` left out: the strongest
  the format, algorithm and backend allow.
- **`writd keys create <writd.yaml> <id>`:** makes the declared key, writes it to the
  keystore, logs it, prints the SSH public key or the armored OpenPGP certificate to register.
  The development keystore follows the declarations.
- **The key-creation verbs may change shape here.** M5 gives the `Signer` one verb for a key
  made outside the backend, `add_key(id, PrivateKey)`, used by a signed policy change that
  names a new key (Ed25519). Declared algorithms and formats may reshape it (an OpenPGP key
  carries its creation time and UIDs; the declaration says what to make): change the
  interface, its contract tests and the [signer page](architecture/signer.md) first, as for
  `sign`'s hash. Settled in M5 ([decision log](decisions.md)), so M5.5 doesn't have to keep
  `add_key` as it is.
- **OpenPGP signatures** (v4, built in `writ-crypto`, never parsed from an agent): the
  certificate with its stored creation time and UID self-signatures; the sign command carries
  the format git asked for, a mismatch with the lease's key denied
  (`DenyCode::SignatureFormat`); the ledger unchanged.
- **RSA through `aws-lc-rs`** (constant time); the `rsa` crate stays banned. P-384 through
  `p384`.
- **Clients:** `writ-sign` as `gpg.program` (`-bsau`, `[GNUPG:] SIG_CREATED`; `--verify` to
  the real `gpg`, its path a client setting); `writ init` writes the OpenPGP settings when the
  lease's key is OpenPGP; `writ prove-key` for an OpenPGP key (Forgejo's
  `/user/gpg_key_verify` challenge).
- Docs: the [product](product.md) scope and non-goals, AGENTS.md's rule 13, the
  [signer](architecture/signer.md), [clients](architecture/clients.md),
  [gateway](architecture/gateway.md) and [flows](flows.md) pages, the operators' references,
  the [stack](stack.md), the [threat model](threat-model.md); the `x509` format stays a
  [backlog idea](backlog/README.md#x509-commit-signatures).

Acceptance:
- [ ] Every backend passes the `Signer` contract with the hash (the software backend for
      every algorithm and hash it declares); an undeclared pair is refused by name.
- [ ] Each refused configuration (format × algorithm, algorithm × hash, backend × algorithm,
      backend × hash, key missing, key held with another algorithm, email without a UID,
      undeclared key, RSA 2048) stops the start with its exact reason; each allowed one starts.
- [ ] `hash` left out picks the strongest the combination allows (tested per combination).
- [ ] A commit signed in OpenPGP with each algorithm verifies with the real `gpg`
      (throwaway `GNUPGHOME`) and is accepted at push through the ledger, as SSH ones.
- [ ] A sign request in the other format than the lease's key is denied with
      `SignatureFormat` and logged; the commit gets no signature.
- [ ] RSA signs in the software backend with no `rsa` crate in the graph (`cargo deny`).
- [ ] `writd keys create` makes, stores and logs a key, and refuses one already there; the
      certificate it prints imports into `gpg` with its UIDs.
- [ ] A UID added without an approver's signature is refused; with one, the new
      self-signature is made and logged.
- [ ] End to end (rule 18, 19): an OpenPGP key proved on Forgejo through `writ prove-key`,
      an agent's commit shown verified there; every new command, flag and key in its
      registry.
- [ ] Writ never reads `~/.gnupg` or uses a GnuPG agent (a test with a hostile `GNUPGHOME`
      and agent socket in the environment).

## M6 — Agent skill, amendments and close

The workflow the agent follows ([Clients](architecture/clients.md#client-list),
[Flows § 6 and § 6b](flows.md#6-out-of-ticket-request)).

- `skill/writ/SKILL.md`: think through the scope, write and submit the ticket, wait, revise on
  refusal, amend on an out-of-ticket denial, close with a summary. One skill for both
  wirings: the agent always runs git through `writ git …` (any command; plain git is the
  same in a `--whole-repo` clone), and adds the `Writ:` trailer where the repo's `ticket_link`
  is `trailer`; decided in M3.
- Amendments (`amends: <id>`): the original lease runs while pending, replaced once signed.
  An amendment changes scope, not time (decided after the M3.5 review,
  [M3.6](history/m3.6-review-after-m3.5.md)): its `expires_at` is capped at the lease's, so
  the certificate's `valid_before` stays the lease's end and a chain of amendments can't
  stretch a lease.
- `writ close` and the activity report: commits, pushes, branches, denials, time used vs
  granted, files touched vs `expected_paths`.
- **Each agent on its own lease.** Today `~/.writ/sessions/current` is one link per Writ
  home, moved by every granted `writ request`, and a wired repo follows it: two agents sharing
  a home silently swap leases, and one's work lands under the other's lease when that lease
  covers it. The session is now chosen, in `writ git`, `writ exec`, `writ init` and
  `writ-sign`, in this order: `WRIT_SESSION=<lease>`, then the repo's pinned lease
  (`writ init --lease <id>`, kept in the record; a whole-repo clone gets that lease's paths),
  then `current`. A chosen session that is unknown or ended is refused with a reason, never
  replaced by `current`; one command uses one session, so `writ-sign` refuses a commit when
  `WRIT_SESSION` names another session than the settings git gave it (a whole-repo clone
  pinned elsewhere). `writ request` prints the `WRIT_SESSION` line for its lease and warns when
  it moves `current` while another lease in the same home is active. The skill sets
  `WRIT_SESSION` for every command after its grant.
- **The host's other leases on the approver's screen.** The ticket records the source it was
  submitted from (an IPv4 address, an IPv6 /64, as `submissions.per_source` counts them; local
  mode is one source), and `writ sign` shows the other active leases from that source: id,
  repos, branches, operations, time left, at most 10 and a count, an overlap with the new
  ticket flagged (a repo in common and branch patterns that intersect). Display only.
- **`max_active_per_source`** in `writd.yaml` (no limit by default): the active leases one
  source may hold at once. Checked at submission (refused early, with its code) and again when
  the ticket is signed (a lease granted meanwhile makes the signature refused, fail closed); an
  amendment replaces its lease, it doesn't add one. A host meant for one agent sets `1`, and
  its agents can't reach each other's leases. Its row in the operator reference and the
  template, a test of its effect (rule 19).
- The threat model and the operators' good practice already say, since this milestone was
  planned, that an agent's reach in detached mode is every active lease on its host unless
  agents are isolated; M6 checks them against what was built.

Acceptance:
- [ ] A real feature on a personal repo goes from prompt to pushed branch through Writ, with
      exactly one Touch ID (the ticket), while I'm away.
- [ ] A refusal round-trip and an amendment round-trip both work from the agent's side using
      only the skill.
- [ ] The activity report matches the audit log for that lease.
- [ ] An amendment applied minutes before the lease ends doesn't move its end: `writ ls`, the
      lease and the certificate all end at the original time.
- [ ] Two agents on one host and one Writ home, each with its `WRIT_SESSION`: every signature
      and push lands under its own lease in the ledger, whichever lease `current` points at.
      A `WRIT_SESSION` naming an unknown or ended lease is refused with its reason, and
      nothing goes out under `current`.
- [ ] `writ init --lease`: a pinned repo uses its lease in both wirings; in a whole-repo clone
      pinned to one lease, `writ-sign` refuses a commit with `WRIT_SESSION` naming another,
      with its reason.
- [ ] `writ sign` lists the source's other active leases and flags an overlap; 11 of them
      show 10 and the count; a lease from another source isn't listed.
- [ ] `max_active_per_source`: one below the limit a submission is accepted, at the limit it
      is refused with its code; a lease granted between submission and signature makes the
      signature refused; a lease ending frees its slot; an amendment doesn't count twice.
- [ ] `WRIT_SESSION`, `writ init --lease` and `max_active_per_source` are used for real by
      end-to-end scenarios, with their rows in the registries (rules 18 and 19).

## M7 — Local mode on the Mac

[Deployment modes](architecture/overview.md#deployment-modes),
[process chain checks](architecture/identity.md#local-mode-process-chain-checks). This
milestone only **adds implementations** of existing interfaces and the local
[configuration preset](architecture/platform.md#configuration-presets). Signer: the software
backend; the Secure Enclave comes in M7.5. The daemon runs as a dedicated `_writd` user, as
the M0 spike decided ([macOS Secure Enclave](architecture/macos-secure-enclave.md#m0-results)).

- Unix socket `Transport` (portable Unix, in `writ-platform`).
- `writ-platform-macos`: process chain `CallerAttestor` (executable path and code signature,
  pid + pidversion), kqueue `SessionWatcher`; the full chain in the audit log.
- Leases bound to a session (`caller.descends_from`), revoked when its root process exits.
- **A daemon isolated from my user**: a LaunchDaemon running as a dedicated role user
  `_writd` (uid below 500, no shell, hidden), its binary root-owned, its keys and state in a
  `0700` directory. The agents' socket sits in a directory my user can reach; the daemon's
  files don't. Created and removed by `make install` / `make uninstall`, like the spike's
  `plan-b/` scripts.
- `writ try` with `--dry-run`, restoring everything on Ctrl-C.

Acceptance:
- [ ] **The graft test:** no change in `writ-core`, `writ-store`, `writ-git`, `writ-gateway`,
      `writ-approval` or the clients, beyond bug fixes; only new implementations, `writd`'s
      wiring and config.
- [ ] The macOS implementations pass the same contract suites as the portable ones.
- [ ] The same agent workflow as M6 works against the local daemon with no client change
      beyond the endpoint.
- [ ] A lease bound to a session refuses a caller outside that process tree, whatever its
      process name or arguments, and refuses every TCP caller.
- [ ] Quitting the session's root process revokes the lease.
- [ ] `writ try` leaves the repo and the machine exactly as before after Ctrl-C.
- [ ] My user (so any agent) can't read the daemon's keystore or attach to the daemon
      (`cat` and `lldb -p` refused), and the daemon starts again after a reboot.

## M7.5 — Secure Enclave signer on the Mac

Non-exportable agent keys in local mode: `se-cryptokit`, the backend the M0 spike picked
([macOS Secure Enclave](architecture/macos-secure-enclave.md#m0-results)), a CryptoKit
Secure Enclave key whose blob lives in `_writd`'s directory. A `Signer` implementation in
`writ-platform-macos` calling a small Swift component (CryptoKit has no C or Rust API) and a
config value; nothing else changes.

- **The key-creation verb first** (hard rule 4): M5's `Signer::add_key` takes a key made
  outside the backend, and a Secure Enclave can't take one: it makes its own. So M7.5 adds the
  verb for that (e.g. `create_key(id, algorithm) -> KeyInfo`, the daemon storing the blob or
  handle the backend returns), or merges both into one verb if that reads better then: the
  interface, its contract tests and the [signer page](architecture/signer.md) change before
  the backend. Each backend implements the verb that fits it and answers `Unsupported` for
  the other; the daemon picks by backend. Settled in M5 ([decision log](decisions.md)); the
  graft test below counts from the interface as M7.5 leaves it.
- The backend, and key creation for it (agent signing keys, the HTTPS approval API's TLS key,
  optionally the upstream credential). The Secure Enclave does P-256, the TLS certificate's
  curve. Moving the TLS key to it makes a new key, so a new certificate: approvers re-pin it
  once (`writd tls-fingerprint`).
- The Swift component and how `writd` calls it (linked in, or a helper process), built from
  the `Makefile`.
- A corrupted or foreign blob refused cleanly: CryptoKit crashes the process on one (M0), so
  it must never take the daemon down.

Acceptance:
- [ ] **The graft test:** only the new `Signer` implementation, `writd`'s wiring and config
      change.
- [ ] It passes the `Signer` contract suite, like the software backend.
- [ ] With the real daemon: signing needs no prompt, works after a reboot and with the screen
      locked; another process, and my user, can't find or use the key.
- [ ] Commits signed with it verify with `git verify-commit`, as in M3.
- [ ] With the TLS key in the Secure Enclave, HTTPS approvals work after re-pinning, and the
      old pin is refused.
- [ ] Going back to the software backend is a config change only.
- [ ] A corrupted blob is refused with a reason and the daemon keeps running.

## M7.6 — Hardware-wrapped secrets

[The backlog page](backlog/hardware-wrapped-secrets.md) holds the design. Every secret the
daemon holds but can't keep in a signer (the HTTPS upstreams' tokens, later the HTTP credential
proxy's, the keystore's data key) is wrapped to a hardware key that alone can unwrap it, and
unwrapped only when used. The interface is the common one: a YubiKey, a TPM or a cloud KMS
backend later brings its recipient as one more implementation, as it brings its `Signer`.

- The unwrap interface first (hard rule 4): `KeystoreUnlock` generalized into a recipient that
  unwraps one secret's file key, its contract suite, a fake, and
  [platform.md](architecture/platform.md) updated. M5's passphrase-unlocked identity becomes
  its first implementation.
- The Secure Enclave recipient in `writ-platform-macos`: P-256 key agreement through M7.5's
  Swift component, no prompt, the key under `_writd`.
- A recovery recipient (an age X25519 identity kept offline, on paper or a spare device), so
  one lost device doesn't lose every secret.
- Secrets unwrapped per use, zeroized after (no cache in this milestone); the keystore's data
  key wrapped the same way, so unsealing needs the approver's signature and no passphrase.
- How the operator adds or rotates a secret: encrypted to the printed public recipient, from
  any machine, through the signed admin change of M5 (`writ admin token`, which then
  encrypts to the daemon host's hardware recipient: the secret lives on the daemon host,
  unwrapped there only when used, instead of being decrypted at unseal).
- **Auto-unseal, opt-in** (`unseal: auto`, never the default): the daemon starts open, with
  no passphrase and no approver, only when nothing on the host opens a secret without a
  human. Every signing key in a hardware backend (the agent signing keys, the `ssh://`
  upstream credentials, and the CA key, moved behind the `Signer` for this), and every secret
  wrapped only to hardware recipients or the offline recovery identity (the tokens, the
  authority MAC key, the keystore's identity). Exempt: the notification token and the boot
  tier's transport keys, which may stay software. Anything else still software: the daemon
  refuses to start, naming each one (refused, never adjusted). The start is logged (`unseal`,
  "automatic") and notified. With the sealed start of M5 and software keys, there is no way
  to start unsealed.
- **The boot tier in hardware, as an option:** the TLS key on the Secure Enclave (M7.5's
  backend), and the SSH host key behind the `Signer` (an adapter so the gateway signs its host
  key proofs through it), so a copy of the boot tier reveals no key either.
- `writd recover` with auto-unseal takes the offline recovery identity (or the passphrase if
  one is kept), never the hardware alone: host access must not replace signed admin changes.
- **The operator guide** gets a step-by-step section for auto-unseal ([sealing](operators/sealing.md#starting-without-a-human-auto-unseal-m76)):
  moving each key and secret to hardware, making and checking the recovery identity, the
  `writd.yaml` change, checking the daemon took it, and the refusal when something is still
  software; its commands run in the end-to-end pipeline.

Acceptance:
- [ ] **The graft test:** the Secure Enclave recipient is a new implementation, `writd`'s
      wiring and config; the keystore, the gateway and the mirrors don't change.
- [ ] Every recipient passes the unwrap contract suite (the passphrase identity, the recovery
      identity, the Secure Enclave).
- [ ] With the real daemon: an HTTPS push unwraps its token with no prompt, after a reboot
      and with the screen locked; another process, and my user, can't unwrap it.
- [ ] A copy of the keys volume, with the passphrase, unwraps nothing that was wrapped to the
      Secure Enclave; the recovery identity alone unwraps everything.
- [ ] Removing the Secure Enclave key makes every secret wrapped only to it unreadable: the
      operation that needs one is refused with a reason, the daemon keeps running.
- [ ] A secret's plaintext is not in the daemon's memory between operations (checked on a
      memory dump of the idle daemon).
- [ ] `unseal: auto` starts the daemon open with every key and secret in hardware (the
      notification token and the transport keys aside), logged and notified; with any one
      still software it refuses to start, naming it; `writd recover` then needs the recovery
      identity, never the hardware alone.
- [ ] The boot tier in hardware: the TLS key on the Secure Enclave and the SSH host key behind
      the `Signer` work as the software ones, pinned the same way.
- [ ] The operator guide's auto-unseal section, followed as written, reaches a daemon that
      starts open, and its refusal when one secret is left in software.

## M8 — Detached deployment

[Deployment](architecture/deployment.md): the daemon on the homelab, agents anywhere on the
LAN or VPN.

- `deploy/Dockerfile` (non-root, minimal image) and `deploy/compose.yaml` with the two
  volumes, the gateway's port and the approval transports in use (SSH, HTTPS). **Builds on
  M4.1's test image** (`e2e/`: the pinned Rust builder stage, the Debian 13 runtime with git ≥
  2.45 and OpenSSH), decided with the user in M4.1: harden it (non-root, minimal, read-only
  where it can be) rather than start over, and `make e2e` then runs against the deploy image.
- Notifications (the configured `Notifier`) for sealed restarts, denials and violations
  (waiting tickets already notify since M2).
- Backup guidance for the ledger and the audit log.

Acceptance:
- [ ] `docker compose up` on the homelab → sealed → `writ unseal` from the Mac → agents on a
      VM and on the Mac both work under their own leases at the same time.
- [ ] A container restart notifies me and fails closed until unsealed.
- [ ] Only port 2222 and the approval transports in use (2223 SSH, 8443 HTTPS) are exposed;
      the process runs as non-root.
- [ ] Detached is only the detached [configuration preset](architecture/platform.md#configuration-presets)
      and packaging: no change to the core crates beyond bug fixes.

## M8.5 — Non-exportable session keys

[The backlog page](backlog/non-exportable-session-keys.md) holds the design. The session key is
the lease holder's whole identity, and today it is a file on the agent host: malware there can
copy it, with the certificate, and act as the lease holder from any address the gateway admits
until the lease ends. Held by hardware, it can be used on that host during the lease, never
copied. It matters once agents reach the gateway over TCP (M8); in local mode the socket and the
process chain already refuse a copied key.

- **The client-side platform seam first** (hard rules 4 and 16): today `writ-platform*` is the
  daemon's. A seam for where a session key lives, its contract suite and a fake, client
  platform crates, and the [dependency directions](architecture/overview.md#dependency-directions)
  and [conventions](conventions.md) updated, before any implementation.
- **A Writ session agent** on the agent host: it speaks the ssh-agent protocol, so git's `ssh`
  and `writ` only see a socket (`IdentityAgent`), and makes one key per lease. Backends: the
  Secure Enclave on a Mac (CryptoKit, no Touch ID, as M7.5) and a TPM 2.0 on Linux. Never the
  user's own ssh-agent (hard rule 8). The `file` kind stays today's Ed25519 key file.
- **On when the host can, off when it can't, never switched silently:** the first
  `writ request` with no recorded choice detects the hardware for real (creates a throwaway
  key and signs with it), records `hardware` or `file` in `~/.writ/`, and says what it chose
  and how to change it. `writ session-key` shows the choice and what the host supports;
  `writ session-key hardware|file` changes it for later leases (current ones keep their key);
  `WRIT_SESSION_KEY` overrides it. A recorded `hardware` that stops working makes
  `writ request` refuse with a reason, never fall back to a file.
- **The kind on the ticket:** the ticket carries the session key's kind (`hardware: secure-enclave`,
  `hardware: tpm`, `file`), and `writ sign` shows it. A client's claim, shown and never enforced
  (hard rule 6): the daemon takes Ed25519 and P-256 session keys and can't tell where one
  lives. Requiring it per template needs attestation (a TPM's), an open question.
- Docs: [identity](architecture/identity.md), [clients](architecture/clients.md), the
  [client settings](operators/clients.md), the [lease model](lease-model.md) (the ticket's
  new field) and the [threat model](threat-model.md); the session agent's binary in
  AGENTS.md's naming table.

Acceptance:
- [ ] **The graft test for the daemon:** no change beyond the ticket's new field, its
      validation and its display.
- [ ] Every backend passes the session key contract suite (the Secure Enclave, the TPM, the
      file).
- [ ] With a hardware session key, the session directory holds no private key; a copy of it
      on another host can't open a connection to the gateway (refused at authentication).
- [ ] Detection: a host with a working TPM (`swtpm` in a container) records `hardware`; one
      with none, or a TPM it can't use, records `file`; both say so and how to change it.
- [ ] A recorded `hardware` with the hardware gone: `writ request` refuses with its exact
      reason and writes no key file.
- [ ] `writ session-key`, both values and `WRIT_SESSION_KEY` used for real by an end-to-end
      scenario (rule 18), with their rows in the registries (rule 19).
- [ ] `writ sign` shows the kind; a ticket claiming a kind its key can't be (Ed25519 with
      `hardware`) is refused with its code.
- [ ] On the Mac, by hand ([manual checks](guides/manual-checks.md)): a Secure Enclave
      session key works with no prompt, with the screen locked, and can't be exported.

## M9 — `proxy` push mode

[Flows § 3b](flows.md#3b-push-proxy-mode), [Q22/Q23](decisions.md).

Acceptance:
- [ ] A repo with `push_modes: [proxy]` pushes with no mirror, with the same denials as M4
      (refs, protected refs, force push, ledger, size).
- [ ] The pack is indexed in a temporary quarantine bounded by `max_push_size` and deleted
      afterwards, accepted or not; `no-thin` is advertised.

## M10 — `direct_ssh` push mode

[Flows § 3c](flows.md#3c-push-direct_ssh-mode).

Acceptance:
- [ ] A per-lease ssh-agent socket holds only the repo's deploy key; signatures are refused
      for another host (`session-bind`), after expiry or over the limits.
- [ ] A repo whose credential is account-wide is refused unless `allow_account_wide: true`,
      and then `writ sign` shows the warning.

## M11 — Multi-user daemon

After v1. [The backlog page](backlog/multi-user.md) holds the design: users declared in the
daemon's configuration, each with their approver and reader keys, the templates they own and
their upstream credential per repo; a lease belongs to one user, whose authority decides who
may approve, refuse, revoke and read it and which credential pushes it; admins make admin
changes and unseal. Its open questions are settled with the user, and its plan written, before
any code; the acceptance below is final then.

Acceptance (draft):
- [ ] Two users push to the same repo at once under their own credentials: the remote shows
      each push as its user's, and both get their notes.
- [ ] Every cross-user attempt (approve, refuse, revoke, `ls`, `show`, push, an admin change
      by a non-admin) is refused with its exact code and logged with both users named.
- [ ] A v1 single-user configuration starts unchanged and behaves as before.
