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
Local mode (M7 on the Mac, M7.1 on Linux) and detached mode (M8) are then implementations and
configuration plugged into an unchanged core, each installed by one installer where a setup is
picked.

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
| M5 | [Sealed start and admin changes](history/m5-sealed-start-and-signed-admin-changes.md) ✅ | Encrypted keystore (one age file per secret, a boot tier for the transport keys), `writd init`, `writ unseal`, signed admin changes to approvers, readers, templates and registry applied live, keys made by a signed policy, `writ admin token`, process hardening, the end-to-end pipeline on the sealed keystore |
| M5.5 | [Signature formats and key algorithms](history/m5.5-signature-formats-and-key-algorithms.md) ✅ | OpenPGP commit signatures beside SSH; each signing key declared with its format, algorithm (Ed25519, P-256, P-384, RSA 3072/4096) and hash, checked against its backend at start; `writd keys create` |
| M5.6 | [Review after M5.5](history/m5.6-review-after-m5.5.md) ✅ | The security and code quality review after M5 and M5.5 and its fixes: tree modes read as git reads them, upload-pack in protocol v0, admin changes bound to their version, a removed approver's leases revoked, the author checked like the committer, a bounded trusted display, notes appended, the three test layers hardened |
| M5.7 | [Memory wiped on free](history/m5.7-memory-wiped-on-free.md) ✅ | Writ's own zero-on-free allocator in `writd`, `writ` and `writ-sign`, on in every build: no library's freed copy of a secret stays in memory, at no measurable cost under heavy load |
| M6 | [Agent skill, amendments, renewals, close](history/m6-agent-skill-amendments-renewals-and-close.md) ✅ | The Writ skill installed by `writ init` for each agent, adaptive timings, amendments, renewals, the estimate, activity report, each agent on its own lease, the host's other leases on the approver's screen: first real task end to end |
| M6.1 | [Multi-repo workspaces](history/m6.1-multi-repo-workspaces.md) ✅ | One agent at the root of a folder of repositories: `writ init` at the root, the `writ-workspace` skill, `writ git` reading git's global options, `writ exec -C` |
| M6.1.5 | [Per-repository tickets](history/m6.1.5-per-repository-tickets.md) ✅ | A ticket given repository by repository (the lease's terms, then each repository's block under its own template), one approval, one lease, one signing key, the strictest template's time and rate, counts per repository; `writ sign` narrowing per repository; `writ policy` for several repositories |
| M6.2 | [Managing the daemon from the CLI](history/m6.2-managing-the-daemon-from-the-cli.md) ✅ | Every key declared in the signed policy, upstream host keys pinned by signed changes, repos naming their templates; `writ admin repo\|template\|key\|host` to read, add step by step and edit one field at a time, with no host access |
| M7 | [Local mode on the Mac](history/m7-local-mode-on-the-mac.md) ✅ | macOS implementations plugged in: Unix socket, process chain, `writ run` binding a lease to the harness it starts, revoke on exit, a daemon isolated from my user, launchd, the installer (a setup to pick, `local` first) and an uninstall as easy that offers to take Writ out of the wired repos |
| M7.1 | [Local mode on Linux](history/m7.1-local-mode-on-linux.md) ✅ | Linux implementations plugged in the same way: the peer's pidfd and a `/proc` process chain read by a capped helper, a pidfd watcher, a systemd service under its own user, the installer's Linux local setup, local mode in `make e2e` |
| M7.2 | [Upstream proxies](history/m7.2-upstream-proxies.md) ✅ | A repo's upstream reached through a named proxy (SOCKS5, Tor included, or HTTP CONNECT, with an optional password from the keystore), for remotes reachable only from some addresses; `writ admin proxy`, host scans through it |
| M7.5 | [Secure Enclave signer](history/m7.5-secure-enclave-signer.md) ✅ | The non-exportable local-mode signer the M0 spike picked: keys made in the Secure Enclave through a helper process, the TLS key rotated live, every key's backend from the CLI, the installer guided |
| M7.6 | [Hardware-wrapped secrets](history/m7.6-hardware-wrapped-secrets.md) ✅ | Each secret unwrapped by a hardware key only when used: the common unwrap interface, the Secure Enclave as its first recipient, a recovery identity, unsealing with no passphrase, the CA behind the `Signer`, auto-unseal |
| M7.7 | [Review after M7.6](#m77--review-after-m76) | The security and code quality review of the whole code after M5.7 to M7.6 (the wiping allocator, the skill, amendments and renewals, workspaces, per-repository tickets, the CLI's admin commands, local mode on both systems, upstream proxies, the Secure Enclave signer, hardware-wrapped secrets) by thirteen reviewers: a report discussed with the user, then every finding fixed with its test, or moved to the milestone that owns it |
| M7.9 | [Local mode checked on the Mac](#m79--local-mode-checked-on-the-mac) | The real install on the Mac, with M7.5's Secure Enclave and M7.6's hardware-wrapped secrets in place: `make install`, `writ unseal`, an agent under `writ run`, the daemon out of my user's reach, a stop through launchd, a reboot, the recovery guide, and `make uninstall` leaving the Mac as before |
| M8 | [Detached deployment](#m8--detached-deployment) | Docker image on the homelab, agents on other hosts; the installer's `detached` and `client` setups |
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

## M4.1 — Real end-to-end scenarios

**Done.** Moved to [history/m4.1-real-end-to-end-scenarios.md](history/m4.1-real-end-to-end-scenarios.md):
the operator's and the agent's paths run for real in containers against Forgejo, in CI; every
command and flag in a scenario; the guides' commands the ones the pipeline runs.

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

**Done.** Moved to [history/m5-sealed-start-and-signed-admin-changes.md](history/m5-sealed-start-and-signed-admin-changes.md):
the encrypted keystore and its boot tier, `writd init`, `writ unseal`, signed admin changes
to approvers, readers and the policy applied live, keys made by a signed policy, `writ admin
token`, process hardening.

## M5.5 — Signature formats and key algorithms

**Done.** Moved to [history/m5.5-signature-formats-and-key-algorithms.md](history/m5.5-signature-formats-and-key-algorithms.md):
the `Signer` with the hash and a `RawSignature`, RSA through `aws-lc-rs`, P-384, signing keys
declared in `writd.yaml` (format, algorithm, hash, backend) and checked at start, OpenPGP user
ids in the policy, `writd keys create`, OpenPGP v4 signatures and certificates written by the
daemon, `writ-sign` as `gpg.openpgp.program`, `writ prove-key` for an OpenPGP key, end-to-end
scenario 18 on Forgejo. Its integration and end-to-end runs passed with M5.6's.

## M5.6 — Review after M5.5

**Done.** Moved to [history/m5.6-review-after-m5.5.md](history/m5.6-review-after-m5.5.md):
the review after M5 and M5.5 and every finding fixed with its test (a tree read only with the
modes git writes, upload-pack in protocol v0, admin changes bound to their daemon and version,
a removed approver's leases revoked, the author checked, a trusted display within 78 columns,
notes appended), the three test layers and the source rules hardened, a second review in four
passes; SIGTERM (M7, M8), `writd keys create` while the daemon runs (M7) and a whole-repo
clone following its lease (M6) left in their sections. `make ci` and `make e2e` passed.

## M5.7 — Memory wiped on free

**Done.** Moved to [history/m5.7-memory-wiped-on-free.md](history/m5.7-memory-wiped-on-free.md):
`writ-alloc`, Writ's own wiping allocator (each block zeroed on free behind a compiler
barrier, checked on the optimized code; `realloc` as a new block and a wiped free), the global
allocator of `writd`, `writ` and `writ-sign`, on in every build: under heavy load it cost
nothing measurable on macOS or Linux (`make bench-alloc`).

## M6 — Agent skill, amendments, renewals and close

**Done.** Moved to [history/m6-agent-skill-amendments-renewals-and-close.md](history/m6-agent-skill-amendments-renewals-and-close.md):
the Writ skill built into `writ` and installed by `writ init` for each agent, adaptive timings
(`writ close`, `writ timings`, `writ mark`, `writ check`), amendments ending with their lease,
renewals (`ticket.renews`, `renew_grace`, `max_renewals`) pushing what their lease signed, the
estimate, `writ close` and `writ report`, each agent on its own lease (`WRIT_SESSION`,
`writ init --lease`), a whole-repo clone following its lease's format, the source's other
leases on the approver's screen, `max_active_per_source`; after the first real run,
`writ policy` and `writ request --dry-run`, the skill read at the start of a task, a
template's `committer_name`. `make ci` and `make e2e` passed; a real agent, its prompts never
naming Writ, took a task to a pushed branch with one Touch ID, then went through a refusal, an
amendment and a renewal ([manual checks with a real agent](guides/manual-checks-e2e.md)).

## M6.1 — Multi-repo workspaces

**Done.** Moved to [history/m6.1-multi-repo-workspaces.md](history/m6.1-multi-repo-workspaces.md):
`writ init` at a folder of repositories (each wired under its registry name, `--repo`
answering, the folder's own repository only when named, the workspace recorded in
`.writ-workspace` so `--undo` there takes every repository back), the `writ-workspace` skill
at the folder, `writ git` reading git's global options and letting git resolve the
repository, `writ exec -C`, timings per set of repositories. `make ci` and `make e2e` passed.

## M7.2 — Upstream proxies

**Done.** Moved to [history/m7.2-upstream-proxies.md](history/m7.2-upstream-proxies.md): named
proxies in the signed policy (SOCKS5, Tor among them, and HTTP CONNECT, an optional password
from the keystore), the upstream's name resolved by the proxy alone, `writ admin proxy`, host
key scans through a proxy, scenario 25 with real proxies.

## M7.5 — Secure Enclave signer on the Mac

**Done.** Moved to [history/m7.5-secure-enclave-signer.md](history/m7.5-secure-enclave-signer.md):
`se-cryptokit` through the `writ-se` helper (each blob framed and checked before the device
sees it), keys made by the device and sealed as blobs, a router over backends per use, every
key's backend from the CLI, the TLS key rotated live (`writ admin tls rotate`), the installer
guided. Its real-install items run with M7.9.

## M7.6 — Hardware-wrapped secrets

**Done.** Moved to [history/m7.6-hardware-wrapped-secrets.md](history/m7.6-hardware-wrapped-secrets.md):
the unwrap interface, tokens unwrapped per use, `piv-p256`, the Secure Enclave recipient, the
keystore's recipients in the signed policy and the recovery key, unsealing with no passphrase,
the SSH CA behind the `Signer` and rotated live, auto-unseal switched from the CLI, the
installer asking all of it. Its real-install items run with M7.9.

## M7.7 — Review after M7.6

A stop before the real install's check, asked for by the user: a security and code quality
review of the whole code (bugs too, where one shows), the first since
[M5.6](history/m5.6-review-after-m5.5.md), over everything M5.7 to M7.6 added (about 84,000
lines of sources, with their tests, the tooling and the docs). The real install's check,
numbered M7.7 until this review took the number, is [M7.9](#m79--local-mode-checked-on-the-mac).

- **The review:** thirteen reviewers in parallel, one per area, each named by the letter of
  its findings: `C` the policy core, `P` configuration, protocol and store, `A` the approval
  service, `G` the gateway and `writ-git`, `M` the mirrors, `K` crypto, the signer and the
  allocator, `S` the keystore, `D` the daemon, `L` local mode and the installers, `U` the
  approver's CLI, `W` the agent's CLI and `writ-sign`, `T` the tests, `X` tooling and docs.
  Each finding was checked against the code, then against the later milestones, the
  [threat model](threat-model.md)'s residual risks, [security.md](security.md)'s known gaps
  and the [open questions](decisions.md#open-questions), before it was kept. Two highs,
  twenty-six mediums, the rest low; findings two reviewers made are merged, fixed once.
- **The report was discussed with the user**, who decided what is fixed here, what moves to a
  later milestone and what is accepted (below, and in the [decision log](decisions.md)).
- **The fixes, in seventeen steps**, each ending with `make ci` passing: (1) docs first: this
  plan, the decisions, the threat model's new row and corrected sentences, the later
  milestones' notes; (2) the unseal checks the authority MAC first; (3) the approval client
  checks what it signs; (4) the session root; (5) the trusted display and the approver's
  commands; (6) the gateway's bounds and floods; (7) rotations and auto-unseal; (8) the data
  key rotated with the recipients; (9) policy and protocol; (10) the lease lifecycle's bugs;
  (11) mirrors, signer, TLS; (12) the daemon's lifecycle; (13) the agent's CLI; (14) the
  installer; (15) tests and tooling; (16) a docs pass, and `daemon.rs` and `writ`'s
  `main.rs` split with no change of behaviour; (17) the history page, this section reduced to
  its pointer.

Decided with the user:
- **Scope:** every finding fixed or addressed here, unless a later milestone owns it; that
  one gets a line in the milestone's section.
- **H1 (`S-1`):** the authority MAC is verified inside the unseal, right after the authority
  key opens, before anything is written or reconciled; `unseal: auto` read at a sealed start
  is untrusted until then.
- **H2 (`L-1`):** the approval client checks every signed document it builds (admin, token,
  unseal, scan, TLS and CA rotation): the daemon a reply names must be the fingerprint of the
  host key or TLS certificate the client authenticated, and a text shown must match its
  digest. No root-owned pins. No separate admin key now: an open question on
  [M11's page](backlog/multi-user.md#open-questions).
- **The session root (`C-1`, `L-3`):** a binding's root must be the direct child of a `writ`
  the daemon recognises by its kernel-attested executable path, the installed one (a
  `writd.yaml` key, its default beside `writd`, checked at start); any other pid refused with
  its exact reason. No new policy key.
- **Expected paths (`U-1`)** are never elided by `writ sign`; agent prose stays cut at 40 rows.
- **Recipients (`S-8`):** removing or replacing a keystore recipient rotates the data key: a
  new identity, every key, token, the authority key and the recovery identity sealed to it,
  crash-safe (a rotation cut short is finished or undone at the next unseal).
- **Residual risks:** one new row (local mode's agents share the approver's OS user) and
  three sentences corrected; no row for the install tree (`L-2`), a token printed back by a
  remote (`M-1`) or the TLS key on a device (`K-3`): their fixes are made, and `K-3` is one
  sentence in the row on listeners without `allow`.
- **Operator pages (`X-4`):** `make check` refuses an operator page holding an `sh` block
  the pipeline's table doesn't list; `sealing.md`, `hardening.md`, `clients.md` and
  `good-practice.md` get their scenarios now; `recovery.md` is owed by M8, `install.md` by
  M7.9.
- **Small forks, the defaults taken:** `writ init --whole-repo` refuses a linked worktree
  (`W-1`); `writ init` refuses an `origin` with a `pushurl` or several URLs, naming the fix
  (`W-3`); the e2e images' apt packages pinned to a Debian snapshot date; the token replay
  (`A-6`) confirmed first, then a per-id counter in the document (`writ-token/3`) if real.

The findings, each with the step that fixes it (the detail is in each report and, at the
end, on the history page):

| # | Severity | Finding | Step |
|---|---|---|---|
| `S-1` | High | The unseal acts on the policy before its MAC is checked: a policy altered at rest gets the data key sealed to an attacker's recovery key, with no human under `unseal: auto` | 2 |
| `L-1` | High | In local mode an agent can relay the approval channel: the client never checks the daemon a reply names nor the shown text's digest, so an admin change the approver never saw gets signed | 3 |
| `C-1`, `L-3` | Medium | A session binding may name any ancestor (pid 1, the terminal), which empties `require_session` | 4 |
| `U-1` | Medium | `writ sign` cuts expected paths, an enforced term, at 40 rows, and the agent picks which fall off | 5 |
| `A-1` | Medium | `writ close` has no rate: from any key, unbounded audit lines and fsyncs under the state lock | 6 |
| `G-1` | Medium | receive-pack's ref command list has no bound in bytes or time: a lease holder exhausts the host's memory | 6 |
| `G-2` | Medium | Local mode: every caller on the approval socket shares 16 slots, so an agent can lock the approver out | 6 |
| `D-1` | Medium | A policy change keeping a key's id never checks it against its new declaration: auto-unseal accepted with a key in software | 7 |
| `D-2`, `S-4` | Medium | `writ admin ca rotate --backend software` accepted under `unseal: auto` | 7 |
| `D-4` | Medium | A CA rotation that half fails is answered and logged "not rotated" while in force, `ca.backend` left stale | 7 |
| `S-2`, `G-4`, `A-5` | Medium | TLS and CA rotations logged best effort, after they are in force; one finished at start never logged | 7 |
| `A-2`, `K-1` | Medium | With the CA on a device, a certificate is signed under the state lock | 7 |
| `P-1` | Medium | Key, token and recipient ids not unique ignoring case, each naming a file on APFS: a token sent to another host | 9 |
| `L-2` | Medium | The install writes root's files from a user temp file under `sudo`, and reads the approval key twice, shown by its path | 14 (the guide's sentence: 1) |
| `L-4` | Medium | An agent under the same OS user can enter a bound session's tree; the threat model said another agent is refused | 1 |
| `W-1` | Medium | `writ init --whole-repo` in a linked worktree rewrites the config every worktree shares | 13 |
| `W-2` | Medium | `writ init` can fail after wiring the repo: left half wired, `--undo` no longer its inverse | 13 |
| `M-2` | Medium | A proxy's `connect_timeout` over 30 s has no effect on syncs and pushes, and the reason is lost | 11 |
| `C-2` | Medium | Once a renewal is amended, every push under it fails with "internal error" | 10 |
| `A-3` | Medium | The last push of a lease without `fetch` is refused: the lease is marked exhausted before it reaches upstream | 10 |
| `C-3` | Medium | A renewal dropping `commit_sign` is refused as wider when the template sets `committer_name` | 10 |
| `T-1` | Medium | Local mode's session binding has no row in the guarantee registry | 4 |
| `T-2` | Medium | The `edit --yes` registry rows rest on edits that change nothing | 15 |
| `T-3` | Medium | The helper's framing bounds are tested on one side only | 15 |
| `T-4`, `S-9` | Medium | A retired CA's deadline is proven inside one pure function only; its record's cap of 16 isn't enforced on read, its deadline not capped | 7, 8 (Q38's wording: M8) |
| `X-1` | Medium | Production code after a test module escapes `check-rules.py` | 15 |
| `X-2` | Medium | `expect`, `unsafe_code`, `cfg_attr` and other spellings go unchecked; nothing checks a crate inherits the workspace lints | 15 |
| `X-4` | Medium | Operator pages show `sh` blocks the pipeline never runs, and nothing refuses one | 15 (`recovery.md`: M8, `install.md`: M7.9) |
| `C-4`, `A-8` | Low | An amendment's subject is checked only after the approver signs | 4 |
| `P-2` | Low | A plain integer key and the same digits quoted or tagged aren't duplicates to the parser: the last wins | 9 |
| `P-3` | Low | List fields are split on commas that patterns and uids may hold: `template add --from` can widen | 9 |
| `P-4` | Low | The six M7.x commands are missing from the protocol's round-trip tests and tables | 9 |
| `A-4` | Low | A removed approver's leases are barred after the lock, one at a time; a crash leaves them active | 10 |
| `A-6` | Low | A token change is bound to a digest that can come back: replayed once the id is declared again | 9 |
| `A-7` | Low | The sign's last phase re-checks `fits`, not the decision, and hashes the paths under the lock | 10 |
| `A-9` | Low | An approver's `revoke` or an agent's `close` the store can't record is never retried | 10 |
| `G-3` | Low | The trailer parser takes `\f` for blank where git doesn't: a trailer git reads is missed | 6 |
| `G-6` | Low | Push facts trust the client's claimed old id; only `--force-with-lease` upstream holds the checks | 6 |
| `G-7` | Low | Commits on the mirror's notes ref count as not new, so one can reach upstream on a branch unsigned | 6 |
| `G-8` | Low | `.git` detection misses `git~1` followed by dots or spaces | 6 |
| `G-9` | Low | A push holds the mirror for up to 2,000 gits before refs outside the lease are refused | 6 |
| `G-10`, `K-5` | Low | Parsed trees and a sign request's preimage cost several times their bytes, with no byte bound | 6 |
| `G-11` | Low | The coalesced denial line credits other sources' denials to the address it names | 6 |
| `M-1` | Low | The token's redaction is bypassed by a line break, git's `remote: ` prefix or a cut | 11 |
| `M-3`, `L-7` | Low | Device unwraps and attestation run on async threads; a broken process reader shuts the approver out | 11 |
| `M-4` | Low | Commits no ref reaches count as held, and their notes are pushed upstream | 11 |
| `M-5` | Low | A sync failure shows the agent the upstream URL and the proxy's name | 11 |
| `M-6` | Low | A direct `ssh://` upstream's byte cap is per git process, not per sync | 11 |
| `M-7` | Low | Paths in ssh's `-o` options are checked for whitespace only, and ssh expands `%` and `${…}` in them | 11 |
| `M-8` | Low | Credential buffers grow with the token in them | 11 |
| `M-9` | Low | The mirror lock's deadline undercounts `writ admin repo check` | 11 |
| `K-2` | Low | A request is written to the helper with no deadline | 11 |
| `K-3` | Low | With the TLS key on a device, each handshake costs a device signature before the client authenticates | 1 (a sentence) |
| `K-4` | Low | The ECDH shared secret passes through buffers Writ doesn't wipe, in `writd` and the helper | 11 |
| `K-7` | Low | TLS session resumption is left at rustls's defaults | 11 |
| `S-3` | Low | A hardware recipient named `recovery` collides with the recovery marker: the keystore can't unseal | 8 |
| `S-5`, `D-3`, `G-5`, `A-5` | Low | A lease approved while the CA rotates can be cut short | 7 |
| `S-6` | Low | `writd recover` changes the keystore before its last refusal | 8 |
| `S-7` | Low | `writd recover` seals new keys to the `recipient` file without checking it | 2 |
| `S-8` | Low | Removing or replacing a recipient never rotates the data key: an old copy keeps its access | 8 |
| `S-10` | Low | `writd init --ca-backend <device>` leaves a half-made keystore when the CA fails | 8 |
| `S-11` | Low | Seven "write whole" helpers with different guarantees; the authority files' sync reads unbounded | 8 |
| `D-5` | Low | The orderly stop can outlast the service manager's 330 s; a second signal is swallowed | 12 |
| `D-6` | Low | A listener's failure skips the orderly stop; the sweeper's failures are silent | 12 |
| `D-7` | Low | A policy change whose rewrap fails is in force but never written back | 7 |
| `D-8` | Low | The work after an unseal isn't serialized with admin changes | 7 |
| `D-9` | Low | The TLS rotation's notification runs inline under the admin lock | 7 |
| `D-10` | Low | The commands printing public keys load private keys in an unhardened process | 12 |
| `D-11` | Low | A TCP listener's address may be a hostname, resolved at start | 9 |
| `L-5` | Low | An upgrade silently cuts every bound session | 14 |
| `L-6` | Low | A session's exit can be missed for good when a thread can't start | 12 |
| `L-8` | Low | A reinstall or an upgrade keeps stale or half-made state | 14 |
| `U-2` | Low | The display's diff sections aren't bounded in rows, the enforced changes first | 5 |
| `U-3` | Low | `writ admin key rotate` never switches a proxy that uses the key | 5 |
| `U-4` | Low | Nothing ties "every field of the ticket is shown" to the type | 5 |
| `U-5` | Low | `writ report`, `close` and `ls` cut text with hints naming commands that can't show it | 5 |
| `U-6` | Low | The admin diff at its bounds: the whole text as additions, no enclosing key, rows not width-bound | 5 |
| `U-7` | Low | A scan shows the daemon's fingerprint strings but pins the key strings | 3 |
| `U-8` | Low | "Not signed" exits differently by command; six hand-copied confirm prompts | 5 |
| `U-9` | Low | The caller row prints the executable path unquoted | 4 |
| `U-10` | Low | The bytes to sign go through a file that survives Ctrl-C | 5 |
| `W-3` | Low | The `origin` rewrite misses `pushurl`, extra URLs and an existing `writ` remote | 13 |
| `W-4` | Low | Workspace members sharing one git common dir are wired twice into one record | 13 |
| `W-5` | Low | Global skill files are treated as one repo's or one workspace's | 13 |
| `W-6` | Low | In wrapper mode with no pin, one `writ git` command can span two leases | 13 |
| `W-7` | Low | `writ init` ignores `WRIT_SESSION` | 13 |
| `W-8` | Low | A token in the `origin` URL is printed and copied by `writ init` | 13 |
| `W-9` | Low | `--undo` rewrites `AGENTS.md` and `info/exclude` whole, line endings changed | 13 |
| `W-10` | Low | The timings file is bounded in size, not in parsing time | 13 |
| `W-11` | Low | `writ check` takes any file starting with `---` for a timings file | 13 |
| `W-12` | Low | A repository's record is read without the bounds the docs claim | 13 |
| `T-5` | Low | Auto-unseal's conditions are tested less than the guarantee claims | 7 |
| `T-6` | Low | The HTTPS-through-a-proxy test can't see a direct connection | 15 |
| `T-7` | Low | Two helper tests where a deadline or a loop decides the outcome | 15 |
| `T-8` | Low | The untrusted-input inventory names two tests that don't exist, and nothing checks its names | 15 |
| `T-9`, `X-3` | Low | `assert_ne!(code, Some(0))` and an imported `sleep` evade the test rules | 15 |
| `T-10` | Low | Tests on the fake helper gated to the Mac read as passes on Linux | 15 |
| `T-11` | Low | The scan nonce cap is tested on one side only | 15 |
| `X-5` | Low | `ureq` keeps its default features in `writd`: gzip and bundled roots | 15 |
| `X-6` | Low | M8's deploy image would build on M4.1's debug builds | M8 |
| `X-7` | Low | The Rust toolchain is pinned in three places, tied by nothing | 15 |
| `X-10` | Low | The pre-push stamp ignores ignored and skip-worktree files | 15 |
| — | Low | Left open by M5.6: the e2e images' apt packages unpinned | 15 |
| `C-5` | Low | The documented order of checks isn't the code's; stale `writ-ticket/2` mentions | 10 |
| `A-10` | Low | Quality: a dead branch, unproven public calls, five copies of one sequence, a missing source that allows | 10 |
| `D-12` | Low | Docs claim checks the daemon doesn't make at start; doc comments on the wrong functions | 9 |
| `D-13` | Low | `daemon.rs` is one object doing everything, with copies that can drift | 16 |
| `S-12` | Low | Stale docs on the unseal and recovery after M7.6 | 8 |
| `U-11` | Low | Comments and docs that contradict the approver's code | 5 |
| `W-13` | Low | `main.rs`'s clap definitions and admin dispatch; small items (`writ-sign -Y sign` reads unbounded) | 13, 16 |
| `K-6` | Low | The threat model names M7.6 as the fix for crafted blobs, which it didn't ship | 11 |
| `K-8` | Low | A dead software TLS path, capabilities never read, smaller items | 11 |
| `X-8` | Low | The untrusted-input inventory and the `unsafe` list lag M7 to M7.6 | 16 |
| `X-9` | Low | Stale statements across the architecture, index and status docs | 16 |
| `L-9` | Low | A stale mitigation in the threat model (per-process rates, M7) | 1 |

Moved to a later milestone or the backlog, each with its line there:
- **M7.9:** `install.md`'s commands are the manual check's (`X-4`).
- **M8:** Q38 as worded must also cover the keys directory's public authority files (`S-9`);
  the deploy image builds the binaries in release (`X-6`); `recovery.md`'s commands run by the
  pipeline (`X-4`).
- **M8.5:** the session key's kind, a new ticket field, passes the display's exhaustiveness
  test this milestone adds (`U-4`).
- **M9:** `proxy` mode reuses the push facts made independent of the client's claimed old id
  here (`G-6`).
- **M11:** whether an admin signs admin changes and unseals with a key distinct from the one
  that approves leases (`L-1`), an [open question](backlog/multi-user.md#open-questions).
- **Backlog:** per-session submission rates in local mode (`L-9`).

Acceptance:
- [ ] Every finding in the table fixed with the test that would have caught it (failing on
      the code before the fix, hardened as [testing.md](testing.md) says), or moved with its
      line in the later milestone's section; a finding found wrong or already handled said so
      on the history page.
- [ ] The guarantee table's new rows, each naming the tests that try to break it: a lease
      bound to a session serves only below the installed `writ`'s direct child, refuses every
      other caller and ends with the session (`C-1`, `T-1`); the approver's client signs only
      for the daemon it authenticated and only the text it showed (`L-1`); a removed or
      replaced recipient opens nothing sealed after (`S-8`). The rows it touches name their
      new tests: a version altered at rest acts on nothing before its MAC is checked (`S-1`),
      a retired CA refused past its deadline at the gateway (`T-4`), expected paths always
      shown (`U-1`).
- [ ] The threat model's new residual-risk row and its three corrected sentences; the stale
      mitigations (`L-9`, `K-6`) pointing at real milestones or the backlog.
- [ ] Every new command, flag and configuration key (the installed `writ`'s path in
      `writd.yaml`) with its registry rows; `make check` refuses an operator page whose `sh`
      blocks the pipeline's table doesn't list.
- [ ] `make ci` and `make e2e` pass.

## M7.9 — Local mode checked on the Mac

The acceptance items of [M7](history/m7-local-mode-on-the-mac.md) that only the real install
can prove, moved here at the user's request: they run them once M7.5 and M7.6 are in place,
the setup that fits their workflow, so the check covers the Secure Enclave signer and the
hardware-wrapped secrets too (M7.6's three real-install items: the
[manual check](guides/manual-checks.md#local-mode-on-the-mac-m7)'s step 3c). Nothing to build: the steps are the
[manual check](guides/manual-checks.md#local-mode-on-the-mac-m7) (updated by M7.5 and M7.6
for what they add), run on the user's Mac, with `sudo` and Touch ID. What it finds is fixed
here, each fix with its test. The [install guide](operators/install.md)'s commands are the
manual check's: the pipeline can't run them (`sudo`, launchd), so they are run here as
written (found unchecked by the [M7.7 review](#m77--review-after-m76), `X-4`).

Acceptance:
- [ ] On a Mac without Writ, the guided `make install` (every question answered at the
      prompt: the `local` setup, the approval key, the Secure Enclave for the TLS key and
      `agent-01`) then `writ unseal` gives a working local daemon with nothing else done by
      hand; the summary before the go lists exactly what the install then makes, and `n`
      there changes nothing; a second `make install` upgrades the binaries and keeps the
      keystore, state and pins.
- [ ] An agent under `writ run -- <agent>` works on a real repository through the local
      daemon (the GitHub throwaway repository of the manual checks): its lease bound to
      `/opt/writ/bin/writ` (signed `dev.writ.writ`), refused from outside the session, revoked
      when the agent quits.
- [ ] My user (so any agent) can't read the daemon's keystore or attach to the daemon
      (`cat` and `lldb -p` refused), and the daemon starts again after a reboot.
- [ ] A stop through launchd (`launchctl kill TERM system/dev.writ.writd`) is the orderly stop:
      the `stopping` and `stopped` lines in `/Library/Logs/Writ/writd.log`, and the daemon
      stays stopped.
- [ ] The recovery guide's macOS steps run as written.
- [ ] `make uninstall` leaves the Mac as before the install (the role user, the
      LaunchDaemon, the binaries, the directories and `~/.writ/`'s pins gone, checked
      against a listing taken before), the daemon's data kept unless `delete` is typed at
      its question; the repositories `writ init` wired taken back when asked.
- [ ] Every `sh` block of [install.md](operators/install.md) run as written along the way.

## M8 — Detached deployment

[Deployment](architecture/deployment.md): the daemon on the homelab, agents anywhere on the
LAN or VPN.

- `deploy/Dockerfile` (non-root, minimal image) and `deploy/compose.yaml` with the two
  volumes, the gateway's port and the approval transports in use (SSH, HTTPS). **Builds on
  M4.1's test image** (`e2e/`: the pinned Rust builder stage, the Debian 13 runtime with git ≥
  2.45 and OpenSSH), decided with the user in M4.1: harden it (non-root, minimal, read-only
  where it can be) rather than start over, and `make e2e` then runs against the deploy image.
- **The deploy image builds the binaries in release** (found by the
  [M7.7 review](#m77--review-after-m76), `X-6`): the test image builds them in debug, where a
  traced `writd` only warns and the release-only refusals (the development keystore among
  them) are missing.
- Notifications (the configured `Notifier`) for sealed restarts, denials and violations
  (waiting tickets already notify since M2).
- Backup guidance for the ledger and the audit log.
- **`docker stop` is an orderly stop** (found by the [M5.6 review](#m56--review-after-m55), L16):
  the SIGTERM handling M7 adds, checked in the container (tini forwards it under
  `init: true`), within compose's `stop_grace_period`.
- **Q38 first** ([open questions](decisions.md#open-questions), left open by M5): the
  keystore's recipient is public, so whoever can write the keys directory, here a Docker
  volume, can plant a secret of their choosing. Settled with the user before building:
  whether each sealed secret file is bound to the state (e.g. a MAC over its digest with the
  authority key, checked at unseal and on every live read); if kept, it is built here.
- **Q38 covers the public authority files too** (found by the
  [M7.7 review](#m77--review-after-m76), `S-9`): as worded it binds only secret files, while
  the keys directory also holds `ca-retired.pub` (a CA written there is trusted until its
  deadline), `ca.backend` (auto-unseal's check) and `recipients/*.pub`.
- **The recovery guide's Docker commands**: `docs/operators/recovery.md`'s placeholders (the
  paths in the image, its user) filled in, and run end to end against the deploy image.
- **`recovery.md` run by the pipeline word for word** (owed since the
  [M7.7 review](#m77--review-after-m76), `X-4`): the page joins
  [commands the docs show](end-to-end.md#commands-the-docs-show), its every `sh` block a
  scenario's.
- **The installer's `detached` setup**, on the daemon host, with M7's frame (the setup
  question, `DRY_RUN=1`, the manifest, the upgrade, `make uninstall`): the image built
  (`make docker`); one directory holding `deploy/compose.yaml` and a `writd.yaml` from the
  detached preset, the approval transports and the `allow` lists asked for (or given:
  `APPROVALS=ssh,https`, `AGENTS_ALLOW=<cidr>…`); the two volumes; `writd init` in the
  container, the passphrase on the terminal; the approver's public key in `approvers`; the
  stack started. It ends by printing what each client pins (the host key, the TLS
  fingerprint) and the `make install` to run on them. Upgrading rebuilds the image and
  restarts the stack in order, the volumes kept. `make uninstall` takes the stack down and
  removes the image and the files it made, the volumes kept unless `delete` is typed at its
  question. Guided like the `local` setup ([conventions](conventions.md#installers-are-guided)).
- **The installer's `client` setup**, on each machine that uses a detached daemon (the
  approver's Mac, an agent VM): `writ` and `writ-sign` on the `PATH`, `~/.writ/` with the
  daemon's endpoints, its host key and TLS certificate pinned (asked at the prompt, each
  checked against the daemon before anything is written; variables answer without a
  terminal), and on the approver's machine (asked whether it is one) the approval key and the
  reader key (`writ reader`), printing the line for the daemon's `readers`. `make uninstall`
  takes it back and asks the repos question as in M7.

Acceptance:
- [ ] `docker compose up` on the homelab → sealed → `writ unseal` from the Mac → agents on a
      VM and on the Mac both work under their own leases at the same time.
- [ ] A container restart notifies me and fails closed until unsealed.
- [ ] `docker stop` stops the daemon in order (the `stopping` line in its log), not killed
      at the grace period's end.
- [ ] Only port 2222 and the approval transports in use (2223 SSH, 8443 HTTPS) are exposed;
      the process runs as non-root, from release builds (a traced start refused).
- [ ] Detached is only the detached [configuration preset](architecture/platform.md#configuration-presets)
      and packaging: no change to the core crates beyond bug fixes.
- [ ] Q38 settled before building; if kept, a secret file planted or swapped in the keys
      directory (a key with its matching `.pub`, a token), or a public authority file
      (`ca-retired.pub`, `ca.backend`, `recipients/*.pub`), stops the unseal, naming the file.
- [ ] The recovery guide's Docker steps run as written, end to end (`make e2e`), the page in
      the pipeline's table.
- [ ] The first item above set up with the guided installer only: `detached` picked on the
      homelab, `client` on the Mac and on the VM, nothing else by hand but `writ unseal` and
      the `readers` line; the setup question on each offers only what that OS can install.
- [ ] `make e2e` sets its agents' containers up with the `client` setup (its variables, no
      terminal), and its daemon from the
      compose file and the `writd.yaml` the `detached` setup writes; a client given a host
      key or TLS pin the daemon doesn't have writes nothing and says why.
- [ ] `make uninstall` takes each setup back, checked against a listing taken before: the
      volumes kept unless `delete` is typed, the clients' repos question as in M7.

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
- **The new field passes the display's exhaustiveness test** (found by the
  [M7.7 review](#m77--review-after-m76), `U-4`): the test M7.7 adds fails on a ticket field
  that is signed but not shown by `writ sign` or not checked by narrowing.
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

- **The push facts as M7.7 leaves them** (found by its [review](#m77--review-after-m76),
  `G-6`): each ref's old value read by the daemon, never the one the client's command claims,
  so the fast-forward and case-twin checks hold without upstream's `--force-with-lease`
  behind them; `proxy` mode reuses them.

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
