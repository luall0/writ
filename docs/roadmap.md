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
| M7.7 | [Review after M7.6](history/m7.7-review-after-m7.6.md) ✅ | The security and code quality review of the whole code after M5.7 to M7.6 (the wiping allocator, the skill, amendments and renewals, workspaces, per-repository tickets, the CLI's admin commands, local mode on both systems, upstream proxies, the Secure Enclave signer, hardware-wrapped secrets) by thirteen reviewers: a report discussed with the user, then every finding fixed with its test, or moved to the milestone that owns it |
| M7.8 | [Approval popup on the Mac](history/m7.8-approval-popup-on-the-mac.md) ✅ | A small native window above every app, full-screen ones too, when a ticket waits for my signature: the whole ticket, Sign or Decline (with feedback), the signature still `writ`'s and Touch ID; a watch route on the approval API |
| M7.9 | [Local mode checked on the Mac](history/m7.9-local-mode-checked-on-the-mac.md) ✅ | The real install on the Mac, with M7.5's Secure Enclave and M7.6's hardware-wrapped secrets in place: `make install`, `writ unseal`, an agent under `writ run`, the daemon out of my user's reach, a stop through launchd, a reboot, the recovery guide, and `make uninstall` leaving the Mac as before |
| M7.9.5 | [Operator experience](history/m7.9.5-operator-experience.md) ✅ | Asked by the user after the real install: amendments showing only what changed, the popup redesigned (its design validated first, as an artifact), every guided prompt and the installer's questions with arrow selection, colour and inline checks, a quick setup guide from `make install` to a first agent run |
| M7.9.6 | [Upgrades](#m796--upgrades) | Asked by the user before M8: the state migrated in steps with a backup first, the policy naming its format and every format change a signed migration (`writ migrate`), the daemon refusing everything else until it is signed, `writd check-upgrade` before the installer changes anything, the installer unsealing and migrating; the push modes `proxy` and `direct_ssh` dropped, their keys removed as format 2 |
| M8 | [Detached deployment](#m8--detached-deployment) | Docker image on the homelab, agents on other hosts; the installer's `detached` and `client` setups |
| M8.5 | [Non-exportable session keys](#m85--non-exportable-session-keys) | The session key in the agent host's hardware (Secure Enclave, TPM) when it has some, detected on first use, switched with `writ session-key` |

M8.5 completes v1. Work after it comes from the [backlog](backlog/README.md), each idea
picked by the user ([multi-user](backlog/multi-user.md) among them).

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
guided. Its real-install items ran with M7.9.

## M7.6 — Hardware-wrapped secrets

**Done.** Moved to [history/m7.6-hardware-wrapped-secrets.md](history/m7.6-hardware-wrapped-secrets.md):
the unwrap interface, tokens unwrapped per use, `piv-p256`, the Secure Enclave recipient, the
keystore's recipients in the signed policy and the recovery key, unsealing with no passphrase,
the SSH CA behind the `Signer` and rotated live, auto-unseal switched from the CLI, the
installer asking all of it. Its real-install items ran with M7.9.

## M7.7 — Review after M7.6

**Done.** Moved to [history/m7.7-review-after-m7.6.md](history/m7.7-review-after-m7.6.md):
thirteen reviewers over everything M5.7 to M7.6 added, two highs (the unseal acting on a policy
before its MAC was checked; the approval client signing what a relay showed it) and every
other finding fixed with its test, or moved with its line in the milestone that owns it
(below: M7.9, M8, M8.5; the multi-user page and the backlog).

## M7.8 — Approval popup on the Mac

**Done.** Moved to [history/m7.8-approval-popup-on-the-mac.md](history/m7.8-approval-popup-on-the-mac.md):
the watch route on the approval API, `writ sign --ui` (the queue of waiting tickets, `writ
sign`'s checks, display and signer, one JSON line each way), the display as a structure of
tagged rows, `writ-popup` (SwiftUI in an `NSPanel` above every space and full-screen app, no
approval by accident), started at login by the installer's LaunchAgent.

## M7.9 — Local mode checked on the Mac

**Done.** Moved to [history/m7.9-local-mode-checked-on-the-mac.md](history/m7.9-local-mode-checked-on-the-mac.md):
the real install on the user's Mac with the Secure Enclave, the hardware-wrapped secrets and
the popup; what it found fixed (a device key made only by the running daemon and probed when
opened, guided scans asking their proxy first, a mirror's first sync with its own limit), and
the real-install items of M7, M7.5 and M7.6 ticked.

## M7.9.5 — Operator experience

**Done.** Moved to [history/m7.9.5-operator-experience.md](history/m7.9.5-operator-experience.md):
amendments shown as what they change, the popup redesigned on validated mockups (three panes,
the rail, a card per repository), every question of `writ` and the installer a menu on a
terminal (`inquire`, `writ prompt`), a quick start from `make install` to a verified commit,
and the operator pages naming no approval agent.

## M7.9.6 — Upgrades

Asked by the user before M8, with the decision to drop the `proxy` and `direct_ssh` push modes
([decision log](decisions.md), 2026-11-15). Writ runs for real since M7.9, and an upgrade can't
carry it over a format change today: the state refuses any other `STATE_VERSION` (an operator
starts from a new state directory, losing the ledger, the leases and the policy's history), and
the policy in force is signed text re-read at every start with unknown keys refused, so a key a
version removes leaves the daemon unable to start. Settled with the user:

- **The state migrates in steps, a backup first.** `writ-store` holds one step per version
  (N → N+1), applied in order at open, each in its own transaction, before anything else reads
  the state. The state is first copied aside whole (`VACUUM INTO`,
  `<state_dir>/backups/state-v<N>-<time>.db`, the daemon's user only, `0600`). A failed step
  rolls back and the daemon refuses to start, naming the step, the copy untouched; a state newer
  than the binary is refused as today (no downgrade). **Version 12 is the first step:** a
  `migrations` table recording each one (from, to, when, the backup), and one audit line per
  migration. Each step is tested from a database written by the schema it starts from, kept
  frozen in the tests with rows in every table. A ticket format change (`writ-ticket/N`) brings
  its step, never rewrites a ticket's signed bytes, and blocks the upgrade while a ticket of the
  old format is pending or its lease active.
- **The policy names its format:** `format: 2` as its first key, written by the canonical
  writer and the template; a text without it is format 1 (every policy before M7.9.6). It is a
  line of the signed text, so the approval and the authority MAC bind it as they bind the rest.
  A format the binary doesn't know (newer) is refused at start. `writ admin apply` and the
  `writ admin` edits only sign the current format (an older one refused with its code, naming
  `writ migrate`).
- **Every format change is a signed migration** (the user's choice: even when the text keeps
  its meaning). A policy in force of an older format leaves a **migration owed**: the daemon
  starts and unseals with the approvers and readers in force, but runs **no policy at all** (no
  template, no repo, no key the policy declares, no mirror synced), and refuses every request
  from every client, tickets, signatures, pushes, fetches, `writ ls`, the `writ admin` commands
  and the rest, with the code `migration_owed` and the command to run (`writ migrate`); only
  `writ unseal` and `writ migrate` are served. It notifies once, and leases in force keep
  counting down. The daemon only ever runs the current format: an older one exists only as the
  migration's rewrite, never as a reader to maintain. `writd init` and `writd recover` take an
  older format too, leaving the migration owed.
- **The daemon proposes the rewrite** (`writ_core::config::migrate`, pure): format N text to
  format N+1 canonical text, one step per format, or the reasons it can't, each naming its
  key. Format 1 → 2: `format: 2` added, a `push_modes` that lists `gateway` dropped (only gateway
  pushes ever ran), `direct_ssh` settings dropped (their mode never pushed); a `push_modes`
  without `gateway` is a reason (its repo or template accepted no push, and the rewrite that
  keeps that meaning is the operator's call).
- **`writ migrate`:** shows what is owed (the formats, the version in force), the proposed text
  as the diff `writ admin apply` shows, and on yes signs it as the policy's admin change
  (`writ-admin/2` naming the version in force, one approval); the daemon applies it as any admin
  change (live, the files written back), loads the policy and serves again. `--file <policy>`
  signs the operator's own text instead (needed when there is no proposal). Declined, nothing
  changes and it can be run again at any time; with nothing owed it says so and exits 0.
- **`writd check-upgrade <writd.yaml>`**: the new binary's dry run, before anything changes.
  Run as the daemon's user while the old daemon runs, it reads `writd.yaml` as a start would,
  copies the state (SQLite's backup) to a temporary file and runs the steps on the copy, and
  reads the policy in force's format and the proposal. It prints what migrates (the state's
  versions, the policy's format with its proposal or the keys to fix by hand) and what blocks (a
  key `writd.yaml` no longer takes, a newer state, a step that fails, an open ticket of a changed
  ticket format), and exits non-zero on a block. It reads the state sealed: a report, never acting
  on what it read.
- **The installer's upgrade** (both local setups): the new `writd` (copied where the daemon's
  user can run it) runs `check-upgrade` before the summary; a block stops with nothing changed,
  and the summary lists the migrations. After the restart, `writ unseal` (unless auto-unseal
  opened it) and, when one is owed, `writ migrate`, both on the terminal as the user. A step
  declined or failed says what to run later. `DRY_RUN=1` runs the check and stops.
- **The push modes `proxy` and `direct_ssh` go**, as format 2: `push_modes` and `direct_ssh.*`
  out of repos and templates (parsing, the canonical writer, the edits and guided prompts, the
  `push_mode` denial), the [lease model](lease-model.md#constraints-and-how-much-to-trust-them)'s
  rows, [flows](flows.md) § 3b and 3c, the gateway's push modes table, the threat model's row, the
  operator reference and template, the registries.
- Docs: the [install](operators/install.md) page's upgrade, [recovery](operators/recovery.md)
  (restoring a backup of the state), [policy and state](architecture/policy-and-state.md)
  (the steps, the record), [approvals](architecture/approvals.md) (the migration),
  [clients](architecture/clients.md) (`writ migrate`, the refusal), the operator reference (the
  `format` key), [security](security.md) (the proposal and `check-upgrade`'s reads in the
  inventory), the [threat model](threat-model.md) (the owed state, the backup as sensitive as the
  state), and the [conventions](conventions.md): how a format change brings its step, its frozen
  schema or format, and its test.

Plan, each step leaving Writ working (`make ci`):
1. This page, the decisions, the parked pages.
2. The state's steps and the backup (`writ-store`), version 12.
3. The policy's format (`format: 2`), `migrate`, the push modes removed.
4. The owed state in the daemon: the start and unseal, the refusals, the approval API's
   migration route; `writd init` and `writd recover` with an older format.
5. `writ migrate`, and every client command's refusal.
6. `writd check-upgrade`.
7. The installer's upgrade.
8. The docs left, the end-to-end scenarios and the registries' rows that weren't with their
   step; the manual check: the real install on the Mac upgraded.

Acceptance:
- [ ] A version 11 state with rows in every table opens as version 12: the rows kept, the
      `migrations` table and the audit log recording it, the backup a version 11 database with
      the same rows. A step that fails leaves the daemon refusing to start with the step named
      and the backup untouched; a version 13 state is refused with its code.
- [ ] A format 1 policy in force (with `push_modes: [gateway]`): the daemon starts and unseals
      owed; every client command is refused with `migration_owed` and the command, each
      checked (a ticket, a sign, a push, a fetch, `writ ls`, `writ admin show`); `writ migrate`
      shows the diff and signs; format 2 is in force, a lease granted before works on, and a
      new ticket is served. Declined, it stays owed and runs again.
- [ ] A format 1 policy with `push_modes: [proxy]`: no proposal, the reason naming the key;
      `writ migrate --file` with the operator's text resolves it. A format 1 text through
      `writ admin apply`, and a migration naming another version than the one in force, are
      refused with their codes.
- [ ] `writd check-upgrade` reports each case (nothing to do, a state step, a policy owed, a
      `writd.yaml` key gone, a newer state) as written, and leaves the state unchanged (its
      digest before and after).
- [ ] `make e2e`: `writ migrate` (proposed, `--file`, declined) and `writd check-upgrade` in
      scenarios, with their rows in the registries (rules 18 and 19); the `format` key in the
      configuration registry.
- [ ] No `push_modes` or `direct_ssh` key is read in format 2: each refused with its error.
- [ ] By hand ([manual checks](guides/manual-checks.md)): the real install on the Mac upgraded
      with `make install`, the preflight, the restart, `writ unseal`, `writ migrate`: state
      11 → 12, policy format 1 → 2, the leases, ledger and audit kept.

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
- **`install.md` run by the pipeline** (owed since
  [M7.9](history/m7.9-local-mode-checked-on-the-mac.md), which ran its `local` setup by hand:
  `sudo`, launchd): its `make install` and `make uninstall` run by the scenarios that set the
  agents' containers up with the `client` setup, and the page joins
  [commands the docs show](end-to-end.md#commands-the-docs-show).
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
- **The `client` setup settles how an HTTPS client checks the daemon's name** (the gap the
  [M7.7 review](#m77--review-after-m76) documented, `L-1`): over HTTPS `writ` authenticates
  the TLS certificate, never the host key the daemon names itself by; settled before detached
  approvers rely on HTTPS.
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
- **The template decides the mode, never the ticket:** a template term
  `session_key: hardware | file`, default `file` (today's key file, so templates written before
  M8.5 keep working), edited from the CLI like every template field (`writ admin template`, a
  signed admin change). The ticket carries its key's kind (`hardware: secure-enclave`,
  `hardware: tpm`, `file`), checked against the key (Ed25519 can't be `hardware`), and it must
  be the template's mode exactly: a `file` ticket under a `hardware` template, or a hardware
  one under a `file` template, is refused by policy with its code, before it reaches the
  approver. There is no `any`: the ticket has no choice to make. One key serves a whole lease,
  so over several repositories their templates must name the same mode, or the ticket is
  refused as the templates disagreeing. A lease keeps the key it was granted with; its
  renewals and amendments are checked against the template's mode in force. `writ sign`
  shows the kind. **A client's claim, enforced as one:** the daemon takes Ed25519 and P-256
  session keys and can't tell where one lives, so the term stops a host set up wrong or
  switched to `file`, never an agent that lies about its key; the
  [lease model](lease-model.md#constraints-and-how-much-to-trust-them) and the
  [threat model](threat-model.md) say so. An `attested` mode the daemon proves (a TPM's chain)
  stays an open question.
- **A client setting, `session_key: auto | hardware | file`** in the settings file
  (`<home>/config`), default `auto`, never switched silently: it says what this host may make,
  never what a lease gets. `auto` makes the kind the template asks for, read by `writ request`
  from the ticket's repositories' templates (as `writ policy` reads them). `hardware` and
  `file` make only that kind: a template asking for the other makes `writ request` refuse
  before submitting, naming the template's mode and the setting to change (a convenience; the
  daemon's check is the boundary). A hardware key the host can't make (no hardware, a TPM
  disabled, an image moved) makes `writ request` refuse with a reason and write no key file,
  never fall back to a file.
- **Switched from the CLI:** `writ session-key` shows the setting and what the host supports
  (detected for real: a throwaway key made and used); `writ session-key auto|hardware|file`
  writes the setting for later leases, current ones keeping their key; `WRIT_SESSION_KEY`
  overrides it, for containers and scripts. The installer's setups that wire an agent host
  (`client`, `local`) ask it, `auto` first.
- **The new field passes the display's exhaustiveness test** (found by the
  [M7.7 review](#m77--review-after-m76), `U-4`): the test M7.7 adds fails on a ticket field
  that is signed but not shown by `writ sign` or not checked by narrowing.
- Docs: [identity](architecture/identity.md), [clients](architecture/clients.md), the
  [client settings](operators/clients.md) (the `session_key` setting), the
  [policy reference](operators/policy-yaml.md) and its template (the template term), the
  [lease model](lease-model.md) (the ticket's new field, the term and its trust row) and the
  [threat model](threat-model.md); the session agent's binary in AGENTS.md's naming table.

Acceptance:
- [ ] **The graft test for the daemon:** no change beyond the ticket's new field, its
      validation and its display, and the template term and its check.
- [ ] Every backend passes the session key contract suite (the Secure Enclave, the TPM, the
      file).
- [ ] With a hardware session key, the session directory holds no private key; a copy of it
      on another host can't open a connection to the gateway (refused at authentication).
- [ ] Detection: `writ session-key` on a host with a working TPM (`swtpm` in a container)
      shows the hardware; on one with none, or a TPM it can't use, shows none.
- [ ] `auto` follows the template: a hardware key under a `hardware` template, a key file
      under a `file` one (the TPM host making a file). A `hardware` template on a host
      without the hardware: `writ request` refuses with its exact reason and writes no key
      file. The host's `hardware` under a `file` template, or `file` under a `hardware` one:
      `writ request` refuses before submitting, naming both.
- [ ] `writ session-key`, its three values and `WRIT_SESSION_KEY` used for real by an
      end-to-end scenario (rule 18); the `session_key` setting and the template term with
      their rows in the registries (rule 19).
- [ ] `writ sign` shows the kind; a ticket claiming a kind its key can't be (Ed25519 with
      `hardware`) is refused with its code.
- [ ] **The ticket can't choose the mode:** a ticket submitted straight to the daemon (no
      `writ` checks) with a `file` key under a `hardware` template, or a hardware key under a
      `file` template (the default one included), is refused with its exact code; each
      accepted with the matching kind. Over two repositories whose templates name different
      modes, every ticket is refused as the templates disagreeing. A renewal of a `file`
      lease after its template is switched to `hardware` is refused with its code. The term
      set and cleared with `writ admin template`.
- [ ] On the Mac, by hand ([manual checks](guides/manual-checks.md)): a Secure Enclave
      session key works with no prompt, with the screen locked, and can't be exported.
