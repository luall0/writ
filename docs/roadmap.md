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
| M7.8 | [Approval popup on the Mac](#m78--approval-popup-on-the-mac) | A small native window above every app, full-screen ones too, when a ticket waits for my signature: the whole ticket, Sign or Decline (with feedback), the signature still `writ`'s and Touch ID; a watch route on the approval API |
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

**Done.** Moved to [history/m7.7-review-after-m7.6.md](history/m7.7-review-after-m7.6.md):
thirteen reviewers over everything M5.7 to M7.6 added, two highs (the unseal acting on a policy
before its MAC was checked; the approval client signing what a relay showed it) and every
other finding fixed with its test, or moved with its line in the milestone that owns it
(below: M7.9, M8, M8.5, M9, M11; and the backlog).

## M7.8 — Approval popup on the Mac

What the real use of M7.9 lacks (asked by the user): today a waiting ticket is a Telegram
message, then `writ sign` in a terminal. M7.8 brings a small window that comes up in front of
every app, full-screen ones too (as Touch ID's prompt does), when a ticket waits for my
signature: the whole ticket, scrollable, and two buttons, **Sign** and **Decline**. Only that:
a UI for everything `writ` does is for later (the [backlog](backlog/README.md#mac-app-for-every-command)).
The forks settled with the user at its start: [decision log](decisions.md), 2026-11-14.

- **A thin native app over `writ`** (pure Swift, AppKit, no cross-platform toolkit). The app
  only shows text and takes a click; `writ` stays the approval client and does everything a
  signature relies on: the transports and their pins, the checks of the review after M7.6
  (`L-1`), the canonical bytes decoded and the display built from them (every field, agent
  text neutralized, the bounds of `U-1`), the signature through `/usr/bin/ssh-keygen -Y sign`
  and Secretive's Touch ID. Nothing of that is written again in Swift. **Before any richer UI,
  or a UI on another platform, the approval client is linked into the app** (an FFI crate over
  `writ-approval` and `writ-cli`'s client, its `unsafe` in one module): mandatory, never a
  second implementation.
- **A watch route on the approval API**, on both transports (an SSH command, `GET
  /v1/tickets/watch` over HTTPS), for a reader key: a long poll that answers as soon as a
  ticket starts waiting that the caller hasn't been told of, or after a bounded time with
  nothing, under the listeners' idle limit; the client asks again. Watches are bounded
  (a cap on those held at once, all readers together, on top of the per-source connection
  limits), refused past it with their reason and logged as refusals; a watch is a read, like
  `GET /v1/tickets`, and writes no line when allowed. It joins
  [security.md](security.md)'s inventory with its bounds and a hostile-input test.
- **`writ sign --ui`**: holds the watch and, for each waiting ticket, writes the display
  `writ sign` builds to stdout in a line protocol (framed, bounded), then reads the app's
  answer on stdin: `sign`, or `refuse` with optional feedback (signed under `decisions:
  signed`, as `writ refuse -m`). Tickets only: new ones, amendments and renewals, all bounded
  by templates; admin changes and `writ unseal` never come to the popup and stay in the
  terminal. No narrowing in the popup (the terminal's `writ sign` keeps it). An answer the
  protocol doesn't hold, or none, signs nothing (fail closed). Its scenario in `make e2e`
  plays the app's part, with its row in the [coverage registry](end-to-end.md#coverage-every-command-and-flag).
- **The app** (Swift sources under `crates/writ-cli/macos/`, built with `swiftc` like
  `writ-se`, ad-hoc signed with the hardened runtime): an agent app with no Dock icon
  (`LSUIElement`), an `NSPanel` at the modal level that joins every space and full-screen
  ones (`canJoinAllSpaces`, `fullScreenAuxiliary`); the display in a scrollable monospaced
  view, shown as `writ` gave it. **No approval by accident:** no default button (a Return
  typed into another app presses nothing), both buttons disabled for about a second after
  the window shows; one ticket at a time, the others queued; a ticket that stops waiting
  (signed elsewhere, withdrawn, expired) closes its window. It starts at login as a per-user
  LaunchAgent and restarts `writ sign --ui` if it ends.
- **The installer**: `make install` puts the app and its LaunchAgent in place for the
  `local` setup on the Mac, `make uninstall` takes them back (in the manifest);
  [install.md](operators/install.md) and the [clients page](operators/clients.md) say so.
  Linux gets no popup in M7.8; `writ sign --ui` and the watch route work everywhere.
- **The threat model** (needs the user's go-ahead, given at the start): the popup doesn't
  close the [residual risk](threat-model.md#residual-risks-v1) of an agent under my user, which
  can draw the same window and ask Secretive for a signature itself; a popup also trains the
  reflex "window, Sign, touch". The row says so and points at the
  [own Mac approver app](backlog/README.md#own-mac-approver-app), whose Touch ID prompt shows
  what it signs.

Steps (each one commit, `make ci` green, its docs in the same commit):
1. **The watch route** (`writ-proto`, `writ-approval`, `writ-gateway`): `writ watch
   [<cursor>]` over SSH, `GET /v1/tickets/watch[?since=<cursor>]` over HTTPS; the cursor the
   SHA-256 of the waiting tickets' ids, the reply the waiting tickets and their cursor, given
   at once when the caller's cursor isn't the one now, else on the first change or after
   240 s; at most 16 watches held at once (a gateway semaphore), past it refused and logged
   (`command`, coalesced per source); over SSH ended with its channel, over HTTPS run in the
   connection's future (it changes nothing), so it ends with its client. Tests: the grammar
   (hostile cursors refused), the service under paused time (at once, on a submission, on a
   ticket leaving the queue, at the limit, an expiry swept), the cap and its line, both
   transports, a key not in `readers`. Docs: [approvals.md](architecture/approvals.md)'s
   routes, [security.md](security.md)'s inventory.
2. **`writ sign --ui`** (`writ-cli`, `approver/ui.rs`): the line protocol (one JSON object
   per line each way, 64 KiB a line from the app, 8 MiB from `writ`), the queue of waiting
   tickets shown one at a time with the display `writ sign --full` prints, **the others
   stacked behind it** (asked by the user: tickets that arrive together are all listed, the
   window saying how many more wait, and the next comes up once one is decided), `sign <id>` and
   `refuse <id> [feedback]` (an empty feedback sent as a fixed line saying none was given),
   `skip <id>` for a window closed; an answer naming another ticket, malformed or over its
   bound signs nothing and is said; the connection made again after a loss; ends on the
   app's end of input. `approve` and `refuse_with` return what they did instead of printing.
   Tests: the protocol's parser (hostile lines), the display the same bytes as `writ sign`'s
   (a guarantee test), an integration scenario with the daemon; the end-to-end scenario
   `approval_popup` playing the app (sign, refuse with and without feedback, a ticket
   withdrawn while shown, a malformed answer, an amendment and a renewal shown, an admin
   change never shown), its row in the coverage registry. Docs:
   [clients.md](architecture/clients.md), [approvals.md](architecture/approvals.md).
3. **`writ-popup`, the Swift app** (`crates/writ-cli/macos/writ-popup.swift`, built by
   `tool/build-writ-popup.sh` beside `writ`, from the Makefile's `test`, `run` and
   `install`): an accessory app (no Dock icon) running `writ sign --ui`, the `NSPanel` above
   every space and full-screen app, the display in a scrollable monospaced view, Sign and
   Decline (a feedback field) with no default button and held for a second, a closed window a
   `skip`; `writ` started again if it ends. Docs: the [manual check](guides/manual-checks.md)'s
   popup section, the [threat model](threat-model.md)'s row, the
   [overview](architecture/overview.md)'s layout, [stack.md](stack.md).
4. **The installer** (`deploy/setups/local-macos.sh`): `writ-popup` in `/opt/writ/bin`,
   signed like the others; a per-user LaunchAgent `dev.writ.popup`
   (`~/Library/LaunchAgents/dev.writ.popup.plist`, the Aqua session, `WRIT_APPROVAL_AGENT`
   from the new `APPROVAL_AGENT` answer, Secretive's socket by default) bootstrapped into
   your GUI session, started again on upgrade, taken back by `make uninstall`; the fake-root
   installer test. Docs: [install.md](operators/install.md),
   [clients.md](operators/clients.md).
5. **Closing:** the acceptance items ticked from what was run, the manual check run by the
   user, the history page.

Acceptance:
- [ ] The watch route answers a reader as soon as a ticket starts waiting, and after its
      bounded time with nothing; a watch past the cap is refused with its reason and logged;
      a key that isn't a reader's is refused; over SSH and over HTTPS alike.
- [ ] `writ sign --ui` writes exactly the display `writ sign` prints for that ticket (every
      field, agent text neutralized), signs on `sign`, refuses with the feedback on
      `refuse`, and signs nothing on a malformed, oversized or missing answer; an admin
      change or an unseal never reaches it; each case an end-to-end scenario.
- [ ] Tickets that arrive together are stacked (asked by the user): the oldest shown, each
      other one listed behind it with its title and repositories and the window saying how
      many more wait; the next one shown once one is decided or gone.
- [ ] The guarantees of the trusted display hold through the popup: the guarantee tests of
      `writ sign` (what is signed is what was displayed, every field shown, a relay naming
      another daemon refused) run against `writ sign --ui` too.
- [ ] The [manual check](guides/manual-checks.md) against the development daemon (`make
      run`): the window comes up over a full-screen app and on another space, Touch ID's
      prompt over it, Return typed in another app presses nothing, Sign gives the lease,
      Decline with feedback reaches the agent's `writ wait`, a ticket withdrawn closes its
      window.
- [ ] `make install` puts the app and its LaunchAgent in place and `make uninstall` takes them
      back (the fake-root installer test); the real install's popup runs with M7.9.

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
      daemon (the GitHub throwaway repository of the manual checks), its ticket signed
      through M7.8's popup (the app started at login by its LaunchAgent): its lease bound to the
      agent `/opt/writ/bin/writ` started (M7.7), refused from outside the session, revoked
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
