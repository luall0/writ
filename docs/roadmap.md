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
| M6.2 | [Managing the daemon from the CLI](#m62--managing-the-daemon-from-the-cli) | Every key declared in the signed policy, upstream host keys pinned by signed changes, repos naming their templates; `writ admin repo\|template\|key\|host` to read, add step by step and edit one field at a time, with no host access |
| M7 | [Local mode on the Mac](#m7--local-mode-on-the-mac) | macOS implementations plugged in: Unix socket, process chain, revoke on exit, a daemon isolated from my user, launchd, the installer (a setup to pick, `local` first) and an uninstall as easy that offers to take Writ out of the wired repos |
| M7.1 | [Local mode on Linux](#m71--local-mode-on-linux) | Linux implementations plugged in the same way: `SO_PEERCRED` and `/proc` process chain, pidfd watcher, a systemd service under its own user, the installer's Linux local setup, local mode in `make e2e` |
| M7.5 | [Secure Enclave signer](#m75--secure-enclave-signer-on-the-mac) | The non-exportable local-mode signer the M0 spike picked |
| M7.6 | [Hardware-wrapped secrets](#m76--hardware-wrapped-secrets) | Each secret unwrapped by a hardware key only when used: the common unwrap interface, the Secure Enclave as its first recipient, unsealing with no passphrase |
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

## M6.2 — Managing the daemon from the CLI

[The backlog page](backlog/daemon-management-from-the-cli.md) holds the design and the plan.
Today keys are declared in two files (signing keys) or not at all (upstream credentials),
upstream host keys are a host file, templates list their repos, and the public keys come only
from host commands: setting up a repo means host access, a restart and a new unseal, which in
local mode (M7) goes through `sudo -u _writd`. After M6.2 the operator does it all from
`writ`, with one signature per change.

- **Every key declared in the signed policy** (`keys:`, signing keys and upstream credentials
  with their use, kind, algorithm, hash, backend, and the OpenPGP user ids), made by the
  change that declares it; `writd.yaml` keeps only the host's settings; `writd keys create`
  goes.
- **Upstream host keys in the policy** (`upstream_hosts`), pinned by a signed change after a
  scan the daemon makes on an approver's signature and the operator compares;
  `mirrors.known_hosts` goes.
- **Repos name their templates** (`repos.<name>.templates`, `[]` pauses a repo); templates
  no longer list repos.
- **No move from the old shape** (Writ isn't deployed): the old fields refused wherever they
  appear, each naming its new place; the state version moves to 10.
- **`writ admin repo|template|key|host`**: `list`, `show` (`key show --public`), `add` and
  `edit` step by step, `set <name> <field>=<value>…` for one field at a time (`+=`, `-=`, `!`),
  `remove` (`--yes` without a terminal; a removed key deleted after its id is typed again),
  `key rotate`, `host rescan` (a pinned host scanned again when its keys changed), `repo check`
  (read and write access proven with nothing pushed). Each
  command one signed change, shown as a diff.

Acceptance:
- [ ] A repo on a new host, with a new upstream key and a new template, set up from the
      approver's machine with `writ admin` only (no host file, no restart, no unseal): one
      signature per change, the key's public half printed, `repo check` passing once it is
      registered.
- [ ] Every refusal of the new shape (an undeclared or wrongly used key, a kind that doesn't
      match the URL, a token for another host, a host with no pin, a backend the daemon
      lacks) stops the change, or the start, with its field named; none is adjusted.
- [ ] Every old field (`templates.<name>.repos`, the policy's `signing_keys`, `writd.yaml`'s
      `signing_keys` and `mirrors.known_hosts`) is refused, in `writd init`, `writd recover`,
      an admin change and at start, naming its new place.
- [ ] `set` changes exactly the fields named (each syntax tested, a field that can't change
      refused with its reason); a change made in between makes it refused; `add` with no
      terminal refuses naming each missing field.
- [ ] A host key scan runs only on an approver's `writ-scan/1` signature: a reader key
      alone, a replayed nonce or a document naming another daemon is refused with its code.
      A host key is never pinned by a scan alone; a scan and a check bounded in time and
      size, logged, and their answers escaped (hostile host keys and upstream messages
      tested).
- [ ] `key remove` deletes the key's sealed file once the change applies, only after its id
      is typed again (a mistyped id sends nothing) or `--yes`; a key still in use is refused,
      naming its users; the audit line keeps its public half.
- [ ] `repos.<name>.templates: []` refuses every ticket for the repo with its reason, and
      `writ policy` says the repo is closed.
- [ ] Every new command and syntax used for real by an end-to-end scenario, with its rows in
      the registries (rules 18 and 19); the threat model and the security inventory updated.
- [ ] The operator pages and guides rewritten for the new commands and the new configuration
      layout: `writd.yaml` the host's settings only, the policy everything else, `writ admin`
      the way to change it, every command they show the one the pipeline runs.

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
  files don't.
- **One installer, a setup to pick**: `make install` runs the installer (`deploy/install.sh`),
  which asks which setup to install, listing only the ones this build offers on this OS
  (`SETUP=<name>` answers without asking; an unknown or unavailable one is refused with the
  list). M7 brings `local` on macOS; [M7.1](#m71--local-mode-on-linux) adds `local` on Linux,
  and [M8](#m8--detached-deployment) `detached` and `client`. Every setup shares one frame:
  the dry run, the manifest, the upgrade, the uninstall; each setup is its own steps, and
  adding one changes no other. The installer runs as my user and asks `sudo` only for the
  steps that need root.
- **The `local` setup on the Mac, in one command**, from the release builds, starting from the
  spike's `plan-b/` install script: the `_writd` role user; `writd`, `writ` and `writ-sign`
  root-owned in one prefix on my `PATH`; the daemon's `0700` directory with a `writd.yaml`
  from the local preset and a starting policy with no repo (repos, keys and templates are then
  added with [`writ admin`](#m62--managing-the-daemon-from-the-cli)); the agents' socket directory; the LaunchDaemon's plist, root-owned,
  loaded; `writd init` run as `_writd` (the keystore's passphrase asked on the terminal, never
  stored or passed as an argument); my approval public key (`APPROVER=<.pub>`) in
  `approvers`; for my user, `~/.writ/` with the daemon's host key pinned and the endpoints
  set. It ends by printing what is left: `writ unseal`, then `writ init` in a repo.
  `DRY_RUN=1` lists every change first and makes none. Run again, it upgrades: new binaries,
  the daemon restarted in order (the SIGTERM below), the keystore, state, configuration and
  pins kept. A step that fails stops the install and says what was done so far, which
  `make uninstall` takes back.
- **`writ init` keeps the list of the repos it wires**, in `~/.writ/repos` (each repo's path
  and wiring mode, whole-repo or wrapper, and a workspace root with its children), and
  `writ init --undo` takes a repo off it: the one client change this milestone allows, for
  the uninstall. A repo wired before M7 isn't on it until `writ init` runs in it again. The
  list is my user's file, so an agent can write it too: an untrusted input, with its row in
  the [security inventory](security.md), its bounds and a hostile-input test.
- **An uninstall as easy**: `make uninstall` takes the Mac back to how it was before. It reads
  the manifest the install wrote (root-owned) as it went, so it knows the setup and removes
  only what was made: the daemon stopped in order and its LaunchDaemon unloaded; every file,
  directory and the role user removed; nothing it didn't make, nothing outside it. The
  daemon's data (keystore, state, ledger, audit log) is kept unless `PURGE=1`, which names
  what it deletes and asks to confirm on the terminal, and a later `make install` picks it up
  again (the role user made with the same uid). `DRY_RUN=1` as for the install.
- **The uninstall asks whether to take Writ out of the repos already set up too**: it lists
  the repos on `~/.writ/repos` (each checked to still hold `writ init`'s record; one that
  doesn't is named and skipped) and asks on the terminal. Yes: `writ init --undo` in each, as
  my user, never as root, before the binaries go, and a repo it can't take back is named with
  why. No: they stay wired and are named, and the question says so before: once `writ` is
  gone, only a new install takes them back. With no terminal it asks nothing and refuses
  unless `REPOS=undo` or `REPOS=keep` answers.
- **`writd recover` checks the daemon is stopped** (left open by M5, found by the
  [M5.6 review](#m56--review-after-m55), L17): today it assumes it,
  and two writers would only refuse each other's versions. For example, `writd run` holds an
  advisory lock on a file in its state directory (released by the kernel when the process
  ends, so a crash leaves none stale) and `writd recover` refuses while it is held, naming it.
  Settled with the user before building.
- **SIGTERM is an orderly stop** (found by the [M5.6 review](#m56--review-after-m55), L16):
  `writd run` stops cleanly on Ctrl-C only (SIGINT); launchd stops a daemon with SIGTERM, which
  kills it at once today (no `stopping` line, an upstream push cut mid-way). `writd run` waits
  on both signals and stops the same way for each, through the platform's signal seam if the
  wait differs by OS (hard rule 4).
- **The recovery guide's macOS commands**: `docs/operators/recovery.md`'s placeholders (the
  LaunchDaemon's label, the daemon's directory and its `writd.yaml`) filled with what
  `make install` makes, and run for real as a manual check.

Acceptance:
- [ ] **The graft test:** no change in `writ-core`, `writ-store`, `writ-git`, `writ-gateway`,
      `writ-approval` or the clients, beyond bug fixes and `writ init`'s list of wired repos;
      only new implementations, `writd`'s wiring and config, and the installer.
- [ ] The macOS implementations pass the same contract suites as the portable ones.
- [ ] The same agent workflow as M6 works against the local daemon with no client change
      beyond the endpoint.
- [ ] A lease bound to a session refuses a caller outside that process tree, whatever its
      process name or arguments, and refuses every TCP caller.
- [ ] Quitting the session's root process revokes the lease.
- [ ] On a Mac without Writ, `make install` (the `local` setup picked at its question, then
      with `SETUP=local`) then `writ unseal` gives a working local daemon with nothing else
      done by hand; `DRY_RUN=1` lists exactly what the install then makes; a second
      `make install` upgrades the binaries and keeps the keystore, state and pins; a
      `SETUP` this OS doesn't offer is refused with the list.
- [ ] `make uninstall` leaves the Mac as before the install (the role user, the
      LaunchDaemon, the binaries, the directories and `~/.writ/`'s pins gone, checked
      against a listing taken before), the daemon's data kept unless `PURGE=1` is
      confirmed; after an install stopped half way, it takes back what was made.
- [ ] The repos question: answered yes, every repo on the list (wrapper, whole-repo, a
      workspace) is back exactly as before its `writ init`, undone as my user; answered no,
      none is touched and each is named; with no terminal and no `REPOS`, the uninstall
      refuses before changing anything. A hostile `~/.writ/repos` (a path that isn't a
      wired repo, a relative path, a link, control characters, an oversized file)
      never makes it touch anything `writ init` didn't wire, and what it skips is named,
      escaped.
- [ ] My user (so any agent) can't read the daemon's keystore or attach to the daemon
      (`cat` and `lldb -p` refused), and the daemon starts again after a reboot.
- [ ] `launchctl stop` (SIGTERM) stops the daemon as Ctrl-C does: the `stopping` line, the
      listeners closed, an upstream operation in flight allowed its deadline.
- [ ] `writd recover` refuses while the daemon runs, naming why, and works once it is
      stopped (both sides tested, a crashed daemon's leftover not
      blocking it); the recovery guide's macOS steps run as written.

## M7.1 — Local mode on Linux

The [backlog idea](backlog/README.md#local-mode-on-linux), picked: local mode on a Linux
workstation, where agents run as my user on the machine that runs the daemon. Like M7, it only
**adds implementations** of existing interfaces and the local preset with them; M7's Unix
socket `Transport` and SIGTERM handling are reused as they are. Signer: the software backend
(a TPM signer stays in the [backlog](backlog/README.md#tpm-signer-backend)).

- `writ-platform-linux`: the process chain `CallerAttestor`, from `SO_PEERCRED` and `/proc`:
  the executable from `/proc/<pid>/exe`, the parent and the start time from
  `/proc/<pid>/stat`, the start time as the pid's generation, each process held by a pidfd
  while it is read, so a process that exits mid-walk and whose pid is reused fails closed.
  Linux has no code signature, so the chain carries no code identity, and a constraint naming
  one denies there. An executable shown as deleted, a caller in another pid or mount
  namespace than the daemon's (a container, a sandbox: its pids and paths mean something
  else), or a `/proc` the daemon can't read (`hidepid`) is refused with its reason. The full
  chain in the audit log, as on the Mac.
- `writ-platform-linux`: a pidfd `SessionWatcher` (Linux 5.3 or later; an older kernel is a
  startup error naming it, never a lease left unwatched).
- **A daemon isolated from my user**: a systemd system service running as a dedicated system
  user `writd` (no shell, no login), its binary root-owned, its keys and state in
  `/var/lib/writ` (`0700`), with systemd's sandboxing (no new privileges, the file system
  read-only but for its state directory, no capabilities). The agents' socket in
  `/run/writ/`, reachable through a `writ` group my user is in; the daemon's files aren't.
  The M5 hardening (not dumpable, no core dumps) keeps my user from attaching to it.
- **The installer's `local` setup on Linux**, with M7's frame: the system user and the group
  (my user added to it, the installer saying a new login is needed for it to apply), the
  binaries, the unit file installed, enabled and started, `writd init` as `writd`,
  `~/.writ/`; `make uninstall` takes back exactly that, the group membership included, and
  asks the repos question as on the Mac. systemd's stop timeout is above an upstream
  operation's deadline, so a stop is always the orderly one.
- **Local mode in the end-to-end pipeline**: in one container, the daemon as `writd` and an
  agent as another user over the Unix socket, so the process chain checks and the revocation
  when a session ends run as scenarios, where the Mac can only check them by hand.
- Docs: the new `attestor` and `session_watcher` values in the
  [operator reference](operators/writd-yaml.md) and its template (rule 19), the
  [platform](architecture/platform.md) preset, [identity](architecture/identity.md),
  [deployment](architecture/deployment.md), the [recovery guide](operators/recovery.md)'s
  Linux local commands, the [threat model](threat-model.md)'s boundary 6 and the
  [product](product.md)'s modes.

Acceptance:
- [ ] **The graft test:** only new implementations in `writ-platform-linux`, `writd`'s wiring
      and config, and the installer's new setup.
- [ ] The Linux implementations pass the same contract suites as the portable and macOS ones.
- [ ] The M6 agent workflow works against the local Linux daemon, as an end-to-end scenario.
- [ ] A lease bound to a session refuses a caller outside that process tree whatever its
      name or arguments, a TCP caller, a caller in another namespace and a pid reused
      mid-walk, each with its exact reason; a `/proc` it can't read refuses, never crashes.
- [ ] Ending the session's root process revokes the lease (end-to-end scenario).
- [ ] My user (so any agent) can't read the daemon's keystore or attach to it (`cat`,
      `gdb -p`, `strace -p` refused), and the daemon starts again after a reboot.
- [ ] `systemctl stop` stops the daemon in order (the `stopping` line).
- [ ] On a Debian 13 machine without Writ (a VM, by hand), `make install` with
      `SETUP=local` then `writ unseal` gives a working daemon; `make uninstall` leaves the
      machine as before, checked against a listing taken before, the repos question as in
      M7; the recovery guide's Linux local steps run as written.

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
- **`docker stop` is an orderly stop** (found by the [M5.6 review](#m56--review-after-m55), L16):
  the SIGTERM handling M7 adds, checked in the container (tini forwards it under
  `init: true`), within compose's `stop_grace_period`.
- **Q38 first** ([open questions](decisions.md#open-questions), left open by M5): the
  keystore's recipient is public, so whoever can write the keys directory, here a Docker
  volume, can plant a secret of their choosing. Settled with the user before building:
  whether each sealed secret file is bound to the state (e.g. a MAC over its digest with the
  authority key, checked at unseal and on every live read); if kept, it is built here.
- **The recovery guide's Docker commands**: `docs/operators/recovery.md`'s placeholders (the
  paths in the image, its user) filled in, and run end to end against the deploy image.
- **The installer's `detached` setup**, on the daemon host, with M7's frame (the setup
  question, `DRY_RUN=1`, the manifest, the upgrade, `make uninstall`): the image built
  (`make docker`); one directory holding `deploy/compose.yaml` and a `writd.yaml` from the
  detached preset, the approval transports and the `allow` lists asked for (or given:
  `APPROVALS=ssh,https`, `AGENTS_ALLOW=<cidr>…`); the two volumes; `writd init` in the
  container, the passphrase on the terminal; the approver's public key in `approvers`; the
  stack started. It ends by printing what each client pins (the host key, the TLS
  fingerprint) and the `make install` to run on them. Upgrading rebuilds the image and
  restarts the stack in order, the volumes kept. `make uninstall` takes the stack down and
  removes the image and the files it made, the volumes kept unless `PURGE=1` is confirmed.
- **The installer's `client` setup**, on each machine that uses a detached daemon (the
  approver's Mac, an agent VM): `writ` and `writ-sign` on the `PATH`, `~/.writ/` with the
  daemon's endpoints, its host key and TLS certificate pinned (asked for, or given as
  `WRIT_URL`, `HOST_KEY`, `TLS_PIN`, and checked against the daemon before anything is
  written), and on the approver's machine (`APPROVER=<.pub>`) the approval key and the
  reader key (`writ reader`), printing the line for the daemon's `readers`. `make uninstall`
  takes it back and asks the repos question as in M7.

Acceptance:
- [ ] `docker compose up` on the homelab → sealed → `writ unseal` from the Mac → agents on a
      VM and on the Mac both work under their own leases at the same time.
- [ ] A container restart notifies me and fails closed until unsealed.
- [ ] `docker stop` stops the daemon in order (the `stopping` line in its log), not killed
      at the grace period's end.
- [ ] Only port 2222 and the approval transports in use (2223 SSH, 8443 HTTPS) are exposed;
      the process runs as non-root.
- [ ] Detached is only the detached [configuration preset](architecture/platform.md#configuration-presets)
      and packaging: no change to the core crates beyond bug fixes.
- [ ] Q38 settled before building; if kept, a secret file planted or swapped in the keys
      directory (a key with its matching `.pub`, a token) stops the unseal, naming the file.
- [ ] The recovery guide's Docker steps run as written, end to end (`make e2e`).
- [ ] The first item above set up with the installer only: `SETUP=detached` on the homelab,
      `SETUP=client` on the Mac and on the VM, nothing else by hand but `writ unseal` and
      the `readers` line; the setup question on each offers only what that OS can install.
- [ ] `make e2e` sets its agents' containers up with `SETUP=client`, and its daemon from the
      compose file and the `writd.yaml` the `detached` setup writes; a client given a host
      key or TLS pin the daemon doesn't have writes nothing and says why.
- [ ] `make uninstall` takes each setup back, checked against a listing taken before: the
      volumes kept unless `PURGE=1` is confirmed, the clients' repos question as in M7.

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
