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
| M4.1 | [Real end-to-end scenarios](#m41--real-end-to-end-scenarios) | The operator's and the agent's paths, run for real in containers against Forgejo, in CI; signature verification on the account |
| M4.5 | [HTTPS upstream](#m45--https-upstream) | Upstream with tokens for HTTPS-only remotes |
| M5 | [Sealed start and admin changes](#m5--sealed-start-and-signed-admin-changes) | Encrypted keystore, `writ unseal`, signed changes to approvers, templates, registry |
| M6 | [Agent skill, amendments, close](#m6--agent-skill-amendments-and-close) | The Writ skill, amendments, activity report: first real task end to end |
| M7 | [Local mode on the Mac](#m7--local-mode-on-the-mac) | macOS implementations plugged in: Unix socket, process chain, revoke on exit, a daemon isolated from my user, launchd, `writ try` |
| M7.5 | [Secure Enclave signer](#m75--secure-enclave-signer-on-the-mac) | The non-exportable local-mode signer the M0 spike picked |
| M8 | [Detached deployment](#m8--detached-deployment) | Docker image on the homelab, agents on other hosts |
| M9 | [`proxy` push mode](#m9--proxy-push-mode) | Relayed pushes with the same checks, no mirror |
| M10 | [`direct_ssh` push mode](#m10--direct_ssh-push-mode) | Lent per-lease ssh-agent socket with a deploy key |

After M10, new work comes from the [backlog](backlog/README.md).

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

Asked by the user after M4's GitHub check, which found two bugs no test saw: `writd host-key`
/ `upstream-keys` needed the approvers file before the operator has one, and a daemon started
on a relative config path ran pushes with no hook at all (no check). Both were on paths only a
real operator takes; every harness took shortcuts (absolute paths, keys made in-process,
files written in another order). M4's `make e2e` ran one scenario through the Rust harness.
This milestone runs **the documented paths themselves**, with the real binaries in their own
containers, against a real Forgejo, so the next such bug fails the pipeline, not a person.

The pipeline (`make e2e`, Docker only on the host):

- **`forgejo`**: pinned (`codeberg.org/forgejo/forgejo:13.0.5`), set up headless (an admin
  user, a token), its own SSH server.
- **`writd`**: the real Linux binaries built in a pinned Rust builder stage (`--locked`), a
  runtime image with git ≥ 2.45 and OpenSSH (Debian 13: git 2.47, OpenSSH 10.0), started the
  way the operator guide says: a `writd.yaml` with relative paths, a relative config path,
  keys printed by `writd host-key` / `tls-fingerprint` / `upstream-keys` before any approver
  exists. **A test image (`e2e/`), decided with the user: M8's deploy image (non-root,
  minimal, compose) builds on it** rather than starting over (see
  [M8](#m8--detached-deployment)).
- **`agent`**: another container (another host, as in detached mode) with the real `writ`,
  `writ-sign`, git and ssh, reaching the daemon by name; the approver's key in a throwaway
  ssh-agent there, `writ sign --yes` over the approval API (SSH and HTTPS).
- **The runner** (decided with the user): scenarios as Rust tests (a test target of their
  own, ignored by `make test`) driving the containers (`docker compose exec`) and Forgejo's
  API; the hardened-test rules hold (readiness by a signal or a bounded poll, exact codes, the
  allowed case beside each refusal); each scenario on its own repo and lease.
- **CI** runs `make e2e` as a job of its own on the Linux runner (decided with the user); the
  pre-push hook keeps running `make ci` only.

Scenarios (each asserts what the agent reads, the audit line, Forgejo's state through its
API, and the mirror):

1. **Operator setup from nothing**, in the order the operator guide and the manual checks give
   it: pins, keys, the deploy key, readers, approvers, start. (The two M4 bugs fail here.)
2. **Ticket lifecycle**: request, sign over SSH and over HTTPS, a signed refusal and a
   revision, a revocation, a ticket that expires unsigned.
3. **Wrapper mode**: a clone from Forgejo, `writ init`, signed commits, `writ git push
   origin`; the operator's plain git in the same clone untouched.
4. **Whole-repo mode**, and `writ init --undo`.
5. **Every push denial** (protected ref, branch outside the lease, force push, deletion,
   unsigned commit, another lease's, an unsigned parent, over `max_push_size`, a ref differing
   only in case, a fetch without `fetch`): Forgejo and the mirror unchanged.
6. **Upstream moved**: refused, then fetch, rebase (a conflict resolved too), signed again,
   pushed.
7. **Forgejo's own branch protection** refusing a push: its reason relayed, the mirror
   unchanged.
8. **Signature verification on the account**: the lease's signing key registered on the
   Forgejo account and proven, the committer email one of the account's: pushed commits are
   verified per Forgejo's API; with the key not registered (or not proven), unverified. The
   GitHub manual check gains the same (the key added as a signing key, the email verified:
   "Verified").
9. **Revocation and expiry with operations in flight**; the certificate refused afterwards.
10. **Restart**: the `writd` container restarted keeps leases, mirrors and ledger; a push works
    after.
11. **A broken or hostile upstream, for real**: Forgejo stopped (fetch and push refused, then
    working once it is back), its host key changed (refused), the deploy key removed (refused
    with Forgejo's reason).

Also built here:

- **Proving an agent signing key to a remote that asks** (proposed with the user, to confirm).
  Forgejo and Gitea verify an SSH signing key only once a challenge is signed with it
  (namespace `gitea`, a 64-hex token, web UI only: checked with Forgejo 13.0.5); GitHub doesn't
  ask. The key never leaves the daemon, which signs commits only through the policy. A proof is
  an **approval**, like a ticket: `writ prove-key <key id> --namespace <ns>` on the approver's
  machine reads the remote's message (stdin, at most 4 KiB), shows the key, the namespace and
  the message (escaped), and signs a `writ-proof/1` document over them with the approver key
  (Touch ID: its own `kind`, so it can never pass for a ticket approval or the other way
  round); the approval API (SSH or HTTPS) takes it, the daemon checks the approver's signature
  over exactly that, the bound, and the namespace (any **but `git` and Writ's own**,
  `writ-approval` and any `writ…`: signing in `git` would make commit signatures outside the
  policy and the ledger), signs through the `Signer`, logs it (key, namespace, the message's
  digest, the approver) and returns the armored signature. A reader key alone can't ask for
  one; nothing on the daemon host is needed, and it works the same with the sealed keystore.
- **`writd signing-keys`**, printing the agent signing public keys to register on accounts
  (today only a lease's grant carries one).

Notes for the implementation (gathered while planning, 2026-11-01):

- **Where it starts**: M4's `make e2e` (`tool/e2e.sh`: Forgejo started headless with
  `FORGEJO__security__INSTALL_LOCK=true`, sqlite, random local ports, `forgejo admin user
  create` and `generate-access-token --scopes all --raw` run in the container; and
  `crates/writ-integration/tests/e2e_forgejo.rs`: a repo and a deploy key made through the
  API, the host key from `ssh-keyscan`, one scenario through the in-process harness). M4.1
  replaces the harness with the real binaries in containers.
- **The two bugs the pipeline must catch** (acceptance below): `5658e4e` (the print commands
  read the approvers file) and `fd57274` (a relative config path left `core.hooksPath`
  relative: git found no hook and took pushes unchecked). Reverting either fix must fail
  `make e2e`.
- **Forgejo's SSH signature verification, as checked by hand with Forgejo 13.0.5**: adding the
  key (`POST /api/v1/user/keys`) is not enough (`verification.reason:
  gpg.error.no_gpg_keys_found`); the key must be proven in the web UI, which has no API (only
  GPG keys have one: `/user/gpg_key_token`, `/user/gpg_key_verify`). The flow a test can
  drive: log in (`POST /user/login` with `_csrf`, `user_name`, `password`, cookies kept); `GET
  /user/settings/keys?verify_ssh=<fingerprint>` with the fingerprint URL-escaped (a `+` must be
  `%2B`, or the page shows no token; the page's own "Verify" link is escaped right); the page
  shows `echo -n '<64-hex token>' | ssh-keygen -Y sign -n gitea …`; `POST /user/settings/keys`
  with `_csrf`, `title=none`, `content=none`, `type=verify_ssh`, `fingerprint`, `signature`
  (303). Then `GET /api/v1/repos/<owner>/<repo>/git/commits/<sha>` gives
  `commit.verification.verified: true` and the signer. The committer email must be one of the
  account's emails (the user was created with `agent@writ.invalid` in the check). GitHub: the
  key added as a **signing** key and the committer email verified on the account; no proof.
- **The runtime image**: Debian 13 (`trixie-slim`) has git 2.47.3 and OpenSSH 10.0
  (`writ_mirror::MIN_GIT` is 2.45; Debian 12's 2.39 is too old).

Acceptance:
- [ ] `make e2e` starts from nothing (Docker and make on the host, no state), runs every
      scenario above, and removes everything, locally and in CI.
- [ ] Reverting either M4 fix (the print commands without the approvers file, the absolute
      hooks path) makes `make e2e` fail.
- [ ] Commits pushed through Writ show as verified on Forgejo once the lease's signing key is
      registered and proven on the account; unverified otherwise.
- [ ] The operator guide's and the manual checks' commands are the ones the pipeline runs
      (a step changed in one is changed in the other).
- [ ] A proof (`writ prove-key`) needs an approver's signature over exactly the key, the
      namespace and the message; one in `git` or a `writ…` namespace, over 4 KiB, from a reader
      key alone, or replayed as a ticket approval is refused with its code and logged.

## M4.5 — HTTPS upstream

Upstream over HTTPS with a token, chosen by the repo's `upstream` URL ([Q4](decisions.md)).

Acceptance:
- [ ] A repo with an `https://` upstream fetches and pushes through the daemon with a token
      read from the keystore; the token never appears in logs, errors or the mirror's config.

## M5 — Sealed start and signed admin changes

[Signer and sealing](architecture/signer.md#startup-and-sealing),
[Flows § 7](flows.md#7-daemon-startup-sealed). From here, Writ may hold real credentials.

- age keystore with a random data key; software keys and tokens only inside it.
- `writd` starts sealed and serves only the unseal endpoint; `writ unseal` sends the
  passphrase and an unseal SSHSIG; active leases reloaded after unsealing.
- Admin changes (approvers, templates, repo registry) only through signed approvals, logged.
- The HTTPS approval API's TLS key behind the `Signer`, like every other key: it lives in the
  keystore under a key id (`tls-01`), the self-signed certificate is made by signing through
  the `Signer`, and rustls signs handshakes through a small adapter (its signing-key trait
  asking the `Signer`, which returns the raw signature; the adapter DER-encodes it). The
  software backend (the `p256` crate, wiped on drop) is the default; a hardware backend is a
  config choice (M7.5). Handshake signatures run off the async threads if the backend is slow.
- Process hardening for every secret the daemon holds in memory (keys, tokens, the data key,
  the TLS key): no core dumps, no debugger attach, secret memory locked out of swap. OS
  calls, so behind a platform interface with its contract suite (hard rule 4), applied at
  startup before any secret is loaded; a platform that can't apply one says so in the log
  and the threat model.

Acceptance:
- [ ] While sealed, every request fails closed with "daemon sealed".
- [ ] Unsealing needs both the right passphrase and a valid approver signature; either alone
      fails and is logged.
- [ ] The keys volume alone reveals no key (checked by inspecting it at rest).
- [ ] A restart keeps active leases working after unseal; their certificates still expire on time.
- [ ] An unsigned or wrongly signed admin change is refused; a signed one applies and is logged.
- [ ] The TLS key is only in the keystore and the `Signer`: no PEM key file, no copy outside
      the `Signer`; HTTPS approvals work as in M2, with the certificate pinned from
      `writd tls-fingerprint`.
- [ ] The running daemon leaves no core dump when it crashes, refuses a debugger attaching
      to it (`lldb -p`, `gdb -p` as the same user), and its secret pages are locked (checked
      on macOS and on Linux).

## M6 — Agent skill, amendments and close

The workflow the agent follows ([Clients](architecture/clients.md#client-list),
[Flows § 6 and § 6b](flows.md#6-out-of-ticket-request)).

- `skill/writ/SKILL.md`: think through the scope, write and submit the ticket, wait, revise on
  refusal, amend on an out-of-ticket denial, close with a summary. One skill for both
  wirings: the agent always runs git through `writ git …` (any command; plain git is the
  same in a `--whole-repo` clone), and adds the `Writ:` trailer; decided in M3.
- Amendments (`amends: <id>`): the original lease runs while pending, replaced once signed.
  An amendment changes scope, not time (decided after the M3.5 review,
  [M3.6](history/m3.6-review-after-m3.5.md)): its `expires_at` is capped at the lease's, so
  the certificate's `valid_before` stays the lease's end and a chain of amendments can't
  stretch a lease.
- `writ close` and the activity report: commits, pushes, branches, denials, time used vs
  granted, files touched vs `expected_paths`.

Acceptance:
- [ ] A real feature on a personal repo goes from prompt to pushed branch through Writ, with
      exactly one Touch ID (the ticket), while I'm away.
- [ ] A refusal round-trip and an amendment round-trip both work from the agent's side using
      only the skill.
- [ ] The activity report matches the audit log for that lease.
- [ ] An amendment applied minutes before the lease ends doesn't move its end: `writ ls`, the
      lease and the certificate all end at the original time.

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
