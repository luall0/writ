# Roadmap

The milestones to [Scope v1](product.md#scope-v1). Work **strictly in order**: each milestone
ends with everything built so far working, tested, and committed. When a milestone is done,
its section moves to [`history/`](history/README.md) with notes on what was done (see
[AGENTS.md](../AGENTS.md#project-status)).

Order rationale: prove the risky protocol pieces first (M0), then build the policy as a pure
library (M1), then add one end-to-end capability per milestone (ticket → signing → pushing).
Writ guards real credentials, so it is used only on **test repos and test forge accounts**
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
| M2.6 | [Security checkup](#m26--security-checkup) | The security review after M2.5 and its fixes; the security conventions (`docs/security.md`), their checks in `make check`, CI |
| M3 | [Signed commits](#m3--signed-commits) | `writ-sign`, the sign command, the ledger, `writ init` |
| M4 | [Gateway push and fetch](#m4--gateway-push-and-fetch) | Mirrors, quarantine, every push check, upstream over SSH |
| M4.5 | [HTTPS upstream](#m45--https-upstream) | Upstream with tokens for HTTPS-only forges |
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

A stop before M3, asked for by the user: a security review of everything built so far
(four reviews by trust boundary, plus the supply chain and the build), the fixes the user
approved, and the security conventions every later change follows.

Decided with the user: reads of the approval API need a registered `readers` key (SSH auth
key, mutual TLS on HTTPS); reductions of privilege never wait for the audit log; ticket
submission is bounded by caps and a required `submitters` address allowlist; CI is
`make ci`, run by GitHub Actions on Linux and by a `pre-push` hook on the Mac; every
finding is fixed now (the shared `sessions/current` pointer waits for M6/M7).

Steps (one commit each): availability and revocation; listener bounds and authenticated
reads; authority files and the trusted display; core hardening; crypto and SSH; files, logs
and clients; supply chain and build; tests; docs.

Acceptance:
- [ ] Every finding of the review is fixed with a test that tries to break it, or deferred
      with its reason.
- [ ] `docs/security.md` exists, AGENTS.md points at it, and `make check` enforces what a
      script can (dependency policy, no test-only features in the binaries, guarantee
      registry, source rules, stricter lints).
- [ ] `make ci` passes locally and on GitHub Actions; the threat model and the decision log
      hold the new residual risks and decisions.

## M3 — Signed commits

[Flows § 2](flows.md#2-signed-commit): commits signed by the daemon under a lease.

- The gateway's `sign` command: parse the commit bytes, check lease, limits, rate, committer
  email, object type (commits only, no tags: [Q11](decisions.md)), `ticket_link: trailer`,
  `paths_check` against `expected_paths`; sign through the `Signer`; append to the ledger.
- `writ-sign` shim; `writ init` writes the remote, signing config and `core.sshCommand`
  ([repo setup](architecture/clients.md#repo-setup-on-an-agent-host)).

Acceptance:
- [ ] In a repo wired by `writ init`, `git commit -S` works without any prompt and
      `git verify-commit` passes with the agent key in `allowed_signers`.
- [ ] Denied cases each fail with the reason printed in the agent's terminal: no lease,
      expired, over `max_signatures`, over the rate, wrong committer email, a tag, a missing or
      wrong `Writ:` trailer, paths outside `expected_paths` with `paths_check: deny`.
- [ ] `paths_check: warn` signs and records the warning for the activity report.
- [ ] Every signed commit is in the ledger with its lease and key.

## M4 — Gateway push and fetch

[Flows § 3 and § 4](flows.md#3-push) in `gateway` mode, upstream over SSH, against a test
forge (local Forgejo or Gitea in Docker) and one throwaway GitHub repo.

- One bare mirror per registered repo; sync on fetch, on push and periodically.
- Push into quarantine; checks: lease covers push and repo, ref matches the branches, protected
  refs, no force push unless allowed, every new commit in the ledger for this lease, size.
- Upstream pusher with the upstream credential from the `Signer`; mirror refs updated only
  after upstream accepted; upstream rejections relayed to the agent.
- `writ init` writes the [URL rewrite](architecture/gateway.md#url-rewrite).
- From the M2.6 security review: mirrors use the reftable ref format (no loose ref files to
  collide by case on APFS), and an update whose name differs only in case from an existing
  ref is refused; `receive.fsckObjects` stays on; decide and consume a push under one store
  transaction, with the rate window and expiry checked there too.

Acceptance:
- [ ] `git push origin agent/x` from a wired repo reaches the forge; `git fetch` works through
      the daemon; the agent host holds no forge credential.
- [ ] Each is denied with a readable reason and nothing reaches upstream: a protected ref, a
      branch outside the lease, a force push, a commit not signed under this lease (including
      one signed under another lease), a pack over `max_push_size`, a fetch without `fetch`.
- [ ] Upstream moved → the push is rejected with the forge's reason; fetch, rebase, re-sign
      and push again succeeds.
- [ ] The mirror never holds refs the forge refused.

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
  refusal, amend on an out-of-ticket denial, close with a summary.
- Amendments (`amends: <id>`): the original lease runs while pending, replaced once signed.
- `writ close` and the activity report: commits, pushes, branches, denials, time used vs
  granted, files touched vs `expected_paths`.

Acceptance:
- [ ] A real feature on a personal repo goes from prompt to pushed branch through Writ, with
      exactly one Touch ID (the ticket), while I'm away.
- [ ] A refusal round-trip and an amendment round-trip both work from the agent's side using
      only the skill.
- [ ] The activity report matches the audit log for that lease.

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
  volumes, the gateway's port and the approval transports in use (SSH, HTTPS).
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
