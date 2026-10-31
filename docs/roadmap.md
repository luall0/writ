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
| M0 | [Protocol spike](#m0--protocol-spike-gono-go) | Go/no-go: git over a russh gateway with certificates, SSHSIGs git and Secretive accept |
| M1 | [Lease model and policy core](#m1--lease-model-and-policy-core) | `writ-core`: tickets, templates, registry, narrowing, lifecycle, decisions; store and audit log |
| M2 | [Ticket flow](#m2--ticket-flow-request-sign-refuse-revoke) | `writ request` / `sign` / `refuse` / `revoke` / `ls`, certificates, ntfy |
| M3 | [Signed commits](#m3--signed-commits) | `writ-sign`, the sign command, the ledger, `writ init` |
| M4 | [Gateway push and fetch](#m4--gateway-push-and-fetch) | Mirrors, quarantine, every push check, upstream over SSH |
| M4.5 | [HTTPS upstream](#m45--https-upstream) | Upstream with tokens for HTTPS-only forges |
| M5 | [Sealed start and admin changes](#m5--sealed-start-and-signed-admin-changes) | Encrypted keystore, `writ unseal`, signed changes to approvers, templates, registry |
| M6 | [Agent skill, amendments, close](#m6--agent-skill-amendments-and-close) | The Writ skill, amendments, activity report: first real task end to end |
| M7 | [Local mode on the Mac](#m7--local-mode-on-the-mac) | macOS implementations plugged in: Unix socket, process chain, revoke on exit, launchd, `writ try` |
| M8 | [Detached deployment](#m8--detached-deployment) | Docker image on the homelab, agents on other hosts |
| M9 | [`proxy` push mode](#m9--proxy-push-mode) | Relayed pushes with the same checks, no mirror |
| M10 | [`direct_ssh` push mode](#m10--direct_ssh-push-mode) | Lent per-lease ssh-agent socket with a deploy key |

After M10, new work comes from the [backlog](backlog/README.md).

## M0 — Protocol spike (go/no-go)

Answer the questions that could change the stack before writing the real daemon. Throwaway
code is fine, but it lives in the workspace created by the
[initialization guide](guides/initialization.md), and `make check` / `make test` exist.
Settles [Q28](decisions.md#open-questions).

Acceptance checklist, all must pass:
- [ ] A russh server with an in-memory CA accepts a key + user certificate it issued, and
      refuses: an unknown CA, an expired certificate, a revoked serial, a plain key.
- [ ] Through that server, plain `git clone`, `git fetch` and `git push` work against a local
      bare repository (shelling out to `git upload-pack` / `git receive-pack`), with
      `core.sshCommand` pointing at the key and certificate.
- [ ] The server can read the ref update lines of a push and reject it with a message that
      git shows to the user.
- [ ] A commit signed with an SSHSIG built in Rust (ed25519 and P-256 software keys) passes
      `git verify-commit` with an `allowed_signers` file.
- [ ] A shim set as `gpg.ssh.program` receives git's `-Y sign` call and returns a signature
      git accepts; `-Y verify` is forwarded to the real `ssh-keygen`.
- [ ] Rust verifies an SSHSIG made by a **Secretive** key (`ssh-keygen -Y sign -n
      writ-approval`, ECDSA P-256) and rejects the same signature under another namespace or
      over other bytes.
- [ ] Results and versions (git, OpenSSH, crates) written in the milestone's history page.

## M1 — Lease model and policy core

[Lease model](lease-model.md) as code in `writ-core`, plus `writ-store`. No network.

- Types for the repo registry, templates, tickets and leases; YAML config loading with
  errors that name the field.
- Canonical encoding of a ticket (the bytes an approval signs), pinned by fixtures.
- Template fit (which template, or why none), narrowing check (signed ⊆ submitted, strict),
  lifecycle state machine, amendments replacing a scope.
- Policy decisions as pure functions: sign request, push (refs, protected refs, force push,
  ledger, size), fetch, limits and rate.
- `CallerFacts` and the lease's caller constraint
  ([Platform interfaces](architecture/platform.md#caller-facts-and-the-policy)): checked purely,
  missing facts deny.
- SQLite lease store + ledger, JSONL audit log ([Policy, state and audit](architecture/policy-and-state.md)).

Acceptance:
- [ ] Table-driven tests for every row of
      [Constraints](lease-model.md#constraints-and-how-much-to-trust-them) checked by the daemon.
- [ ] Property tests: a narrowed ticket never grants anything the submitted one did not; no
      ticket outside every template is ever accepted; ambiguity (two matching leases) denies.
- [ ] A lease with a caller constraint denies when the facts lack a process chain, and when
      the chain doesn't contain the required ancestor (executable and generation).
- [ ] Canonical encoding fixtures stable across runs; any field change changes the bytes.
- [ ] Leases and ledger survive a reopen of the database; the audit log is append-only and
      holds no secret.

## M2 — Ticket flow: request, sign, refuse, revoke

[Flows § 1](flows.md#1-ticket-submit-review-sign-or-refuse) and
[§ 5](flows.md#5-revoke--expire) end to end, against a local `writd` with software keys
(unsealed dev keystore, test only). Settles [Q29](decisions.md#open-questions).

- `writ-platform`: the `Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock` and
  `Notifier` traits, with their contract test suites and fakes, and one portable
  implementation each (TCP, network attestor, no-op watcher, passphrase unlock, ntfy).
  `writd/src/platform.rs` builds them from the config
  ([Platform interfaces](architecture/platform.md)).
- `writd` serving the gateway's lease commands and the approval API.
- `writ request` (session key generation, ticket file in, waits for the decision), `writ ls`,
  `writ revoke`.
- `writ sign` as the [trusted display](architecture/approvals.md#writ-sign-the-trusted-display)
  (control sequences neutralized, diff vs previous revision), signing through the
  `ssh-agent` socket of Secretive; narrowing flags; `writ refuse` with feedback.
- Certificates issued on approval, valid until `expires_at`; revocation through the deny list.
- ntfy notification when a ticket waits.

Acceptance:
- [ ] A ticket outside every template is rejected before reaching me, with the reason.
- [ ] Signed with Secretive → the agent side receives the lease and a certificate the gateway
      accepts; refused → the agent side receives my feedback, and revision n+1 shows it.
- [ ] A signature by a key not in `approvers`, under another namespace, or over different
      bytes is refused; a narrowed ticket that widens anything is refused.
- [ ] After `writ revoke` or expiry, the certificate is refused on the next connection and
      open sessions are dropped.
- [ ] Every grant, refusal, revocation and denial is in the audit log.
- [ ] The gateway, the policy and the approval API only see the platform traits: their tests
      run on the fakes, and no `#[cfg(target_os)]` exists outside `writd/src/platform.rs`.

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

Acceptance:
- [ ] While sealed, every request fails closed with "daemon sealed".
- [ ] Unsealing needs both the right passphrase and a valid approver signature; either alone
      fails and is logged.
- [ ] The keys volume alone reveals no key (checked by inspecting it at rest).
- [ ] A restart keeps active leases working after unseal; their certificates still expire on time.
- [ ] An unsigned or wrongly signed admin change is refused; a signed one applies and is logged.

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
[configuration preset](architecture/platform.md#configuration-presets). Depends on
[Q27](decisions.md#open-questions) (Secure Enclave signer now or later).

- Unix socket `Transport` (portable Unix, in `writ-platform`).
- `writ-platform-macos`: process chain `CallerAttestor` (executable path and code signature,
  pid + pidversion), kqueue `SessionWatcher`; the full chain in the audit log.
- Leases bound to a session (`caller.descends_from`), revoked when its root process exits.
- launchd plist; `writ try` with `--dry-run`, restoring everything on Ctrl-C.

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

## M8 — Detached deployment

[Deployment](architecture/deployment.md): the daemon on the homelab, agents anywhere on the
LAN or VPN.

- `deploy/Dockerfile` (non-root, minimal image) and `deploy/compose.yaml` with the two
  volumes and two ports.
- ntfy for sealed restarts, waiting tickets, denials and violations.
- Backup guidance for the ledger and the audit log.

Acceptance:
- [ ] `docker compose up` on the homelab → sealed → `writ unseal` from the Mac → agents on a
      VM and on the Mac both work under their own leases at the same time.
- [ ] A container restart notifies me and fails closed until unsealed.
- [ ] Only ports 2222 and 8443 are exposed; the process runs as non-root.
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
