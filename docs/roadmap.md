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
| M0 | [Protocol spike](#m0--protocol-spike-gono-go) | Go for the gateway (certificates, git, daemon-signed commits, agent-held approval keys); which Secure Enclave signer local mode can have for free |
| M1 | [Lease model and policy core](#m1--lease-model-and-policy-core) | `writ-core`: tickets, templates, registry, narrowing, lifecycle, decisions; store and audit log |
| M2 | [Ticket flow](#m2--ticket-flow-request-sign-refuse-revoke) | `writ request` / `sign` / `refuse` / `revoke` / `ls`, certificates, ntfy |
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

Answer the questions that could change the stack or the design before writing the real
daemon: the SSH, SSHSIG and git pieces of the gateway (done: **go**), and which Secure Enclave
signer local mode can have without a paid Apple Developer account (to do). Throwaway code is
fine, but it lives in the workspace created by the
[initialization guide](guides/initialization.md), and `make check` / `make test` exist.

Acceptance checklist, all must pass:
- [x] A russh server with an in-memory CA accepts a key + user certificate it issued, and
      refuses: an unknown CA, an expired certificate, a revoked serial, a plain key.
  *`crates/writd/tests/spike.rs` `only_valid_session_certificates_get_in`, with real `ssh`:
  also refuses a certificate not valid yet. Unit checks in
  `crates/writ-crypto/tests/interop.rs` `certificates_are_issued_and_checked` (wrong
  principal too).*
- [x] Through that server, plain `git clone`, `git fetch` and `git push` work against a local
      bare repository (shelling out to `git upload-pack` / `git receive-pack`), with
      `core.sshCommand` pointing at the key and certificate.
  *`fetch_and_push_through_the_gateway`. Protocol v2 works (`GIT_PROTOCOL` is the only
  environment variable taken from the client). Also checked by hand with the `writd spike`
  binary and a key + certificate from `writd spike-cert`.*
- [x] The server can read the ref update lines of a push and reject it with a message that
      git shows to the user.
  *Through git's pre-receive hook, called back into the daemon (see Decisions). Git shows
  `remote: writ: refs/heads/main is protected` and `! [remote rejected] HEAD -> main
  (pre-receive hook declined)`; the bare repo's refs are unchanged.*
- [x] A commit signed with an SSHSIG built in Rust (ed25519 and P-256 software keys) passes
      `git verify-commit` with an `allowed_signers` file.
  *`ed25519_…` and `p256_commits_signed_by_the_daemon_verify_with_git`: `Good "git" signature
  for agent@writ`. Also `rust_signatures_verify_with_ssh_keygen` (`ssh-keygen -Y verify`).*
- [x] A shim set as `gpg.ssh.program` receives git's `-Y sign` call and returns a signature
      git accepts; `-Y verify` is forwarded to the real `ssh-keygen`.
  *`writ-sign` sends the object over the gateway's `writ-sign git` command. `git
  verify-commit` in the same tests goes through the shim's forwarding. With a revoked
  certificate, `git commit -S` fails with `writ-sign: the daemon refused to sign`.*
- [x] Rust verifies an SSHSIG made through an **ssh-agent** (`ssh-keygen -Y sign -n
      writ-approval` with only the public key, the way approvers sign) and rejects the same
      signature under another namespace or over other bytes.
  *`agent_held_keys_sign_approvals_rust_verifies` runs in `make test` against a throwaway
  `ssh-agent` with generated ed25519 and P-256 keys. With a hardware-backed key in your own
  agent (Secure Enclave, YubiKey…): `make test-agent KEY=<public key .pub>
  [AGENT=<socket>]`, which signs a fresh random message and keeps nothing. Run by hand on
  2026-10-31 with a Secure Enclave P-256 key: passes. Nothing of the user's key is stored in
  the repo.*
- [x] The same SSH protocol works over a Unix socket (added in M0 for local mode, M7).
  *`the_same_protocol_works_over_a_unix_socket`: `russh::server::run_stream` on a
  `UnixStream`, the client through `ProxyCommand='nc -U …'`; clone, push and the protected
  ref refusal all work.*
- [x] Results and versions written here.
- [ ] **Secure Enclave signer without a paid Apple account**
      ([macOS Secure Enclave](architecture/macos-secure-enclave.md)): a small test program in
      `spikes/secure-enclave/` (Swift, outside the Cargo workspace) runs the checks of each
      plan, in the doc's order, stopping at the first that passes:
  - [ ] Plan A, Xcode Personal Team + keychain access group: every check in its list.
  - [ ] If A fails: Plan B, CryptoKit key + dedicated `_writd` user: every check in its list,
        including the keybag question (role account, or hidden standard user).
  - [ ] If A and B fail: Plan D's YubiKey PIN caching per PC/SC session.
  - [ ] The result recorded: the backend for [M7.5](#m75--secure-enclave-signer-on-the-mac)
        and how the daemon runs in [M7](#m7--local-mode-on-the-mac) (app bundle or dedicated
        user), in the [decision log](decisions.md) (settles Q27); the doc's status, its ⚠️
        marks and its "What doesn't work" list updated.

### What was done so far

- Cargo workspace per the [initialization guide](guides/initialization.md): `writ-core`
  (empty until M1), `writ-crypto`, `writ-gateway`, `writd`, `writ-sign`; `Makefile`
  (`check`, `test`, `fmt`, `run`), `tool/check-deps.py` for the dependency directions,
  `clippy.toml` allowing `unwrap`/`expect`/`panic` in tests.
- `writ-crypto`: SSHSIG split into `signed_data` → raw signature → `assemble`, the shape the
  `Signer` interface needs; the certificate authority and `validate_user_certificate` with
  one error per reason.
- `writ-gateway`: certificate-only authentication, an allow-list of exec commands
  (`git-upload-pack '<repo>'`, `git-receive-pack '<repo>'`, `writ-sign git`), repo names
  never paths, refused commands answered with a reason on stderr, TCP and Unix socket
  listeners.
- `writd spike <state> <addr|unix:path>` and `writd spike-cert` for trying it by hand (test
  keys only); `writd hook pre-receive` for git's hook.
- `writ-sign`: finds the daemon from `git config writ.url` and the SSH command git uses
  (`GIT_SSH_COMMAND`, `core.sshCommand`, `ssh`).
- `make check` and `make test` pass: 16 tests and one opt-in (unit, `ssh-keygen` and `ssh-agent` interop, 5 end-to-end with
  real `git` and `ssh`, about 4 s). About 2,000 lines of Rust.

### Versions

| | Version |
|---|---|
| git | 2.54.0 (Apple Git-157) |
| OpenSSH | 10.5p1 |
| Rust | 1.99.1 |
| russh | 0.65.0, `ring` backend (default features off) |
| ssh-key | 0.7.0-rc.11, pinned exactly because russh pins it: same `Certificate` and key types |
| tokio | 1.54.1 |

### Decisions

- **Push checks run in git's own quarantine.** `git receive-pack` stores the pushed objects
  in a quarantine and runs the pre-receive hook before any ref moves. The gateway runs it
  with `core.hooksPath` pointing at its own hook, which forwards the ref updates and a
  per-push token to the daemon over a private Unix socket (in the 0700 state directory); the
  daemon decides, and git drops the quarantine on refusal. This gives `gateway` mode the
  quarantine of the design without reimplementing receive-pack's protocol, and the later
  ledger check can walk the new commits there (`git rev-list <new> --not --all`). Recorded as
  [Q31](decisions.md). `proxy` mode (M9) still needs its own pack handling.
- **The shim reaches the daemon with git's own SSH command** and a new `writ.url` git
  setting, so commit signing uses the same key, certificate and known hosts as fetch and push.
- **Crates:** `tokio`, `thiserror`, `anyhow` decided; the other proposed crates are decided
  when the milestone that needs them starts ([Q28](decisions.md#open-questions)).

### Findings

- **Unix socket paths are short** (104 bytes on macOS with the terminator). The hook socket
  lives in the state directory, so a deep state directory failed with an unclear error;
  `Gateway::start` now refuses it with a clear message. Keep it in mind for local mode's
  client socket (`~/Library/Application Support/Writ/writd.sock` fits).
- `ssh-key` is a release candidate, pinned by russh. Upgrading russh will move it too.
- `UnwrapErr(SysRng)` panics if the system random source fails; acceptable (nothing can be
  signed safely then), noted for the review of M1.
- Integration tests need the workspace binaries built (`writ-sign` is another package's
  binary): `make test` builds them first.

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
[configuration preset](architecture/platform.md#configuration-presets). Signer: the software
backend; the Secure Enclave comes in M7.5. How the daemon runs comes from the M0 Secure
Enclave spike ([macOS Secure Enclave](architecture/macos-secure-enclave.md)).

- Unix socket `Transport` (portable Unix, in `writ-platform`).
- `writ-platform-macos`: process chain `CallerAttestor` (executable path and code signature,
  pid + pidversion), kqueue `SessionWatcher`; the full chain in the audit log.
- Leases bound to a session (`caller.descends_from`), revoked when its root process exits.
- **A daemon isolated from my user**, as the M0 spike decided: a LaunchDaemon running as a
  dedicated `_writd` user (Plans B and D), or an app bundle whose keys are bound to its code
  signature (Plan A). The agents' socket sits in a directory my user can reach; the daemon's
  files don't.
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

Non-exportable agent keys in local mode: the backend the M0 spike picked
([macOS Secure Enclave](architecture/macos-secure-enclave.md#signer-backends-this-maps-to)),
`se-keychain` (Plan A) or `se-cryptokit` (Plan B), or `yubikey-piv` if both failed (Plan D).
A `Signer` implementation in `writ-platform-macos` (calling the Swift component if the spike
needed one) and a config value; nothing else changes.

- The backend, and key creation for it (agent signing keys, optionally the upstream
  credential).
- The packaging the plan needs (embedded provisioning profile for Plan A, the `_writd` user's
  key directory for Plan B), done from the `Makefile`.

Acceptance:
- [ ] **The graft test:** only the new `Signer` implementation, `writd`'s wiring and config
      change.
- [ ] It passes the `Signer` contract suite, like the software backend.
- [ ] With the real daemon: signing needs no prompt, works after a reboot and with the screen
      locked; another process, and my user, can't find or use the key.
- [ ] Commits signed with it verify with `git verify-commit`, as in M3.
- [ ] Going back to the software backend is a config change only.
- [ ] For Plan A: what happens when the provisioning profile expires is known and documented
      (and fails closed).

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
