# AGENTS.md — Writ

Writ is a trust broker for AI agents. An agent drafts a **ticket** for its task (repos,
branches, operations, limits, plan); I sign it with an approver key (Secretive, Touch ID), and
the signed ticket becomes a scoped, time-boxed **lease**. The daemon `writd` holds the agent
signing keys and the credentials for the remotes (GitHub, Codeberg, Forgejo…), is the
agents' git remote, checks every signature and push against the lease, and is the only thing
that pushes upstream. Rust; detached mode (Docker on Linux) and local mode (native on the
Mac, or on Linux from M7.1), same protocol.

Full documentation lives in [`docs/`](docs/README.md). This file holds what every agent must
know before touching the repo.

## Project status

If the repo has no `Cargo.toml` yet, the project is not initialized: follow
[docs/guides/initialization.md](docs/guides/initialization.md) first.

Work follows the [roadmap](docs/roadmap.md) **strictly in order**, M0 to M8.5 (M8.5 completes v1); each milestone
ends with a working, tested commit. When a milestone is done, move its section from the
roadmap to `docs/history/m<N>-<slug>.md`, tick its checklist with a note under each item on
how it was verified, add a row at the end of the [history](docs/history/README.md), and leave
a one-line row pointing there in the roadmap's table. After v1, ideas live in
[docs/backlog/](docs/backlog/README.md); the user picks what comes next, and a picked idea
gets its page (the template there) written up to its plan before any code.

## Naming

| Context | Name |
|---|---|
| Product | `Writ` (a signed ticket is "a writ") |
| Daemon binary / Docker image | `writd` / `writ/writd` |
| CLI binary | `writ` (crate `writ-cli`) |
| git signing shim (`gpg.ssh.program`, `gpg.openpgp.program`) | `writ-sign` |
| Approval popup on the Mac (a window over `writ sign --ui`, M7.8) | `writ-popup` |
| Crates | `writ-<part>` under `crates/` ([layout](docs/architecture/overview.md#repository-layout)); platform-only code in `writ-platform-<os>` |
| Lease / ticket ids | `wrt_` + ULID (e.g. `wrt_01JD8X…`) |
| Approval SSHSIG namespace | `writ-approval` |
| Commit trailer (`ticket_link: trailer`) | `Writ: wrt_…` |
| Git notes ref (`ticket_link: notes`) | `refs/notes/commits` (git's own, the default), or `refs/notes/writ` (`notes_ref: writ`) |
| Git remote on agent hosts | `writ` |
| Agent host session files | `~/.writ/sessions/<lease>/` (`current` → active one) |
| Daemon data (container) | `/var/lib/writ/` (keystore in `/var/lib/writ/keys/`) |
| Ports (detached) | `2222` gateway (SSH, agents), `2223` approval API (SSH), `8443` approval API (HTTPS); each approval transport can be disabled, not both |
| SSH users | `git` (lease holders, with a certificate), `writ` (ticket submission with a session key; the approval API with a reader key) |
| Client files | `~/.writ/known_hosts` (the daemon's pinned host key), `~/.writ/tls_pins` (its pinned TLS certificate), `~/.writ/approver.pub`, `~/.writ/reader` (the reader key), `~/.writ/config` (the daemon's endpoints, when no flag or variable gives them), `~/.writ/repos` (the repositories `writ init` wired) |
| Daemon files granting access | `approvers` (who may sign), `readers` (who may use the approval API) |
| Env vars | `WRIT_*` |
| Agent skill | `skill/writ/SKILL.md`; at a workspace root (`writ init` with no repo named), `skill/writ-workspace/SKILL.md` |
| Workspace record (a folder of repositories) | `<folder>/.writ-workspace` |

Words: the agent submits a **ticket**; once signed it is a **lease** (and a writ).
**Templates** cap tickets; the **repo registry** holds hard per-repo limits; the **ledger**
records every commit signed per lease. Use these words in code, logs and docs.

## Hard rules

1. **Policy lives only in the daemon.** Clients (`writ`, `writ-sign`, the skill, a harness)
   are untrusted: a check in a client is a convenience, never the boundary. Client crates never
   depend on daemon crates ([dependency directions](docs/architecture/overview.md#dependency-directions),
   checked by `make check`).
2. **Fail closed.** No matching lease, more than one, sealed daemon, unparsable input, an
   unexpected state or any error → deny with a reason. Never add a default-allow path, a
   "dev mode" bypass in release builds, or a fallback that skips a check.
3. **Agents never hold remote credentials or signing keys.** No API, error message, log line or
   file written on an agent host may contain key material, tokens or the keystore passphrase.
   Secrets in memory are zeroized and never `Debug`-printed.
4. **Platform-agnostic core** ([platform.md](docs/architecture/platform.md)). Anything that
   depends on the OS, hardware or deployment goes behind an interface (`Signer`, `Transport`,
   `CallerAttestor`, `SessionWatcher`, `KeystoreUnwrap`, `Notifier`), implemented in
   `writ-signer` / `writ-platform*` and picked in `writd/src/platform.rs`. No code branches on
   the mode; no `#[cfg(target_os)]` elsewhere. A new platform feature is a new implementation
   (passing the interface's contract suite), never a change to the core. Need a seam that
   doesn't exist? Add the interface, its contract tests and docs first.
5. **Approvals are SSHSIG verifications**, namespace `writ-approval`, by a key in `approvers`,
   over the **canonical** ticket bytes. A click, a flag or a notification is never an approval.
   Narrowing must be a strict subset of what was submitted. Admin changes and unsealing need a
   signed approval too.
6. **Agent-written text is untrusted.** Title, task, plan and summary are displayed as-is
   (with terminal control sequences neutralized by `writ sign`) and never read by the policy
   engine. Only the structured scope is enforced, and always within a template.
7. **Never rewrite commits** (no trailer added or stripped): it changes the hash and breaks the
   signature. Sign at commit time, verify against the ledger at push time.
8. **Never touch personal keys.** Writ never reads, uses or lists Secretive's keys except the
   dedicated approval key, through `ssh-keygen -Y sign` in `writ sign` / `writ unseal`. Tests
   never use the real `~/.ssh`, git config or ssh-agent (only `make test-agent`, run by hand),
   and the repo never stores fixtures made from a real key.
9. **Everything is logged.** Every allow, deny, grant, refusal, revocation, admin change and
   seal/unseal writes one audit line ([audit log](docs/architecture/policy-and-state.md#audit-log));
   only floods are coalesced (denials per source before authentication; a lease's denials and
   its allowed connections per lease after), each one still counted in the log
   ([security](docs/security.md#grants-reductions-and-the-audit-log)).
10. **Remote-agnostic.** No remote-specific API in the core path (GitHub, Gitea, Forgejo… are
    reached through plain git over SSH or HTTPS).
11. **Rust:** no `unwrap()` / `expect()` / `panic!`, unchecked indexing, slicing or
    truncating casts outside tests (clippy denies them; `arithmetic_side_effects` too in
    `writ-core`, `writ-crypto`, `writ-proto`, `writ-git`, `writ-mirror`, `writ-gateway`);
    `thiserror` in library crates, `anyhow` only in
    binaries; `unsafe` denied except in a dedicated module with a `SAFETY` comment.
    `writ-core` stays pure (no I/O).
12. **Every guarantee has a test** that tries to break it ([guarantee tests](docs/testing.md#guarantee-tests)).
    A change that weakens a guarantee or adds a residual risk updates the
    [threat model](docs/threat-model.md) in the same change, and needs the user's go-ahead.
    **Tests are hardened** ([rules](docs/testing.md#hardened-tests)): deterministic (never
    `sleep` then assert, wait on a signal; no real clock where a fake fits; no fixed ports;
    property tests seeded) and adversarial (a denial asserts its exact code or error variant,
    never just `is_err()`; every limit tested on both sides; hostile input where input is
    untrusted). A test that can pass by luck is a bug.
13. **Respect the [non-goals](docs/product.md#non-goals)** (no tag signing, no generic secret
    proxying, no multi-user) unless explicitly asked.
14. **English everywhere** in code, comments, logs, messages and commits.
15. **Keep docs in sync:** a change to behavior, the lease model, the protocol or the
    architecture updates the matching page in `docs/` in the same change. The operator pages
    (`docs/operators/`) stay readable by a human: follow the
    [writing rules](docs/conventions.md#writing-operator-docs). A new decision gets a
    row at the end of the [decision log](docs/decisions.md); a new question goes under its open
    questions.
16. **Follow the [code conventions](docs/conventions.md)** (crate and module layout,
    interfaces and their implementations, errors, secrets, logging, visibility, tests). If a
    convention has to change, change the page in the same change.
17. **Follow the [security conventions](docs/security.md)** and answer its
    [security checklist](docs/security.md#the-security-checklist) for every change that
    touches an input, a grant or a read, the audit log, revocation, a secret, what people
    see, a dependency or a guarantee: in the commit message, and for a milestone on its
    history page. A new untrusted input joins the inventory there, with its bounds and a
    hostile-input test. `make check` enforces what a script can; review enforces the rest.
18. **Every command and flag is tested end to end.** Each command and flag of `writ`, `writd`
    and `writ-sign` is used for real by a scenario of the end-to-end pipeline (`make e2e`:
    the binaries in their own containers, a real Forgejo, the documented commands). A new
    one comes with its scenario and its row in the
    [coverage registry](docs/end-to-end.md#coverage-every-command-and-flag), in the same
    change (`make test` fails on a command or flag without a row, `make check` on a row
    without a scenario); [adding a scenario](docs/end-to-end.md#adding-a-scenario). A
    command a guide shows is the command the pipeline runs, checked both ways
    ([commands the docs show](docs/end-to-end.md#commands-the-docs-show): operator pages
    listed whole, never a marker in them).
19. **Every configuration key is documented and tested.** A key, value, default or bound
    added to or changed in `writd.yaml`, `policy.yaml` or the ticket file, or an environment
    variable a binary reads, updates its row in the [operator reference](docs/operators/README.md)
    and its file's template ([the five steps](docs/conventions.md#configuration-keys))
    and is set by an integration test or an end-to-end scenario that checks its effect, named
    in the [configuration coverage registry](docs/testing.md#configuration-coverage-every-key)
    (`planned: M<n>` while its effect is a later milestone's), in the same change (`make test`
    fails on a key without its rows, `make check` on a row naming no test).

## Definition of done

`make ci` passes (`make check`, then `make test`: unit and integration tests, and both
property-test passes), the [security checklist](docs/security.md#the-security-checklist) is
answered, and the milestone's acceptance items touched by the change were exercised for real:
as integration scenarios in `crates/writ-integration` (real `git`, real `ssh`, the daemon
running), as end-to-end scenarios when a binary's behavior changed (`make e2e` passes,
rule 18), plus the [manual checks](docs/guides/manual-checks.md) for what needs a human
(Touch ID). State in your summary what you ran.

## Commands

From the [Makefile](Makefile) (created in M0 by the [initialization guide](docs/guides/initialization.md#4-makefile)).

| Task | Command |
|---|---|
| Everything CI runs (`check` then `test`); on a clean working tree, a pass stamps the tree for the `pre-push` hook | `make ci` |
| `make ci` (skipped if it already passed on this tree), then `git push`; the way to push | `make push [ARGS="origin main"]` |
| Lint, format check, dependency directions, source rules, doc links, no test-only feature in the binaries, the guarantee, end-to-end and configuration registries, `cargo deny` | `make check` |
| Tests under `cargo-nextest`: unit and integration, property tests with the fixed seed; then `target/` pruned to the last builds | `make test` |
| Property tests with one seed (replay a failure; `random` is CI's pass) | `make test-props SEED=<number\|random>` |
| Approval signature with a key in your own ssh-agent (by hand; may ask for Touch ID) | `make test-agent KEY=<public key .pub> [AGENT=<socket>]` |
| The GitHub manual check as one command (by hand: Touch ID; a throwaway repo; `gh` optional) | `make github-check REPO=<owner>/<repo> [EMAIL=<verified email>]` |
| Pin the development daemon for the client (`dev/data/client/`), before the [manual checks](docs/guides/manual-checks.md) | `make dev-client` |
| Format | `make fmt` |
| Install the git hooks (`pre-push` allows only a tree `make ci` passed on) | `make hooks` |
| Run the development daemon on `dev/writd.yaml` (test keys in `dev/data`, your approval public key in `dev/approvers`; `writd host-key dev/writd.yaml` / `writd tls-fingerprint dev/writd.yaml` print what to pin) | `make run` |
| End-to-end scenarios: the binaries in containers against Forgejo, every command and flag (Docker; `ARGS=<filter>`, `WRIT_E2E_KEEP=1` keeps the stack) | `make e2e [ARGS=<scenario>]` |
| The wiping allocator's benchmark: `writd` with and without it under heavy load, in release (by hand; `LINUX=1` in a Linux container) | `make bench-alloc [RUNS=<n>] [LINUX=1]` |
| The guided installer (by hand: `sudo`): a setup to pick, every choice asked before anything changes; run again, it upgrades ([install](docs/operators/install.md)) | `make install` |
| Take the install back (the daemon's data kept unless `delete` is typed) | `make uninstall` |
| Build the Docker image (from M8) | `make docker` |
| Add a dependency | add its version to `[workspace.dependencies]` in the root `Cargo.toml`, then `dep.workspace = true` in the crate |

## Where to look

| If you are working on… | Read |
|---|---|
| What Writ is, the user story, scope v1, non-goals, principles | [docs/product.md](docs/product.md) |
| What comes next, acceptance checklists | [docs/roadmap.md](docs/roadmap.md) |
| Security conventions, the checklist for every change, untrusted inputs and their bounds | [docs/security.md](docs/security.md) |
| What was built, in order | [docs/history/](docs/history/README.md) |
| Ideas beyond v1 (LLM check, HTTP proxy, hardware signers, apps) | [docs/backlog/](docs/backlog/README.md) |
| Why something is the way it is, open questions | [docs/decisions.md](docs/decisions.md) |
| Attackers, trust boundaries, guarantees, residual risks | [docs/threat-model.md](docs/threat-model.md) |
| Tickets, leases, templates, repo registry, lifecycle (`writ-core`) | [docs/lease-model.md](docs/lease-model.md) |
| Which constraint is checked from what, and how far to trust it | [lease-model.md](docs/lease-model.md#constraints-and-how-much-to-trust-them) |
| Step-by-step sequences (sign, push, fetch, revoke, close, unseal) | [docs/flows.md](docs/flows.md) |
| Component map, crate layout, dependency rules | [docs/architecture/overview.md](docs/architecture/overview.md) |
| SSH gateway, mirrors, quarantine, upstream (`writ-gateway`, `writ-git`) | [docs/architecture/gateway.md](docs/architecture/gateway.md) |
| Policy engine, SQLite store, ledger, audit log (`writ-core`, `writ-store`) | [docs/architecture/policy-and-state.md](docs/architecture/policy-and-state.md) |
| Modes as configuration, platform traits, macOS/Linux implementations (`writ-platform*`, `writd/src/platform.rs`) | [docs/architecture/platform.md](docs/architecture/platform.md) |
| `Signer` trait, key backends, keystore, sealed start (`writ-signer`) | [docs/architecture/signer.md](docs/architecture/signer.md) |
| Secure Enclave on the Mac without a paid Apple account, the local daemon isolated from my user | [docs/architecture/macos-secure-enclave.md](docs/architecture/macos-secure-enclave.md) |
| Approver signatures, `writ sign` display, refusing, narrowing (`writ-approval`, `writ-crypto`) | [docs/architecture/approvals.md](docs/architecture/approvals.md) |
| Session keys, certificates, revocation, local mode process chain | [docs/architecture/identity.md](docs/architecture/identity.md) |
| `writ` CLI, `writ-sign`, the agent skill, agent host git config | [docs/architecture/clients.md](docs/architecture/clients.md) |
| Docker, compose, network exposure, host hardening, launchd | [docs/architecture/deployment.md](docs/architecture/deployment.md) |
| Setting the daemon up, every key of `writd.yaml`, `policy.yaml`, the ticket file and the clients' settings, good practice beside an agent | [docs/operators/](docs/operators/README.md) |
| Crates, external tool versions, pinning | [docs/stack.md](docs/stack.md) |
| Tests: levels, hardening rules, fixtures, guarantee tests, property-test seeds | [docs/testing.md](docs/testing.md) |
| End-to-end scenarios: running, the stack, the coverage registry, adding a scenario | [docs/end-to-end.md](docs/end-to-end.md) |
| Code conventions: crates, modules, errors, secrets, logging, docs | [docs/conventions.md](docs/conventions.md) |
| Bootstrapping an empty repo | [docs/guides/initialization.md](docs/guides/initialization.md) |
| Upgrading a crate, the toolchain, `cargo-deny` or a tool; answering an advisory | [docs/guides/dependency-upgrades.md](docs/guides/dependency-upgrades.md) |
