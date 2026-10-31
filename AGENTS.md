# AGENTS.md — Writ

Writ is a trust broker for AI agents. An agent drafts a **ticket** for its task (repos,
branches, operations, limits, plan); I sign it with an approver key (Secretive, Touch ID), and
the signed ticket becomes a scoped, time-boxed **lease**. The daemon `writd` holds the agent
signing keys and the forge credentials, is the agents' git remote, checks every signature and
push against the lease, and is the only thing that pushes upstream. Rust; detached mode
(Docker on Linux) and local mode (native on the Mac), same protocol.

Full documentation lives in [`docs/`](docs/README.md). This file holds what every agent must
know before touching the repo.

## Project status

If the repo has no `Cargo.toml` yet, the project is not initialized: follow
[docs/guides/initialization.md](docs/guides/initialization.md) first.

Work follows the [roadmap](docs/roadmap.md) **strictly in order**, M0 to M10; each milestone
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
| git signing shim (`gpg.ssh.program`) | `writ-sign` |
| Crates | `writ-<part>` under `crates/` ([layout](docs/architecture/overview.md#repository-layout-planned)); platform-only code in `writ-platform-<os>` |
| Lease / ticket ids | `wrt_` + ULID (e.g. `wrt_01JD8X…`) |
| Approval SSHSIG namespace | `writ-approval` |
| Commit trailer (`ticket_link: trailer`) | `Writ: wrt_…` |
| Git notes ref (`ticket_link: notes`) | `refs/notes/writ` |
| Git remote on agent hosts | `writ` |
| Agent host session files | `~/.writ/sessions/<lease>/` (`current` → active one) |
| Daemon data (container) | `/var/lib/writ/` (keystore in `/var/lib/writ/keys/`) |
| Ports (detached) | `2222` gateway (SSH, agents), `2223` approval API (SSH), `8443` approval API (HTTPS); each approval transport can be disabled, not both |
| SSH users | `git` (lease holders, with a certificate), `writ` (ticket submission and the approval API, with a plain key) |
| Client files | `~/.writ/known_hosts` (the daemon's pinned host key), `~/.writ/tls_pins` (its pinned TLS certificate), `~/.writ/approver.pub` |
| Env vars | `WRIT_*` |
| Agent skill | `skill/writ/SKILL.md` |

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
3. **Agents never hold forge credentials or signing keys.** No API, error message, log line or
   file written on an agent host may contain key material, tokens or the keystore passphrase.
   Secrets in memory are zeroized and never `Debug`-printed.
4. **Platform-agnostic core** ([platform.md](docs/architecture/platform.md)). Anything that
   depends on the OS, hardware or deployment goes behind an interface (`Signer`, `Transport`,
   `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock`, `Notifier`), implemented in
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
   seal/unseal writes one audit line ([audit log](docs/architecture/policy-and-state.md#audit-log)).
10. **Forge-agnostic.** No forge-specific API in the core path (GitHub, Gitea, Forgejo… are
    reached through plain git over SSH or HTTPS).
11. **Rust:** no `unwrap()` / `expect()` / `panic!` outside tests; `thiserror` in library
    crates, `anyhow` only in binaries; `unsafe` denied except in a dedicated module with a
    `SAFETY` comment. `writ-core` stays pure (no I/O).
12. **Every guarantee has a test** that tries to break it ([guarantee tests](docs/testing.md#guarantee-tests)).
    A change that weakens a guarantee or adds a residual risk updates the
    [threat model](docs/threat-model.md) in the same change, and needs the user's go-ahead.
13. **Respect the [non-goals](docs/product.md#non-goals)** (no GPG, no tag signing, no generic
    secret proxying, no multi-user) unless explicitly asked.
14. **English everywhere** in code, comments, logs, messages and commits.
15. **Keep docs in sync:** a change to behavior, the lease model, the protocol or the
    architecture updates the matching page in `docs/` in the same change. A new decision gets a
    row at the end of the [decision log](docs/decisions.md); a new question goes under its open
    questions.

## Definition of done

`make check` passes, `make test` passes, and the milestone's acceptance items touched by the
change were exercised for real (real `git`, real `ssh`, the daemon running). State in your
summary what you ran.

## Commands

From the [Makefile](Makefile) (created in M0 by the [initialization guide](docs/guides/initialization.md#4-makefile)).

| Task | Command |
|---|---|
| Lint, format check, dependency directions | `make check` |
| Tests | `make test` |
| Approval signature with a key in your own ssh-agent (by hand; may ask for Touch ID) | `make test-agent KEY=<public key .pub> [AGENT=<socket>]` |
| Pin the development daemon for the client (`dev/data/client/`), before the [manual checks](docs/guides/manual-checks.md) | `make dev-client` |
| Format | `make fmt` |
| Run the development daemon on `dev/writd.yaml` (test keys in `dev/data`, your approval public key in `dev/approvers`; `writd host-key dev/writd.yaml` / `writd tls-fingerprint dev/writd.yaml` print what to pin) | `make run` |
| End-to-end scenarios against the test forge (Docker, from M4) | `make e2e` |
| Build the Docker image (from M8) | `make docker` |
| Add a dependency | add its version to `[workspace.dependencies]` in the root `Cargo.toml`, then `dep.workspace = true` in the crate |

## Where to look

| If you are working on… | Read |
|---|---|
| What Writ is, the user story, scope v1, non-goals, principles | [docs/product.md](docs/product.md) |
| What comes next, acceptance checklists | [docs/roadmap.md](docs/roadmap.md) |
| What was built, in order | [docs/history/](docs/history/README.md) |
| Ideas beyond v1 (LLM check, HTTP proxy, hardware signers, apps) | [docs/backlog/](docs/backlog/README.md) |
| Why something is the way it is, open questions | [docs/decisions.md](docs/decisions.md) |
| Attackers, trust boundaries, guarantees, residual risks | [docs/threat-model.md](docs/threat-model.md) |
| Tickets, leases, templates, repo registry, lifecycle (`writ-core`) | [docs/lease-model.md](docs/lease-model.md) |
| Which constraint is checked from what, and how far to trust it | [lease-model.md](docs/lease-model.md#constraints-and-how-much-to-trust-them) |
| Step-by-step sequences (sign, push, fetch, revoke, close, unseal) | [docs/flows.md](docs/flows.md) |
| Component map, crate layout, dependency rules | [docs/architecture/overview.md](docs/architecture/overview.md) |
| SSH gateway, mirrors, quarantine, upstream, push modes (`writ-gateway`, `writ-git`) | [docs/architecture/gateway.md](docs/architecture/gateway.md) |
| Policy engine, SQLite store, ledger, audit log (`writ-core`, `writ-store`) | [docs/architecture/policy-and-state.md](docs/architecture/policy-and-state.md) |
| Modes as configuration, platform traits, macOS/Linux implementations (`writ-platform*`, `writd/src/platform.rs`) | [docs/architecture/platform.md](docs/architecture/platform.md) |
| `Signer` trait, key backends, keystore, sealed start (`writ-signer`) | [docs/architecture/signer.md](docs/architecture/signer.md) |
| Secure Enclave on the Mac without a paid Apple account, the local daemon isolated from my user | [docs/architecture/macos-secure-enclave.md](docs/architecture/macos-secure-enclave.md) |
| Approver signatures, `writ sign` display, refusing, narrowing (`writ-approval`, `writ-crypto`) | [docs/architecture/approvals.md](docs/architecture/approvals.md) |
| Session keys, certificates, revocation, local mode process chain | [docs/architecture/identity.md](docs/architecture/identity.md) |
| `writ` CLI, `writ-sign`, the agent skill, `writ try`, agent host git config | [docs/architecture/clients.md](docs/architecture/clients.md) |
| Docker, compose, network exposure, host hardening, launchd | [docs/architecture/deployment.md](docs/architecture/deployment.md) |
| Crates, external tool versions, pinning | [docs/stack.md](docs/stack.md) |
| Tests, fixtures, guarantee tests | [docs/testing.md](docs/testing.md) |
| Bootstrapping an empty repo | [docs/guides/initialization.md](docs/guides/initialization.md) |
