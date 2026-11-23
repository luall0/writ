# Writ documentation

Writ is a trust broker for AI agents. An agent drafts a ticket for its task (repos, branches,
operations, limits); I sign it with an approver key, and the signed ticket becomes a scoped,
time-boxed lease. The daemon `writd` holds the agent signing keys and the credentials for
the remotes (GitHub, Codeberg, Forgejo…), is the agents' git remote, and is the only thing
allowed to push upstream.

Agents working in this repo: start with [`AGENTS.md`](../AGENTS.md). It holds the naming
conventions, hard rules and commands, and points here for details.

## Product
- [Product overview](product.md): problem, goal, user story, deployment modes, scope v1,
  non-goals and design principles.
- [Threat model](threat-model.md): actors, assets, trust boundaries, what Writ guarantees
  (and the tests that try to break each guarantee) and what it doesn't, residual risks.
- [Security conventions](security.md): the rules every change follows, the security
  checklist, the untrusted inputs and their bounds, how each rule is enforced.
- [Backlog](backlog/README.md): what could come next (v1 is complete), each idea's design and
  acceptance checklist, and how one becomes work.
- [History](history/README.md): what was built, in order.
- [Changelog](../CHANGELOG.md): what changed in each release, and what an upgrade asks.
- [Decisions](decisions.md): decision log (Q1–Q32) and open questions.

## Operators
- [Operators](operators/README.md): running Writ. [Setting up the daemon](operators/setup.md);
  every setting, with its default, bounds and status: [`writd.yaml`](operators/writd-yaml.md),
  [`policy.yaml`](operators/policy-yaml.md) (registry and templates),
  [the ticket file](operators/ticket.md), [client settings](operators/clients.md);
  [good practice](operators/good-practice.md) beside an agent (wrapper or whole repo, your own
  keys, guardrails, checking what landed); [installing](operators/install.md) on a Mac or
  Linux host, [daily operations](operators/sealing.md) (unsealing, policy changes, tokens,
  the recovery key, auto-unseal), [hardening](operators/hardening.md) the daemon's process,
  and [recovery](operators/recovery.md) when every approval key is lost.

## Domain
- [Lease model](lease-model.md): repo registry, templates, ticket / lease schema, trust of
  each constraint, lifecycle, rules.
- [Flows](flows.md): ticket submit/sign/refuse, signed commit, push, fetch, revoke,
  out-of-ticket, close, sealed startup.

## Architecture
- [Overview](architecture/overview.md): deployment modes, component map, repository layout
  and dependency directions.
- [Gateway, mirrors and upstream](architecture/gateway.md): SSH gateway, mirrors, upstream
  pusher, URL rewrite.
- [Policy, state and audit](architecture/policy-and-state.md): policy engine, lease store and
  ledger, audit log.
- [Platform interfaces](architecture/platform.md): the platform-agnostic core, its interfaces
  (`Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnwrap`, `Notifier`), where the
  macOS and Linux implementations live, modes as configuration presets.
- [macOS Secure Enclave](architecture/macos-secure-enclave.md): Secure Enclave keys for
  local mode without a paid Apple account, plans A to E, and the daemon isolated from my user.
- [Signer and sealing](architecture/signer.md): `Signer` trait, backends, encrypted keystore,
  sealed start.
- [Approvals](architecture/approvals.md): SSHSIG approvals, `writ sign` as trusted display,
  refusing, narrowing.
- [Identity](architecture/identity.md): session keys and daemon-issued certificates, local
  mode process chain checks.
- [Clients](architecture/clients.md): `writ` CLI, agent skill, `writ-sign`, harness, git config of an agent host.
- [Deployment](architecture/deployment.md): Docker compose, network exposure, host hardening.

## Engineering
- [Stack](stack.md): technology choices (decided and proposed), external tools, pinning.
- [End-to-end scenarios](end-to-end.md): `make e2e`, the stack, the scenarios, the rule that
  every command and flag has one (its registry), and how to add a scenario.
- [Testing](testing.md): the three levels (unit, integration, end to end), the hardened-test
  rules, property-test seeds, what to test in each crate, guarantee tests.
- [Code conventions](conventions.md): crate and module layout, interfaces and their
  implementations, errors, secrets, logging, visibility, docs.
- [Project initialization](guides/initialization.md): one-time bootstrap of the Cargo
  workspace (run only on an empty repo).
- [Upgrading dependencies](guides/dependency-upgrades.md): crates, coupled pins, the
  toolchain, `cargo-deny`, external tools and the Unicode table; what to read, check, test
  and write down; answering an advisory.
- [Manual checks](guides/manual-checks.md): the checks that need a person (Touch ID with
  Secretive), step by step against the development daemon.
- [Manual checks with a real agent](guides/manual-checks-e2e.md): a real agent on a throwaway
  GitHub repository, prompts that never mention Writ: one task with one Touch ID, then a
  refusal, an amendment and a renewal (M6).
