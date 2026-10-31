# Writ documentation

Writ is a trust broker for AI agents. An agent drafts a ticket for its task (repos, branches,
operations, limits); I sign it with an approver key, and the signed ticket becomes a scoped,
time-boxed lease. The daemon `writd` holds the agent signing keys and the forge credentials,
is the agents' git remote, and is the only thing allowed to push upstream.

Agents working in this repo: start with [`AGENTS.md`](../AGENTS.md). It holds the naming
conventions, hard rules and commands, and points here for details.

## Product
- [Product overview](product.md): problem, goal, user story, deployment modes, scope v1,
  non-goals and design principles.
- [Threat model](threat-model.md): actors, assets, trust boundaries, what Writ guarantees and
  what it doesn't, residual risks.
- [Roadmap](roadmap.md): milestones M0–M10 to v1, in order, with acceptance checklists.
- [Backlog](backlog/README.md): ideas beyond v1 and how one becomes work.
- [History](history/README.md): what was built, in order.
- [Decisions](decisions.md): decision log (Q1–Q30) and open questions.

## Domain
- [Lease model](lease-model.md): repo registry, templates, ticket / lease schema, trust of
  each constraint, lifecycle, rules.
- [Flows](flows.md): ticket submit/sign/refuse, signed commit, push (`gateway`, `proxy`,
  `direct_ssh`), fetch, revoke, out-of-ticket, close, sealed startup.

## Architecture
- [Overview](architecture/overview.md): deployment modes, component map, planned repository
  layout and dependency directions.
- [Gateway, mirrors and upstream](architecture/gateway.md): SSH gateway, mirrors, upstream
  pusher, push modes, URL rewrite.
- [Policy, state and audit](architecture/policy-and-state.md): policy engine, lease store and
  ledger, audit log.
- [Platform interfaces](architecture/platform.md): the platform-agnostic core, its interfaces
  (`Transport`, `CallerAttestor`, `SessionWatcher`, `KeystoreUnlock`, `Notifier`), where the
  macOS and Linux implementations live, modes as configuration presets.
- [Signer and sealing](architecture/signer.md): `Signer` trait, backends, encrypted keystore,
  sealed start.
- [Approvals](architecture/approvals.md): SSHSIG approvals, `writ sign` as trusted display,
  refusing, narrowing.
- [Identity](architecture/identity.md): session keys and daemon-issued certificates, local
  mode process chain checks.
- [Clients](architecture/clients.md): `writ` CLI, agent skill, `writ-sign`, `writ try`,
  harness, git config of an agent host.
- [Deployment](architecture/deployment.md): Docker compose, network exposure, host hardening.

## Engineering
- [Stack](stack.md): technology choices (decided and proposed), external tools, pinning.
- [Testing](testing.md): what to test in each crate, guarantee tests.
- [Project initialization](guides/initialization.md): one-time bootstrap of the Cargo
  workspace (run only on an empty repo).
