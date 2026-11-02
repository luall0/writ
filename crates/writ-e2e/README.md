# writ-e2e

Test-only: the end-to-end scenarios. `make e2e` builds the real Linux binaries into their own
containers (`e2e/`), starts a real Forgejo beside them, and runs these scenarios in a runner
container that drives the others. Nothing depends on this crate (checked).

## What it does

- **The harness** (`src/`): the stack's containers reached with `docker exec` ([`docker`]),
  Forgejo's API and its web forms ([`forgejo`]), the operator setup run once from nothing as
  the operator guide says it ([`setup`]), shared and exclusive use of the stack ([`stack`]),
  the agents and the approver ([`agent`]).
- **The scenarios** (`tests/scenarios/`): one module per scenario, one Forgejo repository per
  scenario, every command and flag of `writ`, `writd` and `writ-sign` covered (the registry in
  [docs/end-to-end.md](../../docs/end-to-end.md#coverage-every-command-and-flag), checked by
  `make check` and `make test`).

## Scope

- Only through what a person or an agent would use: the binaries, git, ssh, Forgejo's API
  and web forms, the daemon's files as the operator reads them. Nothing in-process.
- The scenarios are `#[ignore]`d: `cargo test` compiles them, only the pipeline runs them
  (`scenarios --ignored`, in the runner container).

## Docs

[End-to-end scenarios](../../docs/end-to-end.md) (how to run, debug and add one),
[testing](../../docs/testing.md).
