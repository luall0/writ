# writd

The daemon binary: reads the configuration, builds the platform implementations, wires the
crates together and runs them.

## What it does

- `writd init <writd.yaml>`: makes the sealed keystore, once (asks for its passphrase).
- `writd run <writd.yaml>`: the daemon (gateway listeners, approval API, expiry timer).
- `writd host-key <writd.yaml>` / `writd tls-fingerprint <writd.yaml>`: what clients pin.
- `writd hook pre-receive`: the program git's pre-receive hook runs.
- `config`: `writd.yaml`, parsed strictly. `platform`: the implementations it names (the only
  place allowed `#[cfg(target_os)]`). `keystore`: the daemon's keys, from the sealed keystore
  (one age file per secret, opened through one seam, and the boot tier) or the development
  keystore (refused by release builds).
- Logs: `tracing` to stderr, filtered by `WRIT_LOG`. The audit log is separate.
- Its global allocator is `writ_alloc::Wiping`: every block zeroed when it is freed. The
  `system-allocator` feature (the plain system allocator) is the benchmark's baseline only,
  never in a shipped build.

## Scope

- Wiring and configuration only: no policy, no protocol.
- The only crate that reads configuration and picks implementations.

## Depends on

Every library crate of the workspace.

## Docs

[Deployment](../../docs/architecture/deployment.md),
[Platform interfaces](../../docs/architecture/platform.md),
[Signer and sealing](../../docs/architecture/signer.md).
