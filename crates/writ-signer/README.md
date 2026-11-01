# writ-signer

The `Signer` interface: where the daemon's keys live and how they sign, so nothing else
depends on the backend.

## What it does

- **The trait** (`lib`): `list_keys`, `sign` (raw bytes in, an SSH signature out; the caller
  builds what is signed), `capabilities`; `sshsig` builds an SSHSIG through any backend.
- **The software backend** (`software`): Ed25519 and P-256 keys in memory, wiped on drop, moved
  in by whoever loaded them (the daemon's keystore); never printed.
- With the `testing` feature: the contract suite every backend runs (`contract`) and a signer
  that refuses on demand (`testing::FailingSigner`).

## Scope

- Keys and signatures only. Which key signs what is the policy's (templates' `signing_key`),
  applied by the approval service.
- Not here: the keystore at rest (`writd`, sealed in M5), platform-only backends (the Secure
  Enclave in `writ-platform-macos`, M7.5).

## Depends on

`writ-core` (key ids), `writ-crypto` (SSHSIG, keys).

## Docs

[Signer and sealing](../../docs/architecture/signer.md),
[Platform interfaces](../../docs/architecture/platform.md).
