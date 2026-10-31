# Stack

**Rust core** (decided, [Q9](decisions.md)): one codebase for the Linux container and the
native Mac build. Swift only where the Secure Enclave needs it (CryptoKit, an app bundle with
a provisioning profile: settled by the M0 spike) and for the later approver apps.

| Layer | Choice | Status |
|---|---|---|
| Language | Rust stable, edition 2024, Cargo workspace | Decided |
| SSH server and client | `russh` 0.65, `ring` backend | Decided (M0: certificate auth, TCP and Unix socket) |
| SSH keys, certificates, SSHSIG | `ssh-key` =0.7.0-rc.11 (the exact version russh pins) | Decided (M0: SSHSIG both ways with OpenSSH, ed25519 and P-256) |
| Git | Shell out to `git` (`upload-pack`, `receive-pack`, `index-pack`, `rev-list`); parse commit objects in Rust | Decided |
| Leases + ledger | SQLite | Decided |
| Audit log | JSONL, append-only | Decided |
| Keystore | age format | Decided |
| Notifications | ntfy | Decided |
| Async runtime | `tokio` | Decided (M0) |
| SQLite access | `rusqlite` (bundled SQLite) | Proposed |
| age | `age` crate | Proposed |
| Approval API | `axum` + `rustls` | Proposed |
| Config | `serde` + `serde_yaml` | Proposed |
| CLI | `clap` (derive) | Proposed |
| Errors | `thiserror` in library crates, `anyhow` only in binaries | Decided (M0) |
| Secrets in memory | `zeroize` / `secrecy` | Proposed |
| Logging | `tracing` (the audit log is separate and never goes through it) | Proposed |
| Secure Enclave (local mode) | Swift + CryptoKit or the Security framework; Xcode Personal Team for Plan A | To decide in the M0 spike ([macOS Secure Enclave](architecture/macos-secure-enclave.md)) |
| Tests | `proptest` for policy properties, `tempfile`, real `git` and `ssh-keygen` binaries | Proposed |

Settle each "Proposed" row when the milestone that needs it starts, and change it to
"Decided" here ([Q28](decisions.md#open-questions)).

## External tools

| Tool | Minimum | Why |
|---|---|---|
| `git` | 2.34 (M0 ran 2.54) | SSH commit signing (`gpg.format = ssh`) |
| OpenSSH (`ssh`, `ssh-keygen`) | 8.9 (M0 ran 10.5) | `-Y sign/verify`, certificates, `session-bind` (direct_ssh) |
| Docker + compose | recent | Detached mode (M8), test forge (M4) |
| Secretive | any | v1 approver key (Mac) |

Versions used in M0 are in its [notes](roadmap.md#versions).

## Version pinning

- Rust toolchain from **rustup**, pinned by `rust-toolchain.toml` (`stable` with `rustfmt`
  and `clippy`).
- Dependency versions declared once in the root `Cargo.toml` (`[workspace.dependencies]`);
  crates use `dep.workspace = true`.
- `Cargo.lock` is committed (binaries).
