# Stack

**Rust core** (decided, [Q9](decisions.md)): one codebase for the Linux container and the
native Mac build. Swift only for the later Secure Enclave signer/approver app.

| Layer | Choice | Status |
|---|---|---|
| Language | Rust stable, edition 2024, Cargo workspace | Decided |
| SSH server and client | `russh` | Decided (M0 verifies certificate auth) |
| SSH keys, certificates, SSHSIG | `ssh-key` | Decided (M0 verifies Secretive's ECDSA P-256 signatures) |
| Git | Shell out to `git` (`upload-pack`, `receive-pack`, `index-pack`, `rev-list`); parse commit objects in Rust | Decided |
| Leases + ledger | SQLite | Decided |
| Audit log | JSONL, append-only | Decided |
| Keystore | age format | Decided |
| Notifications | ntfy | Decided |
| Async runtime | `tokio` | Proposed ([Q28](decisions.md#open-questions)) |
| SQLite access | `rusqlite` (bundled SQLite) | Proposed |
| age | `age` crate | Proposed |
| Approval API | `axum` + `rustls` | Proposed |
| Config | `serde` + `serde_yaml` | Proposed |
| CLI | `clap` (derive) | Proposed |
| Errors | `thiserror` in library crates, `anyhow` only in binaries | Proposed |
| Secrets in memory | `zeroize` / `secrecy` | Proposed |
| Logging | `tracing` (the audit log is separate and never goes through it) | Proposed |
| Tests | `proptest` for policy properties, `tempfile`, real `git` and `ssh-keygen` binaries | Proposed |

Settle the "Proposed" rows in M0 and change them to "Decided" here, with a row in the
[decision log](decisions.md).

## External tools

| Tool | Minimum | Why |
|---|---|---|
| `git` | 2.34 | SSH commit signing (`gpg.format = ssh`) |
| OpenSSH (`ssh`, `ssh-keygen`) | 8.9 | `-Y sign/verify`, certificates, `session-bind` (direct_ssh) |
| Docker + compose | recent | Detached mode (M8), test forge (M4) |
| Secretive | any | v1 approver key (Mac) |

Verify each version in M0 and update this table.

## Version pinning

- Rust toolchain from **rustup**, pinned by `rust-toolchain.toml` (`stable` with `rustfmt`
  and `clippy`).
- Dependency versions declared once in the root `Cargo.toml` (`[workspace.dependencies]`);
  crates use `dep.workspace = true`.
- `Cargo.lock` is committed (binaries).
