# Stack

**Rust core** (decided, [Q9](decisions.md)): one codebase for the Linux container and the
native Mac build. Swift only where the Secure Enclave needs it (CryptoKit, M7.5) and for the
later approver apps.

| Layer | Choice | Status |
|---|---|---|
| Language | Rust 1.99.1 (pinned), edition 2024, Cargo workspace | Decided |
| SSH server and client | `russh` 0.65, `ring` backend, without `flate2` (no compression); the gateway lists its algorithms explicitly (mlkem768x25519 or curve25519 with strict kex, chacha20-poly1305 or aes256-gcm, Ed25519 and P-256 keys) | Decided (M0: certificate auth, TCP and Unix socket; algorithms M2.6) |
| SSH keys, certificates, SSHSIG | `ssh-key` =0.7.0-rc.11 (the exact version russh pins) | Decided (M0: SSHSIG both ways with OpenSSH, ed25519 and P-256) |
| Git | Shell out to `git` (`upload-pack`, `receive-pack`, `index-pack`, `rev-list`); parse commit and tree objects an agent sends in Rust (`writ-git`, tested against the real `git`) | Decided |
| Git object ids | `sha1-checked` 0.10 (SHA-1 with collision detection, the `sha1dc` algorithm git uses; RustCrypto) and `sha2` (SHA-256, already in the tree): ids of objects an agent sends are computed, never taken | Decided (M3) |
| Leases + ledger | SQLite | Decided |
| Audit log | JSONL, append-only | Decided |
| Keystore | age format | Decided |
| Notifications | Behind the `Notifier` trait; v1: Telegram Bot API (`sendMessage`, plain text) over `ureq` 3, with no proxy (ureq's default would take one from the environment) and no redirects | Decided (M2) |
| Async runtime | `tokio` | Decided (M0) |
| SQLite access | `rusqlite` 0.41 (bundled SQLite) | Decided (M1) |
| age | `age` 0.11 (0.12 pulls `ml-kem` 0.2, whose `kem` pre-release conflicts with russh 0.65's) | Decided (M2) |
| Approval API | The gateway's SSH protocol on its own listener (`russh`), and HTTPS (`hyper` 1 + `rustls` 0.23 with `ring`, `tokio-rustls`; self-signed certificate from `rcgen`); clients pin the host key or the certificate ([Q29](decisions.md)); reader keys as client certificates, parsed with `rustls-webpki` 0.103 (rustls's own parser, no new code in the tree) | Decided (M2; readers M2.6) |
| Config | `serde` + `serde-saphyr` 2 (YAML, duplicate keys refused) + `serde_path_to_error` (errors name the field) | Decided (M1): `serde_yaml` is deprecated |
| CLI | `clap` 4 (derive, env) | Decided (M2) |
| Errors | `thiserror` in library crates, `anyhow` only in binaries | Decided (M0) |
| Secrets in memory | `zeroize` (decided in M2); `secrecy` | Proposed |
| Unix file checks | `rustix` 1.1 (`fs`, `process`): opening without following a link or blocking, the effective uid, for the private-file and authority-file checks (`writ_platform::fs`); safe wrappers, so no `unsafe` in the tree, and already a dependency of `tempfile` | Decided (M2.6) |
| Logging | `tracing` 0.1 in every library crate, `tracing-subscriber` 0.3 (`fmt`, `env-filter`) installed by `writd` only, to stderr, filtered by `WRIT_LOG`; the audit log is separate and never goes through it | Decided (M2.5) |
| Secure Enclave (local mode) | Swift + CryptoKit, key blob under the `_writd` user | Decided (M0 spike, [Q33](decisions.md)); how `writd` calls it is settled in M7.5 |
| Tests | `proptest` for policy properties, `tempfile`, real `git` and `ssh-keygen` binaries | Decided (M1) |
| Time | `jiff` (no default features): RFC 3339 for timestamps; the policy never reads a clock | Decided (M1) |
| Globs | `globset` for `expected_paths` | Decided (M1) |
| Canonical encoding | `serde_json`, compact, fixed field order ([lease model](lease-model.md#canonical-encoding)) | Decided (M1) |

Settle each "Proposed" row when the milestone that needs it starts, and change it to
"Decided" here ([Q28](decisions.md#open-questions)).

## External tools

| Tool | Minimum | Why |
|---|---|---|
| `git` | 2.34 on agent hosts (M0 ran 2.54); 2.45 on the daemon host, 2.47 with an `https://` upstream, checked at startup; 2.47 for the integration tests | SSH commit signing (`gpg.format = ssh`); the daemon's mirrors: reftable (2.45), `fetch --porcelain` (2.41); HTTPS upstreams: a SOCKS proxy on a Unix socket in `http.proxy` (2.47 keeps its path) |
| OpenSSH (`ssh`, `ssh-keygen`) | 8.9 (M0 ran 10.5) | `-Y sign/verify`, certificates, `session-bind` (direct_ssh); the daemon's ssh to upstream (`mirrors.ssh`) |
| Docker + compose | recent | Detached mode (M8); `make e2e` ([end-to-end](end-to-end.md)): its images and Forgejo `13.0.5` are pinned by digest in `e2e/Dockerfile` (`rust:1.99.1-slim-trixie`, `debian:trixie-slim`: git 2.47, OpenSSH 10.0) and `e2e/compose.yaml` (`codeberg.org/forgejo/forgejo:13.0.5`) |
| Secretive | any | v1 approver key (Mac) |

Versions used in M0 are in its [history page](history/m0-protocol-spike.md#versions).

## Version pinning

- Rust toolchain from **rustup**, pinned to an exact version by `rust-toolchain.toml`
  (`1.99.1` with `rustfmt` and `clippy`); moving it is a change of its own.
- Every build is `--locked`: what is built is `Cargo.lock`, never a fresh resolution.
- `cargo-deny` 0.20.2 (`make check`, `deny.toml`): RustSec advisories and yanked crates
  refused (two compile-time-only ones accepted, each with its reason), crates.io as the only
  source, a license allow-list, banned crates (`openssl`, `native-tls`, `rsa`, `log`
  bridges). Installed with `cargo install --locked cargo-deny --version 0.20.2`.
- Release builds keep overflow checks (`[profile.release] overflow-checks = true`).
- Dependency versions declared once in the root `Cargo.toml` (`[workspace.dependencies]`);
  crates use `dep.workspace = true`.
- `Cargo.lock` is committed (binaries).
- How to move any of these: [dependency upgrades](guides/dependency-upgrades.md).
