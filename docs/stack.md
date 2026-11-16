# Stack

**Rust core** (decided, [Q9](decisions.md)): one codebase for the Linux container and the
native Mac build. Swift only where the Secure Enclave needs it (CryptoKit, M7.5), for the
approval popup's window (SwiftUI in an AppKit panel, M7.8: it shows what `writ sign --ui`
sends and does nothing else) and for the later approver apps.

| Layer | Choice | Status |
|---|---|---|
| Language | Rust 1.99.1 (pinned), edition 2024, Cargo workspace | Decided |
| SSH server and client | `russh` 0.65 (0.65.2), `ring` backend, without `flate2` (no compression); the gateway lists its algorithms explicitly (mlkem768x25519 or curve25519 with strict kex, chacha20-poly1305 or aes256-gcm, Ed25519 and P-256 keys) | Decided (M0: certificate auth, TCP and Unix socket; algorithms M2.6) |
| SSH keys, certificates, SSHSIG | `ssh-key` =0.7.0-rc.12 (the exact version russh 0.65.2 pins) | Decided (M0: SSHSIG both ways with OpenSSH, ed25519 and P-256) |
| Git | Shell out to `git` (`upload-pack`, `receive-pack`, `index-pack`, `rev-list`); parse commit and tree objects an agent sends in Rust (`writ-git`, tested against the real `git`) | Decided |
| Git object ids | `sha1-checked` 0.10 (SHA-1 with collision detection, the `sha1dc` algorithm git uses; RustCrypto) and `sha2` (SHA-256, already in the tree): ids of objects an agent sends are computed, never taken | Decided (M3) |
| Leases + ledger | SQLite | Decided |
| Audit log | JSONL, append-only | Decided |
| Keystore | age format | Decided |
| Notifications | Behind the `Notifier` trait; v1: Telegram Bot API (`sendMessage`, plain text) over `ureq` 3, with no proxy (ureq's default would take one from the environment) and no redirects; its features `default-features = false, features = ["rustls"]` only: no gzip (`flate2` stays out of `writd`, as M2.6 decided), and the TLS roots it trusts are its bundled Mozilla set (`webpki-roots`), never the system's: the Bot API is reached on the web PKI wherever the daemon runs | Decided (M2) |
| Async runtime | `tokio` | Decided (M0) |
| SQLite access | `rusqlite` 0.41 (bundled SQLite) | Decided (M1) |
| age | `age` 0.11 (0.12 pulls `ml-kem` 0.2, written for the `kem` pre-release: against the stable `kem` 0.3 russh 0.65's `ml-kem` 0.3 takes, it doesn't build; retried with russh 0.65.2); `bech32` 0.9 (age's own encoding of the keystore's X25519 identity from the 32-byte data key) and `age-core` 0.11 (the stanza and file key types of the keystore's ways, `writ-platform`; age's HKDF and ChaCha20-Poly1305 for the `piv-p256` stanza, `writ-crypto`, M7.6), both already in the tree through `age`; `p256` =0.14.0 with `ecdh` for `piv-p256` (in the tree through `ssh-key`) | Decided (M2; M5; M7.6) |
| Approval API | The gateway's SSH protocol on its own listener (`russh`), and HTTPS (`hyper` 1 + `rustls` 0.23 with `ring`, `tokio-rustls`; self-signed certificate from `rcgen`); clients pin the host key or the certificate ([Q29](decisions.md)); reader keys as client certificates, parsed with `rustls-webpki` 0.103 (rustls's own parser, no new code in the tree) | Decided (M2; readers M2.6) |
| Config | `serde` + `serde-saphyr` 2 (YAML, duplicate keys refused (whatever their YAML form: `1`, `"1"` and `!!str 1` are one key)) + `serde_path_to_error` (errors name the field) | Decided (M1): `serde_yaml` is deprecated |
| CLI | `clap` 4 (derive, env) | Decided (M2) |
| Shell completion | `clap_complete` `=4.6.9` (`unstable-dynamic`: the dynamic engine, `writ` answering each TAB; exempt from semver, so pinned exactly and each shell's registration run for real in a test; brings `is_executable`) | Decided (M7.9.9) |
| Guided prompts | `inquire` 0.9 (`crossterm` only: no fuzzy matcher, a typed answer filters by plain substring) in `writ` only: select, multi-select, validated text, confirm; the plain line prompts kept without a terminal; never a secret (`writ_crypto::passphrase`) | Decided (M7.9.5, with the user) |
| Errors | `thiserror` in library crates, `anyhow` only in binaries | Decided (M0) |
| OpenPGP signatures (M5.5) | A minimal v4 writer in `writ-crypto` (packets, certificate, detached signatures, armor); not `pgp` (rPGP depends on the banned `rsa` crate), never `sequoia-openpgp` (LGPL) | Decided (M5.5 plan) |
| RSA keys (M5.5) | `aws-lc-rs` 1.19 (`aws-lc-sys`, `alloc`, `ring-io`; ISC and Apache-2.0), for RSA only: generation, PKCS#8, constant-time PKCS#1 v1.5 signing and verification. Its C and assembly are built by cargo (a C compiler; no CMake needed on Linux and macOS). The `rsa` crate stays banned (Marvin). `p384` (through `ssh-key`'s `p384` feature) for P-384 | Decided (M5.5) |
| Secrets in memory | `zeroize` (decided in M2); `secrecy` not needed (M5: `zeroize` and age's own secret types cover the keystore) | Decided (M2; M5) |
| Memory wiped on free | Writ's own `writ-alloc` (no dependency): the system allocator, each block zeroed on free behind a compiler barrier, `realloc` as a new block and a wiped free. Not `zeroizing-alloc` (1Password's example crate: the same idea in about 40 lines, without tests) | Decided (M5.7) |
| Unix file checks | `rustix` 1.1 (`fs`, `process`, `termios`): opening without following a link or blocking, the effective uid, for the private-file and authority-file checks (`writ_platform::fs`); the terminal's echo, off while a passphrase is typed (`writ_crypto::passphrase`, M5); safe wrappers, so no `unsafe` in the tree, and already a dependency of `tempfile`. Process hardening (M5 step 6): the core limit (`process`, both), not dumpable (`process`), `mlockall` (`mm`) and the effective capabilities (`thread`) on Linux | Decided (M2.6; M5) |
| macOS calls rustix doesn't wrap | `libc` 0.2 (already in the tree, through tokio and rustix): `ptrace(PT_DENY_ATTACH)` and `proc_pidinfo` (is the process traced, M5); a socket peer's audit token (`LOCAL_PEERTOKEN`), a process's parent, unique ids and pidversion (`proc_pidinfo`, with `proc_uniqidentifierinfo` declared from XNU's private header, its layout checked by the tests), its executable (`proc_pidpath`), and a kqueue on process exits (M7); all in `writ-platform-macos`'s one `unsafe` module (`sys`), each call with its `SAFETY` comment | Decided (M5; M7) |
| Linux calls rustix doesn't wrap | `libc` 0.2 (as above) for `getsockopt(SO_PEERPIDFD)`, a Unix socket peer's pidfd (M7.1), and `linux-raw-sys` 0.12 (already in the tree, through rustix; `net` only) for that option's number on each architecture, which libc doesn't name for glibc yet; and the process reader's seccomp filter (`prctl(PR_SET_SECCOMP)`, its BPF written by hand from libc's constants: x86_64 and aarch64), both in `writ-platform-linux`'s one `unsafe` module (`sys`). Everything else there (pidfds, `poll`, epoll, eventfd, capabilities, the parent's death signal) through `rustix`, no `unsafe` | Decided (M7.1) |
| macOS code signatures (M7) | Security.framework (`SecCodeCopyGuestWithAttributes`, `SecCodeCheckValidity`, `SecCodeCopySigningInformation`) declared by hand, with `core-foundation-sys` 0.8 (already in the tree, through `iana-time-zone`; only its `link` feature) for the Core Foundation types, in the same `sys` module. Not `security-framework`: a larger crate for three calls | Decided (M7) |
| Installer (M7) | POSIX sh (`deploy/`), linted by `shellcheck` 0.10 or newer in `make check` (`tool/shellcheck.sh`, every warning an error; on the Mac `brew install shellcheck`, CI's Ubuntu runner has it); tested in `make test` against a fake root with the system tools stubbed (`crates/writ-integration/tests/installer.rs`) | Decided (M7, with the user) |
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
| `git` | 2.34 on agent hosts (M0 ran 2.54); 2.45 on the daemon host (`mirrors.git`, an absolute path), 2.47 with an `https://` upstream, checked at startup; 2.47 for the integration tests | SSH commit signing (`gpg.format = ssh`); the daemon's mirrors: reftable (2.45), `fetch --porcelain` (2.41); HTTPS upstreams: a SOCKS proxy on a Unix socket in `http.proxy` (2.47 keeps its path) |
| OpenSSH (`ssh`, `ssh-keygen`) | 8.9 (M0 ran 10.5) | `-Y sign/verify`, certificates; the daemon's ssh to upstream (`mirrors.ssh`) |
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
  bridges). Installed with `cargo install --locked cargo-deny --version 0.20.2`; CI uses its
  release binary, checked against the SHA-256 pinned in `tool/ci-tools.sh`.
- `cargo-nextest` 0.9.151 (`make test`, `.config/nextest.toml`, which requires that version):
  the test runner ([how `make test` runs](testing.md#how-make-test-runs)). Installed with
  `cargo install --locked cargo-nextest --version 0.9.151`; CI uses its release binary,
  checked against the SHA-256 pinned in `tool/ci-tools.sh`.
- Release builds keep overflow checks (`[profile.release] overflow-checks = true`).
- Debug builds (and tests) keep line tables only (`[profile.dev] debug = "line-tables-only"`).
- Dependency versions declared once in the root `Cargo.toml` (`[workspace.dependencies]`);
  crates use `dep.workspace = true`.
- `Cargo.lock` is committed (binaries).
- How to move any of these: [dependency upgrades](guides/dependency-upgrades.md).
