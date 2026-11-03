# Project initialization

Run this only when the repo holds nothing but docs. **Skip if `Cargo.toml` exists.** It is
the first step of [M0](../roadmap.md#m0--protocol-spike-gono-go).

## 1. Prerequisites (verify, install if missing)

```bash
rustup --version          # https://rustup.rs (not Homebrew Rust)
git --version             # ≥ 2.47 (SSH commit signing; the daemon's reftable mirrors, HTTPS upstreams)
ssh -V                    # OpenSSH ≥ 8.9
docker compose version    # for the test remote (M4) and detached mode (M8)
```

On the Mac: Secretive with a **dedicated approval key** ("require authentication" on), used
from M2 on ([Approvals](../architecture/approvals.md)).

## 2. Create the workspace

```bash
git init
```

Root `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/*"]

[workspace.package]
edition = "2024"
license = "MIT OR Apache-2.0"   # confirm with the user
publish = false

[workspace.lints.rust]
unsafe_code = "deny"           # allow per module, with a SAFETY comment, only where needed (local mode peer credentials)

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
dbg_macro = "deny"

[workspace.dependencies]
# every dependency version lives here; crates use `dep.workspace = true`
```

Each crate's `Cargo.toml` has `[lints] workspace = true` (`cargo new` inside the workspace
already adds it). A root `clippy.toml` allows `unwrap`, `expect` and `panic` in unit tests
(`allow-unwrap-in-tests` and friends); integration test files under `tests/` start with
`#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` for their helpers.

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

## 3. Create the crates

Start with what M0 needs and add the others when a milestone needs them, following the
[planned layout](../architecture/overview.md#repository-layout):

```bash
cargo new --lib crates/writ-core
cargo new --lib crates/writ-crypto
cargo new --lib crates/writ-gateway
cargo new --bin crates/writd
cargo new --bin crates/writ-sign
```

`writ-core` gets no internal dependency, ever.

## 4. Makefile

| Target | Runs |
|---|---|
| `make check` | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, the dependency-direction check (`tool/check-deps.py`, over `cargo metadata`: see [dependency directions](../architecture/overview.md#dependency-directions)) |
| `make test` | The shipped binaries built on their own (`-p writd -p writ-cli -p writ-sign`, in `target/bins`), then `cargo test --workspace` (the integration tests run those binaries); everything `--locked`. Since M2.6: `make ci` runs `check` then `test`, and `make check` also runs `cargo deny` and the source, feature and guarantee checks (see the [Makefile](../../Makefile)). Since M5: the tests run under `cargo-nextest`, and `make test` prunes `target/` to the last builds at its end ([how `make test` runs](../testing.md#how-make-test-runs)) |
| `make fmt` | `cargo fmt --all` |
| `make run` | `writd` with the dev config in `dev/` (test keys and test repos only) |
| `make e2e` | End-to-end scenarios: the binaries in containers against Forgejo ([end-to-end](../end-to-end.md), from M4.1) |
| `make docker` | Build the `writd` image (from M8) |

Then update the commands table in [AGENTS.md](../../AGENTS.md#commands) so it matches.

## 5. Finish

- `.gitignore` already ignores `target/` and `dev/data/`.
- `make check` and `make test` pass on the empty crates.
- First commit: `chore: initialize Rust workspace`.
