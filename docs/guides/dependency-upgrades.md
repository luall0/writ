# Upgrading dependencies

How to move anything Writ is built from or tested with: crates, the Rust toolchain,
`cargo-deny`, the external tools, the Unicode table, the CI runner. Writ is a security tool: an
upgrade is a change like any other, reviewed, tested and committed on its own, and it answers
the [security checklist](../security.md#the-security-checklist) (item 8 above all). The rules
it applies are in [security.md § Dependencies](../security.md#dependencies); the versions and
why each crate was chosen are in [stack.md](../stack.md).

## When

- **An advisory fails `cargo deny`** (`make check` on your machine or in CI): same day, before
  any other work ([below](#when-cargo-deny-reports-an-advisory)). `main` stays green.
- **Routinely**: once per milestone, at its start, a lockfile refresh (semver-compatible
  versions only) and a look at what's newer in the manifest.
- **When a milestone needs it**: a new version that brings a feature, or the first use of a
  crate (it becomes "Decided" in [stack.md](../stack.md) first).

Never as a side effect: no version change inside a feature commit.

## The kinds of upgrade

| Kind | What changes | How |
|---|---|---|
| Lockfile refresh | `Cargo.lock` only: newer semver-compatible versions of what's already allowed | `cargo update`, one commit for the lot |
| Manifest bump | A version in `[workspace.dependencies]` (a new minor in 0.x, a new major, a pre-release) | One crate (or one coupled group) per commit |
| Coupled pins | Crates that must move together ([table](#coupled-pins)) | Together, in one commit, never one alone |
| Toolchain | `rust-toolchain.toml` | Its own commit ([below](#the-rust-toolchain)) |
| Tools | `cargo-deny`, git, OpenSSH, Python, the CI image | [Below](#tools-outside-cargo) |

## Coupled pins

These versions are tied to each other; the reason is in [stack.md](../stack.md) or the root
`Cargo.toml`. Check every one when any member moves.

| Pin | Tied to | Check |
|---|---|---|
| `ssh-key = "=0.7.0-rc.11"` (exact) | The version `russh` depends on: the gateway passes certificates and keys between them | `cargo tree --locked -i ssh-key` shows **one** version |
| `age` 0.11 | `age` 0.12 pulls `ml-kem` 0.2, whose `kem` pre-release conflicts with `russh`'s | Retry 0.12 whenever `russh` moves; drop the hold when it resolves |
| `rustls-webpki` | The version `rustls` uses (it parses reader certificates with rustls's own parser) | `cargo tree --locked -d` lists no second `rustls-webpki` |
| `rustix` | The version `tempfile` already pulls | `cargo tree --locked -d` lists no second `rustix` |
| `tokio-rustls`, `rustls`, `rcgen`, `ring` | One TLS stack on `ring`, TLS 1.3 only | One `ring`, one `rustls`; no `aws-lc-rs` in `cargo tree --locked -e normal` |
| `hyper`, `hyper-util`, `http-body-util` | Released together | Same release train |

## The procedure

### 1. See what's there

```sh
cargo update --dry-run --verbose            # what a refresh would change
cargo deny --locked check advisories        # anything already flagged
cargo tree --locked -d                      # crates present in two versions
```

For one crate: `cargo info <crate>` (latest version, features) and its changelog.

### 2. Read before you bump

For every crate in a manifest bump, read the changelog between the two versions. For the
crates Writ's security rests on, also read the diff of the code Writ relies on:

| Crate | What Writ relies on (re-check it still holds) |
|---|---|
| `russh` | Certificate and public-key auth calls the handler only after the key is proven; `Preferred` (the gateway lists every algorithm: are the constant names the same, did a default join a list we pass?); no compression without `flate2`; `max_auth_attempts`, `inactivity_timeout` |
| `ssh-key` | SSHSIG verification (namespace, hash), certificate validation; `sk-` signatures still carry the flags byte where `writ_crypto::sshsig::require_user_presence` reads it |
| `rustls`, `rustls-webpki`, `ring` | `ClientCertVerifier` (`client_auth_mandatory`, signature checks); TLS 1.3 only; `CertifiedKey::keys_match`; key loading |
| `rcgen` | Ed25519 PKCS#8 loading for reader certificates |
| `age` | scrypt recipients, work factor limits, decryption errors |
| `zeroize` | Still wipes on drop |
| `serde-saphyr` | The option and budget names in `writ_core::yaml::options`; that anchors, aliases, merge keys, `include` and `properties` stay off with our options and features |
| `hyper`, `tokio-rustls` | Header read timeout, body limits, ALPN |
| `ureq` | Errors never carry the URL (it holds the bot token) |
| `rusqlite` | Bundled SQLite version (its own advisories) |
| `rustix` | `open` flags (`NOFOLLOW`, `NONBLOCK`), `geteuid` |
| `tokio` | `process` (`env_clear`, `kill_on_drop`), `time` |

A breaking change in one of these that touches a guarantee is a decision: a row in the
[decision log](../decisions.md), and the [threat model](../threat-model.md) if a guarantee or a
residual risk moves (with the user's go-ahead, hard rule 12).

### 3. Bump

- **Lockfile refresh**: `cargo update`. For one crate: `cargo update -p <crate>`; to a
  specific version: `cargo update -p <crate> --precise <version>`.
- **Manifest bump**: change the version in `[workspace.dependencies]` of the root
  `Cargo.toml` (never in a crate's manifest), then `cargo update -p <crate>`.
- Keep the **features** as they are: `default-features = false` stays, and a feature is added
  only when the code needs it, with the reason in a comment beside it.

### 4. Check what came in

```sh
git diff Cargo.lock                                    # every crate added, removed, moved
cargo tree --locked -e normal -i <new-crate>           # who pulls each new crate
cargo tree --locked -e features -i <crate>             # no feature turned on behind our back
cargo tree --locked -d                                 # no new duplicate of a coupled pin
cargo deny --locked check                              # advisories, bans, sources, licenses
python3 -I tool/check-features.py                      # no test-only feature in the binaries
```

- A **new transitive crate** is read like a direct one when it touches the network, parsing,
  cryptography, the file system or processes: who maintains it, what it does, why the parent
  pulls it.
- A **new license** fails `cargo deny`: add it to `deny.toml` only if it's compatible
  (permissive, no copyleft for a binary we ship), with the change's reason in the commit.
- A **banned crate** (`openssl`, `native-tls`, `rsa`, a `log` bridge) is never unbanned to make
  an upgrade pass: find the feature that pulls it and turn it off, or don't upgrade.
- An **ignored advisory** in `deny.toml` that the upgrade fixes is removed from the list.
  `cargo deny` warns about an ignore that no longer matches: remove it.

### 5. Test

```sh
make ci
```

Plus, by what moved:

| If it touched | Also run |
|---|---|
| `russh`, `ssh-key` | The OpenSSH interop tests are in `make test`; `make test-agent KEY=<.pub>` with your own agent; the [manual checks](manual-checks.md) |
| `rustls`, `rcgen`, `tokio-rustls`, `hyper` | The HTTPS tests are in `make test`; `writ ls` over HTTPS against `make run` |
| `age` | `cargo test -p writ-platform --test unlock` (already in `make test`) |
| The approval path (`writ sign` and anything it calls) | The Touch ID check in [manual checks](manual-checks.md) |

New clippy warnings from a new version are fixed, not allowed, unless the lint is wrong for
the case, with the reason above the `#[allow]` (checked by `tool/check-rules.py`).

### 6. Write it down

- [stack.md](../stack.md): the version in the crate's row, when it's named there; a new crate
  gets its row ("Decided", why).
- [decisions.md](../decisions.md): a row when a hold, a pin, a ban or an ignored advisory is
  added, changed or lifted.
- The threat model, if a guarantee or a residual risk moved.

### 7. Commit

One commit per manifest bump or coupled group, one for a lockfile refresh:

```
build: upgrade russh 0.65 → 0.66 and ssh-key to its pin

- Read: changelog 0.65..0.66; certificate auth and Preferred unchanged; new kex
  `foo` not in our list.
- Came in: <crates added or removed>, no new license, no duplicate.
- Security checklist: 8 (dependencies) as above; nothing else touched.
- Ran: make ci, make test-agent, the Touch ID manual check.
```

`make ci` is green before the commit; nothing is pushed unasked.

## When `cargo deny` reports an advisory

1. **Read it**: what is affected (versions, functions, platforms), and how Writ reaches the
   crate (`cargo tree --locked -i <crate> -e normal,build`).
2. **Upgrade** when a fixed version exists: the procedure above, as a priority. A fix that
   needs a coupled pin to move moves the group.
3. **No fix yet**: does Writ reach the affected code at all? Only when the answer is no and it
   is written down (compile time only, a function never called, a platform never built) may
   the advisory be accepted:
   - an entry in `deny.toml`'s `ignore` list with its id and that reason;
   - a row in the [decision log](../decisions.md);
   - a residual risk in the [threat model](../threat-model.md) if anything of it remains
     reachable, with the user's go-ahead.
4. **"Unmaintained" advisories** are the same: accepted only with the reason, and replaced
   when a maintained alternative fits.
5. An accepted advisory is looked at again at every upgrade of its parent; the ignore goes the
   day it's no longer needed.

## The Rust toolchain

- Change `channel` in `rust-toolchain.toml` to the new exact version (never `stable`), then
  `rustup toolchain install` (it reads the file).
- New lints: `make check` shows them. Fix them, or allow with the reason; a new lint the
  workspace should deny goes in `[workspace.lints]`.
- New `std` APIs may replace a workaround (`split_at_checked`, `is_none_or` were such): fine in
  the same commit if small.
- Update [stack.md](../stack.md) (the Language row), and run `make ci`. CI picks up the version
  from `rust-toolchain.toml` itself.

## Tools outside Cargo

| Tool | Where its version lives | On upgrade |
|---|---|---|
| `cargo-deny` | `.github/workflows/ci.yml` (`cargo install --locked cargo-deny --version …`), [stack.md](../stack.md) | Install the new version locally with `--locked`, run `cargo deny --locked check`, adapt `deny.toml` to any schema change, update both places in one commit |
| `cargo-nextest` | `.github/workflows/ci.yml` (`cargo install --locked cargo-nextest --version …`), `.config/nextest.toml` (`nextest-version`), [stack.md](../stack.md) | Install the new version locally with `--locked`, run `make test`, read its changelog for changes to retries, timeouts or the config schema, update the three places in one commit |
| The CI runner | `runs-on: ubuntu-24.04` in the workflow (pinned, never `latest`) | Check its git, OpenSSH and `nc` meet the minimums below; run CI on a branch first |
| git, OpenSSH | Minimums in `crates/writ-integration/src/tools.rs` (`MIN_GIT`, `MIN_OPENSSH`) and [stack.md](../stack.md) § External tools | Raising a minimum is a decision (users must have it); the integration tests check it at start |
| `/usr/bin/ssh-keygen` | The default in `writ sign` (`WRIT_SSH_KEYGEN` overrides) | Needs OpenSSH ≥ 8.9 for `-U`; check macOS and Linux still ship it there |
| Python (Unicode data) | The table in `crates/writ-core/src/text/hidden.rs`, generated from Python's `unicodedata` | After a Python upgrade with a newer Unicode version: `python3 -I tool/gen-hidden-chars.py`, review the diff (a newly assigned character leaves the table only if it is visible), `make ci`, commit with the Unicode version in the message. Re-check the default-ignorable list in the script against `DerivedCoreProperties.txt` of that version |
| `proptest` regressions | `crates/writ-core/tests/properties.proptest-regressions`, `crates/writ-approval/tests/sign_phases.proptest-regressions` | Kept across upgrades: a `proptest` upgrade must still read it (the fixed-seed pass fails otherwise) |

## Removing a dependency

A crate nothing uses is removed (code conventions): from the crate's manifest, then from
`[workspace.dependencies]` if no crate uses it, then `cargo update` to drop it from
`Cargo.lock`, and its row in [stack.md](../stack.md). Check with `cargo tree --locked -i <crate>`
that nothing pulls it any more.
