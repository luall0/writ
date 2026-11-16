# Upgrading dependencies

How to move anything Writ is built from or tested with: crates, the Rust toolchain,
`cargo-deny` and `cargo-nextest` (and the binaries CI downloads of them), the external tools, the Unicode table, the CI runner. Writ is a security tool: an
upgrade is a change like any other, reviewed, tested and committed on its own, and it answers
the [security checklist](../security.md#the-security-checklist) (item 8 above all). The rules
it applies are in [security.md § Dependencies](../security.md#dependencies); the versions and
why each crate was chosen are in [stack.md](../stack.md).

## When

- **An advisory fails `cargo deny`** (`make check` on your machine or in CI): same day, before
  any other work ([below](#when-cargo-deny-reports-an-advisory)). `main` stays green.
- **Routinely**: once per milestone, at its start, a lockfile refresh (semver-compatible
  versions only) and a look at what's newer in the manifest and of `cargo-deny` and
  `cargo-nextest`.
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
| Tools | `cargo-deny`, `cargo-nextest`, git, OpenSSH, Python, the CI image | [Below](#tools-outside-cargo) |
| CI's tool binaries | `tool/ci-tools.sh`: the version and SHA-256 of each tool CI downloads | With that tool's version, in the same commit ([below](#the-tool-binaries-ci-downloads)) |

## Coupled pins

These versions are tied to each other; the reason is in [stack.md](../stack.md) or the root
`Cargo.toml`. Check every one when any member moves.

| Pin | Tied to | Check |
|---|---|---|
| `ssh-key = "=0.7.0-rc.12"` (exact) | The version `russh` depends on: the gateway passes certificates and keys between them | `cargo tree --locked -i ssh-key` shows **one** version |
| `age` 0.11 | `age` 0.12 pulls `ml-kem` 0.2, written for the `kem` pre-release, which doesn't build against the stable `kem` 0.3 `russh` takes | Retry 0.12 whenever `russh` moves (`cargo check` on the workspace, not only a resolution: it resolves since russh 0.65.2); drop the hold when it builds |
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
  `rustup toolchain install` (it reads the file). The same version is pinned in two more
  places, moved in the same commit (`make check` compares the three, `tool/check-rules.py`):
  `e2e/Dockerfile` (the `RUST_IMAGE` tag, with its digest, and `RUSTUP_TOOLCHAIN`, which
  overrides the file inside the image) and `tool/bench-alloc.py` (its Linux container's
  `RUSTUP_TOOLCHAIN`).
- New lints: `make check` shows them. Fix them, or allow with the reason; a new lint the
  workspace should deny goes in `[workspace.lints]`.
- New `std` APIs may replace a workaround (`split_at_checked`, `is_none_or` were such): fine in
  the same commit if small.
- Update [stack.md](../stack.md) (the Language row), and run `make ci`. CI picks up the version
  from `rust-toolchain.toml` itself.

## The end-to-end images

`e2e/Dockerfile` pins its base images by digest (`RUST_IMAGE`, `DEBIAN_IMAGE`: multi-arch
indexes) and its apt packages by a Debian snapshot date (`DEBIAN_SNAPSHOT`: every stage built
from a base image installs from `snapshot.debian.org` as it was then). Move them together:
the new digests (`docker buildx imagetools inspect <image>:<tag>`), a snapshot date on or after
the images' (a later date takes the security updates), then `make e2e`.

## Tools outside Cargo

| Tool | Where its version lives | On upgrade |
|---|---|---|
| `cargo-deny` | `tool/ci-tools.sh` (`DENY_VERSION`, `DENY_SHA256`: CI's release binary), [stack.md](../stack.md) | Install the new version locally with `--locked`, run `cargo deny --locked check`, adapt `deny.toml` to any schema change. Move CI's pin ([below](#the-tool-binaries-ci-downloads)); update both places in one commit |
| `cargo-nextest` | `tool/ci-tools.sh` (`NEXTEST_VERSION`, `NEXTEST_SHA256`: CI's release binary), `.config/nextest.toml` (`nextest-version`), [stack.md](../stack.md) | Install the new version locally with `--locked`, run `make test`, read its changelog for changes to retries, timeouts or the config schema. Move CI's pin ([below](#the-tool-binaries-ci-downloads)); update the three places in one commit |
| The CI runner | `runs-on: ubuntu-24.04` in the workflow (pinned, never `latest`) | Check its git, OpenSSH and `nc` meet the minimums below; another architecture needs new pins in `tool/ci-tools.sh` (they are for x86_64 Linux, and the script refuses anything else); run CI on a branch first |
| git, OpenSSH | Minimums in `crates/writ-integration/src/tools.rs` (`MIN_GIT`, `MIN_OPENSSH`) and [stack.md](../stack.md) § External tools | Raising a minimum is a decision (users must have it); the integration tests check it at start |
| `/usr/bin/ssh-keygen` | The default in `writ sign` (`WRIT_SSH_KEYGEN` overrides) | Needs OpenSSH ≥ 8.9 for `-U`; check macOS and Linux still ship it there |
| Python (Unicode data) | The table in `crates/writ-core/src/text/hidden.rs`, generated from Python's `unicodedata` | After a Python upgrade with a newer Unicode version: `python3 -I tool/gen-hidden-chars.py`, review the diff (a newly assigned character leaves the table only if it is visible), `make ci`, commit with the Unicode version in the message. Re-check the default-ignorable list in the script against `DerivedCoreProperties.txt` of that version |
| `proptest` regressions | `crates/writ-core/tests/properties.proptest-regressions`, `crates/writ-approval/tests/sign_phases.proptest-regressions` | Kept across upgrades: a `proptest` upgrade must still read it (the fixed-seed pass fails otherwise) |

## The tool binaries CI downloads

CI doesn't compile `cargo-deny` and `cargo-nextest`: `tool/ci-tools.sh` downloads their release
binaries for the runner (x86_64 Linux) and checks each against a SHA-256 pinned in the script
before anything is unpacked. A developer's machine installs the same versions with
`cargo install --locked` ([stack.md](../stack.md#version-pinning)). So every version move of
either tool moves its pin too, in the same commit, or CI fails on the version check (nextest's
`nextest-version`) or runs another version than the developers.

1. **The asset.** `cargo-deny`: `cargo-deny-<v>-x86_64-unknown-linux-musl.tar.gz` (the project
   ships no gnu build), release tag `<v>`. `cargo-nextest`:
   `cargo-nextest-<v>-x86_64-unknown-linux-gnu.tar.gz`, release tag `cargo-nextest-<v>`. Check
   the archive still holds the binary where the script expects it (`tar tzf`): `cargo-deny`
   in a `cargo-deny-<v>-x86_64-unknown-linux-musl/` folder, `cargo-nextest` at the top.
2. **Its SHA-256, from three sources that must agree**: GitHub's digest of the release asset,
   the project's own published checksum, and your own hash of the file, downloaded into an
   empty folder (never run):

   ```sh
   v=0.9.151 repo=nextest-rs/nextest tag=cargo-nextest-$v asset=cargo-nextest-$v-x86_64-unknown-linux-gnu
   # cargo-deny: v=0.20.2 repo=EmbarkStudios/cargo-deny tag=$v asset=cargo-deny-$v-x86_64-unknown-linux-musl
   curl -fsSL "https://api.github.com/repos/$repo/releases/tags/$tag" \
     | python3 -I -c 'import json,sys; [print(a["digest"]) for a in json.load(sys.stdin)["assets"] if a["name"] == sys.argv[1]]' "$asset.tar.gz"
   curl -fsSL "https://github.com/$repo/releases/download/$tag/$asset.sha256"         # cargo-nextest
   curl -fsSL "https://github.com/$repo/releases/download/$tag/$asset.tar.gz.sha256"  # cargo-deny
   mkdir -p /tmp/pin && cd /tmp/pin && curl -fsSLO "https://github.com/$repo/releases/download/$tag/$asset.tar.gz" \
     && shasum -a 256 "$asset.tar.gz"
   ```

   Any disagreement: stop, and pin nothing.
3. **Update** `DENY_VERSION`/`DENY_SHA256` or `NEXTEST_VERSION`/`NEXTEST_SHA256` in
   `tool/ci-tools.sh`, with the tool's other places (the [table above](#tools-outside-cargo)).
4. **Run it** where CI runs it, an x86_64 Linux with cargo, from the repository:

   ```sh
   docker run --rm --platform linux/amd64 -v "$PWD/tool:/tool:ro" rust:1.99.1-slim-trixie \
     sh -c 'apt-get update -qq && apt-get install -yqq curl >/dev/null && sh /tool/ci-tools.sh'
   docker image rm --force --platform linux/amd64 rust:1.99.1-slim-trixie   # only that variant
   ```

   It prints both tools' versions, the new one included. A wrong pin stops it before
   anything is installed (`sha256sum: … did NOT match`).
5. **Commit** with the tool's version move, the security checklist's item 8 naming the three
   sources that agreed. The first CI run after it is the end-to-end check: its log shows
   both versions.

## Removing a dependency

A crate nothing uses is removed (code conventions): from the crate's manifest, then from
`[workspace.dependencies]` if no crate uses it, then `cargo update` to drop it from
`Cargo.lock`, and its row in [stack.md](../stack.md). Check with `cargo tree --locked -i <crate>`
that nothing pulls it any more.
