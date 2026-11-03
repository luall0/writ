#!/bin/sh
# CI's cargo-deny and cargo-nextest (docs/stack.md#version-pinning): their release binaries for
# the CI runner (x86_64 Linux), each checked against the SHA-256 pinned here before anything is
# unpacked, instead of compiling them from crates.io on every run. The same versions as on a
# developer's machine (`cargo install --locked …`, docs/stack.md); moving one (a version and
# its pin, together): docs/guides/dependency-upgrades.md#the-tool-binaries-ci-downloads.
set -eu

DENY_VERSION=0.20.2
DENY_SHA256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
NEXTEST_VERSION=0.9.151
NEXTEST_SHA256=1d4ce302b820c41f4b89c5fb9bce45f0f0c94882c1cf08fc360caf08be6e7df4

if [ "$(uname -sm)" != "Linux x86_64" ]; then
    echo "ci-tools: these pins are for x86_64 Linux (the CI runner), not $(uname -sm)" >&2
    exit 2
fi
bin="${CARGO_HOME:-$HOME/.cargo}/bin"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# fetch <url> <sha256> <file>: downloads over HTTPS only, and fails unless the file is the pinned one.
fetch() {
    curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$3" "$1"
    echo "$2  $work/$3" | sha256sum --check --strict --quiet -
}

deny="cargo-deny-$DENY_VERSION-x86_64-unknown-linux-musl"
fetch "https://github.com/EmbarkStudios/cargo-deny/releases/download/$DENY_VERSION/$deny.tar.gz" \
    "$DENY_SHA256" deny.tar.gz
tar -xzf "$work/deny.tar.gz" -C "$work" "$deny/cargo-deny"
install -m 0755 "$work/$deny/cargo-deny" "$bin/cargo-deny"

nextest="cargo-nextest-$NEXTEST_VERSION-x86_64-unknown-linux-gnu"
fetch "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$NEXTEST_VERSION/$nextest.tar.gz" \
    "$NEXTEST_SHA256" nextest.tar.gz
tar -xzf "$work/nextest.tar.gz" -C "$work" cargo-nextest
install -m 0755 "$work/cargo-nextest" "$bin/cargo-nextest"

cargo deny --version
cargo nextest --version | head -1
