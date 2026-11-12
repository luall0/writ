#!/bin/sh
# Builds writ-se, the Secure Enclave helper (crates/writ-platform-macos/swift/writ-se.swift),
# into <dir>, beside the writd built there: what `writd` starts by default
# (signers.se_cryptokit.helper). On the Mac only; elsewhere, nothing. Rebuilt when the source
# is newer. Usage: sh tool/build-writ-se.sh <dir>
set -eu
dir=$1
[ "$(uname -s)" = Darwin ] || exit 0
src=$(dirname "$0")/../crates/writ-platform-macos/swift/writ-se.swift
out=$dir/writ-se
mkdir -p "$dir"
if [ ! -x "$out" ] || [ "$src" -nt "$out" ]; then
    swiftc -O -swift-version 6 -o "$out" "$src"
fi
