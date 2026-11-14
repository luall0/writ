#!/bin/sh
# Builds writ-popup, the approval popup (crates/writ-cli/macos/writ-popup.swift, M7.8), into
# <dir>, beside the writ built there: it runs the `writ` next to it (`writ sign --ui`). On the
# Mac only; elsewhere, nothing. Rebuilt when the source is newer.
# Usage: sh tool/build-writ-popup.sh <dir>
set -eu
dir=$1
[ "$(uname -s)" = Darwin ] || exit 0
src=$(dirname "$0")/../crates/writ-cli/macos/writ-popup.swift
out=$dir/writ-popup
mkdir -p "$dir"
if [ ! -x "$out" ] || [ "$src" -nt "$out" ]; then
    swiftc -O -swift-version 6 -o "$out" "$src"
fi
