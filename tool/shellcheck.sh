#!/bin/sh
# make check's shell lint (docs/stack.md): the installer's scripts through shellcheck, POSIX
# sh, every warning an error. shellcheck comes from the system (CI's runner has it; on the Mac,
# `brew install shellcheck`); without it, the check fails saying so, never skipped.
set -eu
if ! command -v shellcheck >/dev/null 2>&1; then
    echo "shellcheck: not installed (brew install shellcheck, or apt-get install shellcheck)" >&2
    exit 1
fi
exec shellcheck --shell=sh --severity=style --external-sources --source-path=. "$@"
