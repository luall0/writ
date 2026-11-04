#!/usr/bin/env python3
"""Checks that no shipped binary is built with a test-only feature: the `testing` features
(fakes, contract suites, a breakable audit log, cheap key derivation) and writd's
`dev-keystore` must never be in the dependency graph of writd, writ or writ-sign as they ship.
"""

import subprocess
import sys

BINARIES = ["writd", "writ-cli", "writ-sign"]
FORBIDDEN = {"testing", "dev-keystore"}


def forbidden_in(package: str) -> list[str]:
    tree = subprocess.check_output(
        # Every target: on Linux CI, the macOS-only dependencies too (the review after M5.5).
        ["cargo", "tree", "--locked", "--target", "all", "-p", package, "-e", "normal,features",
         "--prefix", "none", "--format", "{p} [{f}]"],
        text=True,
    )
    found = []
    for line in tree.splitlines():
        if "[" not in line:
            continue
        name, _, features = line.partition(" [")
        enabled = {f.strip() for f in features.rstrip("]").split(",") if f.strip()}
        if name.startswith("writ") and enabled & FORBIDDEN:
            found.append(f"{name} is built with {sorted(enabled & FORBIDDEN)}")
    return found


errors = []
for binary in BINARIES:
    errors += [f"{binary}: {f}" for f in forbidden_in(binary)]
# The check checks itself: the test-only crate does use `testing`; if it can't be seen there,
# the parsing broke and an empty result above would mean nothing.
if not forbidden_in("writ-integration"):
    errors.append("cannot see the `testing` features of writ-integration: the check is broken")

for e in sorted(set(errors)):
    print(f"check-features: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
