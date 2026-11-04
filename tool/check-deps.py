#!/usr/bin/env python3
"""Checks the dependency directions of docs/architecture/overview.md over `cargo metadata`."""

import json
import subprocess
import sys

# Crates that must never depend on these internal crates.
FORBIDDEN = {
    "writ-core": "*",  # no internal dependency at all
    "writ-alloc": "*",  # the binaries' allocator: no dependency at all
    "writ-cli": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                 "writ-platform", "writ-platform-macos", "writ-platform-linux", "writ-git", "writ-mirror"},
    "writ-sign": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                  "writ-platform", "writ-platform-macos", "writ-platform-linux", "writ-git",
                  "writ-mirror"},
    # Messages only: shared by clients and the daemon.
    "writ-proto": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                   "writ-platform", "writ-platform-macos", "writ-platform-linux", "writ-crypto",
                   "writ-git", "writ-mirror"},
    # Pure object parsing: nothing that holds state, keys or the network.
    "writ-git": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                 "writ-platform", "writ-cli", "writ-sign", "writ-mirror"},
    # Keys only: below the services that use them.
    "writ-signer": {"writ-store", "writ-git", "writ-gateway", "writ-approval", "writd",
                    "writ-platform", "writ-cli", "writ-sign", "writ-mirror"},
    # Platform traits and implementations: below every core crate but writ-core.
    "writ-platform": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                      "writ-cli", "writ-git", "writ-mirror"},
    # Platform-only implementations: below every core crate, like writ-platform.
    "writ-platform-linux": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                            "writ-cli", "writ-sign", "writ-git", "writ-mirror"},
    "writ-platform-macos": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                            "writ-cli", "writ-sign", "writ-git", "writ-mirror"},
    # The daemon's repositories and upstream: below the gateway, beside the approval service.
    "writ-mirror": {"writ-store", "writ-gateway", "writ-approval", "writd", "writ-cli",
                    "writ-sign"},
}
CORE = {"writ-core", "writ-store", "writ-git", "writ-mirror", "writ-gateway", "writ-approval"}
PLATFORM_ONLY = {"writ-platform-macos", "writ-platform-linux"}

meta = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--format-version", "1", "--no-deps"]))
members = {p["name"]: p for p in meta["packages"]}
errors = []
for name, package in members.items():
    internal = {d["name"] for d in package["dependencies"]
                if d["name"] in members and d.get("kind") != "dev"}
    rule = FORBIDDEN.get(name)
    if rule == "*" and internal:
        errors.append(f"{name} must not depend on internal crates: {sorted(internal)}")
    elif isinstance(rule, set) and internal & rule:
        errors.append(f"{name} must not depend on {sorted(internal & rule)}")
    if name in CORE and internal & PLATFORM_ONLY:
        errors.append(f"{name} must use platform traits, not {sorted(internal & PLATFORM_ONLY)}")

# The integration and end-to-end crates are test-only: nothing may depend on them, not even
# for its tests. The end-to-end crate depends on no internal crate either: it drives the
# binaries from outside, as people do.
for name, package in members.items():
    for test_only in ("writ-integration", "writ-e2e"):
        if any(d["name"] == test_only for d in package["dependencies"]):
            errors.append(f"{name} must not depend on {test_only} (test-only)")
e2e = members.get("writ-e2e")
if e2e:
    internal = {d["name"] for d in e2e["dependencies"] if d["name"] in members}
    if internal:
        errors.append(f"writ-e2e must not depend on internal crates: {sorted(internal)}")

for e in errors:
    print(f"check-deps: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
