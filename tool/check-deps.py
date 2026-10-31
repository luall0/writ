#!/usr/bin/env python3
"""Checks the dependency directions of docs/architecture/overview.md over `cargo metadata`."""

import json
import subprocess
import sys

# Crates that must never depend on these internal crates.
FORBIDDEN = {
    "writ-core": "*",  # no internal dependency at all
    "writ-cli": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                 "writ-platform-macos", "writ-platform-linux"},
    "writ-sign": {"writ-store", "writ-signer", "writ-gateway", "writ-approval", "writd",
                  "writ-platform-macos", "writ-platform-linux"},
}
CORE = {"writ-core", "writ-store", "writ-git", "writ-gateway", "writ-approval"}
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

for e in errors:
    print(f"check-deps: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
