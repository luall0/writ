#!/usr/bin/env python3
"""Keeps target/ to the artifacts of the Makefile's last builds (docs/testing.md#how-make-test-runs).

Cargo never deletes anything from target/: each toolchain, dependency version, feature set or
`cargo … -p` by hand leaves a whole build behind, and on macOS a debug build keeps its object
files beside it. Two commands:

  target-cache.py record <name> <cargo subcommand> [arguments…]
      Runs `cargo <subcommand> --message-format=json-render-diagnostics <arguments…>`
      (diagnostics still rendered on stderr) and, if it succeeds, records every unit it built
      or found fresh in target/writ-cache/<name>.json, replacing that name's last record.
  target-cache.py prune
      Deletes from each profile directory a record names (target/debug, target/bins/debug…)
      every artifact in deps/, build/ and .fingerprint/ whose unit no record names. Incremental
      directories can't be matched to a unit: for each crate the newest are kept, as many as
      the recorded units of that crate. Deleting any of these is safe: cargo rebuilds what is
      missing. Nothing is deleted without a record, nor outside the recorded profiles.

Two layouts of cargo's build directory are read. Before Rust 1.100 a unit's hash ends its
names (`deps/libwrit_core-<hash>.rlib`, `build/writ-core-<hash>/`, `.fingerprint/…-<hash>/`);
from 1.100 (build-dir layout v2) each unit is one directory, `build/<package>/<hash>/`, with
its `fingerprint/`, `out/` (rlibs, test and binary executables) and `run/` inside. A record
that names no unit at all is refused: it means cargo moved its layout again.
"""

import fcntl
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORDS = ROOT / "target" / "writ-cache"
# A unit's hash in an artifact's name: `libwrit_core-0391c38aea9412df.rlib`,
# `writ_sign-4ab53e1a87b3a754.<cgu>.rcgu.o`, the directory `writ-core-0391c38aea9412df`.
HASH = re.compile(r"-([0-9a-f]{16})(?=\.|$)")
# Layout v2 (Rust 1.100): the unit's directory, build/<package>/<hash>/.
UNIT_HASH = re.compile(r"[0-9a-f]{16}")
UNIT_DIRS = ("deps", "build", ".fingerprint")
LOCKS = (".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def fail(message: str) -> None:
    print(f"target-cache: {message}", file=sys.stderr)
    sys.exit(2)


def units_of(path: Path, crate: str) -> list[tuple[Path, str]]:
    """The profile directory and unit hash of an artifact cargo reported."""
    parts = path.parts
    # From the end: an OUT_DIR or a checkout path may hold a `build` of its own.
    for i in range(len(parts) - 2, -1, -1):
        if parts[i] not in ("deps", "build"):
            continue
        found = HASH.search(parts[i + 1])
        if found:
            return [(Path(*parts[:i]), found.group(1))]
        if parts[i] == "build" and i + 2 < len(parts) and UNIT_HASH.fullmatch(parts[i + 2]):
            return [(Path(*parts[:i]), parts[i + 2])]
    profile = path.parent
    try:
        # Uplifted (target/debug/writ-sign) before 1.100: a copy of deps/writ_sign-<hash> (a
        # hard link on Linux, a copy on macOS), found by its content.
        if (profile / "deps").is_dir():
            size = path.stat().st_size
            name = re.compile(re.escape(crate) + r"-[0-9a-f]{16}")
            twins = [(profile, e.name[-16:]) for e in os.scandir(profile / "deps")
                     if name.fullmatch(e.name) and e.is_file(follow_symlinks=False)
                     and e.stat(follow_symlinks=False).st_size == size
                     and filecmp.cmp(path, e.path, shallow=False)]
            if twins:
                return twins
        # From 1.100 a binary target keeps no hashed copy: cargo links it straight to its
        # final path, and its unit is the directory whose fingerprint names it,
        # build/<package>/<hash>/fingerprint/bin-<target>. Every link overwrites the final
        # path, so with several such units the binary is the most recently built one's.
        units = [(f.stat().st_mtime, f.parent.parent.name)
                 for f in profile.glob(f"build/*/*/fingerprint/bin-{path.name}")
                 if UNIT_HASH.fullmatch(f.parent.parent.name)]
        return [(profile, max(units)[1])] if units else []
    except OSError:
        return []


def record(name: str, args: list[str]) -> int:
    if not NAME.match(name) or not args:
        fail("usage: target-cache.py record <name> <cargo subcommand> [arguments…]")
    command = ["cargo", args[0], "--message-format=json-render-diagnostics", *args[1:]]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
    units = {}
    assert process.stdout is not None
    for line in process.stdout:
        try:
            message = json.loads(line)
        except ValueError:
            sys.stdout.write(line)
            continue
        reason = message.get("reason")
        if reason == "compiler-artifact":
            paths = list(message.get("filenames") or [])
            if message.get("executable"):
                paths.append(message["executable"])
            crate = message["target"]["name"].replace("-", "_")
            local = message.get("package_id", "").startswith("path+file://")
        elif reason == "build-script-executed":
            paths, crate, local = [message["out_dir"]], "", False
        else:
            continue
        for path in paths:
            found = units_of(Path(path), crate)
            if not found:
                print(f"target-cache: no unit for {path} (it will be rebuilt after a prune)",
                      file=sys.stderr)
            for profile, digest in found:
                units[(str(profile), digest)] = {
                    "profile": str(profile), "hash": digest, "crate": crate or None,
                    "local": local}
    status = process.wait()
    if status != 0:
        return status
    if not units:
        # Cargo reported artifacts and none had a unit: an unknown layout. Saving it would
        # make every prune keep everything again, silently.
        fail(f"{name}: no unit found in cargo's artifact paths (a new build-dir layout?); "
             f"record not saved")
    RECORDS.mkdir(parents=True, exist_ok=True)
    temporary = RECORDS / f".{name}.json.tmp"
    temporary.write_text(json.dumps(
        {"command": command, "units": sorted(units.values(), key=lambda u: (u["profile"], u["hash"]))},
        indent=1))
    temporary.replace(RECORDS / f"{name}.json")
    return 0


def size_of(path: Path) -> int:
    if path.is_symlink() or not path.is_dir():
        return path.lstat().st_size
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file() and not f.is_symlink())


def remove(path: Path) -> int:
    size = size_of(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
    return size


def prune() -> int:
    records = sorted(RECORDS.glob("*.json")) if RECORDS.is_dir() else []
    if not records:
        print("target-cache: no record yet, nothing pruned")
        return 0
    live: dict[str, set[str]] = defaultdict(set)
    compiled: dict[str, Counter] = defaultdict(Counter)
    seen: dict[str, set] = defaultdict(set)
    for path in records:
        try:
            units = json.loads(path.read_text())["units"]
        except (ValueError, KeyError) as error:
            fail(f"{path}: unreadable record ({error}); delete it and run the build again")
        for unit in units:
            live[unit["profile"]].add(unit["hash"])
            key = (unit["crate"], unit["hash"])
            if unit["local"] and unit["crate"] and key not in seen[unit["profile"]]:
                seen[unit["profile"]].add(key)
                compiled[unit["profile"]][unit["crate"]] += 1
    for profile_name, hashes in sorted(live.items()):
        profile = Path(profile_name)
        # Only a cargo profile directory, inside this repository's target directories.
        if (not ((profile / ".fingerprint").is_dir() or (profile / "build").is_dir())
                or ROOT not in profile.parents):
            continue
        locks = []
        try:
            # Cargo's own build locks: never prune under a running build.
            for name in LOCKS:
                if (profile / name).exists() or name == ".cargo-lock":
                    locks.append(open(profile / name, "a"))
                    fcntl.flock(locks[-1], fcntl.LOCK_EX)
            count, freed = 0, 0
            for sub in UNIT_DIRS:
                directory = profile / sub
                if not directory.is_dir():
                    continue
                for entry in os.scandir(directory):
                    found = HASH.search(entry.name)
                    if found:
                        if found.group(1) not in hashes:
                            freed += remove(Path(entry.path))
                            count += 1
                    elif sub == "build" and entry.is_dir(follow_symlinks=False):
                        # layout v2: build/<package>/<hash>/
                        package = Path(entry.path)
                        for unit in os.scandir(package):
                            # Cargo recreates an empty out/ per workspace package on every
                            # test build, unit or not: nothing to free, nothing to report.
                            if (UNIT_HASH.fullmatch(unit.name) and unit.name not in hashes
                                    and any(files for _, _, files in os.walk(unit.path))):
                                freed += remove(Path(unit.path))
                                count += 1
                        if not any(package.iterdir()):
                            package.rmdir()
            incremental = profile / "incremental"
            if incremental.is_dir():
                by_crate = defaultdict(list)
                for entry in os.scandir(incremental):
                    crate, dash, _ = entry.name.rpartition("-")
                    if dash and entry.is_dir(follow_symlinks=False):
                        by_crate[crate].append(Path(entry.path))
                for crate, directories in by_crate.items():
                    directories.sort(key=lambda d: d.stat().st_mtime, reverse=True)
                    for stale in directories[compiled[profile_name][crate]:]:
                        freed += remove(stale)
                        count += 1
        finally:
            for lock in locks:
                lock.close()
        if count:
            print(f"target-cache: {profile.relative_to(ROOT)}: pruned {count} stale "
                  f"artifacts ({freed / 2**20:.0f} MiB)")
    return 0


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "record":
        return record(sys.argv[2], sys.argv[3:])
    if sys.argv[1:] == ["prune"]:
        return prune()
    fail("usage: target-cache.py record <name> <cargo subcommand> [arguments…] | prune")
    return 2


if __name__ == "__main__":
    sys.exit(main())
