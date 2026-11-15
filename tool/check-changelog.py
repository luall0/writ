#!/usr/bin/env python3
"""Checks CHANGELOG.md against the workspace's version (docs/conventions.md#versions-and-the-changelog):

- the file starts with `# Changelog`, then `## Unreleased`, then the releases, newest first,
  each `## <version> — <YYYY-MM-DD>`: a version is MAJOR.MINOR.PATCH (no `v`, no leading
  zero, no pre-release), released once, each lower than the one above it, its date a real
  date no later than the one above it;
- the sections of each are `### <name>` from a fixed list, in that list's order, each once,
  each with at least one `- ` item; every release has `### Upgrading`, first;
- the newest release is the workspace's version (`[workspace.package] version` in
  Cargo.toml): the version moves only with a release added, and a release is added only
  with the version moved;
- every crate takes the workspace's version (`version.workspace = true`, never its own).

No git history is read: CI checks out one commit.
"""

import datetime
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent

SECTIONS = ["Upgrading", "Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"]
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
RELEASE = re.compile(r"## (\S+) — (\S+)")


def version(text: str):
    """The version as a tuple of three numbers, or None when it isn't one."""
    match = VERSION.fullmatch(text)
    return tuple(int(part) for part in match.groups()) if match else None


def check(changelog: str, workspace: str) -> list[str]:
    """Every way `changelog` breaks the rules, for a workspace at version `workspace`."""
    errors = []
    lines = changelog.splitlines()
    if not lines or lines[0] != "# Changelog":
        errors.append("line 1: the file starts with '# Changelog'")
    # Each block: its heading's line number, its title, its sections ([line, name, items]).
    blocks = []
    for number, line in enumerate(lines, start=1):
        if line.startswith("# "):
            if number != 1:
                errors.append(f"line {number}: one '# ' heading only, the first line")
        elif line.startswith("## "):
            blocks.append([number, line, []])
        elif line.startswith("### "):
            if not blocks:
                errors.append(f"line {number}: a section before any release: {line!r}")
                continue
            blocks[-1][2].append([number, line[4:], 0])
        elif line.startswith("#"):
            errors.append(f"line {number}: only '## ' releases and '### ' sections: {line!r}")
        elif line.startswith("- ") and blocks and blocks[-1][2]:
            blocks[-1][2][-1][2] += 1

    if not blocks or blocks[0][1] != "## Unreleased":
        errors.append("the first '## ' heading is '## Unreleased'")
    releases = []
    for number, title, sections in blocks:
        unreleased = title == "## Unreleased"
        if unreleased and number != blocks[0][0]:
            errors.append(f"line {number}: '## Unreleased' comes first, once")
        names = [name for _, name, _ in sections]
        for line, name, items in sections:
            if name not in SECTIONS:
                errors.append(
                    f"line {line}: unknown section {name!r}: one of {', '.join(SECTIONS)}"
                )
            elif names.count(name) > 1:
                errors.append(f"line {line}: {name!r} twice in one release")
            if items == 0:
                errors.append(f"line {line}: {name!r} has no '- ' item")
        known = [name for name in names if name in SECTIONS]
        if known != sorted(set(known), key=SECTIONS.index) and len(set(known)) == len(known):
            errors.append(
                f"line {number}: the sections are in this order: {', '.join(SECTIONS)}"
            )
        if unreleased:
            continue
        match = RELEASE.fullmatch(title)
        if not match:
            errors.append(f"line {number}: a release is '## <version> — <YYYY-MM-DD>': {title!r}")
            continue
        number_text, date_text = match.groups()
        parsed = version(number_text)
        if parsed is None:
            errors.append(
                f"line {number}: {number_text!r} is not a version (MAJOR.MINOR.PATCH, no leading zero)"
            )
            continue
        try:
            date = datetime.date.fromisoformat(date_text)
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date_text):
                raise ValueError
        except ValueError:
            errors.append(f"line {number}: {date_text!r} is not a date (YYYY-MM-DD)")
            continue
        if names[:1] != ["Upgrading"]:
            errors.append(f"line {number}: {number_text} starts with '### Upgrading'")
        releases.append((number, number_text, parsed, date))

    seen = {}
    for (_, _, newer, newer_date), (line, text, older, older_date) in zip(releases, releases[1:]):
        if older == newer:
            continue
        if older > newer:
            errors.append(f"line {line}: {text} is below a lower version: newest first")
        if older_date > newer_date:
            errors.append(f"line {line}: {text} is dated after the release above it")
    for line, text, parsed, _ in releases:
        if parsed in seen:
            errors.append(f"line {line}: {text} is released twice (line {seen[parsed]} too)")
        else:
            seen[parsed] = line

    if version(workspace) is None:
        errors.append(f"the workspace's version {workspace!r} is not MAJOR.MINOR.PATCH")
    elif not releases:
        errors.append(f"no release: the workspace is {workspace}, and it needs its release")
    elif releases[0][1] != workspace:
        errors.append(
            f"the workspace is {workspace} but the newest release is {releases[0][1]}: "
            "the version moves only with its release, and a release only with the version"
        )
    return errors


def crate_errors(root: pathlib.Path) -> list[str]:
    """Every crate that doesn't take the workspace's version."""
    errors = []
    for manifest in sorted(root.glob("crates/*/Cargo.toml")):
        package = tomllib.loads(manifest.read_text()).get("package", {})
        if package.get("version") != {"workspace": True}:
            errors.append(
                f"{manifest.relative_to(root)}: the crate takes the workspace's version "
                "(version.workspace = true)"
            )
    return errors


def main() -> int:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    workspace = cargo.get("workspace", {}).get("package", {}).get("version", "")
    errors = check((ROOT / "CHANGELOG.md").read_text(), workspace) + crate_errors(ROOT)
    for error in errors:
        print(f"CHANGELOG.md: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
