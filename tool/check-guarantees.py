#!/usr/bin/env python3
"""Checks the guarantee registry (docs/threat-model.md § What Writ guarantees): every
guarantee names tests that try to break it, or the milestone that brings them
(`planned: [idea](backlog/<page>.md)`, a page of the backlog); every named test exists
as a test function in the workspace and is not `#[ignore]`d.

And the untrusted-input inventory (docs/security.md § Untrusted inputs): every test it names
(`test `…``, `tests `…`, `…``) exists, so a hostile-input test removed or renamed is seen
(the review after M7.6, T-8).
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL = ROOT / "docs/threat-model.md"
TEST_ATTR = re.compile(r"#\[(tokio::)?test\b|#\[test\]")

text = MODEL.read_text()
start = text.index("## What Writ guarantees")
end = text.index("\n## ", start + 1)
section = text[start:end]

# Every test function in the workspace: name → whether it is ignored. Property tests live in
# proptest! blocks, where the function has no #[test] of its own.
tests: dict[str, bool] = {}
for path in (ROOT / "crates").rglob("*.rs"):
    if "/target/" in path.as_posix():
        continue
    lines = path.read_text().splitlines()
    # Inside a `proptest! { … }` block: its braces counted, so a helper after the block is
    # never taken for a test (the review after M5.5).
    depth = 0
    for i, line in enumerate(lines):
        if depth == 0 and re.search(r"\bproptest!\s*\{", line):
            depth = line.count("{") - line.count("}") or 1
            continue
        in_proptest = depth > 0
        if in_proptest:
            depth += line.count("{") - line.count("}")
        match = re.match(r"\s*(async\s+)?fn ([a-z0-9_]+)\s*\(", line)
        if not match:
            continue
        attrs = " ".join(lines[max(0, i - 4):i])
        if TEST_ATTR.search(attrs) or in_proptest:
            tests[match.group(2)] = "#[ignore" in attrs

# Work still to come: the backlog's pages (docs/backlog/<page>.md, the parked ones aside).
pending = {p.stem for p in (ROOT / "docs/backlog").glob("*.md") if p.name != "README.md"}

errors = []
rows = [l for l in section.splitlines() if l.startswith("| ") and not l.startswith("| Guarantee")]
if not rows:
    errors.append("no guarantee rows found: the registry table moved or changed shape")
for row in rows:
    cells = [c.strip() for c in row.strip("|").split("|")]
    if len(cells) != 2:
        errors.append(f"malformed row: {row}")
        continue
    guarantee, cell = cells
    names = re.findall(r"`([a-z0-9_]+)`", cell)
    if not names:
        planned = re.fullmatch(r"planned: \[[^\]]+\]\(backlog/([a-z0-9-]+)\.md\)", cell)
        if not planned:
            errors.append(f"{guarantee}: no test, and no `planned: [idea](backlog/<page>.md)`")
        elif planned.group(1) not in pending:
            errors.append(
                f"{guarantee}: planned for backlog/{planned.group(1)}.md, which is no backlog page"
            )
        continue
    for name in names:
        if name not in tests:
            errors.append(f"{guarantee}: test `{name}` does not exist")
        elif tests[name]:
            errors.append(f"{guarantee}: test `{name}` is ignored")

# The inventory's named tests: each list after "test" or "tests" (an end-to-end scenario,
# `#[ignore]`d, may be named there too).
security = (ROOT / "docs/security.md").read_text()
start = security.index("## Untrusted inputs")
end = security.index("\n## ", start + 1)
inventory = security[start:end]
named = 0
for listed in re.finditer(r"\btests?\s+((?:`[a-z0-9_]+`(?:,\s*(?:and\s+)?|\s+and\s+)?)+)", inventory):
    for name in re.findall(r"`([a-z0-9_]+)`", listed.group(1)):
        named += 1
        if name not in tests:
            errors.append(f"security.md's inventory: test `{name}` does not exist")
if named == 0:
    errors.append("security.md's inventory names no test: the table moved or changed shape")

for e in errors:
    print(f"check-guarantees: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
