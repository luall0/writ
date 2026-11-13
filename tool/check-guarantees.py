#!/usr/bin/env python3
"""Checks the guarantee registry (docs/threat-model.md § What Writ guarantees): every
guarantee names tests that try to break it, or the milestone that brings them
(`planned: M<n>`, a milestone the roadmap still lists as to come); every named test exists
as a test function in the workspace and is not `#[ignore]`d.
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

# Milestones still to come: the roadmap's table rows not marked done.
pending = set()
for line in (ROOT / "docs/roadmap.md").read_text().splitlines():
    found = re.match(r"\| (M[0-9.]+) \|", line)
    if found and "✅" not in line:
        pending.add(found.group(1))

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
        planned = re.fullmatch(r"planned: (M\d+(?:\.\d+)?)", cell)
        if not planned:
            errors.append(f"{guarantee}: no test, and no `planned: M<n>`")
        elif planned.group(1) not in pending:
            errors.append(
                f"{guarantee}: planned for {planned.group(1)}, which the roadmap doesn't list as to come"
            )
        continue
    for name in names:
        if name not in tests:
            errors.append(f"{guarantee}: test `{name}` does not exist")
        elif tests[name]:
            errors.append(f"{guarantee}: test `{name}` is ignored")

for e in errors:
    print(f"check-guarantees: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
