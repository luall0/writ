#!/usr/bin/env python3
"""Checks the guarantee registry (docs/threat-model.md § What Writ guarantees): every
guarantee names tests that try to break it, or the milestone that brings them
(`planned: M<n>`); every named test exists as a test function in the workspace and is not
`#[ignore]`d.
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
    in_proptest = False
    for i, line in enumerate(lines):
        if "proptest!" in line:
            in_proptest = True
        match = re.match(r"\s*(async\s+)?fn ([a-z0-9_]+)\s*\(", line)
        if not match:
            continue
        attrs = " ".join(lines[max(0, i - 4):i])
        if TEST_ATTR.search(attrs) or in_proptest:
            tests[match.group(2)] = "#[ignore" in attrs

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
        if not re.fullmatch(r"planned: M\d+(\.\d+)?", cell):
            errors.append(f"{guarantee}: no test, and no `planned: M<n>`")
        continue
    for name in names:
        if name not in tests:
            errors.append(f"{guarantee}: test `{name}` does not exist")
        elif tests[name]:
            errors.append(f"{guarantee}: test `{name}` is ignored")

for e in errors:
    print(f"check-guarantees: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
