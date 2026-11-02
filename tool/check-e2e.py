#!/usr/bin/env python3
"""Checks the end-to-end pipeline's registries (docs/end-to-end.md):

- the coverage registry: every row names at least one scenario test, and every name is a
  test function in crates/writ-e2e/tests/ marked `#[ignore = "end to end: make e2e"]`
  (that every command and flag has a row is checked by `make test`: writ-cli's and writd's
  `every_..._is_in_the_end_to_end_registry`);
- the scenarios table: every module in crates/writ-e2e/tests/scenarios/ is a row, and every
  row is a module;
- every scenario test is marked to run only in the pipeline;
- the commands the docs show: each command line of a fenced block right after a
  `<!-- e2e: <file> -->` marker is run by that file through `doc_step*` with exactly that
  text, and every `doc_step*` literal in the e2e crate is a line of a block marked for its
  file. A step changed in one is changed in the other.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs/end-to-end.md"
CRATE = ROOT / "crates/writ-e2e"
SCENARIOS = CRATE / "tests/scenarios"
IGNORE = '#[ignore = "end to end: make e2e"]'

errors = []
text = DOC.read_text()


def section(title: str) -> str:
    start = text.index(f"\n## {title}")
    end = text.find("\n## ", start + 1)
    return text[start:end if end != -1 else len(text)]


def table_rows(body: str) -> list[list[str]]:
    rows = []
    for line in body.splitlines():
        if not line.startswith("| ") or line.startswith("|---"):
            continue
        rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows[1:]  # the header


# Every test function of the e2e crate: name → its attributes.
tests: dict[str, str] = {}
for path in sorted((CRATE / "tests").rglob("*.rs")):
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        match = re.match(r"\s*fn ([a-z0-9_]+)\s*\(", line)
        if not match:
            continue
        attrs = " ".join(l.strip() for l in lines[max(0, i - 4):i])
        if "#[test]" in attrs:
            tests[match.group(1)] = attrs
            if IGNORE not in attrs:
                errors.append(f"{path.relative_to(ROOT)}: {match.group(1)} is not marked {IGNORE}")

# The coverage registry.
rows = table_rows(section("Coverage: every command and flag"))
if not rows:
    errors.append("no coverage rows: the registry moved or changed shape")
for cells in rows:
    if len(cells) != 2 or not cells[0].startswith("`"):
        errors.append(f"malformed coverage row: {cells}")
        continue
    feature, cell = cells
    names = re.findall(r"`([a-z0-9_]+)`", cell)
    if not names:
        errors.append(f"{feature}: no scenario")
    for name in names:
        if name not in tests:
            errors.append(f"{feature}: scenario test `{name}` does not exist in crates/writ-e2e/tests")

# The scenarios table and the modules.
listed = set()
for cells in table_rows(section("Scenarios")):
    match = re.fullmatch(r"`([a-z0-9_]+)`", cells[1]) if len(cells) > 1 else None
    if not match:
        errors.append(f"malformed scenario row: {cells}")
        continue
    listed.add(match.group(1))
modules = {p.stem for p in SCENARIOS.glob("*.rs") if p.stem != "main"}
for missing in sorted(modules - listed):
    errors.append(f"scenario module {missing} has no row in docs/end-to-end.md#scenarios")
for extra in sorted(listed - modules):
    errors.append(f"docs/end-to-end.md#scenarios lists {extra}, which is no module")
main = (SCENARIOS / "main.rs").read_text()
for module in sorted(modules):
    if f"mod {module};" not in main:
        errors.append(f"tests/scenarios/main.rs doesn't declare mod {module}")

# The commands the docs show, both ways.
LITERAL = re.compile(r'doc_step\w*\(\s*[^,]+,\s*"((?:[^"\\]|\\.)*)"', re.S)


def unescape(literal: str) -> str:
    return literal.replace('\\"', '"').replace("\\\\", "\\")


def command(line: str) -> str:
    # A trailing comment: two spaces or more, then `#`.
    return re.split(r"\s{2,}#", line, maxsplit=1)[0].rstrip()


shown: dict[str, set[str]] = {}
for doc in sorted((ROOT / "docs").rglob("*.md")):
    lines = doc.read_text().splitlines()
    for i, line in enumerate(lines):
        match = re.fullmatch(r"<!-- e2e: (\S+) -->", line.strip())
        if not match:
            continue
        target = match.group(1)
        if not (ROOT / target).is_file():
            errors.append(f"{doc.relative_to(ROOT)}:{i + 1}: {target} does not exist")
            continue
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j >= len(lines) or not lines[j].strip().startswith("```"):
            errors.append(f"{doc.relative_to(ROOT)}:{i + 1}: the marker is not followed by a fenced block")
            continue
        j += 1
        while j < len(lines) and not lines[j].strip().startswith("```"):
            body = lines[j].strip()
            if body and not body.startswith("#"):
                shown.setdefault(target, set()).add(command(body))
            j += 1

run: dict[str, set[str]] = {}
for path in sorted(CRATE.rglob("*.rs")):
    rel = path.relative_to(ROOT).as_posix()
    for literal in LITERAL.findall(path.read_text()):
        run.setdefault(rel, set()).add(unescape(literal))

for target, commands in sorted(shown.items()):
    for line in sorted(commands - run.get(target, set())):
        errors.append(f"docs show `{line}` for {target}, which doesn't run it through doc_step")
for target, commands in sorted(run.items()):
    for line in sorted(commands - shown.get(target, set())):
        errors.append(f"{target} runs `{line}` as a documented step, which no marked block shows")

for e in errors:
    print(f"check-e2e: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
