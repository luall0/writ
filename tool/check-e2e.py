#!/usr/bin/env python3
"""Checks the end-to-end pipeline's registries (docs/end-to-end.md):

- the coverage registry: every row names at least one scenario test, and every name is a
  test function in crates/writ-e2e/tests/ marked `#[ignore = "end to end: make e2e"]`
  (that every command and flag has a row is checked by `make test`: writ-cli's and writd's
  `every_..._is_in_the_end_to_end_registry`);
- the scenarios table: every module in crates/writ-e2e/tests/scenarios/ is a row, and every
  row is a module;
- every scenario test is marked to run only in the pipeline;
- the commands the docs show, both ways, so a step changed in one is changed in the other:
  - a page listed in the "Commands the docs show" table: every command line of each of its
    `sh` blocks is run through `doc_step*` with exactly that text by one of the files its row
    names. Operator pages are listed there and carry no marker (they are read by people);
  - elsewhere (a developer guide where only some blocks are run): each command line of a
    fenced block right after a `<!-- e2e: <file> -->` marker is run by that file;
  - every `doc_step*` literal in the e2e crate is a line its file is shown with, by a listed
    page or a marked block;
  - every operator page (docs/operators/*.md) holding an `sh` block is listed, or owed by a
    backlog page (a row `| [page](…) | owed by [idea](backlog/<page>.md) … |`).
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

# Work still to come: the backlog's pages (docs/backlog/<page>.md, the parked ones aside).
pending = {p.stem for p in (ROOT / "docs/backlog").glob("*.md") if p.name != "README.md"}

# Pages run whole: the table's rows, `[page](path) | `file`, `file``; pages owed by a
# milestone to come: `[page](path) | owed by M<n>`.
listed_pages = 0
listed_paths: set[pathlib.Path] = set()
owed_paths: dict[pathlib.Path, str] = {}
for cells in table_rows(section("Commands the docs show")):
    if cells and cells[0] == "Page":
        continue  # the owed table's header
    link = re.search(r"\]\(([^)#]+)\)", cells[0]) if cells else None
    owed = (
        re.fullmatch(r"owed by \[[^\]]+\]\(backlog/([a-z0-9-]+)\.md\)(?: .*)?", cells[1])
        if len(cells) == 2
        else None
    )
    if link and owed:
        page = (DOC.parent / link.group(1)).resolve()
        if not page.is_file():
            errors.append(f"owed row: {link.group(1)} does not exist")
        elif owed.group(1) not in pending:
            errors.append(
                f"{link.group(1)} is owed by backlog/{owed.group(1)}.md, which is no backlog page"
            )
        owed_paths[page] = owed.group(1)
        continue
    files = re.findall(r"`([^`]+)`", cells[1]) if len(cells) == 2 else []
    if not link or not files:
        errors.append(f"malformed commands row: {cells}")
        continue
    page = (DOC.parent / link.group(1)).resolve()
    if not page.is_file():
        errors.append(f"commands row: {link.group(1)} does not exist")
        continue
    for target in files:
        if not (ROOT / target).is_file():
            errors.append(f"commands row for {link.group(1)}: {target} does not exist")
    listed_pages += 1
    listed_paths.add(page)
    lines = page.read_text().splitlines()
    commands = set()
    j = 0
    while j < len(lines):
        if re.fullmatch(r"```sh", lines[j].strip()):
            j += 1
            while j < len(lines) and not lines[j].strip().startswith("```"):
                body = lines[j].strip()
                if body and not body.startswith("#"):
                    commands.add(command(body))
                j += 1
        j += 1
    if not commands:
        errors.append(f"{page.relative_to(ROOT)}: listed in the commands table, and shows no sh block")
    run_by = set()
    for target in files:
        if (ROOT / target).is_file():
            run_by |= {unescape(l) for l in LITERAL.findall((ROOT / target).read_text())}
        shown.setdefault(target, set())
    for line in sorted(commands - run_by):
        errors.append(f"{page.relative_to(ROOT)} shows `{line}`, which none of {', '.join(files)} runs through doc_step")
    for target in files:
        shown[target] |= commands
if not listed_pages:
    errors.append("no commands rows: the table moved or changed shape")

# Every operator page that shows an `sh` block is run whole, or owed (rule 18).
for page in sorted((ROOT / "docs/operators").glob("*.md")):
    shows = any(re.fullmatch(r"```sh", l.strip()) for l in page.read_text().splitlines())
    resolved = page.resolve()
    if resolved in listed_paths and resolved in owed_paths:
        errors.append(f"{page.relative_to(ROOT)} is both listed and owed")
    if shows and resolved not in listed_paths and resolved not in owed_paths:
        errors.append(
            f"{page.relative_to(ROOT)} shows an sh block, and docs/end-to-end.md#commands-the-docs-show "
            "neither lists it nor names the milestone that owes it (or make a block that isn't a step `text`)"
        )

# Marked blocks, in developer guides only: each line run by the file its marker names.
marked: dict[str, set[str]] = {}
for doc in sorted((ROOT / "docs").rglob("*.md")):
    lines = doc.read_text().splitlines()
    for i, line in enumerate(lines):
        match = re.fullmatch(r"<!-- e2e: (\S+) -->", line.strip())
        if not match:
            continue
        if doc.is_relative_to(ROOT / "docs/operators"):
            errors.append(
                f"{doc.relative_to(ROOT)}:{i + 1}: no e2e marker on an operator page: "
                "list the page in docs/end-to-end.md#commands-the-docs-show instead"
            )
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
                marked.setdefault(target, set()).add(command(body))
                shown.setdefault(target, set()).add(command(body))
            j += 1

run: dict[str, set[str]] = {}
for path in sorted(CRATE.rglob("*.rs")):
    rel = path.relative_to(ROOT).as_posix()
    for literal in LITERAL.findall(path.read_text()):
        run.setdefault(rel, set()).add(unescape(literal))

for target, commands in sorted(marked.items()):
    for line in sorted(commands - run.get(target, set())):
        errors.append(f"docs show `{line}` for {target}, which doesn't run it through doc_step")
for target, commands in sorted(run.items()):
    for line in sorted(commands - shown.get(target, set())):
        errors.append(f"{target} runs `{line}` as a documented step, which no listed page or marked block shows")

for e in errors:
    print(f"check-e2e: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
