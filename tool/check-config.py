#!/usr/bin/env python3
"""Checks the configuration coverage registry (docs/testing.md#configuration-coverage-every-key):

- every row names at least one test, or the milestone its effect comes with (`planned: M9`);
- every test named is a test function of the integration crate (crates/writ-integration/tests/,
  not `#[ignore]`d) or an end-to-end scenario (crates/writ-e2e/tests/): a parser's unit test
  doesn't show a key's effect;
- a planned milestone is one the roadmap still lists, not one that is done;
- every `WRIT_*` environment variable a shipped binary reads has an `env:` row, and every
  `env:` row is one of them.

That every key of writd.yaml, policy.yaml and the ticket file has its row is checked by
`make test` (writd's `every_writd_yaml_key_is_in_the_operator_reference`, writ-core's
`every_policy_key_…` and `every_ticket_key_…`), from the parsers themselves.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTING = ROOT / "docs/testing.md"
ROADMAP = ROOT / "docs/roadmap.md"
TEST_DIRS = [ROOT / "crates/writ-integration/tests", ROOT / "crates/writ-e2e/tests"]
# The binaries' sources: the variables an operator or a user sets.
SOURCES = [ROOT / "crates/writd/src", ROOT / "crates/writ-cli/src", ROOT / "crates/writ-sign/src"]
# Set by the daemon for the pre-receive hook it starts, never by a person.
INTERNAL = {"WRIT_HOOK_SOCKET", "WRIT_HOOK_TOKEN"}
FILES = ("writd.yaml", "policy.yaml", "ticket", "env")

errors = []
text = TESTING.read_text()
start = text.find("\n## Configuration coverage: every key")
if start == -1:
    sys.exit("check-config: no configuration coverage registry in docs/testing.md")
end = text.find("\n## ", start + 1)
section = text[start:end if end != -1 else len(text)]

# Every test function of the integration and end-to-end crates: name → whether it is ignored
# outside the end-to-end pipeline.
tests: dict[str, bool] = {}
for directory in TEST_DIRS:
    for path in sorted(directory.rglob("*.rs")):
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            match = re.match(r"\s*(?:async\s+)?fn ([a-z0-9_]+)\s*\(", line)
            if not match:
                continue
            attrs = " ".join(l.strip() for l in lines[max(0, i - 4):i])
            if "#[test]" not in attrs:
                continue
            ignored = "#[ignore" in attrs and 'end to end: make e2e' not in attrs
            tests[match.group(1)] = ignored

# Milestones still to come: the roadmap's table rows not marked done.
pending = set()
for line in ROADMAP.read_text().splitlines():
    match = re.match(r"\| (M[0-9.]+) \|", line)
    if match and "✅" not in line:
        pending.add(match.group(1))

rows = 0
env_rows = set()
for line in section.splitlines():
    if not line.startswith("| `"):
        continue
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) != 2:
        errors.append(f"malformed row: {line}")
        continue
    key, cell = cells
    match = re.fullmatch(r"`([a-z.]+|env): ([^`]+)`", key)
    if not match or match.group(1) not in FILES:
        errors.append(f"malformed key {key}: `<{'|'.join(FILES)}>: <key>`")
        continue
    rows += 1
    if match.group(1) == "env":
        env_rows.add(match.group(2))
    names = re.findall(r"`([a-z0-9_]+)`", cell)
    planned = re.findall(r"planned: (M[0-9.]+)", cell)
    if not names and not planned:
        errors.append(f"{key}: names no test and no planned milestone")
    for name in names:
        if name not in tests:
            errors.append(
                f"{key}: `{name}` is no test in crates/writ-integration/tests or crates/writ-e2e/tests"
            )
        elif tests[name]:
            errors.append(f"{key}: `{name}` is #[ignore]d")
    for milestone in planned:
        if milestone not in pending:
            errors.append(f"{key}: planned for {milestone}, which the roadmap doesn't list as to come")
if rows < 50:
    errors.append(f"only {rows} rows: the registry moved or changed shape")

read = set()
for directory in SOURCES:
    for path in sorted(directory.rglob("*.rs")):
        read.update(re.findall(r'"(WRIT_[A-Z_]+)"', path.read_text()))
read -= INTERNAL
for missing in sorted(read - env_rows):
    errors.append(f"{missing} is read by a binary and has no `env: {missing}` row")
for extra in sorted(env_rows - read):
    errors.append(f"`env: {extra}` is a row, and no binary reads {extra}")

for e in errors:
    print(f"check-config: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
