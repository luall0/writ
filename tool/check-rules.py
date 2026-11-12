#!/usr/bin/env python3
"""Checks source rules of AGENTS.md and docs/conventions.md that the compiler doesn't:

- no `#[cfg(target_os ...)]` outside the platform crates and writd/src/platform.rs (rule 4);
- no `println!` / `eprintln!` in library crates: they log with `tracing` (conventions);
- no `mod.rs` outside `tests/common/` (module layout);
- every crate has a README.md: what it does and its scope (conventions);

and the security rules of docs/security.md:
- a test never asserts a bare `.is_err()` (the exact error, or a `// any error: <why>`
  comment on the line before) nor a bare `!….success()` (the exact exit code);
- no `if let Ok(… .lock())` that silently skips work on a poisoned lock, unless a
  `// poisoned: <why>` comment says why skipping is the safe side;
- no sleep in test code, unless a `// poll: <why>` comment says what it waits for;
- production code runs external programs by absolute path, or says why `PATH` is trusted in
  a `// PATH: <why>` comment;
- an `#[allow]` of a lint the workspace denies, in production code, has a comment above it;
- every binary's global allocator is the wiping one (`writ_alloc::Wiping`).
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"
BINARIES = {"writd", "writ-cli", "writ-sign"}
# Files that are a program's own output, not a library's logs.
PRINT_ALLOWED = {
    # The pre-receive hook runs as its own process; git shows its stderr to the agent.
    "crates/writ-gateway/src/hook/client.rs",
    # The upstream relay runs as its own process (git's ssh); git shows its stderr.
    "crates/writ-mirror/src/relay.rs",
    # The upstream credential helper runs as its own process (git's); git shows its stderr.
    "crates/writ-mirror/src/credential/helper.rs",
    # The upstream tunnel runs as its own process (ssh's ProxyCommand); git shows its stderr.
    "crates/writ-mirror/src/tunnel.rs",
}
CFG_TARGET_OS = re.compile(r"cfg!?\s*\([^)]*target_os")
PRINT = re.compile(r"\b(e?println!|e?print!|dbg!)")
BARE_IS_ERR = re.compile(r"\b(prop_)?assert!\(.*\.is_err\(\)", re.S)
BARE_FAILURE = re.compile(r"\bassert!\(\s*!.*\.success\(\)", re.S)
ASSERT_START = re.compile(r"\b(prop_)?assert!\(")
GIT_RUN = re.compile(r'Command::new\("git"\)')
GIT_ISOLATED = re.compile(r"env_clear|GIT_CONFIG_GLOBAL|GIT_CONFIG_NOSYSTEM")
STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def assertion(lines, start):
    """The `assert!(...)` starting at line `start` (0-based), whole: its lines joined until its
    parentheses close (string literals left out, so a parenthesis in one doesn't count)."""
    text, depth = "", 0
    for line in lines[start:start + 40]:
        code = STRING.sub('""', line.split("//", 1)[0])
        text += " " + code
        depth += code.count("(") - code.count(")")
        if depth <= 0 and "assert" in text:
            break
    return text


def next_item(lines, number):
    """The 0-based index of the first line after line `number` (1-based) that isn't an
    attribute or a comment: the item a `#[cfg(test)]` applies to."""
    for i in range(number, min(len(lines), number + 20)):
        stripped = lines[i].strip()
        if stripped and not stripped.startswith(("#[", "//")):
            return i
    return None


def item_end(lines, start):
    """The 0-based index of the last line of the item starting at `start`: where its braces
    close, or its first line if it has none before a `;`."""
    depth, seen = 0, False
    for i in range(start, len(lines)):
        code = STRING.sub('""', lines[i].split("//", 1)[0])
        depth += code.count("{") - code.count("}")
        seen = seen or "{" in code
        if (seen and depth <= 0) or (not seen and code.rstrip().endswith(";")):
            return i
    return len(lines) - 1
LOCK_SKIP = re.compile(r"if let Ok\(.*\.lock\(\)")
SLEEP = re.compile(r"\b(thread|time)::sleep\(")
RELATIVE_COMMAND = re.compile(r'Command::new\("[^/"][^"]*"\)')
DENIED_ALLOW = re.compile(
    r"#!?\[allow\(.*clippy::(indexing_slicing|string_slice|cast_possible_truncation|"
    r"arithmetic_side_effects|unwrap_used|expect_used|panic)"
)
# Test support compiled behind the `testing` feature or test-only crates: test code.
TEST_SUPPORT = {
    "crates/writ-platform/src/contract.rs",
    "crates/writ-platform/src/testing.rs",
    "crates/writ-approval/src/testing.rs",
    "crates/writ-signer/src/contract.rs",
    "crates/writ-signer/src/testing.rs",
}

errors = []
for crate in sorted(p for p in CRATES.iterdir() if p.is_dir()):
    if not (crate / "README.md").is_file():
        errors.append(f"{crate.relative_to(ROOT)}: no README.md (what it does, its scope)")
    for path in sorted(crate.rglob("*.rs")):
        rel = path.relative_to(ROOT).as_posix()
        if "/target/" in rel:
            continue
        if path.name == "mod.rs" and "/tests/common/" not in rel:
            errors.append(f"{rel}: use `name.rs` + `name/`, not mod.rs")
        text = path.read_text()
        platform_ok = crate.name.startswith("writ-platform") or rel == "crates/writd/src/platform.rs"
        library_src = crate.name not in BINARIES and "/src/" in rel
        test_file = (
            "/tests/" in rel
            or crate.name in ("writ-integration", "writ-e2e")
            or rel in TEST_SUPPORT
        )
        lines = text.splitlines()
        in_tests = test_file
        # The last line of a `#[cfg(test)]` item that isn't the test module (a helper): test
        # code up to there only, never the rest of the file.
        test_item_end = 0
        for number, line in enumerate(lines, 1):
            code = line.split("//", 1)[0]
            # A marker comment may sit up to three lines above (a comment over two lines).
            previous = " ".join(lines[i].strip() for i in range(max(0, number - 4), number - 1))
            if line.strip().startswith("#[cfg(test)]"):
                item = next_item(lines, number)
                if item is not None and lines[item].strip().startswith("mod "):
                    # By convention the tests module ends the file: the rest is test code.
                    in_tests = True
                elif item is not None:
                    test_item_end = item_end(lines, item) + 1
            testing = in_tests or number <= test_item_end
            # Asserts are read whole: rustfmt splits a long one over several lines.
            statement = assertion(lines, number - 1) if ASSERT_START.search(code) else ""
            if CFG_TARGET_OS.search(code) and not platform_ok:
                errors.append(f"{rel}:{number}: #[cfg(target_os)] outside the platform crates")
            if library_src and rel not in PRINT_ALLOWED and PRINT.search(code):
                errors.append(f"{rel}:{number}: a library logs with tracing, not print macros")
            if testing and BARE_IS_ERR.search(statement) and "any error:" not in previous:
                errors.append(
                    f"{rel}:{number}: assert the exact error, not is_err() "
                    "(or say why any error will do in a `// any error:` comment above)"
                )
            if testing and BARE_FAILURE.search(statement):
                errors.append(f"{rel}:{number}: assert the exact exit code, not !success()")
            if not testing and LOCK_SKIP.search(code) and "poisoned:" not in previous:
                errors.append(
                    f"{rel}:{number}: a poisoned lock must not silently skip work "
                    "(fail closed, recover the data, or say why in a `// poisoned:` comment)"
                )
            # A test's git never reads the user's own config (hard rule 8): the environment
            # cleared, or the global and system configs cut off, within the command's builder.
            window = " ".join(lines[number - 1:number + 13])
            if testing and GIT_RUN.search(code) and not GIT_ISOLATED.search(window):
                errors.append(
                    f"{rel}:{number}: a test's git reads the user's config: clear its "
                    "environment or set GIT_CONFIG_GLOBAL and GIT_CONFIG_NOSYSTEM"
                )
            if testing and SLEEP.search(code) and "poll:" not in previous:
                errors.append(
                    f"{rel}:{number}: no sleep in tests: wait for a signal "
                    "(or say what is polled in a `// poll:` comment above)"
                )
            if not testing and RELATIVE_COMMAND.search(code) and "PATH:" not in previous:
                errors.append(
                    f"{rel}:{number}: run programs by absolute path, or say why PATH is trusted "
                    "in a `// PATH:` comment above"
                )
            above = lines[number - 2].strip() if number >= 2 else ""
            if not testing and DENIED_ALLOW.search(code) and not above.startswith("//"):
                errors.append(f"{rel}:{number}: an #[allow] of a denied lint says why, above it")

# Every binary frees through the wiping allocator, so no library's freed copy of a secret stays
# in memory (docs/security.md#secrets); its test proves it at run time, this that it is set.
GLOBAL_ALLOCATOR = re.compile(
    r"^#\[global_allocator\]\nstatic ALLOCATOR: writ_alloc::Wiping = writ_alloc::Wiping::system\(\);$",
    re.M,
)
for binary in sorted(BINARIES):
    main = CRATES / binary / "src" / "main.rs"
    if not GLOBAL_ALLOCATOR.search(main.read_text()):
        errors.append(
            f"{main.relative_to(ROOT)}: the global allocator must be writ_alloc::Wiping::system()"
        )

# The rules above treat everything after `#[cfg(test)]` as test code, so a test module must
# end its file: production code after it would escape them.
for path in sorted(CRATES.rglob("*.rs")):
    rel = path.relative_to(ROOT).as_posix()
    if "/target/" in rel or "/tests/" in rel:
        continue
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if not (line.strip().startswith("#[cfg(test)]") and nxt.startswith("mod ") and nxt.endswith("{")):
            continue
        depth, end = 0, i + 1
        for end in range(i + 1, len(lines)):
            depth += lines[end].count("{") - lines[end].count("}")
            if depth == 0:
                break
        trailing = [n for n in range(end + 1, len(lines)) if lines[n].strip()]
        if trailing:
            errors.append(f"{rel}:{trailing[0] + 1}: code after the test module (it must end the file)")

for e in errors:
    print(f"check-rules: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
