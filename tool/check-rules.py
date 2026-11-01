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
- an `#[allow]` of a lint the workspace denies, in production code, has a comment above it.
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
}
CFG_TARGET_OS = re.compile(r"cfg!?\s*\([^)]*target_os")
PRINT = re.compile(r"\b(e?println!|e?print!|dbg!)")
BARE_IS_ERR = re.compile(r"\b(prop_)?assert!\(.*\.is_err\(\)")
BARE_FAILURE = re.compile(r"assert!\(!.*\.success\(\)")
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
            "/tests/" in rel or crate.name == "writ-integration" or rel in TEST_SUPPORT
        )
        lines = text.splitlines()
        in_tests = test_file
        for number, line in enumerate(lines, 1):
            code = line.split("//", 1)[0]
            # A marker comment may sit up to three lines above (a comment over two lines).
            previous = " ".join(lines[i].strip() for i in range(max(0, number - 4), number - 1))
            if line.strip().startswith("#[cfg(test)]"):
                # By convention the tests module ends the file: the rest is test code.
                in_tests = True
            if CFG_TARGET_OS.search(code) and not platform_ok:
                errors.append(f"{rel}:{number}: #[cfg(target_os)] outside the platform crates")
            if library_src and rel not in PRINT_ALLOWED and PRINT.search(code):
                errors.append(f"{rel}:{number}: a library logs with tracing, not print macros")
            if in_tests and BARE_IS_ERR.search(code) and "any error:" not in previous:
                errors.append(
                    f"{rel}:{number}: assert the exact error, not is_err() "
                    "(or say why any error will do in a `// any error:` comment above)"
                )
            if in_tests and BARE_FAILURE.search(code):
                errors.append(f"{rel}:{number}: assert the exact exit code, not !success()")
            if not in_tests and LOCK_SKIP.search(code) and "poisoned:" not in previous:
                errors.append(
                    f"{rel}:{number}: a poisoned lock must not silently skip work "
                    "(fail closed, recover the data, or say why in a `// poisoned:` comment)"
                )
            if in_tests and SLEEP.search(code) and "poll:" not in previous:
                errors.append(
                    f"{rel}:{number}: no sleep in tests: wait for a signal "
                    "(or say what is polled in a `// poll:` comment above)"
                )
            if not in_tests and RELATIVE_COMMAND.search(code) and "PATH:" not in previous:
                errors.append(
                    f"{rel}:{number}: run programs by absolute path, or say why PATH is trusted "
                    "in a `// PATH:` comment above"
                )
            above = lines[number - 2].strip() if number >= 2 else ""
            if not in_tests and DENIED_ALLOW.search(code) and not above.startswith("//"):
                errors.append(f"{rel}:{number}: an #[allow] of a denied lint says why, above it")

for e in errors:
    print(f"check-rules: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
