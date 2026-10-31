#!/usr/bin/env python3
"""Checks source rules of AGENTS.md and docs/conventions.md that the compiler doesn't:

- no `#[cfg(target_os ...)]` outside the platform crates and writd/src/platform.rs (rule 4);
- no `println!` / `eprintln!` in library crates: they log with `tracing` (conventions);
- no `mod.rs` outside `tests/common/` (module layout);
- every crate has a README.md: what it does and its scope (conventions).
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
        for number, line in enumerate(text.splitlines(), 1):
            code = line.split("//", 1)[0]
            if CFG_TARGET_OS.search(code) and not platform_ok:
                errors.append(f"{rel}:{number}: #[cfg(target_os)] outside the platform crates")
            if library_src and rel not in PRINT_ALLOWED and PRINT.search(code):
                errors.append(f"{rel}:{number}: a library logs with tracing, not print macros")

for e in errors:
    print(f"check-rules: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
