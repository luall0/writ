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
- every binary's global allocator is the wiping one (`writ_alloc::Wiping`);
- every crate inherits the workspace lints (`[lints] workspace = true`), and the six crates
  that parse untrusted bytes keep their `#![deny(clippy::arithmetic_side_effects)]`;
- the shipped binaries listed here are every crate with a `src/main.rs` (a new one is seen);
- a `#[cfg(test)] mod` is closed and ends its file (strings and characters left out of the
  count), however its attributes are spelled.
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
    # The passphrase's prompt, on the terminal the passphrase is typed on (never a log).
    "crates/writ-crypto/src/passphrase.rs",
}
# Rule 4: any cfg on the OS (cfg, cfg!, cfg_attr), by name or by family.
CFG_TARGET_OS = re.compile(
    r"\bcfg(?:_attr)?!?\s*\([^)]*\b(?:target_os|target_family|target_vendor|target_env|unix|windows)\b"
)
PRINT = re.compile(r"\b(e?println!|e?print!|dbg!)|\b(?:std::)?io::std(?:err|out)\(\)")
BARE_IS_ERR = re.compile(r"\b(prop_)?assert!\(.*\.is_err\(\)", re.S)
BARE_FAILURE = re.compile(
    r"\bassert!\(\s*!.*\.success\(\)|\bassert_ne!\(.*\.code\(\)\s*,\s*Some\(0\)", re.S
)
ASSERT_START = re.compile(r"\b(prop_)?assert(_ne)?!\(")
GIT_RUN = re.compile(r'Command::new\("git"\)')
GIT_ISOLATED = re.compile(r"env_clear|GIT_CONFIG_GLOBAL|GIT_CONFIG_NOSYSTEM")
STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
# A character literal ('{', '\''): left out of brace counts like strings (never a lifetime).
CHAR = re.compile(r"'(?:[^'\\]|\\.)'")


def code_only(line: str) -> str:
    """A line without its comment, strings and character literals."""
    return CHAR.sub("' '", STRING.sub('""', line.split("//", 1)[0]))


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


def code_braces(lines, start):
    """Yields (0-based line, character) for each brace or `;` of the code from line `start`
    on, as Rust reads it: never one inside a comment (line or nested block), a string (with
    its escapes, over several lines), a raw string (`r#"…"#`) or a character literal (a
    lifetime is none)."""
    text = "\n".join(lines[start:])
    i, line, n = 0, start, len(text)
    block = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "\n":
            line += 1
            i += 1
            continue
        if block:
            if c == "/" and nxt == "*":
                block, i = block + 1, i + 2
            elif c == "*" and nxt == "/":
                block, i = block - 1, i + 2
            else:
                i += 1
            continue
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and nxt == "*":
            block, i = 1, i + 2
            continue
        raw = re.match(r'b?r(#*)"', text[i:i + 260]) if c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) else None
        if raw:
            close = '"' + raw.group(1)
            end = text.find(close, i + len(raw.group(0)))
            end = n if end == -1 else end + len(close)
            line += text.count("\n", i, end)
            i = end
            continue
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                if i < n and text[i] == "\n":
                    line += 1
                i += 1
            i += 1
            continue
        if c == "'":
            char = re.match(r"'(?:[^'\\\n]|\\(?:[^u]|u\{[0-9a-fA-F]+\}))'", text[i:i + 16])
            if char:
                i += len(char.group(0))
                continue
        if c in "{};":
            yield line, c
        i += 1


def item_end(lines, start):
    """The 0-based index of the last line of the item starting at `start`: where its braces
    close, or its first line if it has none before a `;`; none when its braces never close."""
    depth, seen = 0, False
    for number, c in code_braces(lines, start):
        if c == ";" and not seen:
            return number
        if c == "{":
            depth, seen = depth + 1, True
        elif c == "}":
            depth -= 1
            if seen and depth <= 0:
                return number
    return None
LOCK_SKIP = re.compile(r"if let Ok\(.*\.lock\(\)")
# A sleep however it is reached: `thread::sleep(`, an imported `sleep(`, `sleep_until(`.
SLEEP = re.compile(r"\b(thread|time)::sleep(_until)?\(|(?<![\w:.])sleep(_until)?\(")
RELATIVE_COMMAND = re.compile(r'Command::new\("[^/"][^"]*"\)')
# A `const NAME: &str = "relative";`, then `Command::new(NAME)`.
RELATIVE_CONST = re.compile(r'\bconst\s+([A-Z_][A-Z0-9_]*)\s*:\s*&(?:\'static\s+)?str\s*=\s*"([^/"][^"]*)"')
DENIED_ALLOW = re.compile(
    r"#!?\[(?:cfg_attr\(.*?,\s*)?(?:allow|expect)\(.*(?:clippy::(?:indexing_slicing|string_slice|"
    r"cast_possible_truncation|arithmetic_side_effects|unwrap_used|expect_used|panic|"
    r"undocumented_unsafe_blocks)|\bunsafe_code\b)"
)
# Test support compiled behind the `testing` feature or test-only crates: test code.
TEST_SUPPORT = {
    "crates/writ-platform/src/contract.rs",
    "crates/writ-platform/src/testing.rs",
    "crates/writ-approval/src/testing.rs",
    "crates/writ-signer/src/contract.rs",
    "crates/writ-signer/src/testing.rs",
    "crates/writ-signer/src/bin/writ-fake-se.rs",
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
        relative_consts = [m.group(1) for m in RELATIVE_CONST.finditer(text)]
        const_command = (
            re.compile(r"Command::new\(\s*(?:" + "|".join(relative_consts) + r")\s*\)")
            if relative_consts
            else None
        )
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
                    end = item_end(lines, item)
                    test_item_end = (len(lines) if end is None else end) + 1
            testing = in_tests or number <= test_item_end
            # Asserts are read whole: rustfmt splits a long one over several lines.
            statement = assertion(lines, number - 1) if ASSERT_START.search(code) else ""
            if CFG_TARGET_OS.search(code) and not platform_ok:
                errors.append(f"{rel}:{number}: a cfg on the OS (target_os, unix, target_family…) outside the platform crates")
            if library_src and rel not in PRINT_ALLOWED and not test_file and PRINT.search(code):
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
            relative = RELATIVE_COMMAND.search(code) or (const_command and const_command.search(code))
            if not testing and relative and "PATH:" not in previous:
                errors.append(
                    f"{rel}:{number}: run programs by absolute path, or say why PATH is trusted "
                    "in a `// PATH:` comment above"
                )
            # The comment above the attribute, past the attributes between them.
            k = number - 2
            while k >= 0 and lines[k].strip().startswith("#["):
                k -= 1
            above = lines[k].strip() if k >= 0 else ""
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

# The rules above treat everything after `#[cfg(test)]` + `mod` as test code, so a test
# module must end its file: production code after it would escape them. The module is found
# as the main loop finds it (attributes between them skipped), and closed with strings and
# characters left out of the count; one that never closes is refused.
for path in sorted(CRATES.rglob("*.rs")):
    rel = path.relative_to(ROOT).as_posix()
    if "/target/" in rel or "/tests/" in rel:
        continue
    lines = path.read_text().splitlines()
    for i, line in enumerate(lines):
        if not line.strip().startswith("#[cfg(test)]"):
            continue
        item = next_item(lines, i + 1)
        if item is None or not lines[item].strip().startswith("mod "):
            continue
        if code_only(lines[item]).rstrip().endswith(";"):
            continue  # `mod tests;`: its own file
        end = item_end(lines, item)
        if end is None:
            errors.append(f"{rel}:{item + 1}: a test module that never closes")
            continue
        trailing = [n for n in range(end + 1, len(lines)) if lines[n].strip()]
        if trailing:
            errors.append(f"{rel}:{trailing[0] + 1}: code after the test module (it must end the file)")

# Every crate inherits the workspace's lints: without `[lints] workspace = true` it loses every
# deny (unwrap, panic, indexing, unsafe_code) silently.
for crate in sorted(p for p in CRATES.iterdir() if p.is_dir()):
    manifest = crate / "Cargo.toml"
    if manifest.is_file() and not re.search(r"^\[lints\]\s*\nworkspace\s*=\s*true\s*$", manifest.read_text(), re.M):
        errors.append(f"{manifest.relative_to(ROOT)}: no `[lints]` `workspace = true`")
# The crates that parse untrusted bytes and compute limits: no unchecked arithmetic.
for name in ("writ-core", "writ-crypto", "writ-proto", "writ-git", "writ-mirror", "writ-gateway"):
    lib = CRATES / name / "src" / "lib.rs"
    if not lib.is_file() or not re.search(r"^#!\[deny\(clippy::arithmetic_side_effects\)\]$", lib.read_text(), re.M):
        errors.append(f"{lib.relative_to(ROOT)}: lost `#![deny(clippy::arithmetic_side_effects)]`")
# The binaries the rules above know are every crate with a `src/main.rs`.
mains = {p.parent.parent.name for p in CRATES.glob("*/src/main.rs")} - {"writ-integration", "writ-e2e"}
if mains != BINARIES:
    errors.append(
        f"tool/check-rules.py BINARIES is {sorted(BINARIES)}, the crates with a src/main.rs are "
        f"{sorted(mains)}: a shipped binary is to be listed (here and in check-features.py)"
    )

# The Rust toolchain is pinned in three places: rust-toolchain.toml, the e2e image (its base
# image's tag and RUSTUP_TOOLCHAIN, which overrides the file) and the allocator benchmark's
# Linux container (docs/guides/dependency-upgrades.md#the-rust-toolchain). They must agree.
channel = re.search(r'^channel = "([^"]+)"$', (ROOT / "rust-toolchain.toml").read_text(), re.M)
if not channel:
    errors.append("rust-toolchain.toml: no exact channel")
else:
    version = channel.group(1)
    for rel, needles in [
        ("e2e/Dockerfile", [f"rust:{version}-", f"RUSTUP_TOOLCHAIN={version}"]),
        ("tool/bench-alloc.py", [f"RUSTUP_TOOLCHAIN={version}"]),
    ]:
        target = ROOT / rel
        found = target.read_text() if target.is_file() else ""
        for needle in needles:
            if needle not in found:
                errors.append(f"{rel}: not on the toolchain rust-toolchain.toml pins ({needle} missing)")

for e in errors:
    print(f"check-rules: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
