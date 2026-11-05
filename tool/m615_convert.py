#!/usr/bin/env python3
"""M6.1.5 helper (temporary, deleted when M6.1.5 closes): rewrites the mechanical uses of the
old ticket fields in test files, for tickets naming one repository.

  X.scope.committer_emails|committer_name|signing_key  -> X.common.<field>
  X.scope.operations|branches|force_push               -> om(&X).<field> / omega(&mut X).<field>
  X.text.expected_paths                                -> om(&X).expected_paths / omega(...)
  X.limits.max_signatures|max_pushes|max_push_size     -> om(&X).limits.<field> / omega(...)
  X.template                                           -> om(&X).template / omega(...)
  X.usage.signatures|pushes                            -> used(&mut X.usage).<field>

`omega(&mut X)` when the line assigns or calls a mutating method on it, `om(&X)` otherwise.
Usage: m615_convert.py <file>...
"""
import re
import sys

EXPR = r"((?:&mut\s+|&)?[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*?)"
MUT = re.compile(r"\s*(=[^=]|[+-]=|\.insert\(|\.remove\(|\.clear\(|\.extend\(|\.retain\()")


def repl_terms(line, field_re, suffix_fn):
    out, pos = "", 0
    for m in re.finditer(EXPR + field_re, line):
        expr = m.group(1).replace("&mut ", "").replace("&", "")
        rest = line[m.end():]
        mutating = bool(MUT.match(rest))
        helper = f"omega(&mut {expr})" if mutating else f"om(&{expr})"
        out += line[pos:m.start()] + helper + suffix_fn(m)
        pos = m.end()
    return out + line[pos:]


def convert(text):
    lines = text.split("\n")
    result = []
    for line in lines:
        line = re.sub(r"\.scope\.(committer_emails|committer_name|signing_key)\b", r".common.\1", line)
        line = repl_terms(line, r"\.scope\.(operations|branches|force_push)\b", lambda m: "." + m.group(2))
        line = repl_terms(line, r"\.text\.expected_paths\b", lambda m: ".expected_paths")
        line = repl_terms(line, r"\.limits\.(max_signatures|max_pushes|max_push_size)\b", lambda m: ".limits." + m.group(2))
        line = repl_terms(line, r"\.template\b(?!\()", lambda m: ".template")
        line = re.sub(r"\b([A-Za-z_][\w\.]*?)\.usage\.(signatures|pushes)\b", r"used(&mut \1.usage).\2", line)
        result.append(line)
    return "\n".join(result)


for path in sys.argv[1:]:
    with open(path) as f:
        text = f.read()
    new = convert(text)
    if new != text:
        with open(path, "w") as f:
            f.write(new)
        print("converted", path)
