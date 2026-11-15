#!/usr/bin/env python3
"""Checks that every relative link and #anchor in AGENTS.md, README.md, CHANGELOG.md, docs/ and the crates'
README.md files resolves."""

import glob
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
files = (
    [os.path.join(root, "AGENTS.md"), os.path.join(root, "README.md"), os.path.join(root, "CHANGELOG.md")]
    + glob.glob(os.path.join(root, "docs/**/*.md"), recursive=True)
    + glob.glob(os.path.join(root, "crates/*/README.md"))
)
def slug(h):
    h = h.strip().lower()
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")
def headings(path):
    found = set()
    in_code = False
    for line in open(path):
        if line.startswith("```"):
            in_code = not in_code
        if not in_code and (m := re.match(r"^#+ (.*)", line)):
            found.add(slug(m.group(1)))
    return found


anchors = {}
bad = 0
for f in files:
    text = open(f).read()
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    for m in re.finditer(r"\]\(([^)\s]+)\)", text):
        link = m.group(1)
        if link.startswith("http"): continue
        path, _, anc = link.partition("#")
        target = os.path.realpath(os.path.join(os.path.dirname(f), path)) if path else os.path.realpath(f)
        if os.path.isdir(target): target = os.path.join(target, "README.md")
        if not os.path.exists(target):
            print(f"check-links: {os.path.relpath(f, root)}: missing {link}", file=sys.stderr); bad += 1; continue
        if anc and target.endswith(".md") and target not in anchors:
            anchors[target] = headings(target)
        if anc and anc not in anchors.get(target, set()):
            print(f"check-links: {os.path.relpath(f, root)}: no heading for {link}", file=sys.stderr); bad += 1
sys.exit(1 if bad else 0)
