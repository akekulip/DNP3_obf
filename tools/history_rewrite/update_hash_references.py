#!/usr/bin/env python3
"""Rewrite the commit hashes this repository quotes in its own prose, after a history rewrite.

The rewrite leaves a two-column map of old and new hashes at `.git/filter-repo/commit-map`. Every
commit from the oldest rewritten one onward gets a new hash, so every hash quoted in a document
stops resolving: the frozen-tree comparisons against `8278346`, the `git show` commands that
recover the removed root documents, the reviewed-commit references, and the provenance chains in
`audit_current/`. This walks the tracked text files and substitutes each one, matching any
abbreviation of seven characters or more and replacing it with the same-length abbreviation of the
new hash.

    python3 tools/history_rewrite/update_hash_references.py            # dry run
    python3 tools/history_rewrite/update_hash_references.py --apply

It is deliberately conservative: it only touches hashes that appear in the map, so a hash that was
not rewritten, or a hex string that merely looks like one, is left alone.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

MAP = pathlib.Path(".git/filter-repo/commit-map")
SUFFIXES = {".md", ".txt", ".tex", ".py", ".sh", ".json"}
HEX = set("0123456789abcdef")


def load_map() -> dict[str, str]:
    if not MAP.exists():
        sys.exit("no commit map at %s; run the rewrite first" % MAP)
    out: dict[str, str] = {}
    for line in MAP.read_text().splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        old, new = parts
        if len(old) != 40 or set(old) - HEX:
            continue
        if old == new or set(new) == {"0"}:          # unchanged, or dropped
            continue
        out[old] = new
    return out


def main(apply: bool) -> int:
    mapping = load_map()
    print("commit map: %d rewritten commits" % len(mapping))
    files = [pathlib.Path(p) for p in
             subprocess.run(["git", "ls-files"], capture_output=True,
                            text=True).stdout.split()]
    changed = total = 0
    for f in files:
        if f.suffix not in SUFFIXES or not f.exists():
            continue
        try:
            text = original = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for old, new in mapping.items():
            for n in range(40, 6, -1):               # longest abbreviation first
                token = old[:n]
                if token in text:
                    text = text.replace(token, new[:n])
                    total += 1
        if text != original:
            changed += 1
            print("  %s %s" % ("updating" if apply else "would update", f))
            if apply:
                f.write_text(text)
    print("%d file(s), %d reference(s)" % (changed, total))
    if not apply:
        print("dry run; pass --apply to write")
    return 0


if __name__ == "__main__":
    sys.exit(main("--apply" in sys.argv))
