#!/usr/bin/env python3
"""Verify that Dr. Lin's protected text from his 2026-10 draft is installed word for word.

The source of truth is lin_draft/main_20261019.tex, his LaTeX draft as supplied on 2026-10-19
(hashes in lin_draft/SOURCES.sha256). Protected text is every paragraph of his Introduction,
Background and NOMAD Design Overview that is not marked [Archive], except the two parts Philip
asked to be rewritten: the Introduction paragraph that begins "Unlike previous solutions" and the
contribution list after it. Sections IV onward of the draft are [Archive] and are not protected.

Comparison ignores what installation may legitimately change and nothing else: LaTeX comments,
citation and cross-reference commands (\\cite, \\ref, \\label: a key or a filled reference is not
his prose), font commands (\\textit{x} becomes x), list markup and whitespace. Every word and every
punctuation mark of his prose must appear, in order, as one contiguous run in the manuscript.

    python3 check_lin_verbatim.py              -> exit 0 if every protected paragraph is present
    python3 check_lin_verbatim.py --list       -> print the protected paragraphs
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]
SOURCE = PAPER / "lin_draft" / "main_20261019.tex"
PROTECTED_SECTIONS = ("Introduction", "Background", "NOMAD Design Overview")
REWRITE_FROM = "Unlike previous solutions"


def strip_comments(tex: str) -> str:
    out = []
    for line in tex.splitlines():
        cut = re.search(r"(?<!\\)%", line)
        if cut:
            if not line[:cut.start()].strip():
                continue                      # a comment-only line does not end a paragraph
            line = line[:cut.start()]
        out.append(line)
    return "\n".join(out)


def normalize(text: str) -> list[str]:
    text = re.sub(r"\\(?:cite|ref|label|eqref)\{[^}]*\}", " ", text)
    text = re.sub(r"\\(?:textit|textbf|emph|textrm|mathrm)\{([^{}]*)\}", r"\1", text)
    text = re.sub(r"\\(?:begin|end)\{[^}]*\}(?:\[[^\]]*\])?", " ", text)
    text = re.sub(r"\\item\b", " ", text)
    text = text.replace("\\%", "%").replace("~", " ").replace("``", '"').replace("''", '"')
    text = re.sub(r"\s+([,.;:)])", r"\1", text)
    return text.split()


def protected_paragraphs() -> list[str]:
    body = strip_comments(SOURCE.read_text())
    body = body.split("\\begin{document}", 1)[1]
    paras, section, in_figure = [], None, False
    for block in re.split(r"\n\s*\n", body):
        block = block.strip()
        if not block:
            continue
        head = re.match(r"(?:\\textbf\{\[Archive\]\})?\\section\*?\{([^}]*)\}", block)
        if head:
            section = None if "[Archive]" in block[:40] else head.group(1).strip()
            block = block[head.end():].strip()
            if not block:
                continue
        if section not in PROTECTED_SECTIONS:
            continue
        if section == "Introduction" and block.startswith(REWRITE_FROM):
            section = "Introduction (rewritten)"
            continue
        if "[Archive]" in block or block.startswith("\\begin{figure}") or in_figure:
            in_figure = block.startswith("\\begin{figure}") and "\\end{figure}" not in block
            continue
        block = re.sub(r"^\\subsection\*?\{[^}]*\}\s*", "", block).strip()
        if block and normalize(block):
            paras.append(block)
    return paras


def manuscript_tokens() -> list[str]:
    main = (PAPER / "main.tex").read_text()
    parts = [main]
    for name in re.findall(r"\\input\{(sections/[^}]+)\}", main):
        path = PAPER / (name if name.endswith(".tex") else name + ".tex")
        parts.append(path.read_text())
    return normalize(strip_comments("\n".join(parts)))


def contains(hay: list[str], needle: list[str]) -> bool:
    n = len(needle)
    first = needle[0]
    return any(hay[i:i + n] == needle for i, t in enumerate(hay) if t == first)


def main() -> int:
    paras = protected_paragraphs()
    if "--list" in sys.argv:
        for i, p in enumerate(paras, 1):
            print("[%d] %s\n" % (i, " ".join(normalize(p))))
        return 0
    hay = manuscript_tokens()
    missing = []
    for i, p in enumerate(paras, 1):
        words = normalize(p)
        ok = contains(hay, words)
        print("  [%2d] %-8s %3d words  %s" % (i, "VERBATIM" if ok else "MISSING", len(words), " ".join(words[:8])))
        if not ok:
            missing.append(i)
    if missing:
        print("LIN VERBATIM CHECK: FAIL  (%d of %d protected paragraphs not found word for word: %s)"
              % (len(missing), len(paras), missing))
        return 1
    print("LIN VERBATIM CHECK: PASS  (%d protected paragraphs word for word)" % len(paras))
    return 0


if __name__ == "__main__":
    sys.exit(main())
