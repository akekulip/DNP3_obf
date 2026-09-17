#!/usr/bin/env python3
"""Synchronise the tracked manuscript PDF and every record that describes it, in one step.

Why this exists
---------------
`build.sh` writes `pipeline/build/main.pdf`. The tracked copy at `paper/rewrite/main.pdf`, its
sidecar `main.pdf.sha256` and `PDF_MANIFEST.json` were each updated by hand, and on 2026-09-17 a
review found the sidecar still naming a PDF two builds old while the manifest named the current
one. A record that disagrees with the file it describes is worse than no record, so all three are
now written together by this script and checked together by its `--check` mode.

    python3 pipeline/publish_manuscript.py            # check; non-zero if anything disagrees
    python3 pipeline/publish_manuscript.py --update   # copy the build and rewrite both records

What is recorded
----------------
Besides the PDF's own hash, the manifest carries a **source digest**: one hash over `main.tex`,
every file under `sections/`, and every figure the document includes. That is what makes staleness
detectable without trusting a commit message, because a source edit changes the digest whether or
not anyone committed it. The commit is recorded too, with the working tree's cleanliness, since a
commit alone does not say whether the PDF was built before or after the last edit.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
REPO = PAPER.parent.parent
BUILT = HERE / "build" / "main.pdf"
TRACKED = PAPER / "main.pdf"
SIDECAR = PAPER / "main.pdf.sha256"
MANIFEST = PAPER / "PDF_MANIFEST.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def source_files() -> list[Path]:
    """Everything the PDF is built from: the document, its sections and its figures."""
    out = [PAPER / "main.tex"]
    out += sorted((PAPER / "sections").glob("*.tex"))
    text = "\n".join(p.read_text() for p in out if p.exists())
    for stem in re.findall(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", text):
        for suffix in ("", ".pdf", ".png"):
            cand = PAPER / (stem + suffix)
            if cand.is_file():
                out.append(cand)
                break
    return [p for p in out if p.is_file()]


def source_digest(files: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(files):
        h.update(str(p.relative_to(PAPER)).encode())
        h.update(b"\0")
        h.update(sha256(p).encode())
        h.update(b"\n")
    return h.hexdigest()


def git(*args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True,
                              text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def page_count(pdf: Path) -> int | None:
    out = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout
    m = re.search(r"^Pages:\s+(\d+)", out, re.M)
    return int(m.group(1)) if m else None


def gate_state() -> dict:
    """The most recent gate report and the venue preflight, as they actually stand."""
    reports = sorted((HERE / "reports").glob("main_*.json"))
    gate = "no gate report found"
    if reports:
        try:
            data = json.loads(reports[-1].read_text())
            hard = [c for c in data.get("checks", [])
                    if c.get("hard") and c.get("status") != "PASS"]
            gate = "PASS (no hard-check failures)" if not hard else \
                   "FAIL: " + ", ".join(c.get("name", "?") for c in hard)
        except Exception as exc:                              # a malformed report is not a pass
            gate = f"unreadable gate report: {exc}"
    pre = subprocess.run([sys.executable, str(HERE / "ndss_preflight.py")],
                         capture_output=True, text=True, cwd=str(REPO))
    line = next((l.strip() for l in pre.stdout.splitlines() if "page budget" in l), "")
    verdict = "PASS" if pre.returncode == 0 else re.sub(r"\s+", " ", line) or "FAIL"
    return {"lin_gate": gate, "venue_preflight": verdict}


def build_manifest(files: list[Path]) -> dict:
    return {
        "what": "the tracked PDF at paper/rewrite/main.pdf",
        "sha256": sha256(TRACKED),
        "pages": page_count(TRACKED),
        "source_digest_sha256": source_digest(files),
        "source_files": len(files),
        "built_from_commit": git("rev-parse", "HEAD"),
        "working_tree_clean_at_publish": git("status", "--porcelain") == "",
        "built_by": ("paper/rewrite/pipeline/build.sh, which writes pipeline/build/main.pdf; "
                     "this file is a copy published by pipeline/publish_manuscript.py"),
        **gate_state(),
        "note": ("Every record here is written in one step, so the sidecar hash, the manifest and "
                 "the file cannot disagree. source_digest_sha256 covers main.tex, every section "
                 "and every included figure, so an edit after this publish is detectable without "
                 "trusting a commit. Whether this PDF is a submission candidate is said by "
                 "venue_preflight above, not assumed."),
    }


def main(update: bool) -> int:
    if update:
        if not BUILT.is_file():
            print("no build at %s; run pipeline/build.sh first" % BUILT, file=sys.stderr)
            return 2
        shutil.copy2(BUILT, TRACKED)
        SIDECAR.write_text("%s  main.pdf\n" % sha256(TRACKED))
        MANIFEST.write_text(json.dumps(build_manifest(source_files()), indent=1) + "\n")
        print("published main.pdf, main.pdf.sha256 and PDF_MANIFEST.json")
        print("  sha256        %s" % sha256(TRACKED))
        print("  source digest %s" % source_digest(source_files()))
        return 0

    problems = []
    if not TRACKED.is_file():
        print("main.pdf is missing", file=sys.stderr)
        return 1
    actual = sha256(TRACKED)
    side = SIDECAR.read_text().split()[0] if SIDECAR.is_file() else "(missing)"
    if side != actual:
        problems.append("main.pdf.sha256 says %s, the file is %s" % (side[:12], actual[:12]))
    man = json.loads(MANIFEST.read_text()) if MANIFEST.is_file() else {}
    if man.get("sha256") != actual:
        problems.append("PDF_MANIFEST.json says %s, the file is %s"
                        % (str(man.get("sha256"))[:12], actual[:12]))
    digest = source_digest(source_files())
    if man.get("source_digest_sha256") != digest:
        problems.append("the source has changed since this PDF was published "
                        "(digest %s, manifest %s)"
                        % (digest[:12], str(man.get("source_digest_sha256"))[:12]))
    if BUILT.is_file() and sha256(BUILT) != actual:
        problems.append("pipeline/build/main.pdf differs from the tracked copy")
    for p in problems:
        print("[FAIL] %s" % p)
    if problems:
        print("run: python3 pipeline/publish_manuscript.py --update")
        return 1
    print("[PASS] main.pdf, its sidecar, the manifest and the source all agree")
    return 0


if __name__ == "__main__":
    sys.exit(main("--update" in sys.argv))
