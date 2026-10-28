#!/usr/bin/env python3
"""Record or check one local build, without making a second copy of its PDF.

    python3 paper/pipeline/publish_manuscript.py --build-dir results/paper/BUILD --update
    python3 paper/pipeline/publish_manuscript.py  # check the latest successful build

The PDF, its sidecar, source digest and gate reports live in the same build directory.
This command writes local records only; it does not upload or publish externally.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from paths import PAPER, REPO, RESULTS, latest_build


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def source_files() -> list[Path]:
    """All checked-in inputs needed to build the current manuscript."""
    sources = [PAPER / "main.tex", PAPER / "References.bib", PAPER / "IEEEtran.cls"]
    sources += sorted((PAPER / "sections").glob("*.tex"))
    sources += sorted((PAPER / "tables").glob("*.tex"))
    text = "\n".join(p.read_text() for p in sources if p.suffix == ".tex")
    for stem in re.findall(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", text):
        candidates = [PAPER / (stem + suffix) for suffix in ("", ".pdf", ".png")]
        figure = next((p for p in candidates if p.is_file()), None)
        if figure is None:
            raise FileNotFoundError(f"included figure not found: {stem}")
        sources.append(figure)
    return sorted(set(sources))


def source_digest(files: list[Path]) -> str:
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(str(path.relative_to(PAPER)).encode() + b"\0")
        h.update(sha256(path).encode() + b"\n")
    return h.hexdigest()


def git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True,
                            text=True, timeout=30)
    return result.stdout.strip() if result.returncode == 0 else ""


def record(build: Path) -> dict:
    pdf = build / "main.pdf"
    gate = json.loads((build / "lin_check.json").read_text())
    if gate.get("exit_code") != 0 or not gate.get("checks"):
        raise ValueError("a successful manuscript gate is required")
    files = source_files()
    return {
        "pdf": str(pdf.relative_to(REPO)),
        "sha256": sha256(pdf),
        "source_digest_sha256": source_digest(files),
        "source_files": {str(p.relative_to(PAPER)): sha256(p) for p in files},
        "built_from_commit": git("rev-parse", "HEAD"),
        "working_tree_clean_at_build": (git("status", "--porcelain") == "")
                                      if git("rev-parse", "--is-inside-work-tree") else None,
        "built_by": "paper/pipeline/build.sh (offline Tectonic, style and protected-text gates)",
        "lin_gate": "PASS",
        "note": "A local manuscript build; venue submission readiness is checked separately.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    build = (args.build_dir or latest_build()).resolve()
    if RESULTS.resolve() not in build.parents:
        parser.error("build directory must be inside results/paper")
    manifest = build / "PDF_MANIFEST.json"
    sidecar = build / "main.pdf.sha256"
    current = record(build)
    if args.update:
        manifest.write_text(json.dumps(current, indent=2) + "\n")
        sidecar.write_text(f"{current['sha256']}  main.pdf\n")
        RESULTS.mkdir(parents=True, exist_ok=True)
        (RESULTS / "latest.json").write_text(json.dumps({
            "build_directory": str(build.relative_to(REPO)),
        }, indent=2) + "\n")
        print(f"recorded {build.relative_to(REPO)}/PDF_MANIFEST.json")
        return 0
    saved = json.loads(manifest.read_text())
    problems = [key for key in ("sha256", "source_digest_sha256", "source_files")
                if saved.get(key) != current[key]]
    if sidecar.read_text().split()[0] != current["sha256"]:
        problems.append("main.pdf.sha256")
    if problems:
        print("[FAIL] build records disagree: " + ", ".join(problems))
        return 1
    print(f"[PASS] {build.relative_to(REPO)} PDF, records and current sources agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
