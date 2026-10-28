"""Locations shared by the local paper build and its checks."""
from __future__ import annotations

import json
from pathlib import Path

PAPER = Path(__file__).resolve().parent.parent
REPO = PAPER.parent
RESULTS = REPO / "results" / "paper"


def latest_build() -> Path:
    pointer = RESULTS / "latest.json"
    if not pointer.is_file():
        return RESULTS / "not_built"
    build = (REPO / json.loads(pointer.read_text())["build_directory"]).resolve()
    if RESULTS.resolve() not in build.parents:
        raise ValueError("paper build pointer escapes results/paper")
    return build
