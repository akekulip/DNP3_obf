"""Shared loading for the timing figures: resolve paths, read CSVs, no hard-coded numbers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING_ROOT = HERE.parent.parent                      # defense4/timing
sys.path.insert(0, str(TIMING_ROOT / "analysis"))

EVIDENCE = TIMING_ROOT / "evidence" / "final_read_sbo"
FROZEN_CSV = EVIDENCE / "derived_csv"


def outdir_from_argv():
    """Reproduction output root (build/), passed by reproduce.sh."""
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else (TIMING_ROOT / "build")
    return root


def csv_dir(root):
    """Prefer freshly regenerated CSVs; fall back to the frozen ones."""
    d = root / "derived_csv"
    return d if (d / "native_txn.csv").exists() else FROZEN_CSV


def stats_json(root):
    p = root / "timing_stats.json"
    if not p.exists():
        raise SystemExit("timing_stats.json not found in %s — run reproduce.sh first" % root)
    with open(p) as f:
        return json.load(f), p


def figures_dir(root):
    return root / "figures"
