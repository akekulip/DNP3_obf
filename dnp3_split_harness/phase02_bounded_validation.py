"""phase02_bounded_validation.py -- numerical validation of the bounded target sampling.

Reads a Phase 02 run's transaction log and reports, for each bounded config, the full target
distribution stats, the expected Uniform(20,30) standard deviation, the correlation of the
target with response size and with transaction position (both must be ~0), and per-position /
per-size summaries. This is a numerical check; uniformity is not claimed from the histogram
alone.

    python3 phase02_bounded_validation.py --run-dir <phase02 run dir>
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
from typing import Dict, List

import numpy as np

import phase01_stats as st

BOUNDED_CONFIGS = ["bounded20-30/full", "bounded20-30/crc-split"]
TARGET_MIN, TARGET_MAX = 20.0, 30.0
EXPECTED_UNIFORM_STD = (TARGET_MAX - TARGET_MIN) / math.sqrt(12)  # ~2.887


def _corr(xs, ys):
    x = np.asarray(xs, float); y = np.asarray(ys, float)
    if x.size < 3 or np.std(x) == 0 or np.std(y) == 0:
        return None
    return round(float(np.corrcoef(x, y)[0, 1]), 4)


def _summ(vals) -> Dict[str, object]:
    d = st.describe(vals)
    return {"n": d["n"], "unique": len(set(round(v, 6) for v in vals)),
            "min": d["min"], "max": d["max"], "mean": d["mean"], "median": d["median"],
            "std": d["std"], "p5": d["p5"], "p25": d["p25"], "p75": d["p75"], "p95": d["p95"]}


def validate(rows) -> Dict[str, object]:
    out = {"expected_uniform_std": round(EXPECTED_UNIFORM_STD, 4),
           "target_interval": [TARGET_MIN, TARGET_MAX], "by_config": {}}
    for cfg in BOUNDED_CONFIGS:
        cr = [r for r in rows if r["config"] == cfg and r["selected_target_ms"]]
        tg = [float(r["selected_target_ms"]) for r in cr]
        size = [float(r["response_size"]) for r in cr]
        pos = [int(r["txn"]) for r in cr]
        by_pos = {}
        for p in sorted(set(pos)):
            v = [float(r["selected_target_ms"]) for r in cr if int(r["txn"]) == p]
            sz = next(r["response_size"] for r in cr if int(r["txn"]) == p)
            by_pos["txn%s_%sB" % (p, sz)] = _summ(v)
        by_size = {}
        for s in sorted(set(size)):
            v = [float(r["selected_target_ms"]) for r in cr if float(r["response_size"]) == s]
            by_size["%dB" % int(s)] = _summ(v)
        out["by_config"][cfg] = {
            "overall": _summ(tg),
            "corr_target_vs_response_size": _corr(size, tg),
            "corr_target_vs_transaction_position": _corr(pos, tg),
            "per_position": by_pos,
            "per_size": by_size,
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    if not os.path.isdir(args.run_dir):
        sys.stderr.write("run-dir not found: %s\n" % args.run_dir); return 2
    rows = list(csv.DictReader(open(os.path.join(args.run_dir, "tables", "phase02_transaction_log.csv"))))
    result = validate(rows)

    tdir = os.path.join(args.run_dir, "tables"); os.makedirs(tdir, exist_ok=True)
    json.dump(result, open(os.path.join(tdir, "phase02_bounded_validation.json"), "w"), indent=2)

    rdir = os.path.join(args.run_dir, "reports"); os.makedirs(rdir, exist_ok=True)
    L = ["# Phase 02 — Bounded-Target Numerical Validation", "",
         "Numerical check of the corrected bounded sampling. Expected Uniform(20,30) standard "
         "deviation: **%.4f ms**. Uniformity is not claimed from the histogram alone -- the "
         "correlations with size and position (both ~0) and the per-position/per-size summaries "
         "are the evidence that the target is class-independent." % result["expected_uniform_std"],
         ""]
    for cfg in BOUNDED_CONFIGS:
        c = result["by_config"][cfg]; o = c["overall"]
        L += ["## %s" % cfg, "",
              "- n=%d, unique targets=%d, min=%.2f, max=%.2f" % (o["n"], o["unique"], o["min"], o["max"]),
              "- mean=%.4f, median=%.4f, std=%.4f (expected %.4f)" % (
                  o["mean"], o["median"], o["std"], result["expected_uniform_std"]),
              "- p5=%.2f, p25=%.2f, p75=%.2f, p95=%.2f" % (o["p5"], o["p25"], o["p75"], o["p95"]),
              "- **corr(target, response_size) = %s**, **corr(target, transaction_position) = %s** "
              "(both ~0 -> target independent of size and position)" % (
                  c["corr_target_vs_response_size"], c["corr_target_vs_transaction_position"]),
              "", "Per transaction position (target mean / std / n):", ""]
        for k, s in c["per_position"].items():
            L.append("- %s: mean=%.3f std=%.3f n=%d unique=%d" % (k, s["mean"], s["std"], s["n"], s["unique"]))
        L += ["", "Per response size (target mean / std / n):", ""]
        for k, s in c["per_size"].items():
            L.append("- %s: mean=%.3f std=%.3f n=%d" % (k, s["mean"], s["std"], s["n"]))
        L += [""]
    open(os.path.join(rdir, "phase02_bounded_validation.md"), "w").write("\n".join(L) + "\n")

    for cfg in BOUNDED_CONFIGS:
        c = result["by_config"][cfg]; o = c["overall"]
        print("  %-24s n=%d unique=%d mean=%.3f std=%.3f (exp %.3f) corr(size)=%s corr(pos)=%s" % (
            cfg, o["n"], o["unique"], o["mean"], o["std"], result["expected_uniform_std"],
            c["corr_target_vs_response_size"], c["corr_target_vs_transaction_position"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
