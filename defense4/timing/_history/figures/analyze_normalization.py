#!/usr/bin/env python3
"""Quantify the CLRT normalization for the ONE device (SEL-751), from committed A+B campaign data.

This is a single-device metric: how much the CLRT observable's spread and information collapse under
each mode, relative to OFF. It is NOT a cross-device classification claim (that needs >=2 comparable
devices). It measures what an observer loses about THIS device's response-time signature.

Metrics per mode, pooled over both campaigns:
  - p5-p95 spread and IQR (dispersion), and the reduction factor vs OFF;
  - Shannon entropy of the CLRT over fixed 0.25 ms bins (0..25 ms), and the effective number of
    distinguishable timing states 2^H, and the reduction vs OFF;
  - per-session medians (4 sessions/mode across A+B) to show the shaping is stable, not a pooled
    artifact.
Emits a JSON summary and a per-session small-multiples figure.

  $RESEARCH_PYTHON analyze_normalization.py <out_basename>
"""
import glob
import hashlib
import json
import math
import os
import sys

sys.path.insert(0, os.path.expanduser("~/Projects/Tooling/inkscape_python_figures"))
import utils_mpl
import matplotlib.pyplot as plt

CAMPS = [
    "defense4/timing/evidence/final_run/campaignA_corrected_binary",
    "defense4/timing/evidence/final_run/campaignB_corrected_binary_seed20260807",
]
MODES = ["OFF", "D1", "D2", "D3", "D4"]
COLORS = {"OFF": "#7f7f7f", "D1": "#1f77b4", "D2": "#d62728", "D3": "#2ca02c", "D4": "#9467bd"}
BIN = 0.25
HI = 25.0


def valid_clrt(block):
    out = []
    for r in block.get("rows", []):
        if r.get("rst") or r.get("t_ack") is None or r.get("t_resp") is None:
            continue
        c = r.get("clrt_ms")
        if isinstance(c, (int, float)):
            out.append(c)
    return out


def pcts(xs, ps):
    xs = sorted(xs)
    return {p: (None if not xs else xs[min(len(xs) - 1, int(round(p / 100.0 * (len(xs) - 1))))]) for p in ps}


def entropy_bits(xs):
    if not xs:
        return 0.0
    counts = {}
    for v in xs:
        b = min(int(HI / BIN) - 1, max(0, int(v / BIN)))
        counts[b] = counts.get(b, 0) + 1
    n = len(xs)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "defense4/timing/figures/normalization"
    # gather per-session (per-block) CLRT lists per mode
    per_mode_sessions = {m: [] for m in MODES}   # list of (session_label, [clrt])
    h = hashlib.sha256()
    for camp in CAMPS:
        for bj in sorted(glob.glob(os.path.join(camp, "block_*.json"))):
            with open(bj, "rb") as f:
                h.update(f.read())
            b = json.load(open(bj))
            m = b.get("mode")
            if m in per_mode_sessions:
                per_mode_sessions[m].append((os.path.basename(bj), valid_clrt(b)))
    data_hash = h.hexdigest()[:12]

    summary = {"source_data_sha256_12": data_hash, "campaigns": CAMPS, "modes": {}}
    off_pool = [v for _, s in per_mode_sessions["OFF"] for v in s]
    off_p = pcts(off_pool, [5, 25, 75, 95])
    off_spread = off_p[95] - off_p[5]
    off_iqr = off_p[75] - off_p[25]
    off_H = entropy_bits(off_pool)
    for m in MODES:
        pool = [v for _, s in per_mode_sessions[m] for v in s]
        p = pcts(pool, [5, 25, 50, 75, 95])
        spread = p[95] - p[5]
        iqr = p[75] - p[25]
        H = entropy_bits(pool)
        sess_med = []
        for label, s in per_mode_sessions[m]:
            sp = pcts(s, [50])
            sess_med.append({"session": label, "n": len(s), "median": sp[50]})
        summary["modes"][m] = {
            "n": len(pool), "n_sessions": len(per_mode_sessions[m]),
            "p5": p[5], "p50": p[50], "p95": p[95], "p5_p95_spread_ms": spread, "iqr_ms": iqr,
            "spread_reduction_vs_off": (off_spread / spread) if spread else None,
            "clrt_entropy_bits": H, "effective_states_2^H": 2 ** H,
            "entropy_reduction_bits_vs_off": off_H - H,
            "per_session_median": sess_med,
        }

    # figure: per-session medians (points) + pooled p5-p95 band per mode
    utils_mpl.set_global()
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.4))
    for i, m in enumerate(MODES):
        s = summary["modes"][m]
        meds = [x["median"] for x in s["per_session_median"] if x["median"] is not None]
        ax.plot([i] * len(meds), meds, "o", color=COLORS[m], markersize=4, alpha=0.8)
        ax.plot([i - 0.28, i + 0.28], [s["p5"], s["p5"]], "-", color=COLORS[m], lw=0.8)
        ax.plot([i - 0.28, i + 0.28], [s["p95"], s["p95"]], "-", color=COLORS[m], lw=0.8)
        ax.plot([i, i], [s["p5"], s["p95"]], "-", color=COLORS[m], lw=0.8, alpha=0.5)
    ax.set_xticks(range(len(MODES)))
    ax.set_xticklabels(MODES)
    ax.set_ylabel("CLRT (ms)")
    ax.set_xlabel("mode (dots: per-session medians; bars: p5/p95)")
    ax.set_ylim(-0.5, 20)
    utils_mpl.set_grid(fig, ax)
    fig.savefig(out + ".pdf", transparent=True)
    fig.savefig(out + ".png", dpi=300, transparent=False)

    json.dump(summary, open(out + ".json", "w"), indent=2)
    # console table
    print("mode  n   p5    p50   p95   spread  IQR   spread_redux  H(bits) eff_states  H_redux")
    for m in MODES:
        s = summary["modes"][m]
        print("%-4s %4d %5.2f %5.2f %5.2f %6.2f %5.2f %11s %7.2f %9.1f %8s" % (
            m, s["n"], s["p5"], s["p50"], s["p95"], s["p5_p95_spread_ms"], s["iqr_ms"],
            ("%.1fx" % s["spread_reduction_vs_off"]) if s["spread_reduction_vs_off"] else "-",
            s["clrt_entropy_bits"], s["effective_states_2^H"],
            "%.2f" % s["entropy_reduction_bits_vs_off"]))
    print("source-data hash:", data_hash)


if __name__ == "__main__":
    main()
