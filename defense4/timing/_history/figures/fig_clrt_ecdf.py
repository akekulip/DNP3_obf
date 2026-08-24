#!/usr/bin/env python3
"""CLRT ECDF figure: native (OFF) versus the Defense 4 modes, from a campaign directory.

Reads block_*.json, groups valid CLRT by mode, and plots the empirical CDF of the master-facing
ACK-to-RESPONSE interval for OFF/D1/D2/D3/D4 on a shared linear millisecond axis. This is the timing
picture: OFF is the wide native fingerprint; the deadline modes compress it toward the policy value,
with the late-arrival tail shown honestly (not hidden by a median). Records sample counts and the
source-data hash so the figure is reproducible.

  $RESEARCH_PYTHON fig_clrt_ecdf.py <campaign_dir> [out_basename]
"""
import glob
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/Projects/Tooling/inkscape_python_figures"))
import utils_mpl
import matplotlib.pyplot as plt

MODES = ["OFF", "D1", "D2", "D3", "D4"]
# one colour per mode, consistent; OFF muted grey, defences in a clear sequence
COLORS = {"OFF": "#7f7f7f", "D1": "#1f77b4", "D2": "#d62728", "D3": "#2ca02c", "D4": "#9467bd"}


def valid_clrt(block):
    out = []
    for r in block.get("rows", []):
        if r.get("rst"):
            continue
        if r.get("t_ack") is None or r.get("t_resp") is None:
            continue
        c = r.get("clrt_ms")
        if isinstance(c, (int, float)):
            out.append(c)
    return out


def main():
    d = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(d, "fig_clrt_ecdf")
    per_mode = {m: [] for m in MODES}
    h = hashlib.sha256()
    for bj in sorted(glob.glob(os.path.join(d, "block_*.json"))):
        with open(bj, "rb") as f:
            h.update(f.read())
        b = json.load(open(bj))
        m = b.get("mode")
        if m in per_mode:
            per_mode[m].extend(valid_clrt(b))
    data_hash = h.hexdigest()[:12]

    utils_mpl.set_global()
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.4))
    for m in MODES:
        xs = sorted(per_mode[m])
        if not xs:
            continue
        ys = [(i + 1) / len(xs) for i in range(len(xs))]
        ax.step(xs, ys, where="post", label="%s (n=%d)" % (m, len(xs)), color=COLORS[m], linewidth=1.3)
    ax.set_xlabel("ACK-to-RESPONSE interval, CLRT (ms)")
    ax.set_ylabel("Empirical CDF")
    ax.set_ylim(0, 1.02)
    # clip the x-axis to a readable window but keep the tail visible
    allv = [v for m in MODES for v in per_mode[m]]
    if allv:
        ax.set_xlim(0, min(max(allv) * 1.05, 30))
    ax.legend(fontsize=7, loc="lower right")
    utils_mpl.set_grid(fig, ax)
    fig.savefig(out + ".pdf", transparent=True)
    fig.savefig(out + ".png", dpi=300, transparent=False)

    # sidecar metadata for reproducibility
    meta = {"campaign_dir": d, "source_data_sha256_12": data_hash,
            "counts": {m: len(per_mode[m]) for m in MODES},
            "note": "CLRT = master-facing pure-TCP-ACK to first byte of the matching DNP3 RESPONSE"}
    json.dump(meta, open(out + ".meta.json", "w"), indent=2)
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
