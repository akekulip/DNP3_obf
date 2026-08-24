#!/usr/bin/env python3
"""Figure 3 — timing-feature overlap, timing mode off and on.

Two timing features an observer can measure directly from the master-facing wire:
    x = request-to-ACK latency
    y = ACK-to-response latency (CLRT)
Points are coloured by transaction class. Deliberately an OVERLAP plot, not a clustering
result: no unsupervised algorithm is fitted, no separation score is reported, and t-SNE and
UMAP are avoided because both can manufacture visual separation that is not in the data.

Legend and axis labels only.
"""
import csv

import numpy as np

from _common import csv_dir, figures_dir, outdir_from_argv
from dnp3_timing import FUNC_READ, FUNC_SELECT
import figstyle as fs


def features(path, req_func):
    """Return (request-to-ACK, CLRT) in ms for the analysed transactions of one class."""
    A, C = [], []
    with open(path) as f:
        for r in csv.DictReader(f):
            if int(r["req_func"]) != req_func:
                continue
            if r["cold"].strip() not in ("0", ""):
                continue
            if not (r["t_req"].strip() and r["t_ack"].strip() and r["clrt_ms"].strip()):
                continue
            A.append((float(r["t_ack"]) - float(r["t_req"])) * 1e3)
            C.append(float(r["clrt_ms"]))
    return np.array(A), np.array(C)


def main():
    root = outdir_from_argv()
    cdir = csv_dir(root)
    off, on_read, on_sel = (cdir / "native_txn.csv", cdir / "defended_read_txn.csv",
                            cdir / "defended_txn.csv")

    panels = [
        (fs.LABEL_OFF, "timing_off",
         [(fs.LABEL_READ, features(off, FUNC_READ), fs.TIMING_OFF, "o"),
          (fs.LABEL_SBO, features(off, FUNC_SELECT), fs.TIMING_OFF_ALT, "^")]),
        (fs.LABEL_ON, "timing_on",
         [(fs.LABEL_READ, features(on_read, FUNC_READ), fs.TIMING_ON, "o"),
          (fs.LABEL_SBO, features(on_sel, FUNC_SELECT), fs.TIMING_ON_ALT, "^")]),
    ]

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.5))

    allx = np.concatenate([xy[0] for _, _, ps in panels for _, xy, _, _ in ps])
    ally = np.concatenate([xy[1] for _, _, ps in panels for _, xy, _, _ in ps])
    xlim = (0, np.percentile(allx, 99.9) * 1.15)
    ylim = (0, np.ceil(ally.max()) + 0.5)

    rows = []
    for ax, (title, arm, sets) in zip(axes, panels):
        for label, (x, y), colour, marker in sets:
            ax.scatter(x, y, s=5, marker=marker, facecolors="none", edgecolors=colour,
                       linewidths=0.5, alpha=0.55, label=label)
            rows += [[arm, label, "%.4f" % a, "%.4f" % c] for a, c in zip(x, y)]
        ax.set_xlim(*xlim)
        ax.set_ylim(*ylim)
        ax.set_xlabel("request-to-ACK latency (ms)")
        ax.set_title(title)
        ax.legend(loc="upper right", markerscale=1.8)

        if arm == "timing_on":
            xs = np.concatenate([xy[0] for _, xy, _, _ in sets])
            ys = np.concatenate([xy[1] for _, xy, _, _ in sets])
            ins = ax.inset_axes([0.40, 0.16, 0.46, 0.32])
            for label, (x, y), colour, marker in sets:
                ins.scatter(x, y, s=4, marker=marker, facecolors="none", edgecolors=colour,
                            linewidths=0.4, alpha=0.6)
            ins.set_xlim(xs.min() - 0.2, xs.max() + 0.2)
            ins.set_ylim(ys.min() - 0.02, ys.max() + 0.02)
            ins.tick_params(labelsize=7, pad=1.5)
            ins.grid(alpha=0.3)

    axes[0].set_ylabel("CLRT (ms)")
    fs.grid(fig, list(axes))

    fs.save(fig, figures_dir(root), "fig03_timing_feature_overlap_before_after",
            inputs=[off, on_read, on_sel],
            caption=(
                "Timing-feature overlap with the in-network timing mechanism disabled and "
                "enabled. Each point is one transaction, placed by the two latencies a "
                "passive observer can measure master-facing: request-to-ACK on the "
                "horizontal axis and ACK-to-response (CLRT) on the vertical. Left, timing "
                "mode off: READ and the SELECT phase of SBO occupy visibly different "
                "regions. Right, timing mode on: both classes collapse onto a single point "
                "and are no longer separable by these features; the inset magnifies that "
                "point. This is a display of feature overlap between two transaction classes "
                "on one relay, not a clustering result and not device identification; no "
                "unsupervised algorithm is fitted."),
            stats_note=(
                "Raw per-transaction features: no scaling, no projection, no subsampling, "
                "every analysed transaction plotted. Cold-start transactions excluded as in "
                "Figure 1. Axis limits are shared between panels so the collapse is a "
                "like-for-like comparison; the horizontal limit is the 99.9th percentile of "
                "the pooled feature, which keeps a few extreme points from compressing both "
                "panels."),
            data_header=["arm", "class", "request_to_ack_ms", "clrt_ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
