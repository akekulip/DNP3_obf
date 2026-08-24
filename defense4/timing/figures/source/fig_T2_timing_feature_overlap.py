#!/usr/bin/env python3
"""Figure T2 — timing-feature overlap, native vs defended.

Two timing features an observer can measure directly from the master-facing wire:
    x = request-to-ACK latency   A = T_ack  - T_req
    y = ACK-to-response latency  CLRT      = T_resp - T_ack
Points are coloured by transaction type. The figure is deliberately called an OVERLAP
plot, not a clustering result: no unsupervised algorithm is run, no cluster is fitted, and
no separation score is reported, because with one relay and two transaction types there is
nothing a clustering metric could establish that the classifier in Figure T4 does not
already state more directly. t-SNE and UMAP are avoided for the same reason — both can
manufacture visual separation that is not present in the data.
"""
import csv

import numpy as np

from _common import csv_dir, figures_dir, outdir_from_argv
from dnp3_timing import FUNC_READ, FUNC_SELECT
import figstyle as fs


def features(path, req_func):
    """Return (A, CLRT) in ms for the analysed transactions of one class."""
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
    nat, dread, dsel = (cdir / "native_txn.csv", cdir / "defended_read_txn.csv",
                        cdir / "defended_txn.csv")

    panels = [
        ("Native", [("READ", features(nat, FUNC_READ), fs.NATIVE, "o"),
                    ("SELECT phase of SBO", features(nat, FUNC_SELECT), fs.NATIVE_ALT, "^")]),
        ("Defended", [("READ", features(dread, FUNC_READ), fs.DEFENDED, "o"),
                      ("SELECT phase of SBO", features(dsel, FUNC_SELECT), fs.DEFENDED_ALT, "^")]),
    ]

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.6))

    allx = np.concatenate([xy[0] for _, ps in panels for _, xy, _, _ in ps])
    ally = np.concatenate([xy[1] for _, ps in panels for _, xy, _, _ in ps])
    xlim = (0, np.percentile(allx, 99.9) * 1.15)
    ylim = (0, np.ceil(ally.max()) + 0.5)

    rows = []
    for ax, (title, sets) in zip(axes, panels):
        for label, (x, y), colour, marker in sets:
            ax.scatter(x, y, s=5, marker=marker, facecolors="none", edgecolors=colour,
                       linewidths=0.5, alpha=0.55, label="%s (n=%d)" % (label, x.size))
            rows += [[title.lower(), label, "%.4f" % a, "%.4f" % c] for a, c in zip(x, y)]
        ax.set_xlim(*xlim)
        ax.set_ylim(*ylim)
        ax.set_xlabel("request-to-ACK latency $A$ (ms)")
        ax.set_title(title)
        ax.legend(loc="upper right", markerscale=1.6)

        if title == "Defended":
            # At the shared scale the defended points are one dot. The inset gives the
            # actual extent of that cloud, which is the quantity of interest.
            xs = np.concatenate([xy[0] for _, xy, _, _ in sets])
            ys = np.concatenate([xy[1] for _, xy, _, _ in sets])
            ins = ax.inset_axes([0.10, 0.16, 0.44, 0.34])
            for label, (x, y), colour, marker in sets:
                ins.scatter(x, y, s=4, marker=marker, facecolors="none", edgecolors=colour,
                            linewidths=0.4, alpha=0.6)
            ins.set_xlim(xs.min() - 0.2, xs.max() + 0.2)
            ins.set_ylim(ys.min() - 0.02, ys.max() + 0.02)
            ins.tick_params(labelsize=6, pad=1.5)
            ins.set_title("magnified", fontsize=6.5, pad=2)
            ins.grid(alpha=0.25)
    axes[0].set_ylabel("ACK-to-response latency, CLRT (ms)")
    fig.tight_layout()

    fs.save(fig, figures_dir(root), "fig_T2_timing_feature_overlap",
            inputs=[nat, dread, dsel],
            caption=(
                "Timing-feature overlap before and after normalization. Each point is one "
                "transaction, placed by the two latencies a passive observer can measure "
                "master-facing: request-to-ACK on the horizontal axis and ACK-to-response "
                "(CLRT) on the vertical. Left: native traffic, where READ and the SELECT "
                "phase of SBO occupy visibly different regions. Right: the same testbed "
                "with timing normalization enabled, where both transaction types collapse "
                "onto a single point and the two types are no longer separable by these "
                "features. This is a display of feature overlap, not a clustering result; "
                "no unsupervised algorithm is fitted."),
            stats_note=(
                "Raw per-transaction features, no scaling, no projection, no subsampling — "
                "every analysed transaction is plotted. Cold-start transactions are "
                "excluded as in Figure T1. Axis limits are shared between panels so the "
                "collapse is a like-for-like comparison; the horizontal limit is set at the "
                "99.9th percentile of the pooled native feature to keep a handful of "
                "extreme native points from compressing both panels."),
            data_header=["condition", "class", "request_to_ack_ms", "clrt_ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
