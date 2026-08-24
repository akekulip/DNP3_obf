#!/usr/bin/env python3
"""Figure 1 — READ and SELECT CLRT distributions with the timing mode off and on.

Two panels, one per transaction type, each showing the ACK-to-response latency (CLRT) as a
probability-density histogram for the Timing OFF and Timing ON arms. Every observation is on
the axis: the horizontal range runs to the largest value in each panel (12.3 ms for READ,
18.2 ms for the SELECT phase of SBO), so nothing is clipped and no overflow annotation is
needed. Bins are 0.25 ms so the Timing ON spike at 4.001 ms and the Timing OFF structure are
both legible on one density scale; no kernel smoothing is applied.

The arms are labelled by what actually differed between them: the timing mode. Both ran the
same unified binary with the size-shaping datapath active, so the Timing OFF arm is not an
unmodified SEL-751 baseline.
"""
import numpy as np

from _common import csv_dir, figures_dir, outdir_from_argv
from dnp3_timing import FUNC_READ, FUNC_SELECT, read_txn_csv
import figstyle as fs

BIN_MS = 0.25


def main():
    root = outdir_from_argv()
    cdir = csv_dir(root)
    off = cdir / "native_txn.csv"              # timing mode OFF, shaping active
    on_read = cdir / "defended_read_txn.csv"   # timing mode ON
    on_sel = cdir / "defended_txn.csv"         # timing mode ON

    panels = [
        ("READ (func 1)", "READ",
         np.array(read_txn_csv(off, FUNC_READ)), np.array(read_txn_csv(on_read, FUNC_READ))),
        ("SELECT phase of SBO (func 3)", "SELECT",
         np.array(read_txn_csv(off, FUNC_SELECT)), np.array(read_txn_csv(on_sel, FUNC_SELECT))),
    ]

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.5))

    rows = []
    for k, (ax, (title, cls, off_v, on_v)) in enumerate(zip(axes, panels)):
        xmax = max(off_v.max(), on_v.max())
        edges = np.arange(0.0, np.ceil(xmax) + BIN_MS, BIN_MS)
        ax.hist(off_v, bins=edges, density=True, color=fs.TIMING_OFF, alpha=0.75,
                edgecolor="white", linewidth=0.3,
                label="%s (n=%d)" % (fs.LABEL_OFF, off_v.size))
        ax.hist(on_v, bins=edges, density=True, color=fs.TIMING_ON, alpha=0.75,
                edgecolor="white", linewidth=0.3, hatch="///",
                label="%s (n=%d)" % (fs.LABEL_ON, on_v.size))
        ax.axvline(np.median(on_v), color=fs.TIMING_ON, linestyle="--", lw=0.8, zorder=0)
        ax.set_xlim(0, np.ceil(xmax) + 0.5)
        ax.set_xlabel("ACK-to-response latency, CLRT (ms)")
        ax.set_title(title)
        n_tail = int((off_v > 12.0).sum())
        ax.annotate("full range shown; max %.2f ms\n(%d obs. above 12 ms)" % (off_v.max(), n_tail),
                    xy=(off_v.max(), 0), xytext=(-2, 14), textcoords="offset points",
                    ha="right", va="bottom", fontsize=6.5, color=fs.GREY,
                    arrowprops=dict(arrowstyle="-", color=fs.GREY, lw=0.5))
        if k == 0:
            ax.plot([], [], " ", label=fs.NOTE_BOTH_ARMS)
        ax.legend(loc="upper right", handletextpad=0.5)
        for arm, v in (("timing_off", off_v), ("timing_on", on_v)):
            rows.append([cls, arm, v.size, "%.3f" % np.median(v), "%.3f" % np.std(v),
                         "%.3f" % v.min(), "%.3f" % v.max(), int((v > 12).sum())])

    axes[0].set_ylabel("probability density (1/ms)")
    fig.tight_layout()

    fs.save(fig, figures_dir(root), "fig01_clrt_read_select_before_after",
            inputs=[off, on_read, on_sel],
            caption=(
                "Cross-layer response time (CLRT), the interval from the outstation's TCP "
                "acknowledgment to its DNP3 application response, with the in-network timing "
                "mechanism disabled and enabled, measured master-facing against the physical "
                "SEL-751. Left: READ (function 1). Right: the SELECT phase of "
                "select-before-operate (function 3); these are SELECT observations, not "
                "complete SBO transactions. With the timing mode off, CLRT is spread over "
                "roughly 1 to 18 ms and differs between the two transaction types; with it on, "
                "both collapse onto a 4.001 ms policy value (dashed line) with a standard "
                "deviation of about 0.02 ms. Each panel's horizontal axis runs to its largest "
                "observation, so the full tail is visible. Both arms ran the same unified "
                "switch binary with the size-shaping datapath active; the Timing OFF arm is "
                "therefore not an unmodified device baseline, and the comparison isolates the "
                "timing-mode change."),
            stats_note=(
                "Probability-density histograms of per-transaction CLRT with 0.25 ms bins; "
                "no kernel smoothing. Cold-start transactions (the first of each TCP "
                "connection) are excluded and counted in timing_stats.json under "
                "row_accounting. Nothing is clipped: the axis limit is the largest "
                "observation in each panel. The two arms differ only in the configured timing "
                "mode of one unified binary; the size carve was enabled throughout both, "
                "verified from the response segmentation on the wire."),
            data_header=["class", "arm", "n", "median_ms", "std_ms", "min_ms", "max_ms",
                         "n_over_12ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
