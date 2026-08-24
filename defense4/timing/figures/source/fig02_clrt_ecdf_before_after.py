#!/usr/bin/env python3
"""Figure 2 — READ and SBO CLRT empirical CDFs, four series on one axis.

Timing OFF READ, Timing OFF SBO, Timing ON READ, Timing ON SBO. The horizontal range runs to
the largest observation in the data (18.18 ms), so the SBO tail is shown in full rather than
truncated at 12 ms. An inset magnifies the two Timing ON series, which at full scale are a
single vertical line at 4.001 ms.

Legend and axis labels only; the rest belongs in the caption.
"""
import numpy as np

from _common import csv_dir, figures_dir, outdir_from_argv
from dnp3_timing import FUNC_READ, FUNC_SELECT, read_txn_csv
import figstyle as fs


def ecdf(x):
    x = np.sort(np.asarray(x, dtype=float))
    return x, np.arange(1, x.size + 1) / x.size


def main():
    root = outdir_from_argv()
    cdir = csv_dir(root)
    off = cdir / "native_txn.csv"
    on_read = cdir / "defended_read_txn.csv"
    on_sel = cdir / "defended_txn.csv"

    series = [
        ("%s, %s" % (fs.LABEL_READ, fs.LABEL_OFF), "timing_off", fs.LABEL_READ,
         np.array(read_txn_csv(off, FUNC_READ)), fs.TIMING_OFF, "-"),
        ("%s, %s" % (fs.LABEL_SBO, fs.LABEL_OFF), "timing_off", fs.LABEL_SBO,
         np.array(read_txn_csv(off, FUNC_SELECT)), fs.TIMING_OFF_ALT, "-"),
        ("%s, %s" % (fs.LABEL_READ, fs.LABEL_ON), "timing_on", fs.LABEL_READ,
         np.array(read_txn_csv(on_read, FUNC_READ)), fs.TIMING_ON, "--"),
        ("%s, %s" % (fs.LABEL_SBO, fs.LABEL_ON), "timing_on", fs.LABEL_SBO,
         np.array(read_txn_csv(on_sel, FUNC_SELECT)), fs.TIMING_ON_ALT, "-."),
    ]

    fs.use_ieee()
    fig, ax = fs.plt.subplots(figsize=(fs.COL_WIDTH_IN, 2.8))

    xmax = max(v.max() for _, _, _, v, _, _ in series)
    rows = []
    for label, arm, cls, v, colour, ls in series:
        x, y = ecdf(v)
        ax.step(x, y, where="post", color=colour, linestyle=ls, lw=1.1, label=label)
        rows.append([cls, arm, v.size, "%.3f" % np.median(v), "%.3f" % v.max()])
    ax.set_xlim(0, np.ceil(xmax) + 0.5)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("CLRT (ms)")
    ax.set_ylabel("empirical CDF")
    ax.legend(loc="lower right")

    on = [s for s in series if s[1] == "timing_on"]
    lo = min(v.min() for _, _, _, v, _, _ in on) - 0.01
    hi = max(v.max() for _, _, _, v, _, _ in on) + 0.01
    ins = ax.inset_axes([0.50, 0.58, 0.42, 0.28])
    for label, arm, cls, v, colour, ls in on:
        x, y = ecdf(v)
        ins.step(x, y, where="post", color=colour, linestyle=ls, lw=0.9)
    ins.set_xlim(lo, hi)
    ins.set_ylim(0, 1.05)
    ins.set_xticks([4.00])
    ins.set_yticks([0, 1])
    ins.tick_params(labelsize=7, pad=1.5)
    ins.grid(alpha=0.3)

    fs.grid(fig, ax)
    fs.save(fig, figures_dir(root), "fig02_clrt_ecdf_before_after",
            inputs=[off, on_read, on_sel],
            caption=(
                "Empirical CDF of CLRT for READ and for the SELECT phase of SBO, with the "
                "in-network timing mechanism disabled (solid) and enabled (dashed). With the "
                "timing mode off the two classes separate clearly and the SBO distribution "
                "carries a tail to 18.18 ms, shown in full; with it on, both collapse onto "
                "4.001 ms, and the inset magnifies the two Timing ON curves, which coincide "
                "at full scale. Size shaping was active in both arms, so Timing OFF is not "
                "an unmodified device baseline."),
            stats_note=(
                "Empirical CDFs of per-transaction CLRT; every observation appears, nothing "
                "is smoothed or truncated. Cold-start transactions excluded as in Figure 1."),
            data_header=["class", "arm", "n", "median_ms", "max_ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
