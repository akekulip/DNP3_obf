#!/usr/bin/env python3
"""Figure 4 — master-visible OPERATE ACK-to-echo interval across the configured hold J.

The quantity the defense fixes is the ACK-to-echo interval the master can observe: the interval
between the acknowledgment it sees and the echo it sees, which the design pins to R - A. That
policy value is 4 ms, the same value READ and SBO CLRT are normalized to in Figures 1 and 2.
It is 4 ms for both classes; the 20 ms and 24 ms release offsets are internal anchors, not
the quantity being normalized, and are deliberately not plotted here.

The point of the figure is that this observable does not move with J, so an observer who
subtracts the two timestamps available to it learns nothing about the switch-internal hold.

Legend and axis labels only.
"""
import numpy as np

from _common import csv_dir, figures_dir, outdir_from_argv
from dnp3_timing import read_sbo_csv
import figstyle as fs

SEED_BOOTSTRAP = 20260824
J_VALUES = (2, 6, 12)


def boot_ci_median(x, B=10000, seed=SEED_BOOTSTRAP):
    rng = np.random.default_rng(seed)
    x = np.asarray(x, dtype=float)
    bs = np.median(rng.choice(x, size=(B, x.size)), axis=1)
    return float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))


def main():
    root = outdir_from_argv()
    cdir = csv_dir(root)
    paths = [cdir / ("sbo_j%d.csv" % j) for j in J_VALUES]
    data = {j: read_sbo_csv(p) for j, p in zip(J_VALUES, paths)}

    med = [float(np.median(data[j]["echo"])) for j in J_VALUES]
    cis = [boot_ci_median(data[j]["echo"]) for j in J_VALUES]
    err = np.array([[m - lo for m, (lo, _) in zip(med, cis)],
                    [hi - m for m, (_, hi) in zip(med, cis)]])

    fs.use_ieee()
    fig, ax = fs.plt.subplots(figsize=(fs.COL_WIDTH_IN, 2.2))
    ax.errorbar(J_VALUES, med, yerr=err, color=fs.TIMING_ON_ALT, linestyle="-.",
                marker="D", capsize=2.5, lw=1.0, label=fs.LABEL_SBO)
    ax.set_xticks(J_VALUES)
    ax.set_xlim(0, 14)
    ax.set_ylim(3.90, 4.10)
    ax.set_xlabel("configured hold $J$ (ms)")
    ax.set_ylabel("ACK-to-echo interval (ms)")
    ax.legend(loc="upper right")
    fs.grid(fig, ax)

    rows = [["operation_time", j, len(data[j]["echo"]), "%.3f" % m, "%.3f" % lo, "%.3f" % hi]
            for j, m, (lo, hi) in zip(J_VALUES, med, cis)]

    fs.save(fig, figures_dir(root), "fig04_sbo_operate_timing_by_j",
            inputs=list(paths),
            caption=(
                "Master-visible OPERATE ACK-to-echo interval of a select-before-operate control under three "
                "configured hold values. It is the interval between the "
                "acknowledgment and the echo the master observes, which the design pins to a "
                "4 ms policy value, the same value READ and SBO response times are normalized "
                "to in Figures 1 and 2. It stays at that value across J = 2, 6 and 12 ms, so "
                "an observer who subtracts the two timestamps available to it learns nothing "
                "about the switch-internal hold. Markers are medians of 30 OPERATE "
                "transactions per condition; bars are bootstrap 95 percent confidence "
                "intervals on the median and are smaller than the markers. J is the "
                "configured codebook value; it was not observed on the relay-facing wire, and "
                "exactly-once relay delivery is not demonstrated."),
            stats_note=(
                "Median over the 30 OPERATE transactions of each J condition, with a "
                "percentile bootstrap 95 percent confidence interval on the median (10,000 "
                "resamples, seed %d). The plotted quantity is master-visible throughout. The "
                "absolute release offsets from the request are internal anchors and are not "
                "the normalized quantity; they cancel in this difference." % SEED_BOOTSTRAP),
            data_header=["quantity", "J_ms", "n", "median_ms", "ci95_lo_ms", "ci95_hi_ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
