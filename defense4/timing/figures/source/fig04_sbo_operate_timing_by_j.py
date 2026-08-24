#!/usr/bin/env python3
"""Figure 4 — OPERATE timing across the configured hold J.

Three master-visible quantities per OPERATE transaction, for J = 2, 6 and 12 ms:
    A     = T_ack  - T_req
    R     = T_resp - T_req
    R - A = the echo-to-ACK interval
J is the CONFIGURED codebook value that sets the switch-internal, relay-facing release
delay. It was never observed on the relay-facing wire: that port is an internal
pktgen/recirculation port with no host-capturable tap. The claim the figure supports is
about what the master can see, and only that.
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

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.5))

    # Both series come from the same Timing ON arm, so the neutral series colours are
    # used here rather than the two arm colours.
    series = [("$A$  (request to ACK)", "A", fs.SERIES_1, "-", "o"),
              ("$R$  (request to echo)", "R", fs.SERIES_2, "--", "s")]

    rows = []
    ax = axes[0]
    for label, key, colour, ls, mk in series:
        med = [float(np.median(data[j][key])) for j in J_VALUES]
        cis = [boot_ci_median(data[j][key]) for j in J_VALUES]
        err = np.array([[m - lo for m, (lo, _) in zip(med, cis)],
                        [hi - m for m, (_, hi) in zip(med, cis)]])
        ax.errorbar(J_VALUES, med, yerr=err, color=colour, linestyle=ls, marker=mk,
                    capsize=2.5, lw=1.0, label=label)
        for j, m, (lo, hi) in zip(J_VALUES, med, cis):
            rows.append([key, j, len(data[j][key]), "%.3f" % m, "%.3f" % lo, "%.3f" % hi])
    ax.set_xticks(J_VALUES)
    ax.set_xlabel("configured hold $J$ (ms)")
    ax.set_ylabel("master-visible latency (ms)")
    ax.set_title("Absolute delays")
    ax.legend(loc="center right")

    ax = axes[1]
    med = [float(np.median(data[j]["echo"])) for j in J_VALUES]
    cis = [boot_ci_median(data[j]["echo"]) for j in J_VALUES]
    err = np.array([[m - lo for m, (lo, _) in zip(med, cis)],
                    [hi - m for m, (_, hi) in zip(med, cis)]])
    ax.errorbar(J_VALUES, med, yerr=err, color=fs.SERIES_3, linestyle="-.", marker="D",
                capsize=2.5, lw=1.0, label="$R-A$ (echo minus ACK)")
    for j, m, (lo, hi) in zip(J_VALUES, med, cis):
        rows.append(["echo_minus_ack", j, len(data[j]["echo"]), "%.3f" % m,
                     "%.3f" % lo, "%.3f" % hi])
    ax.axhline(4.0, color=fs.GREY, lw=0.7, linestyle=":", zorder=0)
    ax.annotate("configured $R-A$ = 4 ms", xy=(J_VALUES[-1], 4.0), xytext=(-4, 8),
                textcoords="offset points", ha="right", fontsize=7, color=fs.GREY)
    ax.set_xticks(J_VALUES)
    ax.set_ylim(3.90, 4.10)
    ax.set_xlabel("configured hold $J$ (ms)")
    ax.set_ylabel("$R-A$ (ms)")
    ax.set_title("Echo-to-ACK interval")
    ax.legend(loc="lower right")

    fig.tight_layout()

    fs.save(fig, figures_dir(root), "fig04_sbo_operate_timing_by_j",
            inputs=list(paths),
            caption=(
                "OPERATE timing under three configured hold values. Left: the master-visible "
                "request-to-ACK delay A and request-to-echo delay R, both flat in J. Right: "
                "the echo-to-ACK interval R-A, which stays at about 4.00 ms across J = 2, 6 "
                "and 12 ms, so an observer who subtracts the two observable timestamps "
                "learns nothing about the configured hold. Markers are medians of 30 "
                "OPERATE transactions per condition; bars are bootstrap 95 percent "
                "confidence intervals on the median and are smaller than the markers on the "
                "right-hand panel. J is the configured codebook value; it was not observed "
                "on the relay-facing wire."),
            stats_note=(
                "Median over the 30 OPERATE transactions of each J condition, with a "
                "percentile bootstrap 95 percent confidence interval on the median "
                "(10,000 resamples, seed %d). A and R are master-visible and include a "
                "path and capture offset of roughly 1 ms relative to the configured 20 ms "
                "and 24 ms deadlines; that offset cancels in R-A." % SEED_BOOTSTRAP),
            data_header=["quantity", "J_ms", "n", "median_ms", "ci95_lo_ms", "ci95_hi_ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
