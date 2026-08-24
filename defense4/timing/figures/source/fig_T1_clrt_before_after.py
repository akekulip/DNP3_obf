#!/usr/bin/env python3
"""Figure T1 — READ and SELECT CLRT, native vs defended.

Empirical CDFs rather than a smoothed density: the defended distribution is a 0.02 ms-wide
spike at 4.001 ms, and a kernel density estimate would render that spike as a broad hump
that does not exist in the data. The full native tail is kept on the axis out to the
largest observation (18.2 ms for SELECT), so nothing is clipped; an inset resolves the
defended spike, which is otherwise a vertical line.
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
    nat = cdir / "native_txn.csv"
    dread = cdir / "defended_read_txn.csv"
    dsel = cdir / "defended_txn.csv"

    series = {
        "READ": (read_txn_csv(nat, FUNC_READ), read_txn_csv(dread, FUNC_READ)),
        "SELECT phase of SBO (func 3)": (read_txn_csv(nat, FUNC_SELECT),
                                         read_txn_csv(dsel, FUNC_SELECT)),
    }

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.5), sharey=True)

    rows = []
    for ax, (title, (nvals, dvals)) in zip(axes, series.items()):
        xn, yn = ecdf(nvals)
        xd, yd = ecdf(dvals)
        ax.step(xn, yn, where="post", color=fs.NATIVE, linestyle="-", lw=1.2,
                label="native (n=%d, max %.2f ms)" % (len(nvals), xn.max()))
        ax.step(xd, yd, where="post", color=fs.DEFENDED, linestyle="--", lw=1.2,
                label="defended (n=%d, max %.2f ms)" % (len(dvals), xd.max()))
        top = max(xn.max(), xd.max())
        ax.set_xlim(0, np.ceil(top) + 0.5)
        ax.set_ylim(0, 1.02)
        ax.set_xlabel("CLRT (ms)")
        ax.set_title(title)
        ax.legend(loc="lower right")

        # The defended CDF is narrower than the line width at full scale, so it is shown
        # again on its own axis. Both panels keep the complete native range: nothing is cut.
        ins = ax.inset_axes([0.34, 0.44, 0.40, 0.40])
        ins.step(xd, yd, where="post", color=fs.DEFENDED, linestyle="--", lw=1.0)
        lo, hi = xd.min() - 0.01, xd.max() + 0.01
        ins.set_xlim(lo, hi)
        ins.set_ylim(0, 1.05)
        ins.set_xticks([round(lo + 0.01, 2), 4.00, round(hi - 0.01, 2)])
        ins.set_yticks([0, 0.5, 1.0])
        ins.tick_params(labelsize=6, pad=1.5)
        ins.set_title("defended, magnified", fontsize=6.5, pad=2)
        ins.grid(alpha=0.25)

        cls = "READ" if title == "READ" else "SELECT"
        for cond, v in (("native", nvals), ("defended", dvals)):
            v = np.asarray(v)
            rows.append([cls, cond, len(v), "%.3f" % np.median(v), "%.3f" % np.std(v),
                         "%.3f" % v.min(), "%.3f" % v.max(), int((v > 12).sum())])

    axes[0].set_ylabel("empirical CDF")
    fig.tight_layout()

    fs.save(fig, figures_dir(root), "fig_T1_clrt_before_after",
            inputs=[nat, dread, dsel],
            caption=(
                "Command-to-link response time (CLRT) before and after in-network timing "
                "normalization, measured master-facing against the physical SEL-751. Left: "
                "READ (function 1). Right: the SELECT phase of select-before-operate "
                "(function 3); these are SELECT observations, not complete SBO transactions. "
                "Native CLRT spans roughly 1 to 18 ms and differs between the two "
                "transaction types; after normalization both collapse onto a 4.001 ms "
                "policy value with a standard deviation of about 0.02 ms. Axes show the "
                "full native range, so no tail is clipped; the inset resolves the defended "
                "distribution, which is narrower than the line width at full scale."),
            stats_note=(
                "Empirical CDFs of per-transaction CLRT = T_response - T_ack. Cold-start "
                "transactions (the first of each TCP connection) are excluded and counted "
                "in timing_stats.json under row_accounting. No smoothing, no binning, no "
                "resampling: every observation appears."),
            data_header=["class", "condition", "n", "median_ms", "std_ms", "min_ms",
                         "max_ms", "n_over_12ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
