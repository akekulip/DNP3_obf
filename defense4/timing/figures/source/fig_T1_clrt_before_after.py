#!/usr/bin/env python3
"""Figure T1 — READ and SELECT CLRT with the timing mode off and on.

The two arms are labelled by what actually differed between them: the timing mode. Both
arms ran the same unified binary with the size-shaping datapath active, so the "Timing OFF"
arm is not an unmodified SEL-751 baseline. It is the same relay behind the same switch
program with the timing mechanism disabled. Because shaping was on in both arms it is a held
constant rather than a difference between them, which is what makes the comparison a clean
isolation of the timing-mode change.

Empirical CDFs rather than a smoothed density: the Timing ON distribution is a 0.02 ms-wide
spike at 4.001 ms, and a kernel density estimate would render that spike as a broad hump
that does not exist in the data. The full Timing OFF tail is kept on the axis out to the
largest observation (18.2 ms for SELECT), so nothing is clipped; an inset resolves the
Timing ON spike, which is otherwise a vertical line.
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
    off = cdir / "native_txn.csv"              # timing mode OFF, shaping active
    on_read = cdir / "defended_read_txn.csv"   # timing mode ON
    on_sel = cdir / "defended_txn.csv"         # timing mode ON

    series = {
        "READ": (read_txn_csv(off, FUNC_READ), read_txn_csv(on_read, FUNC_READ)),
        "SELECT phase of SBO (func 3)": (read_txn_csv(off, FUNC_SELECT),
                                         read_txn_csv(on_sel, FUNC_SELECT)),
    }

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.5), sharey=True)

    rows = []
    for k, (ax, (title, (off_vals, on_vals))) in enumerate(zip(axes, series.items())):
        xo, yo = ecdf(off_vals)
        xn, yn = ecdf(on_vals)
        ax.step(xo, yo, where="post", color=fs.TIMING_OFF, linestyle="-", lw=1.2,
                label="%s (n=%d, max %.2f ms)" % (fs.LABEL_OFF, len(off_vals), xo.max()))
        ax.step(xn, yn, where="post", color=fs.TIMING_ON, linestyle="--", lw=1.2,
                label="%s (n=%d, max %.2f ms)" % (fs.LABEL_ON, len(on_vals), xn.max()))
        top = max(xo.max(), xn.max())
        ax.set_xlim(0, np.ceil(top) + 0.5)
        ax.set_ylim(0, 1.02)
        ax.set_xlabel("CLRT (ms)")
        ax.set_title(title)
        if k == 0:
            # Carried as a legend entry with no handle: it can never collide with the data.
            ax.plot([], [], " ", label=fs.NOTE_BOTH_ARMS)
        ax.legend(loc="lower right", handletextpad=0.5)

        # The Timing ON CDF is narrower than the line width at full scale, so it is shown
        # again on its own axis. Both panels keep the complete range: nothing is cut.
        ins = ax.inset_axes([0.34, 0.44, 0.40, 0.40])
        ins.step(xn, yn, where="post", color=fs.TIMING_ON, linestyle="--", lw=1.0)
        lo, hi = xn.min() - 0.01, xn.max() + 0.01
        ins.set_xlim(lo, hi)
        ins.set_ylim(0, 1.05)
        ins.set_xticks([round(lo + 0.01, 2), 4.00, round(hi - 0.01, 2)])
        ins.set_yticks([0, 0.5, 1.0])
        ins.tick_params(labelsize=6, pad=1.5)
        ins.set_title("%s, magnified" % fs.LABEL_ON, fontsize=6.5, pad=2)
        ins.grid(alpha=0.25)

        cls = "READ" if title == "READ" else "SELECT"
        for arm, v in (("timing_off", off_vals), ("timing_on", on_vals)):
            v = np.asarray(v)
            rows.append([cls, arm, len(v), "%.3f" % np.median(v), "%.3f" % np.std(v),
                         "%.3f" % v.min(), "%.3f" % v.max(), int((v > 12).sum())])

    axes[0].set_ylabel("empirical CDF")
    fig.tight_layout()

    fs.save(fig, figures_dir(root), "fig_T1_clrt_before_after",
            inputs=[off, on_read, on_sel],
            caption=(
                "Command-to-link response time (CLRT) with the in-network timing mechanism "
                "disabled and enabled, measured master-facing against the physical SEL-751. "
                "Left: READ (function 1). Right: the SELECT phase of select-before-operate "
                "(function 3); these are SELECT observations, not complete SBO transactions. "
                "With the timing mode off, CLRT spans roughly 1 to 18 ms and differs between "
                "the two transaction types; with it on, both collapse onto a 4.001 ms policy "
                "value with a standard deviation of about 0.02 ms. Both arms ran the same "
                "unified switch binary with the size-shaping datapath active, so the "
                "Timing OFF arm is not an unmodified device baseline: shaping is held "
                "constant across the arms and the comparison isolates the timing-mode "
                "change. Axes show the full range, so no tail is clipped; the inset resolves "
                "the Timing ON distribution, which is narrower than the line width at full "
                "scale."),
            stats_note=(
                "Empirical CDFs of per-transaction CLRT = T_response - T_ack. Cold-start "
                "transactions (the first of each TCP connection) are excluded and counted "
                "in timing_stats.json under row_accounting. No smoothing, no binning, no "
                "resampling: every observation appears. The two arms differ only in the "
                "configured timing mode of one unified binary; the size carve was enabled "
                "throughout both, verified from the response segmentation on the wire. This "
                "figure therefore measures the effect of the timing mode within that "
                "program, not the effect of the whole system against an untouched relay. "
                "Establishing an unmodified device baseline would require a separate "
                "campaign with the shaping datapath disabled."),
            data_header=["class", "arm", "n", "median_ms", "std_ms", "min_ms",
                         "max_ms", "n_over_12ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
