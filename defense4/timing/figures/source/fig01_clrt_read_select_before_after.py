#!/usr/bin/env python3
"""Figure 1 — READ and SBO CLRT distributions, timing mode off and on.

Two panels, one per transaction class. Probability-density histograms of the ACK-to-response
latency (CLRT) for the Timing OFF and Obfuscated arms. The horizontal range runs to the
largest observation in each panel, so the whole tail is on the axis and nothing is clipped.
Bins are 0.25 ms; no kernel smoothing.

The figure carries only its legend and axis labels. Everything explanatory — that both arms
ran the same unified binary with the size-shaping datapath active, so Timing OFF is not an
unmodified device baseline — belongs in the caption.
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
        (fs.LABEL_READ, np.array(read_txn_csv(off, FUNC_READ)),
         np.array(read_txn_csv(on_read, FUNC_READ)), fs.TIMING_OFF, fs.TIMING_ON),
        (fs.LABEL_SBO, np.array(read_txn_csv(off, FUNC_SELECT)),
         np.array(read_txn_csv(on_sel, FUNC_SELECT)), fs.TIMING_OFF_ALT, fs.TIMING_ON_ALT),
    ]

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.4))

    rows = []
    for ax, (cls, off_v, on_v, c_off, c_on) in zip(axes, panels):
        xmax = max(off_v.max(), on_v.max())
        edges = np.arange(0.0, np.ceil(xmax) + BIN_MS, BIN_MS)
        ax.hist(off_v, bins=edges, density=True, color=c_off, alpha=0.85,
                edgecolor="white", linewidth=0.3, label=fs.LABEL_OFF)
        ax.hist(on_v, bins=edges, density=True, color=c_on, alpha=0.85,
                edgecolor="white", linewidth=0.3, hatch="///", label=fs.LABEL_ON)
        ax.set_xlim(0, np.ceil(xmax) + 0.5)
        ax.set_xlabel("CLRT (ms)")
        ax.set_title(cls)
        ax.legend(loc="upper right")
        for arm, v in (("timing_off", off_v), ("timing_on", on_v)):
            rows.append([cls, arm, v.size, "%.3f" % np.median(v), "%.3f" % np.std(v),
                         "%.3f" % v.min(), "%.3f" % v.max()])

    axes[0].set_ylabel("probability density (1/ms)")
    fs.grid(fig, list(axes))

    fs.save(fig, figures_dir(root), "fig01_clrt_read_select_before_after",
            inputs=[off, on_read, on_sel],
            caption=(
                "Cross-layer response time (CLRT), the interval from the outstation's TCP "
                "acknowledgment to its DNP3 application response, with the in-network timing "
                "mechanism disabled (Timing OFF) and enabled (Obfuscated), measured "
                "master-facing against the physical SEL-751. Left: READ (function 1). Right: "
                "the SELECT phase of select-before-operate (function 3), written SBO "
                "throughout; these are SELECT observations, not complete SBO transactions. "
                "With the timing mode off, CLRT is spread over roughly 1 to 18 ms and differs "
                "between the two classes; with it on, both collapse onto the same 4.001 ms "
                "policy value. Timing OFF: 999 READ and 488 SBO transactions; Obfuscated: 599 "
                "and 499. Each panel's horizontal axis runs to its largest observation, so "
                "the full tail is visible. Both arms ran the same unified switch binary with "
                "the size-shaping datapath active, so the Timing OFF arm is not an "
                "unmodified device baseline and the comparison isolates the timing-mode "
                "change."),
            stats_note=(
                "Probability-density histograms of per-transaction CLRT, 0.25 ms bins, no "
                "smoothing. Cold-start transactions (the first of each TCP connection) are "
                "excluded and counted in timing_stats.json under row_accounting. Nothing is "
                "clipped: each axis limit is that panel's largest observation."),
            data_header=["class", "arm", "n", "median_ms", "std_ms", "min_ms", "max_ms"],
            data_rows=rows)


if __name__ == "__main__":
    main()
