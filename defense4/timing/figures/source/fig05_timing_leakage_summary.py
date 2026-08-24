#!/usr/bin/env python3
"""Figure 5 — timing-only leakage with the timing mode off and on.

Two measures of how much the CLRT reveals about which transaction type produced it:
  left   mutual information I(transaction class ; CLRT), against its permutation null
  right  balanced accuracy of a READ-vs-SELECT classifier on CLRT, against chance
Both are read from timing_stats.json; nothing is hard-coded here.

The arms are labelled by the timing mode, which is the only thing that differed. Both ran
the same unified binary with the size-shaping datapath active, so the Timing OFF arm is not
an unmodified SEL-751 baseline.

The claim is transaction-class feature suppression on one relay in one capture session,
with a transaction-disjoint (not session-disjoint) split. It is not device identification
and not multi-device indistinguishability.
"""
import numpy as np

from _common import figures_dir, outdir_from_argv, stats_json
import figstyle as fs


def main():
    root = outdir_from_argv()
    st, st_path = stats_json(root)

    mi = st["MI_class_CLRT_bits_commonbins"]
    clf = st["classifier"]
    rows = []

    fs.use_ieee()
    fig, axes = fs.plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.4))

    # ---- mutual information vs permutation null -------------------------------------
    # Points with intervals, not bars: on a logarithmic axis a bar's baseline is arbitrary,
    # and a bar drawn from zero through its own null band reads as if the band were part of
    # the estimate. A marker for the estimate and a band for the null keeps the two apart.
    ax = axes[0]
    labels = [fs.LABEL_OFF, fs.LABEL_ON]
    vals = [mi["native"], mi["defended"]]   # keys are the stored arm names
    nulls = [mi["native_perm_null_ci"], mi["defended_perm_null_ci"]]
    xs = np.arange(2)
    for x, (lo, hi) in zip(xs, nulls):
        ax.add_patch(fs.plt.Rectangle((x - 0.22, lo), 0.44, max(hi - lo, 1e-6),
                                      facecolor=fs.GREY, alpha=0.30, edgecolor=fs.GREY,
                                      linewidth=0.5, zorder=2))
    for x, v, colour, marker in zip(xs, vals, [fs.TIMING_OFF, fs.TIMING_ON], ["o", "s"]):
        ax.plot([x], [v], marker=marker, color=colour, markersize=6, zorder=4,
                markeredgecolor="black", markeredgewidth=0.5, linestyle="none")
    ax.plot([], [], color=fs.GREY, alpha=0.45, lw=7, label="permutation null, 95%")
    ax.plot([], [], marker="o", color=fs.TIMING_OFF, linestyle="none", markersize=5,
            markeredgecolor="black", markeredgewidth=0.5, label="%s estimate" % fs.LABEL_OFF)
    ax.plot([], [], marker="s", color=fs.TIMING_ON, linestyle="none", markersize=5,
            markeredgecolor="black", markeredgewidth=0.5, label="%s estimate" % fs.LABEL_ON)
    for x, v in zip(xs, vals):
        ax.annotate("%.4f" % v, xy=(x, v), xytext=(9, 0), textcoords="offset points",
                    ha="left", va="center", fontsize=7)
    ax.set_xticks(xs)
    ax.set_xticklabels(labels)
    ax.set_xlim(-0.6, 1.6)
    ax.set_yscale("log")
    ax.set_ylim(1e-4, 2.0)
    ax.set_ylabel("$I$(class ; CLRT)  (bits)")
    ax.set_title("Mutual information")
    ax.legend(loc="lower left", fontsize=6.5)
    for lab, v, (lo, hi) in zip(labels, vals, nulls):
        rows.append(["mutual_information_bits", lab.lower().replace(" ", "_"), "%.6f" % v,
                     "%.6f" % lo, "%.6f" % hi])

    # ---- classifier balanced accuracy ------------------------------------------------
    # Also points with intervals: a bar chart of balanced accuracy would need a baseline at
    # 0.5 rather than 0, and a truncated bar exaggerates the difference it displays.
    ax = axes[1]
    ba = [clf["native_balanced_acc"], clf["defended_balanced_acc"]]
    cis = [clf["native_ba_ci"], clf["defended_ba_ci"]]
    err = np.array([[b - lo for b, (lo, _) in zip(ba, cis)],
                    [hi - b for b, (_, hi) in zip(ba, cis)]])
    ax.errorbar(xs, ba, yerr=err, fmt="none", ecolor="black", elinewidth=0.9, capsize=3,
                zorder=3)
    for x, v, colour, marker in zip(xs, ba, [fs.TIMING_OFF, fs.TIMING_ON], ["o", "s"]):
        ax.plot([x], [v], marker=marker, color=colour, markersize=6, zorder=4,
                markeredgecolor="black", markeredgewidth=0.5, linestyle="none")
    ax.axhline(clf["balanced_acc_chance_baseline"], color="black", linestyle=":", lw=0.9,
               zorder=1, label="chance (0.5)")
    for x, v in zip(xs, ba):
        ax.annotate("%.3f" % v, xy=(x, v), xytext=(10, 7), textcoords="offset points",
                    ha="left", va="center", fontsize=7)
    ax.set_xticks(xs)
    ax.set_xticklabels(labels)
    ax.set_xlim(-0.6, 1.6)
    ax.set_ylim(0.47, 0.66)
    ax.set_ylabel("balanced accuracy")
    ax.set_title("READ vs SELECT classifier")
    ax.legend(loc="upper right", fontsize=6.5)
    for lab, v, (lo, hi) in zip(labels, ba, cis):
        rows.append(["balanced_accuracy", lab.lower().replace(" ", "_"), "%.6f" % v,
                     "%.6f" % lo, "%.6f" % hi])

    fig.tight_layout()

    fs.save(fig, figures_dir(root), "fig05_timing_leakage_summary",
            inputs=[st_path],
            caption=(
                "Timing-only leakage with the in-network timing mechanism disabled and "
                "enabled. Left: mutual information between transaction class and CLRT, with "
                "the shaded band giving the 95 percent permutation null for each arm. With "
                "the timing mode off, CLRT carries about 0.42 bits about whether a "
                "transaction was a READ or the SELECT phase of an SBO; with it on, the "
                "estimate falls inside its own null band, meaning no measurable dependence "
                "remains. Right: balanced accuracy of a classifier trained on Timing OFF "
                "CLRT to separate the two transaction types, applied unchanged to Timing ON "
                "traffic, falling from 0.592 to chance. Both arms ran the same unified "
                "switch binary with the size-shaping datapath active, so the Timing OFF arm "
                "is not an unmodified device baseline; shaping is held constant and the "
                "comparison isolates the timing-mode change. Both panels describe "
                "transaction-class feature suppression on a single SEL-751 in a single "
                "capture session with a transaction-disjoint, not session-disjoint, split. "
                "Neither is a device-identification result, and neither claims "
                "indistinguishability across devices: this relay's timing signature is "
                "replaced by a policy signature."),
            stats_note=(
                "Mutual information is estimated on predeclared common bins, "
                "linspace(0, 12, 61) ms, shared with the distributional comparison, so the "
                "support cannot be tuned after the fact; the null band is the 2.5th to "
                "97.5th percentile of 1000 label permutations. Balanced accuracy comes from "
                "a logistic regression on the single feature CLRT, fitted on a 60 percent "
                "transaction-disjoint split of the Timing OFF data and applied without "
                "refitting to the Timing ON data; intervals are percentile bootstrap 95 "
                "percent over 1000 resamples. All seeds are fixed and recorded in "
                "timing_stats.json. The vertical scale on the left panel is logarithmic so "
                "the Timing ON estimate and its null remain visible. Two caveats. First, "
                "the arms differ only in the configured timing mode of one unified binary; "
                "the size carve was enabled throughout both, verified from the response "
                "segmentation on the wire, so this measures the timing mode's contribution "
                "within that program rather than a whole system against an untouched relay. "
                "Second, on precision: the predeclared bin grid places an edge at exactly "
                "4.000 ms, and 18 percent of Timing ON observations fall within one "
                "microsecond of it, so that point estimate moves between roughly 0.000 and "
                "0.002 bits depending on sub-microsecond rounding and on the phase of the "
                "grid. What is stable, and what the figure claims, is that the Timing ON "
                "estimate lies inside its permutation null under every grid phase tested. "
                "The Timing OFF estimate is insensitive to this and reproduces to six "
                "decimal places."),
            data_header=["quantity", "arm", "value", "interval_lo", "interval_hi"],
            data_rows=rows)


if __name__ == "__main__":
    main()
