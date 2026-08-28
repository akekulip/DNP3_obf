"""Publication figures for the NDSS manuscript, as compact grids.

Layout contract:
  three 2x2 grids at text-block width, panels labelled (a) to (d)
  one 2x1 grid at single-column width, panels labelled (a) and (b)

No result value is written into this file. Release-policy parameters come from
policy_config.json; every statistic comes from the canonical transaction table or from the
analysis JSON produced by stats_campaign.py and leakage_campaign.py.
"""
from __future__ import annotations
import csv, json, sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import NullFormatter
import figstyle_ndss as F

CLASSES = ["READ", "SELECT", "OPERATE"]
ARMS = ["native", "obfuscated"]
CCOL = {"READ": F.C_READ, "SELECT": F.C_SELECT, "OPERATE": F.C_OPERATE}
ACOL = {"native": F.OFF, "obfuscated": F.ON}
INAME = {"READ": "CLRT", "SELECT": "CLRT", "OPERATE": "ACK-to-echo"}


def load_rows(p):
    out = []
    with open(p) as f:
        for r in csv.DictReader(f):
            out.append((r["run"], r["arm"], r["txn_class"],
                        float(r["clrt_ms"]), float(r["ack_ms"]), float(r["rt_ms"])))
    return out


def sel(rows, arm=None, cls=None, col=3):
    return np.array([r[col] for r in rows
                     if (arm is None or r[1] == arm) and (cls is None or r[2] == cls)])


def tag(ax, t, x=0.965, y=0.955, ha="right", va="top"):
    ax.text(x, y, f"({t})", transform=ax.transAxes, va=va, ha=ha, fontsize=8)


def box_pair(ax, rows, col, logy=True):
    """Timing OFF against Obfuscated for the three classes; whiskers span the full range."""
    for k, arm in enumerate(ARMS):
        data = [sel(rows, arm, c, col=col) for c in CLASSES]
        pos = np.arange(3) + (0.19 if arm == "obfuscated" else -0.19)
        bp = ax.boxplot(data, positions=pos, widths=0.32, patch_artist=True,
                        whis=(0, 100), showfliers=False)
        for i in range(3):
            bp["boxes"][i].set(facecolor=ACOL[arm], alpha=0.45, edgecolor=ACOL[arm], lw=0.7,
                               label=F.LBL[arm] if i == 0 else None)
            bp["medians"][i].set(color=ACOL[arm], lw=1.5)
            for kk in ("whiskers", "caps"):
                for art in bp[kk][2 * i:2 * i + 2]:
                    art.set(color=ACOL[arm], lw=0.7)
    if logy:
        ax.set_yscale("log"); ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_xticks(range(3)); ax.set_xticklabels(CLASSES, fontsize=7.5); ax.set_xlim(-0.6, 2.6)


# ============================================================ GRID 1: budget and cost (2x2)
def fig_budget_cost(rows, cfg, stats, out):
    D, H = cfg["release_budget_D_ms"], cfg["fail_open_horizon_H_ms"]
    fig, ax = plt.subplots(2, 2, figsize=(F.PAGE_W, 4.3))
    # (a) Timing OFF tail that the budget must cover
    for c in CLASSES:
        v = np.sort(sel(rows, "native", c))
        ax[0][0].step(v, 1.0 - np.arange(v.size) / v.size, where="post",
                      color=CCOL[c], lw=1.0, label=c, zorder=3)
    ax[0][0].axvline(D, color=F.GREY, ls=":", lw=0.9, zorder=2, label=f"budget $D$={D:g} ms")
    ax[0][0].axvline(H, color="black", ls="-.", lw=0.9, zorder=2, label=f"fail-open $H$={H:g} ms")
    ax[0][0].set_xscale("log"); ax[0][0].set_yscale("log")
    ax[0][0].xaxis.set_minor_formatter(NullFormatter())
    ax[0][0].set_xlim(0.8, 120); ax[0][0].set_ylim(2e-5, 4)
    ax[0][0].set_xlabel("Timing OFF interval (ms)")
    ax[0][0].set_ylabel("Fraction exceeding")
    ax[0][0].legend(loc="lower left", framealpha=1.0, borderpad=0.28, labelspacing=0.16,
                    fontsize=6.4)
    # (b) coverage against the release budget
    nat = sel(rows, "native")
    g = np.unique(np.concatenate([np.linspace(2, 120, 500), [D]]))
    ax[0][1].plot(g, [100 * np.mean(nat > d) for d in g], color=F.C_OPERATE, lw=1.2, zorder=3,
                  label="all classes pooled")
    ax[0][1].plot([D], [100 * float(np.mean(nat > D))], marker="*", ms=10, mfc=F.ON,
                  mec="black", mew=0.7, ls="none", zorder=5, label="operating point")
    ax[0][1].axvline(H, color="black", ls="-.", lw=0.9, zorder=2, label="fail-open $H$")
    ax[0][1].set_yscale("log"); ax[0][1].set_xlim(0, 120); ax[0][1].set_ylim(3e-3, 300)
    ax[0][1].set_xlabel("Release budget $D = D_A + D_R$ (ms)")
    ax[0][1].set_ylabel("Not coverable (%)")
    ax[0][1].legend(loc="upper right", framealpha=1.0, borderpad=0.28, labelspacing=0.16,
                    fontsize=6.4)
    # (c) end-to-end response time, the observed cost
    box_pair(ax[1][0], rows, col=5)
    ax[1][0].set_ylabel("Response time (ms)"); ax[1][0].set_ylim(1, 400)
    ax[1][0].legend(loc="upper left", framealpha=1.0, borderpad=0.28, labelspacing=0.16,
                    fontsize=6.6)
    # (d) master-facing wire cost per exchange
    ov = stats["overhead"]
    vals = [ov["frames_per_exchange"], ov["wire_bytes_per_exchange"]]
    xb = np.arange(2)
    for k, arm in enumerate(ARMS):
        ax[1][1].bar(xb + (k - 0.5) * 0.34, vals, 0.3, color=ACOL[arm], alpha=0.85,
                     edgecolor="black", lw=0.6, hatch=F.HATCH[arm], label=F.LBL[arm])
    ax[1][1].set_yscale("log"); ax[1][1].set_xticks(xb)
    ax[1][1].set_xticklabels(["Frames", "Captured bytes"], fontsize=7.5)
    ax[1][1].set_ylabel("Per DNP3 exchange"); ax[1][1].set_ylim(1, 4000)
    ax[1][1].set_xlim(-0.6, 1.6)
    ax[1][1].yaxis.set_minor_formatter(NullFormatter())
    ax[1][1].legend(loc="upper left", framealpha=1.0, borderpad=0.28, labelspacing=0.16,
                    fontsize=6.6)
    for a, t in zip([ax[0][0], ax[0][1], ax[1][0], ax[1][1]], "abcd"):
        tag(a, t)
    F.grid([ax[0][0], ax[0][1], ax[1][0], ax[1][1]])
    fig.tight_layout()
    over = stats["timing_off_exceeding_budget"]; add = stats["added_response_latency_ms"]
    F.save(fig, out, "fig_budget_cost",
           "\\textbf{Release budget, coverage, and cost.} (a) Fraction of Timing OFF exchanges "
           "whose interval exceeds a given value, per class, with the budget $D$ and the fail-open "
           "horizon $H$. (b) Fraction the switch cannot place on the schedule, against the release "
           f"budget; at $D$={D:g} ms, {over['count']} of {over['n']} exchanges "
           f"({over['percent']:.4f}%) arrive too late. (c) End-to-end response time per class. "
           f"(d) Frames and captured bytes per exchange on the master-facing link, equal in both "
           "arms. Boxes span the quartiles and whiskers the full support; logarithmic ordinates.",
           ["transactions_canonical.csv", "policy_config.json", "stats.json"],
           {"unit": "DNP3 exchange", "added_latency_ms": add,
            "scope": "master-facing link; internal blocker traffic not counted"})


# ============================================================ GRID 2: distributions (2x2)
def fig_distributions(rows, out):
    fig, ax = plt.subplots(2, 2, figsize=(F.PAGE_W, 4.05))
    flat = [ax[0][0], ax[0][1], ax[1][0]]
    for a, c in zip(flat, CLASSES):
        for arm in ARMS:
            v = np.sort(sel(rows, arm, c))
            a.step(v, np.arange(1, v.size + 1) / v.size, where="post", color=ACOL[arm],
                   ls=F.LS[arm], lw=1.2, label=F.LBL[arm], zorder=3)
        a.set_xscale("log"); a.xaxis.set_minor_formatter(NullFormatter())
        a.set_xlim(0.8, 120); a.set_ylim(0, 1.02)
        a.set_xlabel(f"{c}: {INAME[c]} (ms)"); a.set_ylabel("Empirical CDF")
    flat[0].legend(loc="lower right", framealpha=1.0, borderpad=0.28, labelspacing=0.16,
                   fontsize=6.6)
    box_pair(ax[1][1], rows, col=3)
    ax[1][1].set_ylabel("Interval (ms)"); ax[1][1].set_ylim(0.8, 200)
    ax[1][1].legend(loc="upper left", framealpha=1.0, borderpad=0.28, labelspacing=0.16,
                    fontsize=6.6)
    for a, t in zip([ax[0][0], ax[0][1], ax[1][0], ax[1][1]], "abcd"):
        tag(a, t, y=0.93)
    F.grid([ax[0][0], ax[0][1], ax[1][0], ax[1][1]])
    fig.tight_layout()
    mx = {c: {a_: round(float(sel(rows, a_, c).max()), 3) for a_ in ARMS} for c in CLASSES}
    F.save(fig, out, "fig_distributions",
           "\\textbf{Measured interval per transaction class, over 22 grouped runs.} (a) READ, "
           "(b) the SELECT phase of SBO, and (c) OPERATE, as empirical distributions on a "
           "logarithmic abscissa spanning the full support, so no observation is clipped: the "
           f"largest Timing OFF READ interval is {mx['READ']['native']:.2f} ms and the largest "
           f"obfuscated one is {mx['READ']['obfuscated']:.2f} ms. (d) The same measurements as "
           "quartiles, with whiskers spanning the full support.",
           ["transactions_canonical.csv"],
           {"clipping": "none; full support plotted", "maxima_ms": mx,
            "whiskers": "full range, no observation hidden"})


# ============================================================ GRID 3: leakage (2x2)
def fig_leakage(leak, out):
    fig, ax = plt.subplots(2, 2, figsize=(F.PAGE_W, 4.15))
    feats = ["clrt", "ack_clrt"]
    names = {"clrt": "CLRT only", "ack_clrt": "req-to-ACK + CLRT"}
    bars = [("A fixed, Timing OFF", "A_fixed_native_trained", "tested_on_timing_off", F.OFF, "///"),
            ("A fixed, on Obfuscated", "A_fixed_native_trained", "tested_on_obfuscated", F.ON, "\\\\\\"),
            ("B adaptive, on Obfuscated", "B_adaptive_obfuscated_trained", "tested_on_obfuscated",
             "#661100", "xxx")]
    w, xb = 0.26, np.arange(len(feats))
    for k, (lab, grp, key, col, hat) in enumerate(bars):
        m = [leak["classifiers"][f][grp][key]["balanced_accuracy"] for f in feats]
        ci = [leak["classifiers"][f][grp][key]["ci95"] for f in feats]
        err = np.abs(np.array(ci).T - np.array(m))
        ax[0][0].bar(xb + (k - 1) * w, m, w * 0.86, yerr=err, capsize=2, color=col, alpha=0.85,
                     edgecolor="black", lw=0.6, hatch=hat, label=lab, error_kw=dict(lw=0.7))
    ax[0][0].axhline(leak["chance_balanced_accuracy"], color="black", ls=":", lw=0.9,
                     label="chance (1/3)", zorder=4)
    ax[0][0].set_xticks(xb); ax[0][0].set_xticklabels([names[f] for f in feats], fontsize=7.2)
    ax[0][0].set_ylabel("Balanced accuracy"); ax[0][0].set_ylim(0, 1.24)
    ax[0][0].legend(loc="upper left", framealpha=1.0, borderpad=0.28, labelspacing=0.16,
                    fontsize=6.0, ncol=2, columnspacing=0.7)
    mi = leak["mutual_information"]
    xs = np.arange(2)
    obs = [mi[a]["observed_bits"] for a in ARMS]
    se = [mi[a]["jackknife_se_bits"] for a in ARMS]
    ax[0][1].bar(xs, obs, 0.48, yerr=[1.96 * s for s in se], capsize=2,
                 color=[F.OFF, F.ON], alpha=0.85, edgecolor="black", lw=0.6,
                 hatch=["///", "\\\\\\"], error_kw=dict(lw=0.7))
    for i, a_ in enumerate(ARMS):
        ax[0][1].hlines(mi[a_]["null_p99_bits"], i - 0.28, i + 0.28, color="black", lw=1.0,
                        linestyles="dashed", zorder=5,
                        label="permutation null, 99th pct" if i == 0 else None)
    ax[0][1].set_xticks(xs); ax[0][1].set_xticklabels([F.LBL[a] for a in ARMS], fontsize=7.2)
    ax[0][1].set_ylabel("Mutual information (bits)"); ax[0][1].set_ylim(0, max(obs) * 1.5)
    ax[0][1].legend(loc="upper right", framealpha=1.0, borderpad=0.28, fontsize=6.2)
    for a, key, ttl in ((ax[1][0], "ack_clrt/A_obf", "A fixed, on Obfuscated"),
                        (ax[1][1], "ack_clrt/B_obf", "B adaptive, on Obfuscated")):
        cm = np.array(leak["confusion_all_folds"][key])
        a.imshow(cm, cmap="Blues", vmin=0, vmax=1)
        for i in range(3):
            for j in range(3):
                a.text(j, i, f"{cm[i,j]:.2f}", ha="center", va="center", fontsize=6.8,
                       color="white" if cm[i, j] > 0.55 else "black")
        a.set_xticks(range(3)); a.set_yticks(range(3))
        a.set_xticklabels(CLASSES, fontsize=6.4, rotation=30, ha="right")
        a.set_yticklabels(CLASSES, fontsize=6.4)
        a.set_xlabel("Predicted", fontsize=7.5); a.set_ylabel("True", fontsize=7.5)
        a.set_title(ttl, fontsize=7.4)
        for sp in a.spines.values():
            sp.set_linewidth(0.6)
    for a, t in zip([ax[0][0], ax[0][1], ax[1][0], ax[1][1]], "abcd"):
        tag(a, t, x=1.0, y=1.30 if t in "cd" else 0.955)
    F.grid([ax[0][0], ax[0][1]])
    fig.tight_layout()
    F.save(fig, out, "fig_leakage",
           "\\textbf{Transaction-class leakage under the two attacker models}, leaving out one "
           "grouped run at a time over all 22 runs. (a) Balanced accuracy with grouped-run 95\\% "
           "confidence intervals; the fixed adversary is trained on Timing OFF traffic and applied "
           "unchanged, the adaptive adversary is retrained on obfuscated traffic. (b) Mutual "
           "information between the cross-layer response time and the class, in bits, with "
           "jackknife intervals and the 99th percentile of a within-run permutation null. "
           "(c) and (d) Row-normalised confusion over all 22 held-out runs, using both intervals.",
           ["transactions_canonical.csv", "leakage.json"],
           {"folds": leak["n_folds"], "permutations": mi["native"]["n_permutations"],
            "features": "req-to-ACK and CLRT; total response latency is their sum and is excluded",
            "mi_units": "bits, converted from the estimator's nats"})


# ============================================================ GRID 4: stability (2x1, one column)
def fig_stability(rows, cfg, out):
    runs = sorted({r[0] for r in rows})
    xs = np.arange(1, len(runs) + 1)
    fig, ax = plt.subplots(2, 1, figsize=(F.COL_W, 3.3), sharex=True)
    for a, arm in zip(ax, ARMS):
        for c in CLASSES:
            med, lo, hi = [], [], []
            for rn in runs:
                v = np.array([r[3] for r in rows if r[0] == rn and r[1] == arm and r[2] == c])
                q1, q2, q3 = np.percentile(v, [25, 50, 75])
                med.append(q2); lo.append(q2 - q1); hi.append(q3 - q2)
            a.errorbar(xs, med, yerr=[lo, hi], fmt=F.MK[c], ms=2.4, lw=0, elinewidth=0.6,
                       capsize=1.2, color=CCOL[c], label=c, zorder=3)
        a.set_ylabel("Interval (ms)")
        a.set_xlim(0.3, len(runs) + 0.7); a.set_xticks([1, 6, 11, 16, 22])
    ax[0].set_ylim(0, 8.6)
    ax[1].axhline(cfg["scheduled_release_interval_ms"], color=F.GREY, ls=":", lw=0.8, zorder=1)
    ax[1].set_ylim(3.90, 4.10)
    ax[1].set_xlabel("Grouped run, in acquisition order")
    ax[0].legend(loc="upper left", ncol=3, framealpha=1.0, borderpad=0.28, labelspacing=0.14,
                 columnspacing=0.6, fontsize=6.2)
    tag(ax[0], "a"); tag(ax[1], "b")
    F.grid(list(ax)); fig.tight_layout()
    F.save(fig, out, "fig_stability",
           "\\textbf{Within-campaign stability across the 22 grouped runs}, in acquisition order. "
           "(a) Timing OFF and (b) Obfuscated, the latter on a narrow ordinate around the "
           "scheduled release. Markers are the run median and bars span the interquartile range. "
           "The runs come from one campaign and are not independent replications across days, "
           "devices, or deployments.",
           ["transactions_canonical.csv", "policy_config.json"],
           {"markers": "run median", "bars": "interquartile range",
            "note": "panel (b) uses a narrow ordinate; the late-arrival tail is shown in the "
                    "distribution figure, not here"})


def main(canon, statsf, leakf, cfgf, out):
    F.use()
    rows = load_rows(canon)
    stats = json.load(open(statsf)); leak = json.load(open(leakf)); cfg = json.load(open(cfgf))
    print("figures:")
    fig_budget_cost(rows, cfg, stats, out)
    fig_distributions(rows, out)
    fig_leakage(leak, out)
    fig_stability(rows, cfg, out)


if __name__ == "__main__":
    main(*sys.argv[1:6])
