"""Publication figures for the NDSS manuscript, derived only from generated data.

No result value is written into this file. Release-policy parameters come from
policy_config.json; every statistic comes from the canonical transaction table or from
the analysis JSON produced by stats_campaign.py and leakage_campaign.py.
"""
from __future__ import annotations
import csv, json, sys
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import NullFormatter
import figstyle_ndss as F

CLASSES = ["READ", "SELECT", "OPERATE"]
ARMS = ["native", "obfuscated"]
CCOL = {"READ": F.C_READ, "SELECT": F.C_SELECT, "OPERATE": F.C_OPERATE}
# What the reported interval is called for each class. Both are t_response - t_ACK.
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


# --------------------------------------------------------------- Fig: release budget
def fig_budget(rows, cfg, stats, out):
    D = cfg["release_budget_D_ms"]; H = cfg["fail_open_horizon_H_ms"]
    fig, ax = plt.subplots(1, 2, figsize=(F.PAGE_W, 2.5))
    for c in CLASSES:
        v = np.sort(sel(rows, "native", c))
        ax[0].step(v, 1.0 - np.arange(v.size) / v.size, where="post",
                   color=CCOL[c], lw=1.0, label=c, zorder=3)
    ax[0].axvline(D, color=F.GREY, ls=":", lw=0.9, zorder=2, label=f"budget $D$ = {D:g} ms")
    ax[0].axvline(H, color="black", ls="-.", lw=0.9, zorder=2, label=f"fail-open $H$ = {H:g} ms")
    ax[0].set_xscale("log"); ax[0].set_yscale("log")
    ax[0].xaxis.set_minor_formatter(NullFormatter())
    ax[0].set_xlim(0.8, 120); ax[0].set_ylim(2e-5, 4)
    ax[0].set_xlabel("Timing OFF interval (ms)")
    ax[0].set_ylabel("Fraction of exchanges exceeding")
    ax[0].legend(loc="lower left", framealpha=1.0, borderpad=0.3, labelspacing=0.2)
    nat = sel(rows, "native")
    gridD = np.unique(np.concatenate([np.linspace(2, 120, 500), [D]]))
    ax[1].plot(gridD, [100 * np.mean(nat > d) for d in gridD], color=F.C_OPERATE, lw=1.2,
               zorder=3, label="all classes pooled")
    ax[1].plot([D], [100 * float(np.mean(nat > D))], marker="*", ms=10, mfc=F.ON,
               mec="black", mew=0.7, ls="none", zorder=5, label="chosen operating point")
    ax[1].axvline(H, color="black", ls="-.", lw=0.9, zorder=2, label="fail-open $H$")
    ax[1].set_yscale("log"); ax[1].set_xlim(0, 120); ax[1].set_ylim(3e-3, 200)
    ax[1].set_xlabel("Release budget $D = D_A + D_R$ (ms)")
    ax[1].set_ylabel("Exchanges not coverable (%)")
    ax[1].legend(loc="upper right", framealpha=1.0, borderpad=0.3, labelspacing=0.2)
    for a, t in zip(ax, "ab"):
        a.text(0.97, 0.97, f"({t})", transform=a.transAxes, va="top", ha="right", fontsize=8)
    F.grid(list(ax))
    fig.tight_layout()
    over = stats["timing_off_exceeding_budget"]
    F.save(fig, out, "fig_budget_coverage",
           "Release budget and the coverage it buys. (a) Fraction of Timing OFF exchanges whose "
           "measured interval exceeds a given value, per transaction class, with the chosen "
           f"budget $D$ and the fail-open horizon $H$ marked. (b) Fraction of Timing OFF "
           f"exchanges the switch cannot place on the schedule, against the release budget. At "
           f"$D$ = {cfg['release_budget_D_ms']:g} ms, {over['count']} of {over['n']} exchanges "
           f"({over['percent']:.4f}%) arrive too late to be held. Both ordinates are logarithmic; "
           "panel (a) also uses a logarithmic abscissa and shows the full support.",
           ["transactions_canonical.csv", "policy_config.json", "stats.json"],
           {"unit": "DNP3 exchange", "n_native": int(nat.size),
            "measured_vs_modelled": "both panels are measured; no model is fitted"})


# --------------------------------------------------------------- Fig: interval summary
def fig_intervals(rows, out):
    fig, ax = plt.subplots(1, 3, figsize=(F.PAGE_W, 2.35), sharey=True)
    for a, c in zip(ax, CLASSES):
        data = [sel(rows, arm, c) for arm in ARMS]
        bp = a.boxplot(data, positions=[1, 2], widths=0.55, patch_artist=True,
                       whis=(0, 100), showfliers=False)   # whiskers span the full support
        for i, arm in enumerate(ARMS):
            col = F.OFF if arm == "native" else F.ON
            bp["boxes"][i].set(facecolor=col, alpha=0.45, edgecolor=col, lw=0.8)
            bp["medians"][i].set(color=col, lw=1.6)
            for k in ("whiskers", "caps"):
                for art in bp[k][2 * i:2 * i + 2]:
                    art.set(color=col, lw=0.8)
        a.set_yscale("log")
        a.set_xticks([1, 2]); a.set_xticklabels([F.LBL[x] for x in ARMS], fontsize=7.5)
        a.set_title(f"{c}\n{INAME[c]} (n={data[0].size:,} per arm)", fontsize=8)
        a.yaxis.set_minor_formatter(NullFormatter())
    ax[0].set_ylabel("Interval (ms)")
    F.grid(list(ax)); fig.tight_layout()
    F.save(fig, out, "fig_interval_summary",
           "Measured interval per transaction class and arm, over all 22 grouped runs. For READ "
           "and the SELECT phase of SBO the interval is the cross-layer response time; for "
           "OPERATE it is the master-visible ACK-to-echo interval. Boxes span the quartiles and "
           "the whiskers span the full observed range, so the late-arrival tail is visible rather "
           "than suppressed. The ordinate is logarithmic. Sample sizes are given per panel.",
           ["transactions_canonical.csv"],
           {"whiskers": "full range, no outliers hidden", "unit": "DNP3 exchange"})


# --------------------------------------------------------------- Fig: ECDF, full support
def fig_ecdf(rows, cfg, out):
    fig, ax = plt.subplots(1, 3, figsize=(F.PAGE_W, 2.35), sharey=True)
    for a, c in zip(ax, CLASSES):
        for arm in ARMS:
            v = np.sort(sel(rows, arm, c))
            a.step(v, np.arange(1, v.size + 1) / v.size, where="post",
                   color=(F.OFF if arm == "native" else F.ON), ls=F.LS[arm], lw=1.2,
                   label=F.LBL[arm], zorder=3)
        a.set_xscale("log"); a.xaxis.set_minor_formatter(NullFormatter())
        a.set_xlim(0.8, 120); a.set_ylim(0, 1.02)
        a.set_xlabel(f"{INAME[c]} (ms)"); a.set_title(c, fontsize=8)
    ax[0].set_ylabel("Empirical CDF")
    ax[0].legend(loc="lower right", framealpha=1.0, borderpad=0.3, labelspacing=0.2)
    F.grid(list(ax)); fig.tight_layout()
    mx = {c: {arm: round(float(sel(rows, arm, c).max()), 3) for arm in ARMS} for c in CLASSES}
    F.save(fig, out, "fig_ecdf_full_support",
           "Empirical distribution of the measured interval per transaction class, pooled over "
           "22 grouped runs. The abscissa is logarithmic and spans the complete observed range, "
           "so no observation is clipped: the largest Timing OFF READ interval is "
           f"{mx['READ']['native']:.2f} ms and the largest obfuscated READ interval is "
           f"{mx['READ']['obfuscated']:.2f} ms. Under the mechanism each distribution is a step "
           "at the scheduled release, with a small late-arrival tail.",
           ["transactions_canonical.csv"],
           {"clipping": "none; full support plotted", "maxima_ms": mx})


# --------------------------------------------------------------- Fig: within-campaign stability
def fig_stability(rows, cfg, out):
    runs = sorted({r[0] for r in rows})
    xs = np.arange(1, len(runs) + 1)
    fig, ax = plt.subplots(1, 3, figsize=(F.PAGE_W, 2.35), sharex=True, sharey=True)
    for a, c in zip(ax, CLASSES):
        for arm in ARMS:
            med, lo, hi = [], [], []
            for rn in runs:
                v = np.array([r[3] for r in rows if r[0] == rn and r[1] == arm and r[2] == c])
                q1, q2, q3 = np.percentile(v, [25, 50, 75])
                med.append(q2); lo.append(q2 - q1); hi.append(q3 - q2)
            a.errorbar(xs, med, yerr=[lo, hi], fmt=F.MK[c], ms=2.6, lw=0,
                       elinewidth=0.7, capsize=1.3,
                       color=(F.OFF if arm == "native" else F.ON), label=F.LBL[arm], zorder=3)
        a.axhline(cfg["scheduled_release_interval_ms"], color=F.GREY, ls=":", lw=0.8, zorder=1,
                  label="scheduled release")
        a.set_title(c, fontsize=8); a.set_xlabel("Grouped run, in acquisition order")
        a.set_xlim(0.3, len(runs) + 0.7); a.set_ylim(0, 8.4)
        a.set_xticks([1, 6, 11, 16, 22])
    ax[0].set_ylabel("Interval (ms)")
    ax[0].legend(loc="upper left", framealpha=1.0, borderpad=0.3, labelspacing=0.2)
    for a, t in zip(ax, "abc"):
        a.text(0.97, 0.97, f"({t})", transform=a.transAxes, va="top", ha="right", fontsize=8)
    F.grid(list(ax)); fig.tight_layout()
    F.save(fig, out, "fig_within_campaign_stability",
           "Within-campaign stability across the 22 grouped runs of one approximately five-hour "
           "campaign, in acquisition order. Markers are the run median and bars span the "
           "interquartile range. The runs are grouped collections from a single campaign and are "
           "not independent replications across days, devices, or deployments.",
           ["transactions_canonical.csv", "policy_config.json"],
           {"markers": "run median", "bars": "interquartile range"})


# --------------------------------------------------------------- Fig: leakage
def fig_leakage(leak, out):
    fig = plt.figure(figsize=(F.PAGE_W, 4.35))
    gs = fig.add_gridspec(2, 3, height_ratios=[1.0, 1.05], hspace=0.70, wspace=0.42,
                          left=0.085, right=0.985, top=0.965, bottom=0.135)
    a0, a1 = fig.add_subplot(gs[0, :2]), fig.add_subplot(gs[0, 2])
    # (a) balanced accuracy, fixed vs adaptive attacker
    feats = ["clrt", "ack_clrt"]
    names = {"clrt": "CLRT only", "ack_clrt": "req-to-ACK + CLRT"}
    bars = [("A fixed, Timing OFF", "A_fixed_native_trained", "tested_on_timing_off", F.OFF, "///"),
            ("A fixed, applied to Obfuscated", "A_fixed_native_trained", "tested_on_obfuscated", F.ON, "\\\\\\"),
            ("B adaptive, Obfuscated", "B_adaptive_obfuscated_trained", "tested_on_obfuscated", "#661100", "xxx")]
    w, xb = 0.26, np.arange(len(feats))
    for k, (lab, grp, key, col, hat) in enumerate(bars):
        m = [leak["classifiers"][f][grp][key]["balanced_accuracy"] for f in feats]
        ci = [leak["classifiers"][f][grp][key]["ci95"] for f in feats]
        err = np.abs(np.array(ci).T - np.array(m))
        a0.bar(xb + (k - 1) * w, m, w * 0.86, yerr=err, capsize=2, color=col, alpha=0.85,
               edgecolor="black", lw=0.6, hatch=hat, label=lab, error_kw=dict(lw=0.7))
    a0.axhline(leak["chance_balanced_accuracy"], color="black", ls=":", lw=0.9,
               label="chance (1/3)", zorder=4)
    a0.set_xticks(xb); a0.set_xticklabels([names[f] for f in feats], fontsize=7.5)
    a0.set_ylabel("Balanced accuracy"); a0.set_ylim(0, 1.16)
    a0.legend(loc="upper left", ncol=2, framealpha=1.0, borderpad=0.3, labelspacing=0.18,
              columnspacing=0.8, fontsize=6.6)
    a0.text(0.955, 0.04, "(a)", transform=a0.transAxes, va="bottom", ha="right", fontsize=8)
    # (b) mutual information in bits against the permutation null
    mi = leak["mutual_information"]
    xs = np.arange(2)
    obs = [mi[a]["observed_bits"] for a in ARMS]
    se = [mi[a]["jackknife_se_bits"] for a in ARMS]
    a1.bar(xs, obs, 0.5, yerr=[1.96 * s for s in se], capsize=2,
           color=[F.OFF, F.ON], alpha=0.85, edgecolor="black", lw=0.6,
           hatch=["///", "\\\\\\"], error_kw=dict(lw=0.7))
    for i, a_ in enumerate(ARMS):
        a1.hlines(mi[a_]["null_p99_bits"], i - 0.3, i + 0.3, color="black", lw=1.0,
                  linestyles="dashed", zorder=5,
                  label="permutation null, 99th pct" if i == 0 else None)
    a1.set_xticks(xs); a1.set_xticklabels([F.LBL[a] for a in ARMS], fontsize=7.5)
    a1.set_ylabel("Mutual information (bits)")
    a1.set_ylim(0, max(obs) * 1.45)
    a1.legend(loc="upper right", framealpha=1.0, borderpad=0.3, fontsize=6.6)
    a1.text(0.94, 0.04, "(b)", transform=a1.transAxes, va="bottom", ha="right", fontsize=8)
    # (c,d,e) confusion, all 22 folds
    panels = [("clrt/A_obf", "(c) A fixed on Obfuscated, CLRT"),
              ("ack_clrt/A_obf", "(d) A fixed on Obfuscated, both"),
              ("ack_clrt/B_obf", "(e) B adaptive on Obfuscated, both")]
    for j, (key, ttl) in enumerate(panels):
        a = fig.add_subplot(gs[1, j])
        cm = np.array(leak["confusion_all_folds"][key])
        a.imshow(cm, cmap="Blues", vmin=0, vmax=1)
        for i in range(3):
            for k in range(3):
                a.text(k, i, f"{cm[i,k]:.2f}", ha="center", va="center", fontsize=6.4,
                       color="white" if cm[i, k] > 0.55 else "black")
        a.set_xticks(range(3)); a.set_yticks(range(3))
        a.set_xticklabels(CLASSES, fontsize=6.2, rotation=30, ha="right")
        a.set_yticklabels(CLASSES if j == 0 else [""] * 3, fontsize=6.2)
        a.set_title(ttl, fontsize=7.0); a.set_xlabel("Predicted", fontsize=7.5)
        if j == 0:
            a.set_ylabel("True", fontsize=7.5)
        for sp in a.spines.values():
            sp.set_linewidth(0.6)
    F.grid([a0, a1])
    F.save(fig, out, "fig_leakage_attackers",
           "Transaction-class leakage under the two attacker models, evaluated by leaving out one "
           "grouped run at a time over all 22 runs. (a) Balanced accuracy with grouped-run 95% "
           "confidence intervals; the fixed attacker is trained on Timing OFF traffic and applied "
           "unchanged, the adaptive attacker is retrained on obfuscated traffic. (b) Mutual "
           "information between the cross-layer response time and the transaction class, in bits, "
           "with jackknife intervals and the 99th percentile of a within-run permutation null. "
           "(c) to (e) Row-normalised confusion aggregated over all 22 held-out runs. Chance "
           "balanced accuracy for three classes is one third.",
           ["transactions_canonical.csv", "leakage.json"],
           {"folds": leak["n_folds"], "permutations": mi["native"]["n_permutations"],
            "features": "req-to-ACK and CLRT only; total response latency is their sum and is excluded",
            "mi_units": "bits, converted from the estimator's nats"})


# --------------------------------------------------------------- Fig: cost and wire overhead
def fig_cost(rows, cfg, stats, out):
    fig, ax = plt.subplots(2, 1, figsize=(F.COL_W, 3.5))
    for arm in ARMS:
        data = [sel(rows, arm, c, col=5) for c in CLASSES]
        pos = np.arange(3) + (0.18 if arm == "obfuscated" else -0.18)
        bp = ax[0].boxplot(data, positions=pos, widths=0.3, patch_artist=True,
                           whis=(0, 100), showfliers=False)
        col = F.OFF if arm == "native" else F.ON
        for i in range(3):
            bp["boxes"][i].set(facecolor=col, alpha=0.45, edgecolor=col, lw=0.7,
                               label=F.LBL[arm] if i == 0 else None)
            bp["medians"][i].set(color=col, lw=1.5)
            for k in ("whiskers", "caps"):
                for art in bp[k][2 * i:2 * i + 2]:
                    art.set(color=col, lw=0.7)
    ax[0].set_yscale("log"); ax[0].set_xticks(range(3)); ax[0].set_xticklabels(CLASSES, fontsize=7.5)
    ax[0].set_ylabel("Response time (ms)"); ax[0].set_xlim(-0.6, 2.6)
    ax[0].yaxis.set_minor_formatter(NullFormatter())
    ax[0].legend(loc="upper left", framealpha=1.0, borderpad=0.3, labelspacing=0.2)
    ax[0].text(0.97, 0.97, "(a)", transform=ax[0].transAxes, va="top", ha="right", fontsize=8)
    ov = stats["overhead"]
    metrics = ["Frames", "Captured bytes"]
    vals = [ov["frames_per_exchange"], ov["wire_bytes_per_exchange"]]
    xb = np.arange(2)
    for k, arm in enumerate(ARMS):          # identical by measurement; drawn as a pair
        ax[1].bar(xb + (k - 0.5) * 0.34, vals, 0.3, color=(F.OFF if arm == "native" else F.ON),
                  alpha=0.85, edgecolor="black", lw=0.6, hatch=F.HATCH[arm], label=F.LBL[arm])
    ax[1].set_yscale("log"); ax[1].set_xticks(xb); ax[1].set_xticklabels(metrics, fontsize=7.5)
    ax[1].set_ylabel("Per DNP3 exchange"); ax[1].set_ylim(1, 2000); ax[1].set_xlim(-0.6, 1.6)
    ax[1].yaxis.set_minor_formatter(NullFormatter())
    ax[1].legend(loc="upper left", framealpha=1.0, borderpad=0.3, labelspacing=0.2)
    ax[1].text(0.97, 0.97, "(b)", transform=ax[1].transAxes, va="top", ha="right", fontsize=8)
    F.grid(list(ax)); fig.tight_layout()
    add = stats["added_response_latency_ms"]
    F.save(fig, out, "fig_cost_overhead",
           "Cost of the mechanism, per DNP3 request-response exchange. (a) End-to-end response "
           "time per transaction class; boxes span the quartiles and whiskers the full observed "
           "range. The median rises by "
           f"{add['READ']:.1f} ms for READ, {add['SELECT']:.1f} ms for SELECT and "
           f"{add['OPERATE']:.1f} ms for OPERATE. (b) Frames and captured bytes per exchange on "
           "the master-facing link, which are equal in the two arms. The switch also generates "
           "internal blocker traffic, which never reaches the master-facing link and is therefore "
           "outside this measurement.",
           ["transactions_canonical.csv", "stats.json", "policy_config.json"],
           {"denominator": f"{ov['exchanges_per_capture']} DNP3 exchanges per capture",
            "scope": "master-facing link only"})


def main(canon, statsf, leakf, cfgf, out):
    F.use()
    rows = load_rows(canon)
    stats = json.load(open(statsf)); leak = json.load(open(leakf)); cfg = json.load(open(cfgf))
    print("figures:")
    fig_budget(rows, cfg, stats, out)
    fig_intervals(rows, out)
    fig_ecdf(rows, cfg, out)
    fig_stability(rows, cfg, out)
    fig_leakage(leak, out)
    fig_cost(rows, cfg, stats, out)


if __name__ == "__main__":
    main(*sys.argv[1:6])
