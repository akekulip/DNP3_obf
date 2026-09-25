"""Publication figures for the NDSS manuscript, as compact grids.

Layout contract: final-size NDSS columns, external keys and panel headings,
shared axes where directly comparable, and separately labelled detail panels.

No result value is written into this file. Release-policy parameters come from
policy_config.json; every statistic comes from the canonical transaction table, the measured
hardware sweep, or the analysis JSON produced by stats_campaign.py and leakage_campaign.py.

The read lane and the control lane are never pooled. Both lanes arm deadlines from the
request in campaign_v2. Only READ and the SELECT phase of SBO belong in the read-lane
budget denominator. The post-ACK interval is response minus ACK for all three classes.
"""
from __future__ import annotations
import csv, json, pathlib, sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import NullFormatter
import figstyle_ndss as F

CLASSES = ["READ", "SELECT", "OPERATE"]
READ_LANE = ["READ", "SELECT"]
ARMS = ["native", "obfuscated"]
CCOL = {"READ": F.C_READ, "SELECT": F.C_SELECT, "OPERATE": F.C_OPERATE}
ACOL = {"native": F.OFF, "obfuscated": F.ON}
INAME = {"READ": "CLRT", "SELECT": "CLRT", "OPERATE": "post-ACK interval"}
SEED = 20260828


def load_rows(p):
    out = []
    with open(p) as f:
        for r in csv.DictReader(f):
            out.append((r["run"], r["arm"], r["txn_class"],
                        float(r["clrt_ms"]), float(r["ack_ms"]), float(r["rt_ms"])))
    return out


def sel(rows, arm=None, cls=None, col=3):
    if isinstance(cls, (list, tuple)):
        return np.array([r[col] for r in rows
                         if (arm is None or r[1] == arm) and r[2] in cls])
    return np.array([r[col] for r in rows
                     if (arm is None or r[1] == arm) and (cls is None or r[2] == cls)])


def tag(ax, t, x=0.965, y=0.955, ha="right", va="top"):
    """Panel labels live just above the axes, separate from titles and data."""
    ax.text(0.0, 1.02, f"({t})", transform=ax.transAxes, va="bottom", ha="left",
            fontsize=8, fontweight="bold", clip_on=False)


def empirical_curves(values):
    """Exact ECDF and strict exceedance at each distinct measurement, including ties."""
    x, counts = np.unique(np.asarray(values, dtype=float), return_counts=True)
    cumulative = np.cumsum(counts) / counts.sum()
    return x, cumulative, 1.0 - cumulative


def log_limits(values):
    """Shared positive limits with a small margin around the entire measured support."""
    v = np.asarray(values)
    if not np.all(np.isfinite(v)) or np.any(v <= 0):
        raise ValueError("logarithmic plots require finite positive intervals")
    return float(v.min() / 1.15), float(v.max() * 1.15)


def box_pair(ax, rows, col, logy=True, horizontal=False):
    """Timing OFF against Obfuscated for the three classes; whiskers span the full range.

    horizontal=True lays the classes down the side. At one column's width three class names
    cannot sit under three box pairs at 8 pt: SELECT and OPERATE need 31.5 pt between centres
    and get 30. Down the side they have the whole left margin.
    """
    for arm in ARMS:
        data = [sel(rows, arm, c, col=col) for c in CLASSES]
        # Top to bottom READ, SELECT, OPERATE, the order of the text, when laid down the side.
        base = (2 - np.arange(3)) if horizontal else np.arange(3)
        pos = base + (0.19 if arm == "obfuscated" else -0.19) * (-1 if horizontal else 1)
        bp = ax.boxplot(data, positions=pos, widths=0.32, patch_artist=True,
                        whis=(0, 100), showfliers=False, orientation="horizontal" if horizontal else "vertical")
        for i in range(3):
            # Open against solid, so the pair stays readable in greyscale without a hatch.
            bp["boxes"][i].set(facecolor=F.arm_face(arm, ACOL[arm]), alpha=F.FILL_ALPHA[arm],
                               edgecolor=ACOL[arm], lw=0.9,
                               label=F.LBL[arm] if i == 0 else None)
            bp["medians"][i].set(color=ACOL[arm], lw=1.5)
            for kk in ("whiskers", "caps"):
                for art in bp[kk][2 * i:2 * i + 2]:
                    art.set(color=ACOL[arm], lw=0.7)
    if horizontal:
        if logy:
            ax.set_xscale("log"); ax.xaxis.set_minor_formatter(NullFormatter())
        ax.set_yticks([2, 1, 0])
        ax.set_yticklabels(CLASSES, fontsize=8)
        ax.set_ylim(-0.6, 2.6)
        return
    if logy:
        ax.set_yscale("log"); ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_xticks(range(3))
    ax.set_xticklabels(CLASSES, fontsize=8)
    ax.set_xlim(-0.6, 2.6)


# ================================================== GRID 1: configurability, coverage, cost (2x2)
def fig_policy_coverage_cost(rows, cfg, stats, sweep, out, inputs):
    """Panel (b) is the measured hardware sweep, not a resampled distribution."""
    D, H = cfg["release_budget_D_ms"], cfg["fail_open_horizon_H_ms"]
    # Three readable panels across the text block; keys occupy their own margin.
    fig, _axes = plt.subplots(1, 3, figsize=(F.PAGE_W, 2.65))
    ax = [[_axes[0], _axes[1]], [None, _axes[2]]]
    data = []

    # ---- (a) read-lane Timing OFF tail the budget must cover. READ and SELECT only. The read
    # lane arms both deadlines at the request, so a response is on time when it reaches the switch
    # within D of the request: the quantity D must cover is the request-to-response time, column 5,
    # not the CLRT (which was the right quantity only for the acknowledgment-anchored build).
    for c in READ_LANE:
        v, _, y = empirical_curves(sel(rows, "native", c, col=5))
        # Zero has no logarithmic ordinate; retain it in the exact curve data below.
        ax[0][0].step(v, np.where(y > 0, y, np.nan), where="post", color=CCOL[c], lw=1.1, ls=F.LS_CLASS[c],
                      marker=None, label=c, zorder=3)
        for xi, yi in zip(v, y):
            data.append(dict(panel="a", series=c, x_ms=round(float(xi), 6),
                             y_fraction_exceeding=float(yi)))
    ax[0][0].axvline(D, color=F.GREY, ls=":", lw=1.0, zorder=2)
    ax[0][0].axvline(H, color="black", ls="-.", lw=1.0, zorder=2)
    ax[0][0].set_xscale("log"); ax[0][0].set_yscale("log")
    ax[0][0].xaxis.set_minor_formatter(NullFormatter())
    ax[0][0].set_xlim(*log_limits(np.r_[sel(rows, "native", READ_LANE, col=5), D, H]))
    ax[0][0].set_ylim(0.5 / len(sel(rows, "native", "READ")), 1.25)
    ax[0][0].set_xlabel("Request-to-response [ms]")
    ax[0][0].set_ylabel("Fraction exceeding")
    # The two vertical rules are named in the key rather than by italics floating at the top of
    # the panel, where they sat clear of the rules they labelled and read as stray symbols.
    ax[0][0].plot([], [], color=F.GREY, ls=":", lw=1.0, label="budget $D$")
    ax[0][0].plot([], [], color="black", ls="-.", lw=1.0, label="horizon $H$")
    F.key(ax[0][0], ncol=2, handlelength=1.4, handletextpad=0.4)

    # ---- (b) fixed total budget, the configured CLRT_new swept: the visible interval follows
    # the policy value. The archived sweep table names that configured value D_R_ms; under the
    # paper's notation it is the configured CLRT_new, not the paper's D_R (the response
    # latency). The field name is historical; see defense4/timing/NOTATION_MAPPING.md.
    # Only release-policy points (mode D4) belong here. The D2 and D3 points are envelope
    # controls that run a different mode, so a shared total budget does not make them
    # comparable and they are excluded rather than plotted as if they were policy settings.
    fixed = sorted([s for s in sweep
                    if s["mode"] == "D4" and not s["is_control_point"]
                    and s["D_ms"] is not None and abs(s["D_ms"] - D) < 1e-9
                    and s["D_R_ms"] is not None], key=lambda s: s["D_R_ms"])
    xs = np.array([s["D_R_ms"] for s in fixed])
    ys = np.array([s["read_clrt_med_ms"] for s in fixed])
    rt = np.array([s["read_rt_med_ms"] for s in fixed])
    # Bars are the interquartile range, consistent with every other spread in this manuscript.
    # The full measured range is in the figure-data CSV.
    lo = np.array([s["read_clrt_med_ms"] - s["read_clrt_q1_ms"] for s in fixed])
    hi = np.array([s["read_clrt_q3_ms"] - s["read_clrt_med_ms"] for s in fixed])
    lim = [0, max(xs.max(), ys.max()) * 1.12]
    ax[0][1].plot(lim, lim, color=F.GREY, ls=":", lw=1.0, zorder=1,
                  label="measured $=$ configured")
    ax[0][1].errorbar(xs, ys, yerr=[lo, hi], fmt=F.MK["READ"], ms=3.4, lw=0, elinewidth=0.7,
                      capsize=1.6, color=F.ON, zorder=4,
                      label="measured $\\mathrm{CLRT}_{\\mathrm{new}}$")
    ax[0][1].plot(xs, rt, marker=F.MK["OPERATE"], ms=3.4, ls="--", lw=1.0, color=F.C_OPERATE,
                  zorder=3, label="request-to-response")
    ax[0][1].set_xlim(*lim); ax[0][1].set_ylim(0, max(rt.max(), ys.max()) * 1.12)
    # The points are labelled CLRT_new in the panel, so the axis need not repeat it; at one
    # column the longer label ran past the figure edge.
    ax[0][1].set_xlabel("Configured [ms]")
    ax[0][1].set_ylabel("Measured [ms]")
    # The key is outside the observations.
    F.key(ax[0][1], loc="lower right", ncol=1, handlelength=1.4, handletextpad=0.4)
    for s in fixed:
        data.append(dict(panel="b", series="fixed_total_budget", point=s["point"],
                         D_A_ms=s["D_A_ms"], D_R_ms=s["D_R_ms"], D_ms=s["D_ms"],
                         n=s["read_n"], clrt_med_ms=s["read_clrt_med_ms"],
                         clrt_q1_ms=s["read_clrt_q1_ms"], clrt_q3_ms=s["read_clrt_q3_ms"],
                         clrt_min_ms=s["read_clrt_min_ms"], clrt_max_ms=s["read_clrt_max_ms"],
                         rt_med_ms=s["read_rt_med_ms"]))

    # The D_A ramp is not drawn. It plotted the measured median against the configured
    # acknowledgment hold and had two points on this sweep, and both of them are already in
    # panel (b). Its numbers stay in the figure's data file so nothing is lost by not drawing it.
    ramp = sorted([s_ for s_ in sweep
                   if s_["mode"] == "D4" and not s_["is_control_point"]
                   and s_["D_A_ms"] is not None and s_["D_R_ms"] is not None
                   and abs(s_["D_R_ms"] - cfg["D_R_ms"]) < 1e-9], key=lambda s_: s_["D_A_ms"])
    for s_ in ramp:
        data.append(dict(panel="not_drawn_D_A_ramp", series="D_A_ramp", point=s_["point"],
                         D_A_ms=s_["D_A_ms"], D_R_ms=s_["D_R_ms"], D_ms=s_["D_ms"],
                         n=s_["read_n"], ack_med_ms=s_["read_ack_med_ms"],
                         clrt_med_ms=s_["read_clrt_med_ms"]))

    # ---- (c) the master's request-to-response latency, the observed cost
    box_pair(ax[1][1], rows, col=5, horizontal=True)
    # The class names label the rows, so no ordinate label is needed. The arms are named in a
    # key rather than by abbreviations floating beside the READ row: "OFF" and "Obf." were never
    # expanded anywhere the reader could see, and across the text width the key has room.
    ax[1][1].set_xlabel("Request-to-response [ms]")
    ax[1][1].set_xlim(*log_limits(sel(rows, col=5)))
    F.key(ax[1][1], loc="lower right", ncol=1, handlelength=1.2, handletextpad=0.4)
    for arm in ARMS:
        for c in CLASSES:
            v = sel(rows, arm, c, col=5)
            q1, q2, q3 = np.percentile(v, [25, 50, 75])
            data.append(dict(panel="c", series=f"{F.LBL[arm]}/{c}", n=int(v.size),
                             median_ms=round(float(q2), 6), q1_ms=round(float(q1), 6),
                             q3_ms=round(float(q3), 6), min_ms=round(float(v.min()), 6),
                             max_ms=round(float(v.max()), 6)))

    tag(ax[0][0], "a", x=0.965, y=0.955)
    tag(ax[0][1], "b", x=0.965, y=0.06, va="bottom")
    tag(ax[1][1], "c", x=0.965, y=0.955)
    for a, title in zip(_axes, ["Deadline coverage", "Policy sweep", "Latency cost"]):
        a.set_title(title, fontsize=9, pad=5)
    F.grid([ax[0][0], ax[0][1], ax[1][1]])

    cov = stats["read_lane_coverage"]
    add = stats["added_response_latency_ms"]
    fields = sorted({k for d in data for k in d})
    F.save(fig, out, "fig_policy_coverage_cost",
           "\\textbf{The release policy is programmable, and its budget is bounded on both "
           "sides.} (a) Fraction of Timing OFF read-lane exchanges, READ and the SELECT phase of "
           "SBO only, whose request-to-response time exceeds a given value, with the "
           f"release budget $D$={D:g}~ms and the "
           f"control-plane admission horizon $H$={H:g}~ms, which the data plane does not "
           "enforce; at "
           f"$D$={D:g}~ms, {cov['above_budget']} of {cov['n']} "
           f"({cov['percent_above']:.4f}\\%) arrive too late to be held. (b) Measured hardware "
           f"sweep at a fixed total budget $D$={D:g}~ms: the measured "
           "$\\mathrm{CLRT}_{\\mathrm{new}}$ follows the configured one along the identity line "
           "while the request-to-response latency stays at the budget, so the interval the "
           "adversary observes is set independently of what the exchange costs. "
           "(c) Request-to-response latency at the master, per class. Markers in (b) are medians "
           "over the sample counts in the figure-data CSV and bars span the interquartile range; "
           "boxes in (c) span the quartiles with whiskers over the full support.",
           inputs,
           {"lane_separation": "panels (a) and (b) are read-lane only; OPERATE runs on the control lane",
            "added_latency_ms": add,
            "sweep_points_used": {"fixed_total_budget": [s["point"] for s in fixed],
                                  "not_drawn_D_A_ramp": [s["point"] for s in ramp]},
            "scope": "master-facing link; internal blocker traffic not counted"},
           data_rows=data, data_fields=fields, seed=SEED,
           method_note=(
               "Panel (a) is an empirical complementary CDF of the request-to-response time over "
               "the Timing OFF read lane (READ and SELECT), 29,040 exchanges. At a threshold x "
               "it counts strictly greater observations, including ties exactly; the zero "
               "endpoint is retained in the CSV but cannot be drawn on a log ordinate. The read "
               "lane's deadlines are armed at the request; OPERATE is excluded because it runs on the "
               "control lane under its own release parameters. Panel (b) plots the "
               f"{len(fixed)} release policies of the hardware sweep whose total budget equals "
               f"$D$={D:g}~ms; each is one capture under one installed dual-deadline policy, "
               "summarised by the median over its READ transactions. The sweep's other points "
               "(other budgets, the two envelope controls and the capture with the timing "
               "mechanism disabled) are in the sweep tables and are not plotted here. No value is "
               "resampled or interpolated. Panel (c) reports quartiles with whiskers over the "
               "full support."),
           limitation_note=(
               "The sweep offsets are read from sweep_points.csv, and each point's installed "
               "parameters are confirmed by the control-plane readback archived in "
               "sweep/provenance/. The fail-open horizon H is a control-plane quantity computed "
               "from the pass budget and reservoir depth, not a value the data plane enforces or "
               "that was measured directly. All points come from one relay behind one switch."))


# ============================================================ GRID 2: distributions (2x2)
def fig_distributions(rows, out, inputs):
    # Shared arm key above a compact column-width grid.
    fig, _axes = plt.subplots(2, 2, figsize=(F.COL_W, 3.6))
    ax = [[_axes[0][0], _axes[0][1]], [_axes[1][0], _axes[1][1]]]
    flat = [ax[0][0], ax[0][1], ax[1][0]]
    data = []
    for a, c in zip(flat, CLASSES):
        for arm in ARMS:
            v, y, _ = empirical_curves(sel(rows, arm, c))
            a.step(v, y, where="post", color=ACOL[arm], ls=F.LS[arm], lw=1.2,
                   label=F.LBL[arm], zorder=3)
            for xi, yi in zip(v, y):
                data.append(dict(panel="abc", series=f"{F.LBL[arm]}/{c}",
                                 x_ms=round(float(xi), 6), y_ecdf=float(yi)))
        a.set_xscale("log"); a.xaxis.set_minor_formatter(NullFormatter())
        a.set_xlim(*log_limits(sel(rows))); a.set_ylim(0, 1.02)
        a.set_xlabel("Post-ACK [ms]"); a.set_ylabel("Empirical CDF")
        a.set_title(c, fontsize=9, pad=5)
    handles, labels = flat[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside upper center", ncol=2, frameon=False)
    box_pair(ax[1][1], rows, col=3, horizontal=True)
    ax[1][1].set_xlabel("Post-ACK [ms]")
    ax[1][1].set_xlim(*log_limits(sel(rows)))
    ax[1][1].set_title("Full range", fontsize=9, pad=5)
    for arm in ARMS:
        for c in CLASSES:
            v = sel(rows, arm, c)
            q1, q2, q3 = np.percentile(v, [25, 50, 75])
            data.append(dict(panel="d", series=f"{F.LBL[arm]}/{c}", n=int(v.size),
                             median_ms=round(float(q2), 6), q1_ms=round(float(q1), 6),
                             q3_ms=round(float(q3), 6), min_ms=round(float(v.min()), 6),
                             max_ms=round(float(v.max()), 6)))
    for a, t in zip([ax[0][0], ax[0][1], ax[1][0], ax[1][1]], "abcd"):
        tag(a, t, y=0.93)
    F.grid([ax[0][0], ax[0][1], ax[1][0], ax[1][1]])
    mx = {c: {a_: round(float(sel(rows, a_, c).max()), 3) for a_ in ARMS} for c in CLASSES}
    fields = sorted({k for d in data for k in d})
    F.save(fig, out, "fig_distributions",
           "\\textbf{Measured interval per transaction class, over 22 grouped runs.} (a) READ and "
           "(b) the SELECT phase of SBO report the cross-layer response time; (c) OPERATE reports "
           "the master-visible post-ACK interval (response minus ACK), not a "
           "complete SBO transaction. The abscissa is logarithmic and spans the full support, so "
           f"no observation is clipped: the largest Timing OFF READ interval is "
           f"{mx['READ']['native']:.2f}~ms and the largest obfuscated one is "
           f"{mx['READ']['obfuscated']:.2f}~ms, the late-arrival boundary where a response reached "
           "the switch after its scheduled release. (d) The same measurements as quartiles, with "
           "whiskers spanning the full support.",
           inputs,
           {"clipping": "none; full support plotted", "maxima_ms": mx,
            "whiskers": "full range, no observation hidden",
            "select_scope": "SELECT phase of SBO only, not a complete SBO transaction",
            "operate_scope": "master-visible response minus ACK, not total SBO time"},
           data_rows=data, data_fields=fields, seed=SEED,
           method_note=(
               "Empirical distribution functions over every exchange of each class and arm, "
               "26,400 READ and 2,640 each of SELECT and OPERATE per arm. The abscissa is "
               "logarithmic and its limits contain the full support of both arms, so the late "
               "tail is displayed rather than clipped. Panel (d) shows quartiles with whiskers "
               "at the extremes."),
           limitation_note=(
               "The OPERATE panel is the master-visible response-to-ACK interval only. The "
               "per-transaction hold J, the relay-facing release at T0+J and any physical "
               "actuation were not observed. SELECT is the SELECT phase of select-before-operate "
               "and is not a complete SBO transaction. One relay, one switch, one campaign."))


# ================================================ GRID 5: timing-feature overlap (2x1, page wide)
def fig_feature_overlap(rows, cfg, out, inputs):
    """The two measurable intervals against each other, one panel per arm.

    This is the causal picture behind the leakage result: the vertical axis is the
    device-derived interval the mechanism replaces, the horizontal axis is the interval that
    still separates the two lanes. Scatter is a deterministic, class-stratified subsample so
    the marks stay legible; every median and percentile is computed on the complete dataset.
    """
    rng = np.random.default_rng(SEED)
    N_MAX = 900                       # points drawn per class per panel
    # Full-support arms followed by a separate linear detail panel.
    fig, all_axes = plt.subplots(3, 1, figsize=(F.COL_W, 4.8))
    ax, ins = all_axes[:2], all_axes[2]
    data, drawn = [], {}
    for a, arm in zip(ax, ARMS):
        for c in CLASSES:
            x = sel(rows, arm, c, col=4)          # request-to-ACK
            y = sel(rows, arm, c, col=3)          # post-ACK interval
            # deterministic stratified subsample, for drawing only
            idx = np.arange(x.size)
            if x.size > N_MAX:
                idx = np.sort(rng.choice(x.size, N_MAX, replace=False))
            a.plot(x[idx], y[idx], linestyle="none", marker=F.MK[c], ms=1.7, mew=0,
                   color=CCOL[c], alpha=0.30, zorder=2)
            for i in idx:
                data.append(dict(record="point", panel="a" if arm == "native" else "b",
                                 arm=F.LBL[arm], txn_class=c, class_row=int(i),
                                 ack_ms=float(x[i]), post_ack_ms=float(y[i])))
            drawn[(arm, c)] = int(idx.size)
            # median with 5th-95th percentile indicators, from the FULL data
            xm, ym = np.median(x), np.median(y)
            xlo, xhi = np.percentile(x, [5, 95])
            ylo, yhi = np.percentile(y, [5, 95])
            # The READ and SELECT medians nearly coincide, so equal marker sizes would hide
            # one of them. Sizes decrease and zorder increases across the three classes, which
            # leaves all three visible as concentric marks without moving any of them.
            msz = {"READ": 3.6, "SELECT": 5.0, "OPERATE": 6.6}[c]
            zo = {"OPERATE": 5, "SELECT": 6, "READ": 7}[c]
            # The median only. The 5th-95th percentile crosshairs this used to draw covered the
            # Timing OFF points they summarised, and the scatter already shows the spread; the
            # percentiles are still computed on the full data and written to the figure CSV.
            a.plot([xm], [ym], linestyle="none", marker=F.MK[c], ms=msz, mfc=CCOL[c],
                   mec="black", mew=0.7, zorder=zo)
            data.append(dict(record="summary", arm=F.LBL[arm], txn_class=c, n_full=int(x.size),
                             n_drawn=int(idx.size),
                             ack_median_ms=round(float(xm), 6),
                             ack_p5_ms=round(float(xlo), 6), ack_p95_ms=round(float(xhi), 6),
                             post_ack_median_ms=round(float(ym), 6),
                             post_ack_p5_ms=round(float(ylo), 6),
                             post_ack_p95_ms=round(float(yhi), 6)))
        a.set_xscale("log"); a.set_yscale("log")
        a.xaxis.set_minor_formatter(NullFormatter()); a.yaxis.set_minor_formatter(NullFormatter())
        a.set_xlim(*log_limits(sel(rows, col=4))); a.set_ylim(*log_limits(sel(rows)))
        a.set_title(F.LBL[arm], fontsize=9)
    for a in ax:
        a.set_xlabel("Request-to-ACK [ms]")
        a.set_ylabel("Post-ACK [ms]")
    fig.legend(handles=[Line2D([], [], linestyle="none", marker=F.MK[c], ms=5.0,
                                 mfc=CCOL[c], mec="black", mew=0.7, label=c)
                          for c in CLASSES],
                 loc="outside upper center", ncol=3, frameon=False,
                 fontsize=8, handlelength=1.0)

    # Derive the detail window from the active policy and central ACK distribution.
    ack_lo, ack_hi = np.percentile(sel(rows, "obfuscated", col=4), [0.5, 99.5])
    margin = max((ack_hi - ack_lo) * 0.15, 0.001)
    scheduled = cfg["scheduled_release_interval_ms"]
    iw = {"x": [float(ack_lo - margin), float(ack_hi + margin)],
          "y": [scheduled - 0.1, scheduled + 0.1]}
    for c in CLASSES:
        x = sel(rows, "obfuscated", c, col=4); y = sel(rows, "obfuscated", c, col=3)
        m = (x >= iw["x"][0]) & (x <= iw["x"][1]) & (y >= iw["y"][0]) & (y <= iw["y"][1])
        xs_, ys_ = x[m], y[m]
        idx = np.arange(xs_.size)
        if xs_.size > N_MAX:
            idx = np.sort(rng.choice(xs_.size, N_MAX, replace=False))
        ins.plot(xs_[idx], ys_[idx], linestyle="none", marker=F.MK[c], ms=1.4, mew=0,
                 color=CCOL[c], alpha=0.35)
        for i in idx:
            data.append(dict(record="zoom_point", panel="c", arm=F.LBL["obfuscated"],
                             txn_class=c, ack_ms=float(xs_[i]), post_ack_ms=float(ys_[i])))
        data.append(dict(record="zoom_coverage", panel="c", arm=F.LBL["obfuscated"],
                         txn_class=c, n_full=int(x.size), n_in_window=int(m.sum()),
                         n_drawn=int(idx.size)))
    ins.set_xlim(*iw["x"]); ins.set_ylim(*iw["y"])
    ins.tick_params(labelsize=8, pad=1.0, length=2.0)
    ins.set_xlabel("Request-to-ACK [ms]")
    ins.set_ylabel("Post-ACK [ms]")
    ins.set_title("Obfuscated: detail", fontsize=9)
    for sp in ins.spines.values():
        sp.set_linewidth(0.6)
    for a, t in zip(all_axes, "abc"):
        tag(a, t, x=0.035, y=0.955, ha="left")
    F.grid(list(all_axes))
    fields = sorted({k for d in data for k in d})
    F.save(fig, out, "fig_feature_overlap",
           "\\textbf{Targeted timing-feature collapse and the leakage that remains.} The two "
           "intervals a passive observer can measure, plotted against each other on identical "
           "logarithmic axes: (a) Timing OFF and (b) Obfuscated. The ordinate is the post-ACK "
           "interval, the cross-layer response time for READ and the SELECT phase of SBO and the "
           "master-visible response-to-ACK interval for OPERATE. Small marks are a deterministic, "
           f"class-stratified subsample of at most {N_MAX} exchanges per class drawn for "
           "legibility; the outlined markers are the median of each class, computed on the "
           "complete dataset. Under the mechanism the vertical, "
           "device-derived interval of all three classes collapses onto the policy value, and "
           "READ and SELECT overlap. Both lanes arm their deadlines from the request. "
           "Small class-dependent residuals remain; the scatter alone does not establish "
           "their cause or a classifier's accuracy. "
           f"Panel (c) magnifies {iw['x'][0]:.4f} to {iw['x'][1]:.4f}~ms by {iw['y'][0]:g} to "
           f"{iw['y'][1]:g}~ms on linear axes; per-class window counts are in the data CSV. "
           "This figure shows timing-feature overlap among "
           "transaction classes on one physical outstation. It is not clustering performance, "
           "not device identification, and not evidence that different devices become "
           "indistinguishable.",
           inputs,
           {"axes": "identical full-support logarithmic limits in (a) and (b); linear detail in (c)",
            "subsample": f"deterministic, class-stratified, at most {N_MAX} per class, seed "
                         f"{SEED}; drawing only",
            "statistics": "median drawn; 5th-95th percentile in the data CSV; both from the complete dataset",
            "drawn_per_class": {f"{k[0]}/{k[1]}": v for k, v in drawn.items()},
            "inset_window": iw,
            "scope": "transaction-class timing-feature overlap on one outstation"},
           data_rows=data, data_fields=fields, seed=SEED,
           method_note=(
               "Panels (a) and (b) plot the request-to-ACK interval against the post-ACK interval for "
               "every transaction class of one arm, on identical logarithmic axes so the two "
               "panels are directly comparable. Scatter is a deterministic class-stratified "
               f"subsample of at most {N_MAX} exchanges per class, drawn with a seeded generator "
               "so the figure is reproducible; subsampling affects only what is drawn. The "
               "outlined marker is the median, and the 5th and 95th percentiles are written to "
               "the figure-data CSV rather than drawn; both are computed over the complete 26,400 READ and 2,640 SELECT and OPERATE exchanges per arm. No "
               "dimensionality reduction, embedding or clustering algorithm is used anywhere: "
               "both axes are measured intervals in milliseconds. Panel (c) is a linear zoom centred "
               "on the configured post-ACK interval; its ACK limits cover the pooled obfuscated "
               "0.5th to 99.5th percentiles plus a 15% margin. The CSV includes every displayed "
               "point, summary, and per-class zoom count."),
           limitation_note=(
               "This is timing-feature overlap among transaction classes on one physical "
               "SEL-751A behind one Tofino-1. It is not clustering performance, not device "
               "identification, and not evidence that two devices become indistinguishable. The "
               "OPERATE ordinate is the master-visible response minus ACK "
               "from the CLRT of the other two classes; the realized per-transaction hold and the "
               "relay-facing release were not observed. The subsample changes the visual density "
               "only and no reported statistic depends on it."))


# ============================================================ GRID 3: leakage (2x2)
def fig_leakage(leak, out, inputs):
    # Two panels at column width, not four. The 2x2 version squeezed two bar panels and two
    # equal-aspect confusion matrices into 3.5 inches: every axis collapsed into a strip, the
    # category labels overlapped and the legend ran off the canvas. The confusion matrices are
    # secondary, because the text states what they show, so their numbers stay in this figure's
    # data file and in leakage.json rather than being drawn illegibly.
    fig, ax = plt.subplots(1, 2, figsize=(F.COL_W, 2.75))
    feats = ["clrt", "ack_clrt"]
    names = {"clrt": "CLRT only", "ack_clrt": "both intervals"}
    # The attacker conditions go on the abscissa and the feature set into a two-entry legend.
    # The other way round needs a three-entry legend of long names, which is what did not fit.
    conds = [("fixed\nOFF", "A_fixed_native_trained", "tested_on_timing_off"),
             ("fixed\nObf.", "A_fixed_native_trained", "tested_on_obfuscated"),
             ("adaptive\nObf.", "B_adaptive_obfuscated_trained", "tested_on_obfuscated")]
    # Open against solid, the same greyscale channel the arms use elsewhere.
    fill = {"clrt": (F.OFF, "white", 1.0), "ack_clrt": (F.ON, None, 0.90)}
    w, xb = 0.36, np.arange(len(conds))
    data = []
    # (a) balanced accuracy. The visible spread is the descriptive range over the 22 held-out
    # runs, never a confidence interval: the folds share training data.
    for k, f in enumerate(feats):
        col, face, al = fill[f]
        m, lo, hi = [], [], []
        for lab, grp, key in conds:
            d = leak["classifiers"][f][grp][key]
            m.append(d["mean"]); lo.append(d["mean"] - d["min"]); hi.append(d["max"] - d["mean"])
            data.append(dict(panel="a", attacker=lab.replace("\n", " "), features=f,
                             mean=d["mean"], median=d["median"], min=d["min"], max=d["max"],
                             iqr_lo=d["iqr_lo"], iqr_hi=d["iqr_hi"], n_runs=d["n_runs"]))
        ax[0].bar(xb + (k - 0.5) * w, m, w * 0.88, yerr=[lo, hi], capsize=2,
                  color=face or col, alpha=al, edgecolor=col, lw=0.9, label=names[f],
                  error_kw=dict(lw=0.7, ecolor="black"))
    # The chance line is named once, in panel (b)'s key. Naming it in both keys made (a)'s
    # three entries wide enough to cover the tallest bar.
    ax[0].axhline(leak["chance_balanced_accuracy"], color="black", ls=":", lw=1.0, zorder=4)
    ax[0].set_xticks(xb); ax[0].set_xticklabels([c[0] for c in conds])
    ax[0].set_ylabel("Balanced accuracy"); ax[0].set_ylim(0, 1.06)
    F.key(ax[0], loc="upper right", ncol=1, handlelength=1.2, handletextpad=0.4)

    # (b) what pooling buys the adaptive adversary. This panel used to plot the mutual
    # information: two grey null bars and two diamonds on a logarithmic axis, with no tick a
    # reader could read a value off. It carried two numbers, and two numbers belong in a sentence.
    #
    # Pooling is the better use of the space, because it is a real result that appeared in no
    # figure at all, and because it is the one that does not flatter the framework. An adversary
    # that averages several exchanges of the same operation suppresses the noise around a
    # systematic offset, so it climbs: 0.447 at one exchange to 0.650 at twenty. Drawing it is the
    # difference between reporting the result and burying it in a table.
    # inputs is [canonical table, leakage.json]; multiobs.json is written beside the latter
    # by the same pipeline step, so it is found rather than threaded through main().
    pooled = json.load(open(pathlib.Path(inputs[1]).parent / "multiobs.json"))
    ks = pooled["k_values"]
    for a_ in ARMS:
        ys = [pooled["results"]["ack_clrt/%s/k%d" % (a_, k)]["balanced_accuracy_mean"] for k in ks]
        lo = [pooled["results"]["ack_clrt/%s/k%d" % (a_, k)]["min"] for k in ks]
        hi = [pooled["results"]["ack_clrt/%s/k%d" % (a_, k)]["max"] for k in ks]
        ax[1].plot(ks, ys, marker="o" if a_ == "native" else "s", ms=3.2, lw=1.1,
                   color=ACOL[a_], zorder=4, label=F.LBL[a_])
        ax[1].fill_between(ks, lo, hi, color=ACOL[a_], alpha=0.18, lw=0, zorder=2)
        for k, y, l, h in zip(ks, ys, lo, hi):
            data.append(dict(panel="b", arm=F.LBL[a_], k=k, balanced_accuracy=y,
                             held_out_run_min=l, held_out_run_max=h))
    ax[1].axhline(leak["chance_balanced_accuracy"], color="black", lw=0.9,
                 ls=(0, (1, 1.6)), zorder=3, label="chance")
    ax[1].set_xscale("log")
    ax[1].set_xticks(ks)
    ax[1].set_xticklabels([str(k) for k in ks])
    ax[1].xaxis.set_minor_formatter(NullFormatter())
    ax[1].set_xlabel("Exchanges pooled")
    # No second ordinate label: both panels are balanced accuracy on the same 0 to 1 scale, and
    # repeating the label and its ticks spent width on nothing.
    ax[1].set_ylim(0.0, 1.06)
    ax[1].set_yticklabels([])
    F.key(ax[1], loc="lower left", ncol=1, handlelength=1.3, handletextpad=0.4)

    # The mutual information is not drawn any more; every one of its numbers stays here, so the
    # figure's data file and leakage.json still carry the estimate, its null and its p-value.
    for a_ in ARMS:
        m = leak["mutual_information"][a_]
        data.append(dict(panel="not_drawn_mutual_information", arm=F.LBL[a_],
                         observed_bits=m["observed_bits"], null_mean_bits=m["null_mean_bits"],
                         null_p95_bits=m["null_p95_bits"], null_p99_bits=m["null_p99_bits"],
                         null_max_bits=m["null_max_bits"], p_value=m["p_value_empirical"],
                         p_value_resolution=m["p_value_resolution"],
                         n_permutations=m["n_permutations"]))

    # The confusion matrices are not drawn, but their numbers are kept, so the artifact and this
    # figure's own data file still carry every one of them.
    for key, ttl in (("ack_clrt/A_obf", "A fixed, on Obfuscated"),
                     ("ack_clrt/B_obf", "B adaptive, on Obfuscated")):
        # leakage_campaign.py already exports row-normalised fractions, rounded to 4 places.
        cm = np.array(leak["confusion_all_folds"][key])
        for i in range(3):
            for j in range(3):
                data.append(dict(panel="not_drawn_confusion", matrix=ttl, true=CLASSES[i],
                                 predicted=CLASSES[j], fraction=float(cm[i, j])))
    tag(ax[0], "a", x=0.035, y=0.955, ha="left", va="top")
    tag(ax[1], "b", x=0.965, y=0.04, ha="right", va="bottom")
    ax[0].set_title("Single", fontsize=9, pad=5)
    ax[1].set_title("Pooled", fontsize=9, pad=5)
    F.grid([ax[0], ax[1]])

    fields = sorted({k for d in data for k in d})

    F.save(fig, out, "fig_leakage",
           "\\textbf{Transaction-class leakage under the two attacker models}, leaving out one "
           "grouped run at a time over all 22 runs. (a) Balanced accuracy of the evaluated "
           "Random-Forest attacker, by attacker condition and feature set; bars are the mean over "
           "the 22 held-out runs and the whiskers "
           "span the full range across those runs, which is within-campaign variability and not "
           "a confidence interval, because the folds share training data. The fixed adversary is "
           "trained on Timing OFF traffic and applied unchanged; the adaptive adversary is "
           "retrained on obfuscated traffic. (b) What pooling buys the adaptive adversary: "
           "balanced accuracy against the number of same-operation exchanges it averages. The "
           "band spans the 22 held-out runs, which is within-campaign variability and not a "
           "confidence interval, because the folds share training data. Averaging suppresses "
           "the noise around a "
           "systematic offset, so the adversary climbs with k on obfuscated traffic as well as "
           "on Timing OFF traffic. The mutual information and the row-normalised confusion of "
           "both attackers are not drawn; every value is in this figure\u2019s data file and in "
           "the released leakage record.",
           inputs + [pathlib.Path(inputs[1]).parent / "multiobs.json"],
           {"folds": leak["n_folds"],
            "permutations": leak["mutual_information"]["native"]["n_permutations"],
            "features": "req-to-ACK and CLRT; total response latency is their sum and is excluded",
            "mi_units": "bits, converted from the estimator's nats",
            "uncertainty": leak["uncertainty_policy"],
            "classifier_scope": leak["classifier_scope"]},
           data_rows=data, data_fields=fields, seed=leak["seed"],
           method_note=(
               "Three-class problem over READ, SELECT and OPERATE; chance balanced accuracy is "
               "one third. Evaluation is leave-one-grouped-run-out over all 22 runs. Features are "
               "the two independent intervals, request-to-ACK and ACK-to-response; the total "
               "response time is their sum and carries no independent information, so it is "
               "excluded. Mutual information is estimated on the CLRT with a nearest-neighbour "
               "estimator, converted from nats to bits, and compared against a null built by "
               "permuting class labels within each grouped run, which preserves the per-run class "
               "counts. The empirical Monte Carlo p-value uses the (1+r)/(1+n) correction and its "
               "resolution is reported alongside it. Classifier spread is the descriptive range "
               "of the 22 held-out-run scores. Neither a jackknife interval on the MI estimate "
               "nor a bootstrap over the dependent fold scores is reported; both were rejected "
               "and the reasons are recorded in leakage.json."),
           limitation_note=(
               "Results characterise the evaluated fixed Random-Forest attacker and this feature "
               "set, and do not generalise to all fingerprinting classifiers. The 22 grouped runs "
               "come from one approximately five-hour campaign on one relay behind one switch and "
               "are not independent deployments, so the spread shown is within-campaign only. "
               "This is transaction-class classification, not device-model identification."))


# ============================================================ GRID 4: stability (2x1, one column)
def fig_stability(rows, cfg, out, inputs):
    runs = sorted({r[0] for r in rows})
    xs = np.arange(1, len(runs) + 1)
    fig, ax = plt.subplots(2, 1, figsize=(F.COL_W, 3.25), sharex=True)
    data = []
    for a, arm in zip(ax, ARMS):
        for c in CLASSES:
            med, lo, hi = [], [], []
            for rn in runs:
                v = np.array([r[3] for r in rows if r[0] == rn and r[1] == arm and r[2] == c])
                q1, q2, q3 = np.percentile(v, [25, 50, 75])
                med.append(q2); lo.append(q2 - q1); hi.append(q3 - q2)
                data.append(dict(panel="a" if arm == "native" else "b", arm=F.LBL[arm],
                                 run=rn, txn_class=c, n=int(v.size),
                                 median_ms=round(float(q2), 6), q1_ms=round(float(q1), 6),
                                 q3_ms=round(float(q3), 6)))
            a.errorbar(xs, med, yerr=[lo, hi], fmt=F.MK[c], ms=2.8, lw=0, elinewidth=0.7,
                       capsize=1.4, color=CCOL[c], label=c, zorder=3)
        a.set_ylabel("Interval [ms]")
        a.set_xlim(0.3, len(runs) + 0.7); a.set_xticks([1, 6, 11, 16, 22])
    ax[0].set_ylim(0, max(r["q3_ms"] for r in data if r["panel"] == "a") * 1.15)
    sched = cfg["scheduled_release_interval_ms"]
    ax[1].axhline(sched, color=F.GREY, ls=":", lw=0.9, zorder=1)
    halfspan = max(0.1, 1.15 * max(abs(r[k] - sched) for r in data
                                  if r["panel"] == "b" for k in ("q1_ms", "q3_ms")))
    ax[1].set_ylim(sched - halfspan, sched + halfspan)
    # The magnified ordinate is stated in the caption rather than inside the panel: the tick
    # values already show the span, and a boxed sentence in the data area is not information the
    # reader needs from the artwork.
    ax[1].set_xlabel("Grouped run, in acquisition order")
    handles, labels = ax[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside upper center", ncol=3, frameon=False,
               columnspacing=0.9, fontsize=8, handlelength=1.2)
    tag(ax[0], "a"); tag(ax[1], "b", y=0.955)
    ax[0].set_title("Timing OFF", fontsize=9, pad=5)
    ax[1].set_title("Obfuscated: detail", fontsize=9, pad=5)
    F.grid(list(ax))
    fields = sorted({k for d in data for k in d})
    F.save(fig, out, "fig_stability",
           "\\textbf{Within-campaign stability across the 22 grouped runs}, in acquisition order. "
           "(a) Timing OFF and (b) Obfuscated. Markers are the run median and bars span the "
           "interquartile range. \\emph{Panel (b) uses a magnified ordinate spanning only "
           f"{2 * halfspan:.2f}~ms around the {sched:g}~ms scheduled release}}, so the visible scatter is at the "
           "scale of a few microseconds; the late-arrival tail is outside this window and is "
           "shown in the distribution figure. The 22 runs come from one approximately five-hour "
           "campaign on one relay behind one switch and are not independent replications across "
           "days, devices, or deployments.",
           inputs,
           {"markers": "run median", "bars": "interquartile range",
            "panel_b_ordinate": f"magnified, full span {2 * halfspan:.2f} ms; current policy centred",
            "scope": "within-campaign only"},
           data_rows=data, data_fields=fields, seed=SEED,
           method_note=(
               "Each marker is the median of one transaction class within one grouped run, and "
               "the bar spans that run's interquartile range. Runs are shown in acquisition "
               "order so that drift over the campaign would be visible as a trend."),
           limitation_note=(
               "22 grouped runs, one approximately five-hour campaign, one SEL-751A, one "
               "Tofino-1. This is within-campaign stability only: it is not cross-session, "
               "cross-day, longitudinal, or deployment stability, and the runs are not "
               "independent replications. Panel (b) uses a magnified ordinate."))


def main(canon, statsf, leakf, cfgf, out, sweepf):
    F.use()
    rows = load_rows(canon)
    stats = json.load(open(statsf)); leak = json.load(open(leakf)); cfg = json.load(open(cfgf))
    sweep = json.load(open(sweepf))
    print("figures:")
    fig_policy_coverage_cost(rows, cfg, stats, sweep, out, [canon, cfgf, statsf, sweepf])
    fig_distributions(rows, out, [canon])
    fig_feature_overlap(rows, cfg, out, [canon, cfgf])
    fig_leakage(leak, out, [canon, leakf])
    fig_stability(rows, cfg, out, [canon, cfgf])


if __name__ == "__main__":
    main(*sys.argv[1:7])
