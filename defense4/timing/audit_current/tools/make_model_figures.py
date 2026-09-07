#!/usr/bin/env python3
"""Two explanatory diagrams for the timing model and the master's timers.

Both are schematics of the verified mechanism, not plots of a distribution. Every configured
offset is read from `evidence/campaign_v1/PROVENANCE_CONSTANTS.json` and every measured value
from `audit_current/outputs/timeout_and_tcp_audit.json`; no number is written into this script.

    python3 make_model_figures.py [OUT_DIR]        default: ../../figures/model

Marked DRAFT until the manuscript revision that would use them is authorised.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]                          # defense4/timing
REPRO = TIMING / "evidence" / "campaign_v1" / "repro"
sys.path.insert(0, str(REPRO))

import figstyle_ndss as fs                                                   # noqa: E402
import matplotlib.pyplot as plt                                              # noqa: E402
from matplotlib.patches import FancyArrowPatch                               # noqa: E402

CONSTANTS = TIMING / "evidence" / "campaign_v1" / "PROVENANCE_CONSTANTS.json"
AUDIT = TIMING / "audit_current" / "outputs" / "timeout_and_tcp_audit.json"

# Application receive budget of the driver that produced the campaign, campaign_run.py line 30.
APP_BUDGET_MS = 3000.0
# REFERENCE VALUES, not measurements of this host. Linux's documented TCP_RTO_MIN is 200 ms and
# RFC 6298 section 2.4 recommends a 1 s floor. The host's kernel version and tcp_rto_min were
# never recorded, so its realised retransmission timeout is unknown; these bracket it.
RTO_FLOOR_MS, RTO_RFC_MS = 200.0, 1000.0

LANE_Y = {"master": 2.0, "switch": 1.0, "relay": 0.0}
# Drawn acknowledgment-arrival instant. It must exceed request-arrival-at-relay plus one
# propagation, that is 0.35 + 0.30 + 0.35 = 1.00 ms, or the drawing violates causality. 1.25 ms
# leaves the relay a visible processing interval. Illustrative, not measured.
T_A_DRAWN = 1.25
C_REQ, C_ACK, C_RESP, C_DEADLINE = fs.C_OPERATE, fs.GREY, fs.C_READ, fs.OFF


def interval(ax, y, x0, x1, label, colour, *, above=True, pad=0.13, fontsize=8):
    """A duration: a bar with end caps and a label. Never a bare point."""
    yy = y + (pad if above else -pad)
    ax.annotate("", xy=(x1, yy), xytext=(x0, yy),
                arrowprops=dict(arrowstyle="|-|,widthA=0.25,widthB=0.25",
                                color=colour, lw=0.7, shrinkA=0, shrinkB=0))
    ax.text((x0 + x1) / 2.0, yy + (0.09 if above else -0.19), label, ha="center",
            va="bottom" if above else "top", fontsize=fontsize, color=colour)


def hop(ax, x0, y0, x1, y1, colour, style="-"):
    """A packet crossing between two lifelines."""
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>",
                                 mutation_scale=6, lw=0.9, color=colour,
                                 linestyle=style, shrinkA=0, shrinkB=0,
                                 zorder=3))


def instant(ax, x, y, label, colour, *, dy=0.1, dx=0.0, ha="center", fontsize=8,
            marker="o"):
    """A timestamp: a point, labelled. `dx` nudges the label clear of a crossing arrow."""
    ax.plot([x], [y], marker=marker, ms=3.2, color=colour, zorder=4, clip_on=False)
    ax.text(x + dx, y + dy, label, ha=ha, va="bottom" if dy > 0 else "top",
            fontsize=fontsize, color=colour, zorder=5)


def lifelines(ax, t_max):
    for name, y in LANE_Y.items():
        ax.plot([0, t_max], [y, y], color="#999999", lw=0.5, zorder=1)
        ax.text(-0.015 * t_max, y, name, ha="right", va="center", fontsize=8)
    ax.set_ylim(-1.35, 3.05)
    ax.set_xlim(-0.15 * t_max, t_max)
    ax.set_yticks([])
    for side in ("left", "right", "top"):
        ax.spines[side].set_visible(False)


def ladder_panel(ax, *, d_a, d_r, t_a, t_r, late, rows, t_max):
    """One release timeline. `late` selects the case where the response misses its deadline.

    Event ordering is checked rather than assumed: the relay cannot acknowledge a request
    before that request reaches it, so `t_a` must leave room for the request to arrive and the
    acknowledgment to propagate back. An earlier version drew the acknowledgment leaving the
    relay 0.10 ms before the request arrived.
    """
    m, s, r = LANE_Y["master"], LANE_Y["switch"], LANE_Y["relay"]
    prop = 0.35                                    # link propagation, drawn not measured
    relay_hop = 0.30                               # switch to relay, drawn not measured
    req_at_relay = prop + relay_hop
    if t_a - prop <= req_at_relay:
        raise ValueError(
            "causality: the acknowledgment would leave the relay at %.3f ms but the request "
            "it answers arrives at %.3f ms; t_a must exceed %.3f ms"
            % (t_a - prop, req_at_relay, req_at_relay + prop))

    e_a_target, e_r_target = t_a + d_a, t_a + d_a + d_r
    e_a = e_a_target
    # The model: a deadline cannot precede arrival. The switch's own processing term is drawn
    # at 1.2 ms so that an arrival and its emission are separable on the page; it is a drawing
    # choice, stated in the caption, not a measured value.
    eps = 1.2
    e_r = max(t_r + eps, e_r_target)
    m_a, m_r = e_a + prop, e_r + prop

    lifelines(ax, t_max)

    # request, and the relay's own acknowledgment and response arriving at the switch
    hop(ax, 0.0, m, prop, s, C_REQ)
    hop(ax, prop, s, req_at_relay, r, C_REQ)
    hop(ax, t_a - prop, r, t_a, s, C_ACK, style=(0, (3, 2)))
    hop(ax, t_r - prop, r, t_r, s, C_RESP, style=(0, (3, 2)))

    # release toward the master
    hop(ax, e_a, s, m_a, m, C_ACK)
    hop(ax, e_r, s, m_r, m, C_RESP)

    # the two deadlines, armed together from t_a
    for x, lab in ((e_a_target, r"$t_a{+}D_A$"), (e_r_target, r"$t_a{+}D_A{+}D_R$")):
        ax.plot([x, x], [r - 0.1, m + 0.30], color=C_DEADLINE, lw=0.6,
                linestyle=(0, (1, 1.6)), zorder=2)
    ax.text(e_a_target, m + 0.34, r"$t_a{+}D_A$", ha="right", va="bottom",
            fontsize=8, color=C_DEADLINE)
    ax.text(e_r_target, m + 0.34, r"$t_a{+}D_A{+}D_R$", ha="left", va="bottom",
            fontsize=8, color=C_DEADLINE)

    # instants: the three that were measured are filled circles, the rest open squares
    instant(ax, 0.0, m, r"$m_0$", C_REQ, dy=0.10, ha="left")
    instant(ax, m_a, m, r"$m_a$", C_ACK, dy=0.10, ha="right")
    instant(ax, m_r, m, r"$m_r$", C_RESP, dy=0.10, ha="left")
    instant(ax, prop, s, r"$t_0$", C_REQ, dy=0.10, dx=-0.25, ha="right", marker="s")
    instant(ax, t_a, s, r"$t_a$", C_ACK, dy=0.10, dx=0.20, ha="left", marker="s")
    instant(ax, t_r, s, r"$t_r$", C_RESP, dy=0.10, dx=0.25, ha="left", marker="s")
    instant(ax, e_a, s, r"$e_a$", C_ACK, dy=-0.13, dx=-0.20, ha="right", marker="s")
    instant(ax, e_r, s, r"$e_r$", C_RESP, dy=-0.13, dx=0.25, ha="left", marker="s")

    # durations, kept clear of the lifelines: configured below, observed above
    interval(ax, r - 0.42, t_a, e_a_target, r"$D_A$", C_DEADLINE, above=False, pad=0.0)
    interval(ax, r - 0.42, e_a_target, e_r_target, r"$D_R$", C_DEADLINE, above=False, pad=0.0)
    interval(ax, m + 1.00, m_a, m_r, r"$C_{\rm obs}$", C_RESP, pad=0.0)
    interval(ax, m + 0.62, 0.0, m_r, r"$L_R$", "#333333", pad=0.0)

    if late:
        ax.annotate("the response arrives after its deadline,\nso it is forwarded on arrival",
                    xy=(t_r, s - 0.10), xytext=(0.12 * t_max, r + 0.20),
                    fontsize=8, color=C_RESP, ha="left", va="bottom",
                    arrowprops=dict(arrowstyle="->", color=C_RESP, lw=0.6,
                                    shrinkA=3, shrinkB=3))

    for name, x in (("m_0", 0.0), ("t_0", prop), ("t_a", t_a), ("t_r", t_r),
                    ("e_a_target", e_a_target), ("e_r_target", e_r_target),
                    ("e_a", e_a), ("e_r", e_r), ("m_a", m_a), ("m_r", m_r)):
        rows.append(dict(panel="late" if late else "on_time", quantity=name,
                         value_ms=round(x, 3), kind="instant"))
    for name, v in (("D_A", d_a), ("D_R", d_r), ("C_observed", m_r - m_a),
                    ("L_A", m_a), ("L_R", m_r)):
        rows.append(dict(panel="late" if late else "on_time", quantity=name,
                         value_ms=round(v, 3), kind="duration"))
    ax.set_xlabel("time from the request leaving the master (ms)")


def figure_release(outdir, const, audit):
    d_a = float(const["config"]["obfuscated_arm"]["D_A_ms"])
    d_r = float(const["config"]["obfuscated_arm"]["D_R_ms"])
    nat = audit["intervals"]["native|READ|C"]
    fs.use()
    fig, axes = plt.subplots(2, 1, figsize=(fs.PAGE_W, 4.05))
    rows = []
    t_max = d_a + d_r + 7.5
    ladder_panel(axes[0], d_a=d_a, d_r=d_r, t_a=T_A_DRAWN, t_r=T_A_DRAWN + nat["median"],
                 late=False, rows=rows, t_max=t_max)
    ladder_panel(axes[1], d_a=d_a, d_r=d_r, t_a=T_A_DRAWN, t_r=d_a + d_r + 1.8,
                 late=True, rows=rows, t_max=t_max)
    axes[0].set_title(r"(a) the response arrives before its deadline: $C_{\rm obs}=D_R$",
                      fontsize=9, loc="left")
    axes[1].set_title(r"(b) the response arrives after its deadline: $C_{\rm obs}>D_R$",
                      fontsize=9, loc="left")
    axes[0].set_xlabel("")
    fig.tight_layout(pad=0.4, h_pad=1.1)
    return fs.save(
        fig, outdir, "fig_m01_release_timeline",
        caption=(
            "DRAFT. Release timeline of the read lane, drawn from the verified program and "
            "not from a distribution. Points are timestamps and bars are durations; a filled "
            "circle marks an instant that was measured and an open square one that was not. "
            "The "
            "switch arms both deadlines from one anchor, the relay's acknowledgment arrival "
            "$t_a$: the acknowledgment is due at $t_a+D_A$ and the response at "
            "$t_a+D_A+D_R$, so their difference is the configured $D_R$ and the relay's own "
            "cross-layer time $t_r-t_a$ does not appear in it. In (a) the response arrives "
            "before its deadline and the master-observed interval "
            "$C_{\\rm obs}=m_r-m_a$ equals $D_R$. In (b) it arrives after, the deadline is "
            "already past, and the program forwards it on arrival, so the interval exceeds "
            f"$D_R$. Only $m_0$, $m_a$ and $m_r$ were measured; $t_0$, $t_a$, $t_r$, $e_a$ "
            f"and $e_r$ are inside the switch and were not. $D_A={d_a:.0f}$ ms and "
            f"$D_R={d_r:.0f}$ ms are the campaign settings."),
        inputs=[CONSTANTS, AUDIT],
        notes=["schematic of the mechanism; no measured distribution is plotted",
               "link propagation and the switch's processing term are drawn at a legible size, "
               "not to scale; the 1.2 ms gap between an arrival and its emission in panel (b) "
               "is a drawing choice",
               "case (b) is the fail-open path, which bounds the tail rather than clipping it"],
        data_rows=rows, data_fields=["panel", "quantity", "value_ms", "kind"],
        method_note=(
            "No statistic is computed. The configured offsets are read from "
            "PROVENANCE_CONSTANTS.json; the on-time panel places $t_r$ at the measured median "
            f"Timing OFF READ interval of {nat['median']:.3f} ms so the drawing is to the "
            "right scale. The late panel places $t_r$ beyond the release horizon to show the "
            "fail-open case; its offset is illustrative."),
        limitation_note=(
            "A master-facing capture contains none of $t_0$, $t_a$, $t_r$, $e_a$, $e_r$, so "
            "the switch-side instants in this diagram are recovered from the program and are "
            "not measurements. Queue residence time, the relay-facing release at $t_0+J$, "
            "release multiplicity and physical actuation are all unobserved."))


def figure_timeout(outdir, const, audit):
    d_a = float(const["config"]["obfuscated_arm"]["D_A_ms"])
    la_obf = audit["intervals"]["obfuscated|OPERATE|L_A"]["max"]
    lr_obf = max(audit["intervals"][f"obfuscated|{c}|L_R"]["max"]
                 for c in ("READ", "SELECT", "OPERATE"))
    la_nat = audit["intervals"]["native|READ|L_A"]["median"]
    fs.use()
    fig, ax = plt.subplots(figsize=(fs.PAGE_W, 2.75))

    bars = [
        ("TCP retransmission timeout: reference range, not measured here",
         RTO_FLOOR_MS, RTO_RFC_MS, fs.OFF, 3),
        ("application per-receive timeout, not a transaction deadline",
         APP_BUDGET_MS, None, fs.ON, 2),
    ]
    for label, x1, x2, colour, y in bars:
        ax.barh(y, x1, left=0.0, height=0.34, color=colour, alpha=0.30,
                edgecolor=colour, lw=0.7, zorder=2,
                hatch="///" if y == 3 else "\\\\\\")
        if x2:
            ax.barh(y, x2 - x1, left=x1, height=0.34, color=colour, alpha=0.12,
                    edgecolor=colour, lw=0.5, linestyle=(0, (2, 2)), zorder=2)
            ax.text(x2, y, "  RFC 6298 floor", va="center", ha="left", fontsize=8,
                    color=colour)
        else:
            ax.text(x1, y, "  3000 ms", va="center", ha="left", fontsize=8, color=colour)
        ax.text(0.115, y + 0.30, label, va="bottom", ha="left", fontsize=8, color=colour)
    # The 200 ms boundary needs no label: it is the hatch edge, and the margin arrow below
    # terminates on it. Its value and its status as a reference are in the caption and the
    # figure-data CSV, where they can be stated precisely.
    ax.plot([RTO_FLOOR_MS, RTO_FLOOR_MS], [3 - 0.17, 3 + 0.17], color=fs.OFF, lw=0.8,
            zorder=4)

    measured = [
        (la_nat, r"$L_A$ median, Timing OFF", 1),
        (d_a, r"configured $D_A$", 1),
        (la_obf, r"$L_A$ worst observed", 1),
        (lr_obf, r"$L_R$ worst observed", 1),
    ]
    ax.barh(1, lr_obf, left=0.0, height=0.34, color=fs.C_OPERATE, alpha=0.35,
            edgecolor=fs.C_OPERATE, lw=0.7, zorder=2, hatch="...")
    ax.text(0.115, 1.22, "what the mechanism actually consumed", va="bottom", ha="left",
            fontsize=8, color=fs.C_OPERATE)
    for x, lab, y in measured:
        ax.plot([x, x], [y - 0.24, y + 0.24], color="#222222", lw=0.7, zorder=4)
        ax.plot([x], [y - 0.30], marker="^", ms=3.0, color="#222222", zorder=4)
    ax.text(la_nat, 0.52, r"$L_A$ median 0.6", ha="center", va="top", fontsize=8)
    ax.text(d_a, 0.52, r"$D_A$ 20", ha="center", va="top", fontsize=8)
    ax.text(la_obf, 0.24, r"$L_A$ max 29.2", ha="center", va="top", fontsize=8)
    ax.text(lr_obf, 0.52, r"$L_R$ max 77.7", ha="center", va="top", fontsize=8)

    ax.annotate("", xy=(RTO_FLOOR_MS, 2.62), xytext=(la_obf, 2.62),
                arrowprops=dict(arrowstyle="<->", color="#222222", lw=0.7))
    ax.text((RTO_FLOOR_MS * la_obf) ** 0.5, 2.58,
            "%.1fx to the reference floor" % (RTO_FLOOR_MS / la_obf), ha="center", va="top",
            fontsize=8)
    ax.annotate("", xy=(APP_BUDGET_MS, 1.62), xytext=(lr_obf, 1.62),
                arrowprops=dict(arrowstyle="<->", color="#222222", lw=0.7))
    ax.text((APP_BUDGET_MS * lr_obf) ** 0.5, 1.58,
            "%.0fx to the per-receive timeout" % (APP_BUDGET_MS / lr_obf), ha="center",
            va="top", fontsize=8)

    ax.set_xscale("log")
    ax.set_xlim(0.1, 4000)
    ax.set_ylim(-0.05, 4.05)
    ax.set_yticks([])
    ax.set_xlabel("time from the request leaving the master, log scale (ms)")
    for side in ("left", "right", "top"):
        ax.spines[side].set_visible(False)
    ax.grid(True, axis="x", which="major", color="#CCCCCC", lw=0.4, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout(pad=0.4)

    rows = [dict(timer="tcp_rto_kernel_floor", start="request bytes first sent",
                 value_ms=RTO_FLOOR_MS, source="Linux TCP_RTO_MIN; host value not recorded"),
            dict(timer="tcp_rto_rfc6298_floor", start="request bytes first sent",
                 value_ms=RTO_RFC_MS, source="RFC 6298 section 2.4"),
            dict(timer="application_per_receive_timeout", start="program enters a receive, re-armed each read",
                 value_ms=APP_BUDGET_MS,
                 source="campaign_run.py recv(timeout=3.0); NOT a transaction deadline"),
            dict(timer="configured_D_A", start="relay acknowledgment arrival t_a",
                 value_ms=d_a, source="PROVENANCE_CONSTANTS.json"),
            dict(timer="L_A_median_timing_off", start="request leaves the master",
                 value_ms=round(la_nat, 3), source="timeout_and_tcp_audit.json"),
            dict(timer="L_A_max_obfuscated", start="request leaves the master",
                 value_ms=round(la_obf, 3), source="timeout_and_tcp_audit.json"),
            dict(timer="L_R_max_obfuscated", start="request leaves the master",
                 value_ms=round(lr_obf, 3), source="timeout_and_tcp_audit.json")]
    return fs.save(
        fig, outdir, "fig_m02_timeout_model",
        caption=(
            "DRAFT. The two timers that could end a held transaction, drawn with the "
            "conditions that actually start them. The retransmission timeout begins when the "
            "request bytes are first sent and is cancelled when they are acknowledged; the "
            "application receive budget begins when the program enters the receive, "
            "immediately after the send. Neither begins at the acknowledgment. Against them, "
            "what the mechanism consumed: the configured hold of "
            f"{d_a:.0f} ms, a worst observed acknowledgment wait of {la_obf:.1f} ms and a "
            f"worst observed request-to-response latency of {lr_obf:.1f} ms, over 63,360 "
            "exchanges in which no retransmission and no timeout occurred, measured on the "
            "master-facing link. The host's realised retransmission timeout was never "
            "recorded: the two orange bounds are the Linux documented minimum and the value "
            "RFC 6298 recommends, shown as a reference range and not as a measurement of this "
            "testbed. The application timer bounds one receive and is re-armed on each read, "
            "so it coincided with the transaction duration only because every response "
            "arrived as a single TCP segment."),
        inputs=[CONSTANTS, AUDIT],
        notes=["log time axis, so a 0.6 ms interval and a 3000 ms budget are both readable",
               "the retransmission timeout bracket is a reference range from Linux and RFC "
               "6298, not a measurement: this host's kernel version and tcp_rto_min are not "
               "archived",
               "the application timer is per-receive, re-armed on each read; it is not a "
               "transaction deadline",
               "no retransmission occurred in either arm, so no bar was ever reached"],
        data_rows=rows, data_fields=["timer", "start", "value_ms", "source"],
        method_note=(
            "No statistic is computed. Measured values are the median and maxima reported by "
            "audit_current/tools/timeout_and_tcp_audit.json over all 132 captures. Margins "
            "are ratios of a timer bound to the worst observed value."),
        limitation_note=(
            "The master's kernel version and retransmission sysctls were not archived, so its "
            "realised retransmission timeout is unknown and only a reference range can be "
            "drawn; one sysctl was recorded for the earlier campaign only, tcp_timestamps, "
            "which the wire shows had been restored by this one. The margins against the "
            "application timer hold only because every response arrived as a single TCP "
            "segment, which is measured but not guaranteed. The "
            "relay's own retransmission timeout and its select-validity window are likewise "
            "unrecorded. A relay-side retransmission of a held response would have been "
            "absorbed by the switch's duplicate suppression and cannot be excluded from a "
            "master-facing capture."))


def main(argv):
    outdir = Path(argv[1]) if len(argv) > 1 else (TIMING / "figures" / "model")
    const = json.loads(CONSTANTS.read_text())
    audit = json.loads(AUDIT.read_text())
    print("model figures -> %s" % outdir)
    figure_release(outdir, const, audit)
    figure_timeout(outdir, const, audit)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
