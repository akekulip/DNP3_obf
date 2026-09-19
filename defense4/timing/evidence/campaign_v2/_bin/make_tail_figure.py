#!/usr/bin/env python3
"""The release tail, rebuilt from campaign_v2's own sweep.

The tail is the gap between a packet's deadline and the moment the switch actually emits it. It
belongs to the switch's scheduling and not to the outstation, and on the request-anchored build
that statement is finally true without qualification: the deadline is computed from the request, so
nothing the outstation did enters it.

The figure the manuscript carried before this one came from the 2026-09-18 tail sweep, which
measured the acknowledgment-anchored build. There the tail was a function of when a request
happened to arrive, and it moved by 0.78 ms when nothing changed but how often the master polled.
None of that transfers, so the family is re-measured rather than re-plotted.

Two panels, and the second one is the honest half.

  (a) the tail against the acknowledgment hold, one series per transaction class. It is flat, at
      about 0.10 ms across every hold the switch can sustain. Past roughly 31 ms the acknowledgment
      leaves at 31.07 ms whatever the setting, so the hold is not achieved and the difference
      between the two is not a tail; the series stops there and the knee is drawn, because it is
      what bounds the usable range.

  (b) the tail's distribution at the shipped policy, one series per class. READ and SELECT lie on
      top of each other. OPERATE sits about six microseconds higher, and that offset is the whole
      of what an adaptive adversary still recovers. It is queue phase, not the device: an OPERATE
      arrives 0.354 ms after its own SELECT response where a READ follows its predecessor by
      20.5 ms, so it meets the blocker loop at a different point in the cycle.

    RESEARCH_PYTHON=~/.venvs/research/bin/python $RESEARCH_PYTHON make_tail_figure.py
"""
from __future__ import annotations
import csv
import json
import pathlib
import statistics as st
import sys

import numpy as np
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parent.parent
TIMING = ROOT.parent.parent
sys.path.insert(0, str(TIMING / "analysis"))
import figstyle as fs                                            # noqa: E402

FIGDIR = TIMING.parent.parent / "paper" / "rewrite" / "figures" / "tail"
SWEEP_TIMING = ROOT / "sweep" / "sweep_timing.json"
SWEEP_POINTS = ROOT / "sweep" / "sweep_points.csv"
POLICY = ROOT / "repro" / "policy_config.json"
TXNS = ROOT / "derived" / "transactions.csv"

CLASSES = ["READ", "SELECT", "OPERATE"]
COLOUR = {"READ": fs.SERIES_1, "SELECT": fs.SERIES_2, "OPERATE": fs.SERIES_3}
MARKER = {"READ": "o", "SELECT": "s", "OPERATE": "^"}
TICK_NS = 256


def quantised_ms(ms: float) -> float:
    """A deadline offset as the switch stores it: whole 256 ns ticks, rounded down."""
    return int(round(ms * 1e6) // TICK_NS) * TICK_NS / 1e6


def main() -> int:
    fs.use_ieee()
    timing = json.loads(SWEEP_TIMING.read_text())
    points = {r["point"]: r for r in csv.DictReader(open(SWEEP_POINTS))}
    cfg = json.loads(POLICY.read_text())
    d_a_ship = float(cfg["D_A_ms"])

    # ---- panel (a): the tail against the acknowledgment hold, at the campaign's own D_R --------
    series, rows = {c: ([], []) for c in CLASSES}, []
    # Beyond about 31 ms the switch cannot sustain the hold: the acknowledgment leaves at 31.07 ms
    # however large the setting, so the measured interval minus the setting goes NEGATIVE and is
    # not a release tail at all. Those points say something real and it is not this panel's
    # subject, so the series stops at the knee and the knee is drawn.
    KNEE_MS = 31.0
    for name, rec in sorted(points.items()):
        if rec["mode"] != "D4" or not rec["D_A_ms"] or float(rec["D_R_ms"] or 0) != 4.0:
            continue
        d_a = float(rec["D_A_ms"])
        if d_a > KNEE_MS:
            continue
        for c in CLASSES:
            per = timing.get(name, {}).get(c)
            if not per:
                continue
            tail = per["ack_med"] - quantised_ms(d_a)
            series[c][0].append(d_a)
            series[c][1].append(tail)
            rows.append(dict(panel="a", point=name, txn_class=c, d_a_ms=d_a,
                             ack_med_ms=per["ack_med"], tail_ms=round(tail, 6), n=per["n"]))

    # ---- panel (b): the tail's distribution at the shipped policy ------------------------------
    d_a_q = quantised_ms(d_a_ship)
    tails = {c: [] for c in CLASSES}
    with open(TXNS) as fh:
        for r in csv.DictReader(fh):
            if r["arm"] != "obfuscated":
                continue
            tails[r["txn_class"]].append(float(r["ack_ms"]) - d_a_q)

    fig, (ax0, ax1) = plt.subplots(1, 2, figsize=(fs.COL_WIDTH_IN, 1.85))

    for c in CLASSES:
        x, y = series[c]
        order = np.argsort(x)
        ax0.plot(np.array(x)[order], np.array(y)[order], marker=MARKER[c], ms=3.0, lw=1.0,
                 color=COLOUR[c], label=c, zorder=3)
    # A linear ordinate anchored at zero. On a logarithmic one the nine microseconds that separate
    # the extreme points became a dramatic V, which is the opposite of what the panel shows: the
    # tail does not depend on the hold.
    ax0.axvline(KNEE_MS, color=fs.GREY, lw=0.8, ls=(0, (4, 2)), zorder=2)
    ax0.annotate("hold not\nsustained", xy=(KNEE_MS - 0.8, 0.012), fontsize=8, color=fs.GREY,
                 ha="right", va="bottom")
    ax0.set_xlabel("Acknowledgment hold [ms]")
    ax0.set_ylabel("Release tail [ms]")
    ax0.set_ylim(0.0, 0.16)
    ax0.set_xlim(0.0, 36.0)
    leg = ax0.legend(loc="upper left", fontsize=8, frameon=True, handlelength=1.2,
                     handletextpad=0.4, borderpad=0.3, labelspacing=0.2)
    leg.get_frame().set_linewidth(0.5)
    leg.get_frame().set_edgecolor(fs.GREY)

    lo = min(min(v) for v in tails.values())
    hi = max(np.percentile(v, 99.5) for v in tails.values())
    edges = np.linspace(lo, hi, 31)
    width = (edges[1] - edges[0]) / len(CLASSES)
    for i, c in enumerate(CLASSES):
        counts, _ = np.histogram(tails[c], bins=edges)
        ax1.bar(edges[:-1] + i * width, 100.0 * counts / len(tails[c]), width=width,
                align="edge", color=COLOUR[c], edgecolor=COLOUR[c], linewidth=0.3,
                hatch=(None, "////", "\\\\\\\\")[i], zorder=3, label=c)
    ax1.set_xlabel("Release tail [ms]")
    ax1.set_ylabel("Transactions [%]")

    for a, letter in ((ax0, "a"), (ax1, "b")):
        a.annotate("(%s)" % letter, xy=(0.97, 0.05), xycoords="axes fraction",
                   fontsize=8, color=fs.GREY, ha="right", va="bottom")
    fig.tight_layout(pad=0.3, w_pad=0.7)

    for c in CLASSES:
        v = tails[c]
        rows.append(dict(panel="b", point="shipped", txn_class=c, d_a_ms=d_a_ship,
                         ack_med_ms=round(st.median(v) + d_a_q, 6),
                         tail_ms=round(st.median(v), 6), n=len(v)))

    med = {c: st.median(tails[c]) for c in CLASSES}
    fs.save(fig, FIGDIR, "fig_release_tail",
            inputs=[SWEEP_TIMING, SWEEP_POINTS, TXNS, POLICY],
            caption=(
                "Release tail of the framework, measured on campaign_v2. (a) The tail against the "
                "acknowledgment hold, one series per transaction class. "
                "It is flat at about 0.10 ms across every hold the switch can sustain. Past the dashed "
                "line the acknowledgment leaves at 31.07 ms whatever the setting, so the hold is not "
                "achieved and no tail is defined. (b) Its distribution at the "
                "shipped policy. READ and SELECT coincide; OPERATE sits about six microseconds "
                "higher because it arrives at a different point in the blocker cycle, not because "
                "the outstation did anything different."),
            stats_note=(
                "Tail = the measured request-to-acknowledgment median minus the acknowledgment "
                "hold as the switch stores it, whole 256 ns ticks rounded down. Panel (a) uses the "
                "sweep's per-point per-class medians at a configured interval of 4 ms; panel (b) "
                "uses every obfuscated exchange of the campaign at D_A = %g ms. Medians: "
                "READ %.6f, SELECT %.6f, OPERATE %.6f ms."
                % (d_a_ship, med["READ"], med["SELECT"], med["OPERATE"])),
            data_rows=[[r["panel"], r["point"], r["txn_class"], r["d_a_ms"], r["ack_med_ms"],
                        r["tail_ms"], r["n"]] for r in rows],
            data_header=["panel", "point", "txn_class", "d_a_ms", "ack_med_ms", "tail_ms", "n"])
    print("fig_release_tail -> %s" % FIGDIR)
    print("  tail medians at the shipped policy: " +
          "  ".join("%s %.6f ms" % (c, med[c]) for c in CLASSES))
    print("  OPERATE minus READ: %.1f us" % (1000.0 * (med["OPERATE"] - med["READ"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
