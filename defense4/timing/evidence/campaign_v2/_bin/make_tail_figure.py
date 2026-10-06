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

  (a) the tail against the ACK deadline, one series per transaction class. It is flat, at
      about 0.10 ms across every deadline the switch can sustain. Past roughly 31 ms the
      acknowledgment leaves at 31.07 ms whatever the setting, so the deadline is not achieved
      and the difference between the two is not a tail; the series stops there and the knee is
      drawn, because it is what bounds the usable range.

  (b) the tail's distribution at the shipped policy, one series per class. READ and SELECT lie on
      top of each other. OPERATE sits about six microseconds higher. Its request arrives 0.354 ms
      after its own SELECT response where a READ follows its predecessor by 20.5 ms
      (`repro/proof_analyses.py`), so it meets the blocker loop in a different state.

    $RESEARCH_PYTHON make_tail_figure.py            generate and publish into figures/tail/
    $RESEARCH_PYTHON make_tail_figure.py --check    rebuild into a temporary directory and compare
                                                    against the published copies and FIGURES.sha256
"""
from __future__ import annotations
import csv
import json
import math
import pathlib
import statistics as st
import sys
import hashlib
import tempfile

import os
# A fixed creation date makes the vector PDF byte-reproducible, so --check can compare hashes.
os.environ.setdefault("SOURCE_DATE_EPOCH", "0")
import numpy as np
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parent.parent
TIMING = ROOT.parent.parent
sys.path.insert(0, str(ROOT / "repro"))
import figstyle_ndss as fs                                       # noqa: E402
import pcap_dnp3 as pd3                                          # noqa: E402

FIGDIR = TIMING.parent.parent / "paper" / "rewrite" / "figures" / "tail"
SWEEP_TIMING = ROOT / "sweep" / "sweep_timing.json"
SWEEP_POINTS = ROOT / "sweep" / "sweep_points.csv"
POLICY = ROOT / "repro" / "policy_config.json"
PCAP_READER = ROOT / "repro" / "pcap_dnp3.py"

CLASSES = ["READ", "SELECT", "OPERATE"]
COLOUR = {"READ": fs.C_READ, "SELECT": fs.C_SELECT, "OPERATE": fs.C_OPERATE}
MARKER = {"READ": "o", "SELECT": "s", "OPERATE": "^"}
TICK_NS = 256
TAIL_HIST_BINS = 30
TAIL_HIST_FINITE_PERCENTILE = 99.5


def quantised_ms(ms: float) -> float:
    """A deadline offset as the switch stores it: whole 256 ns ticks, rounded down."""
    return quantised_ns(ms) / 1e6


def quantised_ns(ms: float) -> int:
    """A deadline offset as integer nanoseconds, in the switch's whole 256 ns ticks."""
    return int(round(ms * 1e6) // TICK_NS) * TICK_NS


def _class_name(exchange) -> str:
    return pd3.FUNC_NAME.get(exchange.func, "UNKNOWN")


def load_shipped_policy_tails_exact(d_a_ms: float) -> tuple[dict[str, list[float]], list[pathlib.Path]]:
    """Panel (b) data from raw campaign pcaps, using integer capture timestamps."""
    d_a_ns = quantised_ns(d_a_ms)
    tails = {c: [] for c in CLASSES}
    inputs = []
    for pc in sorted(ROOT.glob("s[0-9][0-9]/raw_pcaps/*_obfuscated.pcap")):
        inputs.append(pc)
        for e in pd3.extract(pc).exchanges:
            c = _class_name(e)
            if c in tails:
                tails[c].append((e.ack_gap_ns - d_a_ns) / 1e6)
    return tails, inputs


def load_sweep_series_exact(points: dict[str, dict], knee_ms: float) -> tuple[dict, list[dict], list[pathlib.Path]]:
    """Panel (a) medians from selected sweep pcaps, using integer capture timestamps."""
    series, rows, inputs = {c: ([], []) for c in CLASSES}, [], []
    for name, rec in sorted(points.items()):
        if rec["mode"] != "D4" or not rec["D_A_ms"] or float(rec["D_R_ms"] or 0) != 4.0:
            continue
        d_a = float(rec["D_A_ms"])
        if d_a > knee_ms:
            continue
        pc = ROOT / "sweep" / "raw_pcaps" / (name + ".pcap")
        inputs.append(pc)
        by_class = {c: [] for c in CLASSES}
        for e in pd3.extract(pc).exchanges:
            c = _class_name(e)
            if c in by_class:
                by_class[c].append(e.ack_gap_ns)
        for c in CLASSES:
            vals = by_class[c]
            if not vals:
                continue
            ack_med_ns = st.median(vals)
            ack_med = ack_med_ns / 1e6
            tail = (ack_med_ns - quantised_ns(d_a)) / 1e6
            series[c][0].append(d_a)
            series[c][1].append(tail)
            rows.append(dict(panel="a", record="sweep_median", point=name, txn_class=c,
                             d_a_ms=d_a, ack_med_ms=round(ack_med, 6),
                             tail_ms=round(tail, 6), n=len(vals), category="",
                             bin_lo_ms="", bin_hi_ms="", edge_convention="",
                             transactions="", denominator="", percent_of_class=""))
    return series, rows, inputs


def release_tail_histogram(tails: dict[str, list[float]]) -> tuple[np.ndarray, list[dict]]:
    """Histogram rows for panel (b), including the explicit far-tail category.

    The finite bins stop at the next 0.001 ms boundary above the cross-class 99.5th percentile
    used for the printed body of the distribution. Values at or above that exact labelled edge
    are not dropped; they become the overflow category and keep the class's full transaction
    count as the denominator.
    """
    lo = min(min(v) for v in tails.values())
    raw_hi = max(float(np.percentile(v, TAIL_HIST_FINITE_PERCENTILE)) for v in tails.values())
    cutoff = math.ceil(raw_hi * 1000.0 - 1e-12) / 1000.0
    # Count on the same decimal boundaries that the CSV publishes. An unrounded
    # linspace can put an exact capture timestamp just below its intended bin edge.
    edges = np.round(np.linspace(lo, cutoff, TAIL_HIST_BINS + 1), 9)
    rows = []
    for c in CLASSES:
        vals = np.asarray(tails[c], dtype=float)
        finite = vals[vals < cutoff]
        overflow = int(np.count_nonzero(vals >= cutoff))
        counts, _ = np.histogram(finite, bins=edges)
        accounted = int(counts.sum()) + overflow
        if accounted != len(vals):
            raise SystemExit("%s tail histogram accounts for %d of %d transactions"
                             % (c, accounted, len(vals)))
        denom = int(len(vals))
        for i, count in enumerate(counts):
            rows.append(dict(
                panel="b", record="histogram_bin", point="shipped", txn_class=c,
                d_a_ms="", ack_med_ms="", tail_ms="", n="",
                category="finite", bin_lo_ms=round(float(edges[i]), 9),
                bin_hi_ms=round(float(edges[i + 1]), 9),
                edge_convention="[lo, hi)", transactions=int(count),
                denominator=denom,
                percent_of_class=round(100.0 * int(count) / float(denom), 9)))
        rows.append(dict(
            panel="b", record="histogram_bin", point="shipped", txn_class=c,
            d_a_ms="", ack_med_ms="", tail_ms="", n="",
            category="overflow", bin_lo_ms=round(float(cutoff), 9), bin_hi_ms="inf",
            edge_convention="[cutoff, inf)", transactions=overflow, denominator=denom,
            percent_of_class=round(100.0 * overflow / float(denom), 9)))
    return edges, rows, raw_hi, cutoff


def build(outdir: pathlib.Path) -> dict:
    fs.use()
    plt.rcParams["figure.constrained_layout.use"] = False
    points = {r["point"]: r for r in csv.DictReader(open(SWEEP_POINTS))}
    cfg = json.loads(POLICY.read_text())
    d_a_ship = float(cfg["D_A_ms"])

    # ---- panel (a): the tail against the ACK deadline, at the campaign's own D_R ----------------
    # Beyond about 31 ms the switch cannot sustain the deadline: the acknowledgment leaves at
    # 31.07 ms however large the setting, so the measured interval minus the setting goes
    # NEGATIVE and is not a release tail at all. Those points say something real and it is not
    # this panel's subject, so the series stops at the knee and the knee is drawn.
    KNEE_MS = 31.0
    series, rows, sweep_inputs = load_sweep_series_exact(points, KNEE_MS)

    # ---- panel (b): the tail's distribution at the shipped policy ------------------------------
    tails, campaign_inputs = load_shipped_policy_tails_exact(d_a_ship)

    fig, (ax0, ax1) = plt.subplots(1, 2, figsize=(fs.COL_W, 2.3),
                                   constrained_layout=False)

    for c in CLASSES:
        x, y = series[c]
        order = np.argsort(x)
        ax0.plot(np.array(x)[order], np.array(y)[order], marker=MARKER[c], ms=3.0, lw=1.0,
                 color=COLOUR[c], label=c, zorder=3)
    # A linear ordinate anchored at zero. On a logarithmic one the nine microseconds that separate
    # the extreme points became a dramatic V, which is the opposite of what the panel shows: the
    # tail does not depend on the hold.
    ax0.axvline(KNEE_MS, color=fs.GREY, lw=0.8, ls=(0, (4, 2)), zorder=2)
    ax0.set_title("(a) Sweep", loc="left", pad=4.0)
    ax0.set_xlabel("ACK deadline [ms]")
    ax0.set_ylabel("Release tail [ms]")
    ax0.set_ylim(0.0, 0.16)
    ax0.set_xlim(0.0, 36.0)

    edges, hist_rows, raw_cutoff, labelled_cutoff = release_tail_histogram(tails)
    bin_w = edges[1] - edges[0]
    width = bin_w / len(CLASSES)
    overflow_x = edges[-1] + 5.0 * bin_w
    for i, c in enumerate(CLASSES):
        finite_rows = [r for r in hist_rows if r["txn_class"] == c and r["category"] == "finite"]
        counts = np.asarray([r["transactions"] for r in finite_rows], dtype=float)
        denom = float(finite_rows[0]["denominator"])
        overflow = next(r for r in hist_rows
                        if r["txn_class"] == c and r["category"] == "overflow")
        ax1.bar(edges[:-1] + i * width, 100.0 * counts / denom, width=width,
                align="edge", color=COLOUR[c], edgecolor=COLOUR[c], linewidth=0.3,
                hatch=(None, "////", "\\\\\\\\")[i], zorder=3, label=c)
        ax1.bar(overflow_x + i * width, float(overflow["percent_of_class"]), width=width,
                align="edge", color=COLOUR[c], edgecolor=COLOUR[c], linewidth=0.3,
                alpha=0.45, hatch=(None, "////", "\\\\\\\\")[i], zorder=3)
    ax1.axvline(edges[-1] + 2.5 * bin_w, color=fs.GREY, lw=0.7, ls=(0, (1, 2)), zorder=4)
    ax1.set_title("(b) Shipped policy", loc="left", pad=4.0)
    ax1.set_xlabel("Release tail [ms]")
    ax1.set_ylabel("Transactions [%]")
    ax1.set_xlim(edges[0], edges[-1] + 7.0 * bin_w)
    ax1.set_xticks([0.05, 0.10, overflow_x + 1.5 * width])
    ax1.set_xticklabels(["0.05", "0.10", "$\\geq\\!%.3f$" % edges[-1]])

    handles, labels = ax0.get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.53, 0.99),
               ncol=3, frameon=False, handlelength=1.4, columnspacing=0.9)
    fig.set_layout_engine("none")
    fig.subplots_adjust(left=0.12, right=0.94, bottom=0.22, top=0.78, wspace=0.50)

    for c in CLASSES:
        v = tails[c]
        tail_med = st.median(v)
        rows.append(dict(panel="b", record="class_median", point="shipped", txn_class=c,
                         d_a_ms=d_a_ship, ack_med_ms=round(tail_med + quantised_ms(d_a_ship), 6),
                         tail_ms=round(tail_med, 6), n=len(v), category="",
                         bin_lo_ms="", bin_hi_ms="", edge_convention="", transactions="",
                         denominator="", percent_of_class=""))
    rows.extend(hist_rows)

    med = {c: st.median(tails[c]) for c in CLASSES}
    fs.save(fig, outdir, "fig_release_tail",
            inputs=[SWEEP_POINTS, POLICY, PCAP_READER] + sweep_inputs + campaign_inputs,
            caption=(
                "Release tail of the framework, measured on campaign_v2. (a) The tail against the "
                "ACK deadline, one series per transaction class. "
                "It is flat at about 0.10 ms across every deadline the switch can sustain. Past "
                "the dashed line the acknowledgment leaves at 31.07 ms whatever the setting, so "
                "the deadline is not achieved and no tail is defined. (b) Its distribution at the "
                "campaign policy, with the far right category collecting every transaction at "
                "or above %.3f ms. READ and SELECT coincide; OPERATE sits about six microseconds "
                "higher, and its request reaches the switch 0.354 ms after the SELECT response "
                "where a READ follows its predecessor by 20.5 ms." % labelled_cutoff),
            notes=[
                "panel b retains each class's full denominator; observations at or above the "
                "%.3f ms finite-bin cutoff are exported and drawn as overflow" % labelled_cutoff],
            method_note=(
                "Tail = the measured request-to-acknowledgment median minus the ACK deadline as "
                "the switch stores it, whole 256 ns ticks rounded down. Panel (a) uses the "
                "selected sweep pcaps' exact integer-nanosecond request-to-ACK intervals, grouped "
                "by point and class, at a configured CLRT_new of 4 ms; panel (b) uses every "
                "obfuscated exchange from the 66 campaign pcaps at D_A = %g ms. The raw "
                "cross-class %.1fth percentile is %.6f ms; the plotted finite histogram range "
                "rounds that value up to the next 0.001 ms boundary, %.3f ms. Values at or "
                "above that labelled boundary are an explicit overflow category and remain in "
                "the denominator. Frozen derived CSV and sweep JSON float summaries are not used "
                "for plotted tail values. "
                "Medians: "
                "READ %.6f, SELECT %.6f, OPERATE %.6f ms."
                % (d_a_ship, TAIL_HIST_FINITE_PERCENTILE, raw_cutoff, labelled_cutoff,
                   med["READ"], med["SELECT"], med["OPERATE"])),
            limitation_note=(
                "The switch timestamps no departure, so the tail is inferred at the master and "
                "contains the path between master and switch. One relay, one switch. Points past "
                "the knee are not plotted because the hold is not achieved there and no tail is "
                "defined."),
            data_rows=rows,
            data_fields=["panel", "record", "point", "txn_class", "d_a_ms", "ack_med_ms",
                         "tail_ms", "n", "category", "bin_lo_ms", "bin_hi_ms",
                         "edge_convention", "transactions", "denominator",
                         "percent_of_class"])
    return med


AUTHORITATIVE = ["fig_release_tail.pdf", "fig_release_tail_data.csv",
                 "fig_release_tail.caption.md", "fig_release_tail.method.md",
                 "fig_release_tail.limitations.md"]


def _sha(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        problems = []
        with tempfile.TemporaryDirectory() as td:
            build(pathlib.Path(td))
            man = {}
            if (FIGDIR / "FIGURES.sha256").exists():
                for line in (FIGDIR / "FIGURES.sha256").read_text().splitlines():
                    if line.strip() and not line.startswith("#"):
                        h, n = line.split(None, 1)
                        man[n.strip()] = h
            for name in AUTHORITATIVE:
                new, pub = pathlib.Path(td) / name, FIGDIR / name
                if not pub.exists():
                    problems.append("published %s is missing" % name)
                elif _sha(new) != _sha(pub):
                    problems.append("%s differs from the rebuild" % name)
                if man.get(name) != _sha(new):
                    problems.append("FIGURES.sha256 entry for %s does not match the rebuild" % name)
        print("release tail figure: %d problems" % len(problems))
        for p in problems:
            print("  PROBLEM:", p)
        return 1 if problems else 0
    med = build(FIGDIR)
    (FIGDIR / "FIGURES.sha256").write_text(
        "# Authoritative artefacts of the release-tail family, written by make_tail_figure.py.\n"
        "# The .png preview is not gated: its bytes vary with the interpreter build.\n"
        + "".join("%s  %s\n" % (_sha(FIGDIR / n), n) for n in AUTHORITATIVE))
    print("fig_release_tail -> %s" % FIGDIR)
    print("  tail medians at the campaign policy: " +
          "  ".join("%s %.6f ms" % (c, med[c]) for c in CLASSES))
    print("  OPERATE minus READ: %.1f us" % (1000.0 * (med["OPERATE"] - med["READ"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
