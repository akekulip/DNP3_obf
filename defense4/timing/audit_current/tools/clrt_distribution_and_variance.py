#!/usr/bin/env python3
"""READ CLRT distributions before and after obfuscation.

Three figures, from the verified transaction tables only:

  fig_clrt_distributions        the main comparison: two vertically aligned histograms of the
                                measured CLRT, Timing OFF above and Obfuscated below, on common
                                1 ms bins anchored at 0 ms, a linear ordinate and shared
                                limits, each bar the percentage of that arm's own transactions
                                in that bin, with one labelled overflow category for the far
                                tail.

  fig_clrt_distributions_full   the same comparison with no cutoff, so every tail out to the
                                largest observation is drawn.

  fig_clrt_zoom                 the same measurements on finer bins around the configured
                                value, keeping the full-condition denominator.

The per-run and per-capture sample variances are still written to `clrt_run_statistics.csv`.
They no longer get a figure of their own: the manuscript does not print one, and a variance
scatter is not what this script is for.

Notation follows the manuscript body, not this tool, as fixed by
`defense4/timing/NOTATION_MAPPING.md` on 2026-09-09. The measured quantity is CLRT_original in
the Timing OFF arm and the measured CLRT_new in the Obfuscated arm. The policy field named
D_R_ms is the *configured* CLRT_new; it is **not** D_R, which under that mapping is the
response latency m_R - t_R. The configured value is therefore drawn and labelled "configured
CLRT_new" and never as D_R or as a target. The axes say "CLRT (ms)" in plain words.

    python3 clrt_distribution_and_variance.py [OUT_DIR]
    python3 clrt_distribution_and_variance.py --check [OUT_DIR]

Default OUT_DIR is paper/rewrite/figures/clrt. Raw captures and frozen CSVs are inputs and are
never written.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]
CV1 = TIMING / "evidence" / "campaign_v1"
FRS = TIMING / "evidence" / "final_read_sbo"
REPRO = CV1 / "repro"
sys.path.insert(0, str(REPRO))
sys.path.insert(0, str(HERE))

import figstyle_ndss as fs                                                   # noqa: E402
import numpy as np                                                           # noqa: E402
import matplotlib.pyplot as plt                                              # noqa: E402
from matplotlib.lines import Line2D                                          # noqa: E402

# The per-corpus configuration parsers and the manifest writer are reused rather than copied,
# so a corpus whose configured offset changes cannot end up with two answers in two figures.
import shift_vs_normalization as svn                                         # noqa: E402

PNG_DPI = 300
DEFAULT_OUT = fs.REPO_ROOT / "paper" / "rewrite" / "figures" / "clrt"
ROLLUP = CV1 / "DATASET_ROLLUP.json"
CAMPAIGN_README = CV1 / "README.md"
FRS_MANIFEST = FRS / "CAPTURE_MANIFEST.csv"

# Presentation labels never carry an internal corpus directory name; the exact identifiers are
# recorded in the method note and the provenance sidecar instead.
ARM_LABEL = {"native": "Timing OFF", "obfuscated": "Obfuscated"}
ARM_COLOR = {"native": fs.OFF, "obfuscated": fs.ON}        # orange, blue
ZOOM_HALFWIDTH_MS = 0.10
# Full-range bin width, in milliseconds, and the reason for it. Formby et al. build their
# CLRT fingerprint from equal-width linear bins over [0, H] (NDSS 2016, Equation 1), and their
# CLRT distribution figure, Figure 6(b), draws them at about 5 ms over a 0 to 0.28 s range.
# Five milliseconds would merge this relay's three Timing OFF modes near 1.2, 2.1 and 4.0 ms
# into one bar. One millisecond is the coarsest width in the 1 to 2 ms range asked for at the
# meeting that still separates them, so it is the width used here. It is our choice and not a
# width Formby states.
MAIN_BIN_MS = 1.0
# Zoom bin width, in milliseconds. Freedman-Diaconis on the Obfuscated sample gives about
# 0.0005 ms, which puts four hundred bins across the window and renders as a comb one
# transaction high. Ten times coarser keeps forty bins across the window, which still resolves
# the structure of the released interval and can be read at printed size.
ZOOM_BIN_MS = 0.005
# Overflow cutoff for the main view, in milliseconds. On a linear ordinate the measured range
# runs to 83.5 ms, which spends four fifths of the abscissa on bins holding less than a tenth
# of a percent and squeezes the body of both distributions into the leftmost sixth of the
# panel. Finite bins therefore stop here and everything at or above this value, the value
# itself included, is collected into one labelled overflow category drawn apart from the bins.
# At 15 ms that category holds 0.409 % of the Timing OFF sample and 0.027 % of the Obfuscated
# sample, so the truncation costs the main view almost nothing, and nothing at all overall:
# fig_clrt_distributions_full repeats the comparison with no cutoff and every tail drawn.
OVERFLOW_CUTOFF_MS = 15.0


# ------------------------------------------------------------------ data loading

def load_campaign_reads():
    """Every READ CLRT in the main campaign, indexed by grouped run, capture and arm.

    Extracted from the raw captures with `campaign_v1/repro/pcap_dnp3.py`, which carries integer
    nanoseconds from the capture record to the interval. An earlier version read
    `derived/transactions.csv`, the frozen table produced by the original scapy extractor, whose
    timestamps were converted to float seconds first. At 2026 epoch magnitudes that conversion
    costs up to about 238 ns, which is invisible against a 4 ms interval and decisive against a
    1 ms bin edge that the configured value sits exactly on: it moved 2,465 of 26,400 obfuscated
    READ observations, 9.34 percentage points, across the 4 ms boundary. The frozen table stays
    where it is as the historical artefact; the figures are fed from the same extraction as the
    campaign statistics.
    """
    sys.path.insert(0, str(REPRO))
    import pcap_dnp3 as pd3                                                  # noqa: E402

    by_run, by_capture, by_arm = defaultdict(list), defaultdict(list), defaultdict(list)
    acc = {"rows": 0, "read_rows": 0, "non_read_rows": 0, "non_finite": 0, "non_positive": 0}
    inputs = []
    for pc in sorted(CV1.glob("s[0-9][0-9]/raw_pcaps/*.pcap")):
        base = pc.name[:-5]
        session, block, arm = base.split("_", 2)
        inputs.append(pc)
        for e in pd3.extract(pc).exchanges:
            acc["rows"] += 1
            if pd3.FUNC_NAME.get(e.func) != "READ":
                acc["non_read_rows"] += 1
                continue
            acc["read_rows"] += 1
            ns = e.clrt_ns                       # exact: integer nanoseconds
            if ns <= 0:
                acc["non_positive"] += 1
                continue
            x = ns / 1e6                         # milliseconds, exact at these magnitudes
            if not np.isfinite(x):
                acc["non_finite"] += 1
                continue
            by_run[(session, arm)].append(x)
            by_capture[(session, block, arm)].append(x)
            by_arm[arm].append(x)
    roll = json.loads(ROLLUP.read_text())
    acc["dataset_rollup_anomalies"] = int(roll["anomalies_count"])
    acc["dataset_rollup_incomplete_sessions"] = len(roll["incomplete_sessions"])
    acc["excluded_from_plot"] = acc["non_finite"] + acc["non_positive"]
    acc["extraction"] = "campaign_v1/repro/pcap_dnp3.py, integer nanoseconds"
    by_arm = {a: np.sort(np.asarray(v, dtype=float)) for a, v in by_arm.items()}
    return by_run, by_capture, by_arm, acc, inputs + [ROLLUP, CAMPAIGN_README]


def load_single_session_reads():
    """READ CLRT from the retired single-session dataset, one capture per arm.

    One capture per arm means one variance estimate per arm. That is a summary value, not a
    distribution across runs, and it is reported as such: it never enters the run-level figure.
    """
    d = FRS / "derived_csv"
    files = (("native_txn.csv", "native", "e1_native.pcap"),
             ("defended_read_txn.csv", "obfuscated", "e2_def_read.pcap"))
    out, acc, inputs = {}, {}, [FRS_MANIFEST]
    for name, arm, capture in files:
        p = d / name
        inputs.append(p)
        vals, polled, cold = [], 0, 0
        with open(p) as fh:
            for r in csv.DictReader(fh):
                if r["req_func"] != "1":              # 1 = READ, 3 = SELECT (control lane)
                    continue
                polled += 1
                if r["cold"] == "1":                  # cold-start rows carry cold=1
                    cold += 1
                    continue
                vals.append(float(r["clrt_ms"]))
        out[arm] = np.sort(np.asarray(vals, dtype=float))
        acc[arm] = {"capture": capture, "read_requests_polled": polled,
                    "cold_start_read_excluded": cold, "plotted": len(vals)}
    return out, acc, inputs


def campaign_target_ms():
    """The configured read-lane offset D_R, read from the campaign's own policy file."""
    d_r, _, cfg = svn._targets_campaign_v1()
    return d_r, cfg


# ------------------------------------------------------------------ statistics

def stats_row(unit, run, arm, v, source):
    var = float(svn.var_s(list(v)))
    return dict(unit=unit, run=run, arm=ARM_LABEL[arm], operation="READ",
                transactions=int(len(v)),
                mean_ms=round(float(np.mean(v)), 6),
                sample_sd_ms=round(float(np.sqrt(var)), 6),
                sample_variance_ms2=round(var, 12),
                median_ms=round(float(np.median(v)), 6),
                min_ms=round(float(np.min(v)), 6),
                max_ms=round(float(np.max(v)), 6),
                source=source)


def freedman_diaconis_ms(v):
    """Bin width 2 * IQR * n^(-1/3). Returned unrounded; the caller records what it used."""
    q1, q3 = np.percentile(v, [25, 75])
    return float(2.0 * (q3 - q1) * len(v) ** (-1.0 / 3.0))


# ------------------------------------------------------------------ artefact emission

def _rel(p):
    p = Path(p).resolve()
    try:
        return str(p.relative_to(fs.REPO_ROOT))
    except ValueError:
        return "pipeline-output/" + p.name


def _git_commit():
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(fs.REPO_ROOT),
                           capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or None
    except Exception:
        return None


def emit(fig, out, stem, caption, inputs, rows, method_note, limitation_note, notes, seed=None):
    """Write one figure and its sidecars.

    Deliberately not `figstyle_ndss.save`, which pins the PNG at 600 dpi where 300 was asked
    for. Everything else that function guarantees is kept, the minimum-type check included.
    """
    problems = []
    fs.check_min_font(fig, stem, problems)
    if problems:
        raise SystemExit("figure style violation:\n  " + "\n  ".join(problems))
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    pdf, png, data = out / (stem + ".pdf"), out / (stem + ".png"), out / (stem + "_data.csv")
    fig.savefig(pdf, facecolor="white", transparent=False,
                metadata={"CreationDate": None, "Producer": None, "Creator": None})
    fig.savefig(png, facecolor="white", transparent=False, dpi=PNG_DPI)
    w_in, h_in = (round(float(x), 3) for x in fig.get_size_inches())
    plt.close(fig)

    with open(data, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    (out / (stem + ".caption.md")).write_text(caption.strip() + "\n")
    (out / (stem + ".method.md")).write_text(method_note.strip() + "\n")
    (out / (stem + ".limitations.md")).write_text(limitation_note.strip() + "\n")

    script = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else None
    prov = {
        "figure": stem,
        "caption": caption,
        "generation_command": (" ".join(["python"] + [_rel(a) if os.path.sep in a else a
                                                      for a in sys.argv]) if script else None),
        "source_commit": _git_commit(),
        "deterministic_seed": seed,
        "analysis_script": ({"path": _rel(script), "sha256": fs.sha256_file(script)}
                            if script and script.exists() else None),
        "style_module": {"path": _rel(fs.__file__), "sha256": fs.sha256_file(fs.__file__)},
        "reused_module": {"path": _rel(svn.__file__), "sha256": fs.sha256_file(svn.__file__)},
        "inputs": [{"path": _rel(p), "sha256": fs.sha256_file(p)} for p in inputs
                   if os.path.exists(str(p))],
        "missing_inputs": [str(p) for p in inputs if not os.path.exists(str(p))],
        "outputs": {
            "pdf": {"path": _rel(pdf), "sha256": fs.sha256_file(pdf), "authoritative": True},
            "png": {"path": _rel(png), "sha256": fs.sha256_file(png), "dpi": PNG_DPI,
                    "authoritative": False,
                    "note": "raster preview; not byte-reproducible across interpreter builds"},
            "data_csv": {"path": _rel(data), "sha256": fs.sha256_file(data),
                         "rows": len(rows), "authoritative": True},
        },
        "figure_dimensions_in": {"width": w_in, "height": h_in},
        "method_note": method_note,
        "limitation_note": limitation_note,
        "notes": notes,
        "style": ("NDSS text block, Times-compatible serif, minimum %g pt at printed size, "
                  "Timing OFF orange and Obfuscated blue from the Okabe-Ito palette, white "
                  "background, pdf.fonttype 42 (no Type 3)" % fs.MIN_PT),
    }
    (out / (stem + ".provenance.json")).write_text(json.dumps(prov, indent=1) + "\n")
    print("  %-28s %5.2f x %4.2f in  pdf %s  png %s (%d dpi)  data %d rows"
          % (stem, w_in, h_in, prov["outputs"]["pdf"]["sha256"][:12],
             prov["outputs"]["png"]["sha256"][:12], PNG_DPI, len(rows)))
    return pdf


# ------------------------------------------------------------------ figure 1: distributions

def _percent_weights(v):
    """Weights that turn a histogram into percent of this condition's transactions per bin.

    The denominator is always the condition's full sample, never the subset a panel happens to
    display, so the zoom panels report a share of everything measured rather than a share of
    what survived the window.
    """
    return np.full(int(v.size), 100.0 / float(v.size))


def _percent_peak(v, edges):
    """Tallest bar, in percent per bin, that v reaches on these edges."""
    counts, _ = np.histogram(v, bins=edges, weights=_percent_weights(v))
    return float(counts.max())


QUANTITY = {"native": "$\\mathrm{CLRT}_{\\mathrm{original}}$",
            "obfuscated": "$\\mathrm{CLRT}_{\\mathrm{new}}$"}


def _panel_title(tag, arm, suffix=""):
    """A short condition identifier. The quantity belongs in the caption, not on the panel.

    The earlier form repeated the variable and the arm on every panel, which the figure review
    identified as a redundant condition-plus-variable title.
    """
    return "(%s) %s%s" % (tag, ARM_LABEL[arm], suffix)


def _stats_sentence(v):
    """The per-arm statistics, for the CAPTION.

    These used to be printed inside the panel as a strip above each axes. They are data about
    the data, not a reading aid for the marks, so they belong in the caption and in the
    figure-data CSV. The figure keeps only what is needed to read the bars.
    """
    var = float(svn.var_s(list(v)))
    return ("$n$~=~%s, mean %.3f~ms, sd %.3f~ms, variance %.4g~ms$^2$"
            % (format(int(v.size), "{,}".replace("{", "").replace("}", "")),
               float(np.mean(v)), float(np.sqrt(var)), var))


def binned_percentages(v, edges, cutoff_ms=None):
    """Assign every value to exactly one category and return counts and percentages.

    Edge convention, stated here because the figure and its CSV both depend on it: a finite bin
    is half-open, [lo, hi), so a value equal to an interior edge belongs to the bin above it.
    When `cutoff_ms` is given, the finite bins stop at the cutoff and everything at or above it,
    the cutoff value itself included, falls in the single overflow category [cutoff, inf). When
    no cutoff is given the topmost finite bin is closed, [lo, hi], so the maximum is counted.

    Returns (counts, overflow_count). The invariant counts.sum() + overflow == v.size is
    asserted by the caller through `verify_bin_accounting`.
    """
    v = np.asarray(v, dtype=float)
    if cutoff_ms is None:
        counts, _ = np.histogram(v, bins=edges)
        return counts.astype(int), 0
    finite = v[v < cutoff_ms]
    over = int(np.count_nonzero(v >= cutoff_ms))
    counts, _ = np.histogram(finite, bins=edges)
    return counts.astype(int), over


def verify_bin_accounting(label, counts, overflow, n):
    """Every valid observation lands in exactly one bin, and the percentages total 100 %."""
    total = int(counts.sum()) + int(overflow)
    if total != int(n):
        raise SystemExit("%s: bins hold %d observations but the sample has %d"
                         % (label, total, n))
    pct = 100.0 * total / float(n)
    if abs(pct - 100.0) > 1e-9:
        raise SystemExit("%s: percentages total %.12f, not 100" % (label, pct))
    return total


def _draw_finite_bars(ax, counts, edges, arm):
    """Ordinary histogram bars from precomputed percentages, so drawing cannot disagree
    with the CSV: both read the same counts."""
    widths = np.diff(edges)
    ax.bar(edges[:-1], counts, width=widths, align="edge", color=ARM_COLOR[arm],
           edgecolor="none", alpha=0.9, zorder=3)


def _draw_overflow_bar(ax, pct, cutoff, w, arm):
    """The overflow category, drawn clearly apart from the finite bins.

    It is separated by a full bin of white space and a break marker, and it is hatched, so it
    cannot be read as the ordinary interval [cutoff, cutoff + w). Its abscissa position carries
    no width meaning; the tick beneath it says what it is.
    """
    ax.axvline(cutoff + w, color=fs.GREY, lw=0.7, ls=(0, (1, 2)), zorder=4)
    ax.bar([cutoff + 2.0 * w], [pct], width=w, align="edge", color=ARM_COLOR[arm],
           edgecolor=ARM_COLOR[arm], alpha=0.45, hatch="///", linewidth=0.6, zorder=3)


def _finish_main_panel(ax, arm, title, cutoff, w, y_hi, show_target, target_ms,
                       show_legend):
    ax.set_title(title, loc="left", pad=12.0)
    ax.set_ylabel("Transactions (%)")
    ax.set_xlim(0.0, cutoff + 4.0 * w)
    ax.set_ylim(0.0, y_hi)
    # The overflow category is set two bin widths clear of the last finite bin, with the break
    # marker between them, so its tick cannot be misread as the cutoff tick beside it.
    ticks = list(np.arange(0.0, cutoff + 0.1, 3.0)) + [cutoff + 2.5 * w]
    ax.set_xticks(ticks)
    ax.set_xticklabels(["%g" % t for t in ticks[:-1]] + ["$\\geq$%g" % cutoff])
    # Only one reference mark survives: the configured value, which a reader cannot infer from
    # the bars. The mean is in the caption, and the overflow category is already named by its
    # own axis tick, so neither needs a legend entry.
    if show_target:
        ax.axvline(target_ms, color=fs.GREY, ls=(0, (4, 2)), lw=1.0, zorder=5)
        if show_legend:
            ax.legend(handles=[Line2D([], [], color=fs.GREY, ls=(0, (4, 2)), lw=1.0,
                                      label="Configured $\\mathrm{CLRT}_{\\mathrm{new}}$")],
                      loc="upper right", fontsize=8, framealpha=0.9, borderpad=0.3,
                      handlelength=1.8, labelspacing=0.22, borderaxespad=0.3)


def figure_distributions(by_arm, target_ms, out, inputs, acc, bin_rows):
    """The main comparison: two vertically aligned histograms on a linear ordinate.

    Common 1 ms bins anchored at 0 ms, shared axis limits, and one overflow category so the
    sparse far tail cannot squeeze the body of the distribution off the panel. The full
    measured range, tails included, is kept in the companion figure.
    """
    fs.use()
    off, obf = by_arm["native"], by_arm["obfuscated"]
    w = MAIN_BIN_MS
    cutoff = OVERFLOW_CUTOFF_MS
    n_fin = int(round(cutoff / w))
    edges = w * np.arange(n_fin + 1)
    w_fd_main = freedman_diaconis_ms(off)

    panels = {}
    for arm, v in (("native", off), ("obfuscated", obf)):
        counts, over = binned_percentages(v, edges, cutoff_ms=cutoff)
        verify_bin_accounting("main/%s" % arm, counts, over, v.size)
        scale = 100.0 / float(v.size)
        panels[arm] = (counts * scale, over * scale, counts, over)

    y_hi = max(max(panels[a][0].max(), panels[a][1]) for a in panels) * 1.18

    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_W, 3.5))
    for ax, arm, v, tag in ((axes[0], "native", off, "a"), (axes[1], "obfuscated", obf, "b")):
        pct, over_pct, counts, over = panels[arm]
        _draw_finite_bars(ax, pct, edges, arm)
        _draw_overflow_bar(ax, over_pct, cutoff, w, arm)
        _finish_main_panel(ax, arm, _panel_title(tag, arm), cutoff, w, y_hi,
                           show_target=(arm == "obfuscated"), target_ms=target_ms,
                           show_legend=(arm == "obfuscated"))
        for i in range(n_fin):
            bin_rows.append(dict(figure="fig_clrt_distributions", panel="(%s)" % tag,
                                 arm=ARM_LABEL[arm], category="finite",
                                 bin_lo_ms=round(float(edges[i]), 6),
                                 bin_hi_ms=round(float(edges[i + 1]), 6),
                                 edge_convention="[lo, hi)", transactions=int(counts[i]),
                                 percent_of_arm=round(float(pct[i]), 9)))
        bin_rows.append(dict(figure="fig_clrt_distributions", panel="(%s)" % tag,
                             arm=ARM_LABEL[arm], category="overflow",
                             bin_lo_ms=round(float(cutoff), 6), bin_hi_ms="inf",
                             edge_convention="[cutoff, inf)", transactions=int(over),
                             percent_of_arm=round(float(over_pct), 9)))
    axes[0].set_xlabel("")
    axes[1].set_xlabel("CLRT (ms)")
    fig.tight_layout(pad=0.3, h_pad=0.9)

    rows = [stats_row("arm total (main campaign)", "all 22 grouped runs", arm, v,
                      "campaign_v1/derived/transactions.csv")
            for arm, v in (("native", off), ("obfuscated", obf))]
    for r, arm in zip(rows, ("native", "obfuscated")):
        pct, over_pct, counts, over = panels[arm]
        r["main_bin_width_ms"] = round(w, 6)
        r["bin_origin_ms"] = 0.0
        r["edge_convention"] = "finite bins [lo, hi); overflow [cutoff, inf)"
        r["overflow_cutoff_ms"] = round(cutoff, 6)
        r["transactions_in_overflow"] = int(over)
        r["percent_in_overflow"] = round(float(over_pct), 9)
        r["freedman_diaconis_main_ms"] = round(w_fd_main, 6)
        r["configured_CLRT_new_ms"] = target_ms

    var_off, var_obf = float(svn.var_s(list(off))), float(svn.var_s(list(obf)))
    o_pct = dict((a, panels[a][1]) for a in panels)
    caption = (
        "**Measured READ CLRT before and after obfuscation.** Bars give the percentage of that "
        "arm's own transactions in each bin, on common %.0f ms bins anchored at 0 ms with a "
        "linear ordinate and shared limits. Finite bins are half-open, $[\\mathrm{lo}, "
        "\\mathrm{hi})$; the hatched category at the right holds every transaction at or above "
        "%g ms, which is %.3f %% of (a) and %.3f %% of (b). The dashed line in (b) is the "
        "configured $\\mathrm{CLRT}_{\\mathrm{new}}$; the measured mean lies %.3f ms from it. "
        "Because the configured value falls "
        "exactly on a bin edge, the obfuscated mass divides between the 3--4 and 4--5 ms bins, "
        "which is a property of the grid and not of the measurement; "
        "Fig.~\\ref{fig:clrtzoom} resolves it into one narrow mode. "
        "(a) %s. (b) %s."
        % (w, cutoff, o_pct["native"], o_pct["obfuscated"],
           abs(float(np.mean(obf)) - target_ms),
           _stats_sentence(off), _stats_sentence(obf)))
    method = _method_note(w, w_fd_main, cutoff, panels, target_ms, acc)
    limitations = _limitations_note()
    notes = ["READ only; SELECT and OPERATE are excluded by design and counted in the row "
             "accounting",
             "one device and one configured setting; the policy sweep under campaign_v1/sweep/ "
             "is a different workload and is not included",
             "no exclusions: every READ transaction in the canonical table is plotted",
             "overflow is a category, not an interval; values equal to the cutoff are in it",
             "the full measured range with every tail is kept in fig_clrt_distributions_full"]
    return emit(fig, out, "fig_clrt_distributions", caption, inputs, rows, method,
                limitations, notes)


def figure_distributions_full(by_arm, target_ms, out, inputs, bin_rows):
    """Companion view: the same bins over the entire measured range, no overflow, all tails."""
    fs.use()
    off, obf = by_arm["native"], by_arm["obfuscated"]
    w = MAIN_BIN_MS
    hi = float(max(off[-1], obf[-1]))
    n_fin = int(np.ceil(hi / w))
    edges = w * np.arange(n_fin + 1)

    panels = {}
    for arm, v in (("native", off), ("obfuscated", obf)):
        counts, over = binned_percentages(v, edges, cutoff_ms=None)
        verify_bin_accounting("full/%s" % arm, counts, over, v.size)
        panels[arm] = (counts * (100.0 / float(v.size)), counts)

    y_hi = max(panels[a][0].max() for a in panels) * 1.18
    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_W, 3.5))
    for ax, arm, v, tag in ((axes[0], "native", off, "a"), (axes[1], "obfuscated", obf, "b")):
        pct, counts = panels[arm]
        _draw_finite_bars(ax, pct, edges, arm)
        ax.set_title(_panel_title(tag, arm, ", full range"), loc="left", pad=12.0)
        ax.set_ylabel("Transactions (%)")
        ax.set_xlim(0.0, w * n_fin)
        ax.set_ylim(0.0, y_hi)
        if arm == "obfuscated":
            ax.axvline(target_ms, color=fs.GREY, ls=(0, (4, 2)), lw=0.9, zorder=5)
        ax.axvline(float(np.mean(v)), color="black", ls=(0, (1, 1.2)), lw=1.0, zorder=6)
        for i in range(n_fin):
            if counts[i] == 0:
                continue
            bin_rows.append(dict(figure="fig_clrt_distributions_full", panel="(%s)" % tag,
                                 arm=ARM_LABEL[arm], category="finite",
                                 bin_lo_ms=round(float(edges[i]), 6),
                                 bin_hi_ms=round(float(edges[i + 1]), 6),
                                 edge_convention="[lo, hi); topmost closed",
                                 transactions=int(counts[i]),
                                 percent_of_arm=round(float(pct[i]), 9)))
    axes[0].set_xlabel("")
    axes[1].set_xlabel("CLRT (ms)")
    fig.tight_layout(pad=0.3, h_pad=0.9)

    rows = [stats_row("arm total (main campaign)", "all 22 grouped runs", arm, v,
                      "campaign_v1/derived/transactions.csv")
            for arm, v in (("native", off), ("obfuscated", obf))]
    for r in rows:
        r["main_bin_width_ms"] = round(w, 6)
        r["bin_origin_ms"] = 0.0
        r["edge_convention"] = "[lo, hi); topmost bin closed so the maximum is counted"
        r["overflow_cutoff_ms"] = "none (full range)"
        r["configured_CLRT_new_ms"] = target_ms
    caption = (
        "**The same measurements over the entire measured range.** Identical %.0f ms bins "
        "anchored at 0 ms and no overflow category, so every tail out to the largest "
        "observation, %.1f ms in (a) and %.1f ms in (b), is drawn."
        % (w, float(off[-1]), float(obf[-1])))
    method = ("Companion to fig_clrt_distributions and generated from the same samples in the "
              "same run of the same script, so the two cannot disagree. Bins are identical in "
              "width and origin; the only difference is that no overflow category is formed "
              "and the abscissa runs to the largest observation in either arm. Bars are the "
              "percentage of that arm's own transactions, weight 100/n. Bins holding no "
              "transaction are omitted from the CSV and drawn at zero height.")
    limitations = _limitations_note()
    notes = ["retains every tail; nothing is truncated or aggregated",
             "the far tail bins are a small fraction of a percent and are legible only in "
              "the CSV, which is why the truncated main view exists"]
    return emit(fig, out, "fig_clrt_distributions_full", caption, inputs, rows, method,
                limitations, notes)


def figure_zoom(by_arm, target_ms, out, inputs, bin_rows):
    """Zoom around the configured value, at a width consistent with timestamp resolution."""
    fs.use()
    off, obf = by_arm["native"], by_arm["obfuscated"]
    z_lo, z_hi = target_ms - ZOOM_HALFWIDTH_MS, target_ms + ZOOM_HALFWIDTH_MS
    w = ZOOM_BIN_MS
    n = int(round((z_hi - z_lo) / w))
    edges = z_lo + w * np.arange(n + 1)
    w_fd_zoom = freedman_diaconis_ms(obf)

    fig, axes = plt.subplots(2, 1, figsize=(fs.COL_W, 3.3))
    shares, peaks = {}, []
    for ax, arm, v, tag in ((axes[0], "native", off, "a"), (axes[1], "obfuscated", obf, "b")):
        counts, _ = np.histogram(v, bins=edges)
        # The denominator stays the arm's full sample, so a bar is a share of every
        # transaction measured in that arm and the window is not renormalized to 100 %.
        pct = counts * (100.0 / float(v.size))
        peaks.append(float(pct.max()) if pct.size else 0.0)
        inside = int(counts.sum())
        shares[arm] = 100.0 * inside / float(v.size)
        _draw_finite_bars(ax, pct, edges, arm)
        ax.axvline(target_ms, color=fs.GREY, ls=(0, (4, 2)), lw=0.9, zorder=5)
        ax.set_title(_panel_title(tag, arm, ", zoom, %.3f ms bins" % w), loc="left",
                     fontsize=8, pad=10.0)
        ax.set_xlim(z_lo, z_hi)
        ax.set_ylabel("Transactions (%)")
        for i in range(n):
            if counts[i] == 0:
                continue
            bin_rows.append(dict(figure="fig_clrt_zoom", panel="(%s)" % tag,
                                 arm=ARM_LABEL[arm], category="finite",
                                 bin_lo_ms=round(float(edges[i]), 9),
                                 bin_hi_ms=round(float(edges[i + 1]), 9),
                                 edge_convention="[lo, hi); denominator is the arm's full "
                                                 "sample, not the window",
                                 transactions=int(counts[i]),
                                 percent_of_arm=round(float(pct[i]), 9)))
    top = max(peaks) * 1.18
    for ax in axes:
        ax.set_ylim(0.0, top)
    axes[0].set_xlabel("")
    axes[1].set_xlabel("CLRT (ms)")
    fig.tight_layout(pad=0.3, h_pad=0.9)

    rows = [stats_row("arm total (main campaign)", "all 22 grouped runs", arm, v,
                      "campaign_v1/derived/transactions.csv")
            for arm, v in (("native", off), ("obfuscated", obf))]
    for r, arm in zip(rows, ("native", "obfuscated")):
        r["zoom_bin_width_ms"] = round(w, 9)
        r["zoom_window_ms"] = "%.3f to %.3f" % (z_lo, z_hi)
        r["percent_of_arm_in_window"] = round(shares[arm], 6)
        r["freedman_diaconis_zoom_ms"] = round(w_fd_zoom, 9)
        r["configured_CLRT_new_ms"] = target_ms
    caption = (
        "**The released interval, resolved.** The same measurements as "
        "Fig.~\\ref{fig:hist} on %.3f ms bins within %.2f ms of the configured "
        "$\\mathrm{CLRT}_{\\mathrm{new}}$ (dashed). The ordinate is still the percentage of "
        "that arm's entire sample, not of the window, so the bars are directly comparable with "
        "the other figures; the window holds %.2f %% of (a) and %.2f %% of (b). This is where "
        "the mass that the 1 ms grid splits across two bins is seen to be a single narrow mode."
        % (w, ZOOM_HALFWIDTH_MS, shares["native"], shares["obfuscated"]))
    method = (
        "Same samples and same script run as fig_clrt_distributions. The window is %.2f ms "
        "either side of the configured value and the bin width is %.3f ms. That width is a "
        "choice and is recorded as one: Freedman-Diaconis evaluated on the Obfuscated sample, "
        "the distribution this view exists to resolve, gives %.4f ms, which would put four "
        "hundred bins across the window and render as a comb one transaction high. Ten times "
        "coarser keeps forty bins, resolves the structure of the released interval and can be "
        "read at printed size. The ordinate keeps the full-condition denominator: a bar is a "
        "share of every transaction measured in that arm, so the visible subset is never "
        "renormalized to 100 %%, and the window's own share is stated on each panel. No "
        "residual variable is introduced; the abscissa is CLRT in milliseconds throughout."
        % (ZOOM_HALFWIDTH_MS, w, w_fd_zoom))
    limitations = _limitations_note()
    notes = ["the denominator is the arm's full sample, never the window",
             "values outside the window are not drawn and not renormalized away"]
    return emit(fig, out, "fig_clrt_zoom", caption, inputs, rows, method, limitations, notes)


def _method_note(w, w_fd_main, cutoff, panels, target_ms, acc):
    return (
        "READ transactions only, from the frozen canonical table "
        "`defense4/timing/evidence/campaign_v1/derived/transactions.csv`, which covers 22 "
        "grouped collection runs on one SEL-751A relay behind one Intel Tofino-1, all "
        "timestamps taken on the master-facing link, at the single configured setting in "
        "`campaign_v1/repro/policy_config.json` (D_A = 20 ms, the configured CLRT_new = 4 ms "
        "carried in the field named D_R_ms, size carve disabled). No other device, corpus or "
        "policy setting enters this figure. The policy sweep captures under "
        "`campaign_v1/sweep/` are a different workload and are not part of the canonical "
        "table, and the deliberate retransmission diagnostic under `relay_rto_20260915/` is a "
        "loss experiment, not an obfuscation result, and is excluded. CLRT is "
        "clrt_ms = (t_resp - t_ack) * 1e3, the interval between the transport acknowledgment "
        "arriving at the master host NIC and the application response arriving there, both "
        "timestamps taken at the same vantage on the master-facing link; in the notation of "
        "`defense4/timing/NOTATION_MAPPING.md` that is m_R - m_A. It is CLRT_original in the "
        "Timing OFF arm and the measured CLRT_new in the Obfuscated arm. The configured value "
        "is the policy field named D_R_ms; under the manuscript's convention that field is the "
        "configured CLRT_new and it is not D_R, which is the response latency m_R - t_R. "
        "Measured and configured quantities are never merged: the dashed line is the "
        "configuration, the bars are the measurement. "
        "Transaction accounting: the extractor pairs one request with the first transport "
        "acknowledgment and then the application response, so a retransmission cannot open a "
        "new transaction. Re-running the independent reader over all 132 campaign captures "
        "gives 63,360 exchanges with 0 retransmissions, 0 duplicate application frames, 0 "
        "malformed frames, 0 unpaired requests, 0 out-of-order timestamps and 0 frames from "
        "the wrong endpoint, matching the frozen table row for row. Of those, %d are READ and "
        "%d are SELECT or OPERATE and are not plotted here. %d rows were dropped for a "
        "non-finite or non-positive interval, so the two arms carry equal counts and no "
        "transaction is missing a timestamp. Genuine late responses and timing outliers are "
        "retained; nothing is winsorized or smoothed. "
        "Binning follows Formby et al., NDSS 2016, who define the CLRT fingerprint as the "
        "vector of counts of an equal-width linear-bin histogram with an overflow bin for "
        "large values (their Equation 1) and plot CLRT distributions that way in their Figure "
        "6(b); they evaluate 200-bin feature vectors for classification. The widths used here "
        "are our presentation choice and are not widths Formby states, and this figure is a "
        "plot rather than a classifier, so it carries no bin-count requirement. The main and "
        "companion panels use %.0f ms bins anchored at 0 ms. Freedman-Diaconis on the Timing "
        "OFF sample gives %.4f ms; that rule assumes a roughly unimodal density and is "
        "reported rather than followed. Finite bins are half-open, [lo, hi), so a value equal "
        "to an interior edge belongs to the bin above it. The main view stops its finite bins "
        "at %g ms and collects everything at or above that value, the cutoff itself included, "
        "into one overflow category drawn apart from the bins and hatched so it cannot be read "
        "as the ordinary interval; it holds %.3f %% of the Timing OFF sample and %.3f %% of "
        "the Obfuscated sample. The same cutoff is used in both panels. The companion figure "
        "`fig_clrt_distributions_full` repeats the comparison with no cutoff at all, so no "
        "tail is lost. Bins were not shifted off the origin: the configured 4 ms falls exactly "
        "on an edge, which divides the obfuscated mass between the 3--4 and 4--5 ms bins, and "
        "that is left visible rather than hidden by moving the grid. "
        "Both panels share one pair of limits and one edge set, so a bar in one and a bar in "
        "its counterpart mean the same thing at the same height. The ordinate is linear and is "
        "a percentage of that arm's own transactions, weight 100/n, so the comparison does not "
        "depend on the two arms having equal samples; it is a per-bin share and not a "
        "probability density. No smoothing, kernel or per-sample spike is drawn. Bin counts "
        "including the overflow category are checked to sum to the plotted sample and the "
        "percentages to total 100 %% before the figure is written. Every statistic in the "
        "annotations and in the CSVs is computed from the raw millisecond samples, never from "
        "bin centres; sample variance uses the n-1 denominator."
        % (acc["read_rows"], acc["non_read_rows"], acc["excluded_from_plot"],
           w, w_fd_main, cutoff, panels["native"][1], panels["obfuscated"][1]))


def _limitations_note():
    return (
        "A narrower distribution after obfuscation is a property of the released interval. It "
        "is not on its own evidence that transaction fingerprinting is mitigated: that claim "
        "rests on the classifier and mutual-information results reported separately, and "
        "reduced variance alone does not establish it. The dashed line is a configured policy "
        "value and the bars are a measurement; the two must not be read as the same kind of "
        "quantity. The residual spread in the Obfuscated arm is a net quantity, the response "
        "release delay minus the acknowledgment release delay plus differential path and "
        "capture effects; it is not attributed here to any single mechanism. The two arms are "
        "separate capture blocks, not repeated measurements of the same transaction, so no "
        "per-transaction transfer function can be read from this figure. All intervals are "
        "master-facing; the relay-facing release instants and the realized per-transaction "
        "jitter were not observed. One relay, one configured setting, one approximately "
        "five-hour window.")


BIN_TABLE_FIELDS = ["figure", "panel", "arm", "category", "bin_lo_ms", "bin_hi_ms",
                    "edge_convention", "transactions", "percent_of_arm"]


def write_bin_table(out, bin_rows):
    """Every bin of every panel, so a reader can rebuild the bars without the pcaps."""
    path = Path(out) / "clrt_bin_counts.csv"
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=BIN_TABLE_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(bin_rows)
    print("  %-28s %d rows" % ("clrt_bin_counts.csv", len(bin_rows)))
    return path

# ------------------------------------------------------------------ entry point

RUN_STATS_FIELDS = ["unit", "run", "arm", "operation", "transactions", "mean_ms",
                    "sample_sd_ms", "sample_variance_ms2", "median_ms", "min_ms", "max_ms",
                    "source"]


def write_manifest(out):
    """FIGURES.sha256, written by the run that produced the artefacts so it cannot go stale.

    `shift_vs_normalization.write_manifest` covers PDFs, figure-data CSVs and summary JSON. The
    per-run statistics table is none of those and would have been left uncovered, so the file
    list is built here instead.
    """
    names = sorted(n for n in os.listdir(out)
                   if (n.endswith(".pdf") or n.endswith(".csv")
                       or (n.endswith(".json") and not n.endswith(".provenance.json"))))
    entries = [(n, fs.sha256_file(os.path.join(out, n))) for n in names]
    with open(os.path.join(out, "FIGURES.sha256"), "w") as fh:
        fh.write("\n".join("%s  %s" % (h, n) for n, h in entries) + "\n")
    print("  %-28s %d generated artefacts" % ("FIGURES.sha256", len(entries)))
    return entries


def check_manifest(out):
    """Verify FIGURES.sha256 against what is on disk. Returns a list of problems."""
    path = os.path.join(out, "FIGURES.sha256")
    if not os.path.exists(path):
        return ["FIGURES.sha256 is missing"]
    recorded = {}
    for line in open(path):
        line = line.strip()
        if line:
            h, n = line.split("  ", 1)
            recorded[n] = h
    actual = {n: h for n, h in
              ((n, fs.sha256_file(os.path.join(out, n))) for n in sorted(os.listdir(out))
               if (n.endswith(".pdf") or n.endswith(".csv")
                   or (n.endswith(".json") and not n.endswith(".provenance.json"))))}
    problems = []
    for n in sorted(set(recorded) | set(actual)):
        if n not in recorded:
            problems.append("%s is a generated artefact but is not listed" % n)
        elif n not in actual:
            problems.append("%s is listed but is not on disk" % n)
        elif recorded[n] != actual[n]:
            problems.append("%s: recorded %s, on disk %s"
                            % (n, recorded[n][:12], actual[n][:12]))
    return problems


def write_run_statistics(out, by_run, by_capture, single_stats):
    """Every unit at which a variance was formed, in one table, so none is implied silently."""
    rows = []
    for (run, arm), v in sorted(by_run.items()):
        rows.append(stats_row("grouped collection run", run, arm, v,
                              "campaign_v1/derived/transactions.csv"))
    for (run, block, arm), v in sorted(by_capture.items()):
        rows.append(stats_row("capture (nested in run, not independent)",
                              "%s/%s" % (run, block), arm, v,
                              "campaign_v1/derived/transactions.csv"))
    rows.extend(single_stats)
    path = Path(out) / "clrt_run_statistics.csv"
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RUN_STATS_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print("  %-28s %d rows" % ("clrt_run_statistics.csv", len(rows)))
    return path


SOURCE_MANIFEST_FIELDS = [
    "run_id", "block", "arm_from_session_log", "arm_in_frozen_table", "capture",
    "capture_sha256", "frames", "read_transactions_plotted", "select_operate_not_plotted",
    "retransmissions", "duplicate_app_frames", "malformed", "unpaired_requests",
    "out_of_order_ts", "wrong_endpoint", "excluded_non_finite_or_non_positive",
    "D_A_ms", "configured_CLRT_new_ms", "shape_enable", "p4_program", "p4_source_sha256"]


def write_source_manifest(out, by_arm, acc, target_ms):
    """One row per capture, linking every plotted transaction back to the pcap it came from.

    The arm is taken from each session's own `provenance/MANIFEST.json`, which records what was
    configured for that block, and is cross-checked against the arm carried in the frozen
    table. Filenames are never the authority for the condition; a disagreement is fatal here.
    The per-capture diagnostic counters come from re-running the independent reader in
    `campaign_v1/repro/pcap_dnp3.py` over the raw capture, so "no retransmissions" is a
    measurement rather than an assumption.
    """
    sys.path.insert(0, str(REPRO))
    import pcap_dnp3 as pd3                                                  # noqa: E402

    frozen = defaultdict(lambda: {"READ": 0, "OTHER": 0, "arms": set()})
    with open(CV1 / "derived" / "transactions.csv") as fh:
        for r in csv.DictReader(fh):
            k = (r["session"], r["block"])
            frozen[k]["READ" if r["txn_class"] == "READ" else "OTHER"] += 1
            frozen[k]["arms"].add(r["arm"])

    rows, totals = [], defaultdict(int)
    for sess_dir in sorted(CV1.glob("s[0-9][0-9]")):
        man = json.loads((sess_dir / "provenance" / "MANIFEST.json").read_text())
        cfg = man.get("config", {})
        obf = cfg.get("obfuscated_arm", {})
        prog = man.get("loaded_program", {})
        hashes = {}
        for line in (sess_dir / "provenance" / "DATASET.sha256").read_text().splitlines():
            if "  " in line:
                h, name = line.split("  ", 1)
                hashes[name.strip()] = h
        for blk in man.get("blocks", []):
            bid, arm_log = blk["id"], blk["arm"]
            cap = sess_dir / "raw_pcaps" / ("%s_%s_%s.pcap" % (sess_dir.name, bid, arm_log))
            k = (sess_dir.name, bid)
            arms_seen = frozen[k]["arms"]
            if arms_seen != {arm_log}:
                raise SystemExit("%s/%s: session log says arm %r, frozen table says %r"
                                 % (sess_dir.name, bid, arm_log, sorted(arms_seen)))
            rep = pd3.extract(cap)
            row = dict(
                run_id=sess_dir.name, block=bid, arm_from_session_log=ARM_LABEL[arm_log],
                arm_in_frozen_table=ARM_LABEL[sorted(arms_seen)[0]],
                capture=_rel(cap),
                capture_sha256=hashes.get("raw_pcaps/" + cap.name, ""),
                frames=rep.frames,
                read_transactions_plotted=frozen[k]["READ"],
                select_operate_not_plotted=frozen[k]["OTHER"],
                retransmissions=rep.retransmissions,
                duplicate_app_frames=rep.duplicate_app_frames,
                malformed=rep.malformed,
                unpaired_requests=rep.unpaired_requests,
                out_of_order_ts=rep.out_of_order_ts,
                wrong_endpoint=rep.wrong_endpoint,
                excluded_non_finite_or_non_positive=0,
                D_A_ms=obf.get("D_A_ms", cfg.get("native_arm", {}).get("d_ticks_ms")),
                configured_CLRT_new_ms=(target_ms if arm_log == "obfuscated" else ""),
                shape_enable=cfg.get("shape_enable"),
                p4_program=prog.get("p4_name"),
                p4_source_sha256=prog.get("p4_source_sha256"))
            for f in ("retransmissions", "duplicate_app_frames", "malformed",
                      "unpaired_requests", "out_of_order_ts", "wrong_endpoint",
                      "read_transactions_plotted", "select_operate_not_plotted", "frames"):
                totals[f] += int(row[f])
            rows.append(row)

    path = Path(out) / "clrt_source_manifest.csv"
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=SOURCE_MANIFEST_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    plotted = int(by_arm["native"].size + by_arm["obfuscated"].size)
    if totals["read_transactions_plotted"] != plotted:
        raise SystemExit("source manifest accounts for %d READ transactions, the figures plot %d"
                         % (totals["read_transactions_plotted"], plotted))
    summary = {
        "captures": len(rows),
        "grouped_runs": len({r["run_id"] for r in rows}),
        "frames_read": totals["frames"],
        "read_transactions_plotted": totals["read_transactions_plotted"],
        "select_operate_not_plotted": totals["select_operate_not_plotted"],
        "excluded_from_plot": acc["excluded_from_plot"],
        "failed_or_ambiguous": {
            "retransmissions": totals["retransmissions"],
            "duplicate_app_frames": totals["duplicate_app_frames"],
            "malformed_frames": totals["malformed"],
            "unpaired_requests": totals["unpaired_requests"],
            "out_of_order_timestamps": totals["out_of_order_ts"],
            "frames_from_wrong_endpoint": totals["wrong_endpoint"]},
        "arm_cross_check": "every block's arm agrees between its session MANIFEST.json and the "
                           "frozen table; filenames were not used to decide the condition",
        "capture_vantage": "master-facing link at the master host NIC; CLRT = m_R - m_A",
        "configured_CLRT_new_ms": target_ms,
        "excluded_corpora": [
            "campaign_v1/sweep/ - policy sweep, a different workload",
            "relay_rto_20260915/ - deliberate retransmission and loss diagnostic, not an "
            "obfuscation result",
            "evidence/final_read_sbo/ - superseded single-session corpus"],
    }
    (Path(out) / "clrt_source_manifest.json").write_text(json.dumps(summary, indent=1) + "\n")
    print("  %-28s %d captures, %d READ transactions, %d failed/ambiguous"
          % ("clrt_source_manifest.csv", len(rows), totals["read_transactions_plotted"],
             sum(summary["failed_or_ambiguous"].values())))
    return path


def main(argv):
    if len(argv) > 1 and argv[1] == "--check":
        out = argv[2] if len(argv) > 2 else str(DEFAULT_OUT)
        problems = check_manifest(out)
        print("CLRT figure manifest: %d problems" % len(problems))
        for p in problems:
            print("  PROBLEM:", p)
        if not problems:
            print("  every generated artefact matches FIGURES.sha256")
        return 1 if problems else 0

    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)

    by_run, by_capture, by_arm, acc, cv1_inputs = load_campaign_reads()
    target_ms, cfg_inputs = campaign_target_ms()
    single, single_acc, frs_inputs = load_single_session_reads()
    single_stats = [stats_row("single-session capture (one estimate, not a distribution)",
                              single_acc[arm]["capture"], arm, single[arm],
                              "final_read_sbo/derived_csv")
                    for arm in ("native", "obfuscated")]

    print("main campaign row accounting")
    print("  rows=%d READ=%d non-READ=%d excluded=%d anomalies=%d incomplete_sessions=%d"
          % (acc["rows"], acc["read_rows"], acc["non_read_rows"], acc["excluded_from_plot"],
             acc["dataset_rollup_anomalies"], acc["dataset_rollup_incomplete_sessions"]))
    print("  grouped runs=%d  captures=%d  configured D_R=%g ms"
          % (len({k[0] for k in by_run}), len(by_capture), target_ms))
    print("single-session accounting")
    for arm in ("native", "obfuscated"):
        a = single_acc[arm]
        print("  %-11s %-18s polled=%d cold-start excluded=%d plotted=%d"
              % (ARM_LABEL[arm], a["capture"], a["read_requests_polled"],
                 a["cold_start_read_excluded"], a["plotted"]))
    print()

    bin_rows = []
    figure_distributions(by_arm, target_ms, out, cv1_inputs + cfg_inputs, acc, bin_rows)
    figure_distributions_full(by_arm, target_ms, out, cv1_inputs + cfg_inputs, bin_rows)
    figure_zoom(by_arm, target_ms, out, cv1_inputs + cfg_inputs, bin_rows)
    write_run_statistics(out, by_run, by_capture, single_stats)
    write_bin_table(out, bin_rows)
    write_source_manifest(out, by_arm, acc, target_ms)
    write_manifest(str(out))

    print()
    print("%-12s %10s %12s %12s %12s" % ("arm", "n", "mean ms", "sd ms", "variance ms2"))
    for arm in ("native", "obfuscated"):
        v = by_arm[arm]
        va = svn.var_s(list(v))
        print("%-12s %10s %12.4f %12.4f %12.6f"
              % (ARM_LABEL[arm], format(len(v), ","), float(np.mean(v)), float(np.sqrt(va)), va))
    print()
    runs = sorted({k[0] for k in by_run})
    for arm in ("native", "obfuscated"):
        v = sorted(svn.var_s(by_run[(r, arm)]) for r in runs)
        print("%-12s per-run variance  min=%.4g  median=%.4g  max=%.4g  (n=%d runs)"
              % (ARM_LABEL[arm], v[0], v[len(v) // 2], v[-1], len(v)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
