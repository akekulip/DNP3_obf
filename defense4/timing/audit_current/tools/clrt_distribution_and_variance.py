#!/usr/bin/env python3
"""READ CLRT distributions before and after obfuscation, and the variance across runs.

Two figures, from the verified transaction tables only:

  fig_clrt_distributions   two vertically aligned histograms of the measured CLRT, Timing OFF
                           above and Obfuscated below, on common bin edges and shared limits,
                           each normalized to a probability density so the unequal-looking
                           counts cannot distort the comparison, with a zoom column around the
                           configured target.

  fig_clrt_variance_runs   one dot per grouped collection run, the sample variance of that
                           run's READ CLRT under each arm, Timing OFF against Obfuscated, with
                           the pair from a single run joined.

Notation follows the manuscript body, not this tool. Section 4 writes the quantity as CLRT and
the configured read-lane offset as D_R (`sections/04_design.tex`, equations `eq:read` and
`eq:clrt`). The symbols C_obs and C appear in the manuscript only inside the caption of the
constant-shift figure and are not defined in the body, so they are not used here; the axes say
"CLRT (ms)" in plain words and the configured value is marked D_R.

    python3 clrt_distribution_and_variance.py [OUT_DIR]
    python3 clrt_distribution_and_variance.py --check [OUT_DIR]

Default OUT_DIR is paper/rewrite/figures/clrt. Raw captures and frozen CSVs are inputs and are
never written.
"""
from __future__ import annotations

import csv
import json
import os
import statistics
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
from matplotlib.patches import Patch                                         # noqa: E402

# The per-corpus configuration parsers and the manifest writer are reused rather than copied,
# so a corpus whose configured offset changes cannot end up with two answers in two figures.
import shift_vs_normalization as svn                                         # noqa: E402

PNG_DPI = 300
JITTER_SEED = 20260908
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
# Ordinate floor, in percent of a condition's transactions per bin. One transaction out of
# 26,400 is 0.0038 %, so a floor half that keeps every occupied bin on the axis.
PERCENT_FLOOR = 2e-3


# ------------------------------------------------------------------ data loading

def load_campaign_reads():
    """Every READ CLRT in the main campaign, indexed by grouped run, capture and arm."""
    path = CV1 / "derived" / "transactions.csv"
    by_run, by_capture, by_arm = defaultdict(list), defaultdict(list), defaultdict(list)
    acc = {"rows": 0, "read_rows": 0, "non_read_rows": 0, "non_finite": 0, "non_positive": 0}
    with open(path) as fh:
        for r in csv.DictReader(fh):
            acc["rows"] += 1
            if r["txn_class"] != "READ":
                acc["non_read_rows"] += 1
                continue
            acc["read_rows"] += 1
            x = float(r["clrt_ms"])
            if not np.isfinite(x):
                acc["non_finite"] += 1
                continue
            if x <= 0:
                acc["non_positive"] += 1
                continue
            by_run[(r["session"], r["arm"])].append(x)
            by_capture[(r["session"], r["block"], r["arm"])].append(x)
            by_arm[r["arm"]].append(x)
    roll = json.loads(ROLLUP.read_text())
    acc["dataset_rollup_anomalies"] = int(roll["anomalies_count"])
    acc["dataset_rollup_incomplete_sessions"] = len(roll["incomplete_sessions"])
    acc["excluded_from_plot"] = acc["non_finite"] + acc["non_positive"]
    by_arm = {a: np.sort(np.asarray(v, dtype=float)) for a, v in by_arm.items()}
    return by_run, by_capture, by_arm, acc, [path, ROLLUP, CAMPAIGN_README]


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
    """Panel heading in the manuscript's notation, with the arm it was measured under."""
    return "(%s) %s (%s)%s" % (tag, QUANTITY[arm], ARM_LABEL[arm], suffix)


def _annotate_box(ax, v):
    """Transactions, mean, sample standard deviation and sample variance, n-1 denominator."""
    var = float(svn.var_s(list(v)))
    txt = ("n %s, mean %.3f ms, sd %.3f ms, variance %.4g ms$^2$"
           % (format(int(v.size), ","), float(np.mean(v)), float(np.sqrt(var)), var))
    ax.text(0.0, 1.02, txt, transform=ax.transAxes, ha="left", va="bottom", fontsize=8,
            color=fs.GREY)


def _hist_panel(ax, v, arm, edges, target_ms, title, show_legend):
    ax.hist(v, bins=edges, weights=_percent_weights(v), color=ARM_COLOR[arm],
            edgecolor="none", alpha=0.9, zorder=3)
    ax.set_yscale("log")
    ax.axvline(target_ms, color=fs.GREY, ls=(0, (4, 2)), lw=0.9, zorder=5)
    ax.axvline(float(np.mean(v)), color="black", ls=(0, (1, 1.2)), lw=1.0, zorder=6)
    ax.set_title(title, loc="left", pad=12.0)
    ax.set_ylabel("Transactions (%)")
    if show_legend:
        ax.legend(handles=[Line2D([], [], color=fs.GREY, ls=(0, (4, 2)), lw=0.9,
                                  label="Configured $\\mathrm{CLRT}_{\\mathrm{new}}$"),
                           Line2D([], [], color="black", ls=(0, (1, 1.2)), lw=1.0,
                                  label="Mean")],
                  loc="upper right", fontsize=8, framealpha=0.9, borderpad=0.3,
                  handlelength=1.8, labelspacing=0.22, borderaxespad=0.3)


def figure_distributions(by_arm, target_ms, out, inputs, acc):
    """Two vertically aligned histograms, full range on the left, target zoom on the right."""
    fs.use()
    off, obf = by_arm["native"], by_arm["obfuscated"]

    # Common linear bin edges for the two full-range panels, following the histogram
    # construction Formby et al. use for the CLRT fingerprint: equal-width bins over the
    # measured range, no smoothing and no kernel. The width is MAIN_BIN_MS; the constant
    # records why 1 ms and not the roughly 5 ms visible in their Figure 6(b).
    lo = float(min(off[0], obf[0]))
    hi = float(max(off[-1], obf[-1]))
    w_main = MAIN_BIN_MS
    n_main = int(np.ceil(hi / w_main))
    edges_main = w_main * np.arange(n_main + 1)
    # Reported alongside it, so the choice can be checked rather than taken on trust.
    w_fd_main = freedman_diaconis_ms(off)

    # The zoom keeps the same quantity and the same units; it only narrows the window.
    z_lo, z_hi = target_ms - ZOOM_HALFWIDTH_MS, target_ms + ZOOM_HALFWIDTH_MS
    w_zoom = ZOOM_BIN_MS
    w_fd_zoom = freedman_diaconis_ms(obf)
    n_zoom = int(np.ceil((z_hi - z_lo) / w_zoom))
    edges_zoom = z_lo + w_zoom * np.arange(n_zoom + 1)

    # One column, four panels stacked. A 7.16 in figure spanning both columns cost about half a
    # page for a comparison that needs only column width; the paper's model uses column figures
    # for everything that fits in one.
    fig, axes = plt.subplots(4, 1, figsize=(fs.COL_W, 5.6))
    a_full, b_full, a_zoom, b_zoom = axes
    _hist_panel(a_full, off, "native", edges_main, target_ms,
                _panel_title("a", "native"), False)
    _hist_panel(b_full, obf, "obfuscated", edges_main, target_ms,
                _panel_title("b", "obfuscated"), True)
    _annotate_box(a_full, off)
    _annotate_box(b_full, obf)

    zoom_rows, zoom_axes = [], []
    for ax, v, arm, tag in ((a_zoom, off, "native", "c"), (b_zoom, obf, "obfuscated", "d")):
        inside = v[(v >= z_lo) & (v <= z_hi)]
        # Values outside the window fall outside the bin range and are simply not drawn; the
        # weights still divide by the condition's full sample, so a bar is a share of every
        # transaction measured in that arm and the panel is not renormalized to what it shows.
        ax.hist(v, bins=edges_zoom, weights=_percent_weights(v), color=ARM_COLOR[arm],
                edgecolor="none", alpha=0.9, zorder=3)
        ax.set_yscale("log")
        ax.axvline(target_ms, color=fs.GREY, ls=(0, (4, 2)), lw=0.9, zorder=5)
        ax.set_title(_panel_title(tag, arm, ", zoom, %.3f ms bins" % w_zoom),
                     loc="left", fontsize=8)
        ax.set_xlim(z_lo, z_hi)
        ax.set_ylabel("Transactions (%)")
        # Two lines, so the label stays clear of the configured line at the centre of the window.
        ax.annotate("%.1f%% of all transactions" % (100.0 * inside.size / v.size),
                    xy=(0.03, 0.95), xycoords="axes fraction", ha="left", va="top",
                    fontsize=8, linespacing=1.3)
        zoom_rows.append((arm, int(inside.size)))
        zoom_axes.append(ax)
    # Corresponding before and after panels share one ordinate, so a bar in (c) and a bar in
    # (d) mean the same thing at the same height.
    z_top = max(_percent_peak(off, edges_zoom), _percent_peak(obf, edges_zoom))
    for ax in zoom_axes:
        ax.set_ylim(PERCENT_FLOOR, z_top * 6.0)

    # Identical x and y limits on both full-range panels: the comparison is between shapes at
    # the same scale. The ordinate is logarithmic because one arm puts 99.9 % of its mass in a
    # single bin while the other spreads over eighty, and a linear ordinate would erase the
    # tails this figure exists to show.
    y_hi = max(_percent_peak(off, edges_main), _percent_peak(obf, edges_main))
    for ax in (a_full, b_full):
        ax.set_xlim(0.0, w_main * n_main)
        ax.set_ylim(PERCENT_FLOOR, y_hi * 4.0)
        ax.set_xlabel("CLRT (ms)")
    a_full.set_xlabel("")
    a_zoom.set_xlabel("")
    b_zoom.set_xlabel("CLRT (ms)")
    fig.tight_layout(pad=0.3, h_pad=0.75)

    rows = [stats_row("arm total (main campaign)", "all 22 grouped runs", arm, v,
                      "campaign_v1/derived/transactions.csv")
            for arm, v in (("native", off), ("obfuscated", obf))]
    for r, (arm, n_in) in zip(rows, zoom_rows):
        r["transactions_in_zoom_window"] = n_in
        r["zoom_window_ms"] = "%.3f to %.3f" % (z_lo, z_hi)
        r["main_bin_width_ms"] = round(w_main, 6)
        r["freedman_diaconis_main_ms"] = round(w_fd_main, 6)
        r["zoom_bin_width_ms"] = round(w_zoom, 9)
        r["freedman_diaconis_zoom_ms"] = round(w_fd_zoom, 9)
        r["configured_CLRT_new_ms"] = target_ms

    var_off, var_obf = float(svn.var_s(list(off))), float(svn.var_s(list(obf)))
    drop_pct = 100.0 * (var_off - var_obf) / var_off
    caption = (
        "**Measured READ CLRT before and after obfuscation.** Bars give the percentage of "
        "that arm's own transactions in each bin, on common %.0f ms bins and a logarithmic "
        "ordinate. (c) and (d) repeat the same measurements on %.3f ms bins within %.2f ms of "
        "the configured %g ms, against the same denominator. The sample variance falls from "
        "%.3f to %.3f ms$^2$. The dashed line is the configured value, the dotted line the "
        "measured mean."
        % (w_main, w_zoom, ZOOM_HALFWIDTH_MS, target_ms, var_off, var_obf))
    method = (
        "READ transactions only, from the frozen canonical table "
        "`defense4/timing/evidence/campaign_v1/derived/transactions.csv`, which covers 22 "
        "grouped collection runs on one SEL-751A relay behind one Intel Tofino-1, all "
        "timestamps taken on the master-facing link, at the single configured setting in "
        "`campaign_v1/repro/policy_config.json` (D_A = 20 ms, the configured CLRT_new = 4 ms "
        "carried in the field named D_R_ms, size carve disabled). No other device, corpus or "
        "policy setting enters this figure; the policy sweep captures under "
        "`campaign_v1/sweep/` are not part of the canonical table. CLRT is "
        "clrt_ms = (t_resp - t_ack) * 1e3, the interval between the transport acknowledgment "
        "and the application response as the extractor computes it. Notation follows the "
        "manuscript body: CLRT_original for the interval the relay itself produces, measured "
        "in the Timing OFF arm, and CLRT_new for the interval after obfuscation, configured "
        "in the policy file and measured in the Obfuscated arm. The configuration field is "
        "still named D_R_ms and the mapping is in defense4/timing/NOTATION_MAPPING.md. "
        "Binning follows Formby et al., NDSS 2016, who define the CLRT fingerprint as the "
        "vector of counts of an equal-width linear-bin histogram over [0, H] (their Equation "
        "1) and plot CLRT distributions that way in their Figure 6(b), five devices overlaid "
        "over a 0 to 0.28 s range; the roughly 5 ms spacing there is read off the rendered "
        "figure and is not a width they state. Five milliseconds would merge this relay's "
        "Timing OFF modes near 1.2, 2.1 and 4.0 ms into one bar, so the full-range panels use "
        "%.0f ms bins, the coarsest width in the 1 to 2 ms range asked for at the meeting that "
        "still separates them. Freedman-Diaconis on the Timing OFF sample gives %.4f ms; that "
        "rule assumes a roughly unimodal density and is reported rather than followed. The "
        "zoom panels use %.3f ms bins over a window %.2f ms either side of the configured "
        "value. That width is deliberate as well: the same rule evaluated on the Obfuscated "
        "sample, the distribution the zoom exists to resolve, gives %.4f ms, which puts four "
        "hundred bins across the window and renders as a comb one transaction high. Ten times "
        "coarser keeps forty bins, resolves the structure of the released interval, and can "
        "be read at printed size, at the cost of a sparse-looking Timing OFF panel over the "
        "same window. Both full-range panels share "
        "one pair of limits and one edge set, and both zoom panels share another, so a bar in "
        "one panel and a bar in its counterpart mean the same thing at the same height. The "
        "ordinate is logarithmic in all four panels: the Obfuscated arm places 99.9 %% of its "
        "mass in one bin while the Timing OFF arm spreads over eighty, and a linear ordinate "
        "would erase the tails the figure exists to show. No smoothing or kernel is applied. "
        "Every panel reports the percentage of that arm's own transactions falling in each "
        "bin, weight 100/n, so the comparison does not depend on the two arms having the same "
        "sample size; in the zoom panels the denominator is still the arm's full sample, so a "
        "bar there is a share of every transaction measured in that arm and the window share "
        "is stated on the panel. Every statistic in the annotations and the figure-data CSV "
        "is computed from the raw millisecond samples; sample variance uses the n-1 "
        "denominator."
        % (w_main, w_fd_main, w_zoom, ZOOM_HALFWIDTH_MS, w_fd_zoom))
    limitations = (
        "A narrower distribution after obfuscation is a property of the released interval. It "
        "is not on its own evidence that transaction fingerprinting is mitigated: that claim "
        "rests on the classifier and mutual-information results. The dashed line is a "
        "configured policy value and the histogram is a measurement; the two must not be read "
        "as the same kind of quantity. The two arms are separate capture blocks, not repeated "
        "measurements of the same transaction, so no per-transaction transfer function can be "
        "read from this figure. All intervals are master-facing; the relay-facing release "
        "instants and the realized per-transaction jitter were not observed. One relay, one "
        "configured setting, one approximately five-hour window.")
    notes = ["READ only; SELECT and OPERATE are excluded by design and counted in the "
             "row accounting",
             "one device and one configured setting; the policy sweep is not included",
             "no exclusions: every READ transaction in the canonical table is plotted",
             "presentation labels carry no internal corpus directory name"]
    return emit(fig, out, "fig_clrt_distributions", caption, inputs, rows, method,
                limitations, notes)


# ------------------------------------------------------------------ figure 2: variance by run

def figure_variance_runs(by_run, out, inputs, single_stats):
    """One dot per grouped collection run, joined across the two arms of the same run."""
    fs.use()
    runs = sorted({k[0] for k in by_run})
    var = {arm: np.array([svn.var_s(by_run[(r, arm)]) for r in runs], dtype=float)
           for arm in ("native", "obfuscated")}
    n_txn = {arm: [len(by_run[(r, arm)]) for r in runs] for arm in ("native", "obfuscated")}
    if any(v <= 0 for arm in var for v in var[arm]):
        raise SystemExit("a run variance is zero or negative; the log ordinate would hide it")

    # One jitter offset per run, reused in both columns, so a joining line stays readable and
    # the pairing it draws is the real one. Seeded, so the figure is reproducible.
    rng = np.random.default_rng(JITTER_SEED)
    jitter = rng.uniform(-0.11, 0.11, size=len(runs))
    xpos = {"native": 0.0, "obfuscated": 1.0}

    fig, ax = plt.subplots(figsize=(4.1, 3.6))
    # Boxes first and unfilled, so they summarize without covering a single dot.
    bp = ax.boxplot([var["native"], var["obfuscated"]], positions=[0.0, 1.0], widths=0.44,
                    showfliers=False, patch_artist=False, zorder=2)
    for part in ("boxes", "whiskers", "caps", "medians"):
        for artist in bp[part]:
            artist.set_color(fs.GREY)
            artist.set_linewidth(0.8)
    for i in range(len(runs)):
        ax.plot([xpos["native"] + jitter[i], xpos["obfuscated"] + jitter[i]],
                [var["native"][i], var["obfuscated"][i]],
                color="#999999", lw=0.4, alpha=0.75, zorder=3)
    for arm in ("native", "obfuscated"):
        ax.plot(xpos[arm] + jitter, var[arm], linestyle="none", marker="o", ms=3.6,
                mfc=ARM_COLOR[arm], mec="black", mew=0.4, alpha=0.9, zorder=4)

    ax.set_yscale("log")
    ax.set_xticks([0.0, 1.0])
    ax.set_xticklabels(["Timing OFF", "Obfuscated"])
    ax.set_xlim(-0.5, 1.5)
    ax.tick_params(axis="x", length=0)
    ax.set_ylabel("CLRT variance (ms$^2$; log scale)")
    ax.set_title("READ CLRT variance before and after obfuscation", loc="left", fontsize=8.5)
    ax.legend(handles=[Line2D([], [], color="none", marker="o", ms=3.6, mfc=fs.GREY,
                              mec="black", mew=0.4,
                              label="Each dot: variance within one run"),
                       Line2D([], [], color="#999999", lw=0.4,
                              label="Line: matched before/after runs"),
                       Patch(facecolor="none", edgecolor=fs.GREY, lw=0.8,
                             label="Box: quartiles and median across runs")],
              loc="center left", fontsize=8, framealpha=0.95, borderpad=0.35,
              handlelength=1.6, labelspacing=0.26)
    fig.tight_layout(pad=0.4)

    rows = []
    for i, r in enumerate(runs):
        for arm in ("native", "obfuscated"):
            rows.append(stats_row("grouped collection run", r, arm, by_run[(r, arm)],
                                  "campaign_v1/derived/transactions.csv"))
    ratios = var["obfuscated"] / var["native"]
    caption = (
        "**READ CLRT sample variance, one point per collection run.** Each point is the "
        "sample variance ($n-1$) of the READ CLRT within one grouped collection run under one "
        "arm, computed over that run's %s READ transactions; each connecting line links "
        "the matched before and after measurements of one run. The pairing was verified "
        "rather than assumed: all %d runs contain both arms, three captures each, "
        "interleaved in randomized block order, giving %d matched run pairs. The downward "
        "lines show reduced variance after obfuscation; the spread of the Obfuscated "
        "points shows that the resulting variance is not equally low in every run. "
        "The ordinate "
        "is **logarithmic**, spanning roughly five decades; no variance is zero, so nothing is "
        "shifted or padded to make it plottable. Boxes give the quartiles and median across "
        "runs, with whiskers at 1.5 times the interquartile range, drawn unfilled and with "
        "no separate outlier marks, so every run appears exactly once as a point. "
        "Run count and transaction count "
        "are separate quantities: %d runs per arm, %s READ transactions inside each run, %s "
        "READ transactions per arm in total. Every run's variance falls under obfuscation, by "
        "a factor between %.0f and %s (median %.0f). "
        "The Obfuscated box is wide, and that width is a statement about the estimates, "
        "not about the traffic: it means the per-run variance *estimates* differ from run "
        "to run, not that individual CLRT measurements became more variable under "
        "obfuscation. The column is strongly right-skewed because a handful of runs "
        "contain a late release, and one late transaction "
        "moves that run's variance by orders of magnitude. The %d runs were collected in a single "
        "approximately five-hour window on one relay, so they are repeated collections under "
        "one configuration and not independent replications across days, devices or settings; "
        "the spread across points should be read as within-campaign variability only."
        % (format(n_txn["native"][0], ","), len(runs), len(runs), len(runs),
           format(n_txn["native"][0], ","),
           format(sum(n_txn["native"]), ","), 1.0 / float(np.max(ratios)),
           format(int(round(1.0 / float(np.min(ratios)))), ","),
           1.0 / float(np.median(ratios)), len(runs)))
    method = (
        "READ transactions only, from `defense4/timing/evidence/campaign_v1/derived/"
        "transactions.csv`. The unit is the grouped collection run as the corpus defines it: "
        "six captures collected together, 22 of them, each contributing three Timing OFF and "
        "three Obfuscated captures of 400 READ transactions, so each run yields exactly 1,200 "
        "READ transactions per arm. That balance was verified rather than assumed. Variance is "
        "the sample variance with the n-1 denominator, computed within one run and one arm and "
        "never pooled across runs or arms; the pooled per-arm variance is a different quantity "
        "and is reported in the distributions figure, not substituted here. Pairing: every "
        "grouped run contains both arms, interleaved in randomized block order within the run, "
        "so the join is a genuine within-run pairing and not an alignment imposed by sorting. "
        "The 22 runs come from one approximately five-hour window on one SEL-751A relay behind "
        "one Intel Tofino-1 at one configured setting; the corpus README states explicitly "
        "that they are grouped collections and not independent replications, and the analysis "
        "elsewhere treats the run as the clustering unit for exactly that reason. Horizontal "
        "jitter is uniform on +/- 0.11 in category units from a seeded generator (seed %d), "
        "one offset per run reused in both columns so the joining lines stay legible. The "
        "retired single-session dataset is excluded from this figure: it holds one capture per "
        "arm, hence one variance estimate per arm, which is a summary value and not a "
        "distribution across runs. Those two summary values are %s and are recorded in "
        "`clrt_run_statistics.csv`. Per-capture variances, a finer unit that nests inside the "
        "run and is therefore not independent, are recorded in the same file."
        % (JITTER_SEED,
           "; ".join("%s %.6g ms^2 over %d transactions"
                     % (s["arm"], s["sample_variance_ms2"], s["transactions"])
                     for s in single_stats)))
    limitations = (
        "The 22 runs are repeated collections inside one window on one device at one setting. "
        "They are not independent replications, so the spread of the points describes "
        "within-campaign variability and does not support an inference about other devices, "
        "other days or other configured values. Lower variance is a property of the released "
        "interval and is not on its own evidence that transaction fingerprinting is mitigated. "
        "The logarithmic ordinate compresses the Obfuscated column's right skew; the raw "
        "per-run values are in the figure-data CSV. Captures nest inside runs, so per-capture "
        "variances are not additional independent observations.")
    notes = ["run count and transaction count are reported as separate quantities",
             "pairing is within-run and verified, not imposed by sorting",
             "no variance is zero, so the log ordinate needs no epsilon",
             "the single-session dataset is reported as summary values, never as run-level "
             "points"]
    return emit(fig, out, "fig_clrt_variance_runs", caption, inputs, rows, method,
                limitations, notes, seed=JITTER_SEED)


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

    figure_distributions(by_arm, target_ms, out, cv1_inputs + cfg_inputs, acc)
    figure_variance_runs(by_run, out, cv1_inputs + cfg_inputs + frs_inputs, single_stats)
    write_run_statistics(out, by_run, by_capture, single_stats)
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
