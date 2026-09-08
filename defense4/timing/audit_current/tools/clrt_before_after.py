#!/usr/bin/env python3
"""Original versus resulting READ CLRT, and the sample variance of each.

Two panels, built from the verified transaction tables only:

  (a) the distribution of the master-observed interval C_observed = m_r - m_a for every READ
      transaction, one distribution per arm per corpus, drawn side by side;
  (b) the sample variance of those same distributions, n-1 denominator, one bar per group.

Panel (a) is deliberately NOT a paired per-transaction plot. The two arms are separate capture
blocks: a campaign_v1 session runs six blocks of 400 READ polls, three with the timing
mechanism disabled and three with it enabled, in randomized block order, so the k-th poll of a
Timing OFF block and the k-th poll of an Obfuscated block are different transactions taken at
different times. No per-transaction correspondence exists to plot against a shared transaction
number, so the distributions are shown side by side instead.

Neither the two corpora nor the two arms are ever pooled. campaign_v1 is the active authority
(22 grouped runs); final_read_sbo is the retired single-session dataset. Each corpus supplies
its own configured target C from its own configuration; no target and no result value is
written into this script.

    python3 clrt_before_after.py [OUT_DIR]      default: paper/rewrite/figures/clrt
    python3 clrt_before_after.py --check [OUT_DIR]

Raw captures and frozen CSVs are inputs and are never written.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
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

# The per-corpus configuration parsers, the sample-variance helper and the manifest writer are
# reused from the constant-shift tool rather than copied, so a corpus whose configured target
# changes cannot end up with two different answers in two figures.
import shift_vs_normalization as svn                                         # noqa: E402

PNG_DPI = 300                  # requested raster resolution; the NDSS pipeline default is 600
DEFAULT_OUT = fs.REPO_ROOT / "paper" / "rewrite" / "figures" / "clrt"
STEM = "fig_clrt_before_after"
ROLLUP = CV1 / "DATASET_ROLLUP.json"
# Used only to COUNT how far the obfuscated tail reaches, never to exclude anything. Half the
# smallest configured step in the policy sweep, the same threshold the constant-shift tool
# reports tolerance coverage against.
OFF_TARGET_MS = svn.PRIMARY_TOL_MS


# ------------------------------------------------------------------ data loading

def load_campaign_v1():
    """READ CLRT per arm, with a full accounting of every row in the canonical table."""
    path = CV1 / "derived" / "transactions.csv"
    vals = {"native": [], "obfuscated": []}
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
            vals[r["arm"]].append(x)
    roll = json.loads(ROLLUP.read_text())
    acc["dataset_rollup_anomalies"] = int(roll["anomalies_count"])
    acc["dataset_rollup_incomplete_sessions"] = len(roll["incomplete_sessions"])
    acc["excluded_from_plot"] = acc["non_finite"] + acc["non_positive"]
    return vals, acc, [path, ROLLUP]


def load_final_read_sbo():
    """READ CLRT per arm from the retired tree, excluding its cold-start rows.

    All three transaction tables are read, the control-lane one included, so the rows that do
    not enter this figure are counted rather than passed over in silence.
    """
    d = FRS / "derived_csv"
    files = (("native_txn.csv", "native"), ("defended_read_txn.csv", "obfuscated"),
             ("defended_txn.csv", "obfuscated"))
    vals = {"native": [], "obfuscated": []}
    acc = {"rows": 0, "read_rows": 0, "non_read_rows": 0, "cold_start_read": 0,
           "non_finite": 0, "non_positive": 0, "per_file": {}}
    inputs = []
    for name, arm in files:
        p = d / name
        inputs.append(p)
        f_rows = f_read = f_cold = 0
        with open(p) as fh:
            for r in csv.DictReader(fh):
                acc["rows"] += 1
                f_rows += 1
                if r["req_func"] != "1":               # 1 = READ, 3 = SELECT (control lane)
                    acc["non_read_rows"] += 1
                    continue
                acc["read_rows"] += 1
                f_read += 1
                if r["cold"] == "1":                   # cold-start rows carry cold=1
                    acc["cold_start_read"] += 1
                    f_cold += 1
                    continue
                x = float(r["clrt_ms"])
                if not np.isfinite(x):
                    acc["non_finite"] += 1
                    continue
                if x <= 0:
                    acc["non_positive"] += 1
                    continue
                vals[arm].append(x)
        acc["per_file"][name] = {"rows": f_rows, "read_rows": f_read,
                                 "cold_start_read_excluded": f_cold}
    acc["excluded_from_plot"] = (acc["cold_start_read"] + acc["non_finite"]
                                 + acc["non_positive"])
    return vals, acc, inputs


# ------------------------------------------------------------------ groups and statistics

def build_groups():
    """The four plotted groups in plot order, each carrying its own configured target."""
    cv1, cv1_acc, cv1_inputs = load_campaign_v1()
    c_cv1, _, cfg_cv1 = svn._targets_campaign_v1()
    frs, frs_acc, frs_inputs = load_final_read_sbo()
    c_frs, _, cfg_frs = svn._targets_final_read_sbo()

    corpora = [("campaign_v1", "campaign_v1\n22 grouped runs", cv1, c_cv1, cv1_acc,
                cv1_inputs + cfg_cv1),
               ("final_read_sbo", "final_read_sbo\nretired, 1 session", frs, c_frs, frs_acc,
                frs_inputs + cfg_frs)]
    groups, inputs = [], []
    for corpus, corpus_label, vals, c, acc, ins in corpora:
        inputs.extend(ins)
        for arm in ("native", "obfuscated"):
            v = np.sort(np.asarray(vals[arm], dtype=float))
            if v.size < 2:
                raise SystemExit("%s/%s: %d samples, a sample variance needs at least two"
                                 % (corpus, arm, v.size))
            groups.append(dict(corpus=corpus, corpus_label=corpus_label, arm=arm,
                               label=fs.LBL[arm], values=v, target_c_ms=c, accounting=acc))
    return groups, inputs


def summarize(g):
    """Sample statistics for one plotted group. Sample variance uses the n-1 denominator."""
    v = g["values"]
    var = float(svn.var_s(list(v)))
    return dict(corpus=g["corpus"], arm=g["label"], operation="READ",
                configured_target_C_ms=g["target_c_ms"],
                n=int(v.size),
                mean_ms=round(float(np.mean(v)), 6),
                sample_variance_ms2=round(var, 9),
                sample_sd_ms=round(float(np.sqrt(var)), 6),
                median_ms=round(float(np.median(v)), 6),
                q1_ms=round(float(np.percentile(v, 25)), 6),
                q3_ms=round(float(np.percentile(v, 75)), 6),
                min_ms=round(float(np.min(v)), 6),
                max_ms=round(float(np.max(v)), 6),
                n_farther_than_tol_from_C=int(np.count_nonzero(
                    np.abs(v - g["target_c_ms"]) > OFF_TARGET_MS)),
                tol_ms=OFF_TARGET_MS,
                n_excluded_from_this_corpus=g["accounting"]["excluded_from_plot"])


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


def emit(fig, out, stem, caption, inputs, rows, method_note, limitation_note, notes):
    """Write the figure and its sidecars.

    Deliberately not `figstyle_ndss.save`: that function pins the PNG at 600 dpi, and this
    figure was asked for at 300. Everything else it guarantees is kept, the minimum-type check
    included, so the artefact set matches the rest of the manuscript's figures.
    """
    problems = []
    fs.check_min_font(fig, stem, problems)
    if problems:
        raise SystemExit("figure style violation:\n  " + "\n  ".join(problems))

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    pdf, png, data = out / (stem + ".pdf"), out / (stem + ".png"), out / (stem + "_data.csv")
    meta = {"CreationDate": None, "Producer": None, "Creator": None}
    fig.savefig(pdf, facecolor="white", transparent=False, metadata=meta)
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
                                                      for a in sys.argv])
                               if script else None),
        "source_commit": _git_commit(),
        "deterministic_seed": None,
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
                    "note": ("raster preview; byte-identity is not guaranteed across "
                             "interpreter builds and is not gated")},
            "data_csv": {"path": _rel(data), "sha256": fs.sha256_file(data),
                         "rows": len(rows), "authoritative": True},
        },
        "figure_dimensions_in": {"width": w_in, "height": h_in},
        "method_note": method_note,
        "limitation_note": limitation_note,
        "notes": notes,
        "style": ("NDSS 7.16 in text block, Times-compatible serif, minimum %g pt at printed "
                  "size, Okabe-Ito palette, hatch and line style vary with colour so the "
                  "figure reads in greyscale, pdf.fonttype 42 (no Type 3), opaque white "
                  "background" % fs.MIN_PT),
    }
    (out / (stem + ".provenance.json")).write_text(json.dumps(prov, indent=1) + "\n")
    print("  %-26s %5.2f x %4.2f in  pdf %s  png %s (%d dpi)  data %d rows"
          % (stem, w_in, h_in, prov["outputs"]["pdf"]["sha256"][:12],
             prov["outputs"]["png"]["sha256"][:12], PNG_DPI, len(rows)))
    return pdf


# ------------------------------------------------------------------ the figure

XPOS = [0.0, 1.0, 2.6, 3.6]        # two groups per corpus, a wider gap between corpora
XTICKS_MS = [1, 2, 4, 8, 16, 32, 64]
# Corpus is carried by line style so the two arms keep one colour each across both panels.
LS_CORPUS = {"campaign_v1": "-", "final_read_sbo": (0, (3, 1.4))}


def _decorate_categorical(ax, groups):
    """One label per corpus, centred under its pair of arms.

    The arms themselves are identified by colour, hatch and the legend. Naming the corpus under
    every group instead put two long identical names side by side, and they overlapped.
    """
    ax.set_xticks([(XPOS[0] + XPOS[1]) / 2.0, (XPOS[2] + XPOS[3]) / 2.0])
    ax.set_xticklabels([groups[0]["corpus_label"], groups[2]["corpus_label"]])
    ax.set_xlim(XPOS[0] - 0.7, XPOS[-1] + 0.7)
    ax.tick_params(axis="x", length=0)


def panel_distributions(ax, groups):
    """Empirical cumulative distributions of the measured interval, logarithmic abscissa.

    An ECDF rather than a violin or a box. The two arms differ in spread by roughly four
    orders of magnitude in variance, so on any shared CLRT axis a width-based summary renders
    the Obfuscated arm as a flat line and shows nothing about its shape. In an ECDF the spread
    is carried by the steepness of the curve instead of by a width that has to be resolved, so
    both distributions are drawn in full on the same axes: every sample contributes a step, and
    nothing is binned, smoothed or clipped.
    """
    for g in groups:
        x, y = svn.ecdf(g["values"])
        ax.step(x, y, where="post",
                color=(fs.OFF if g["arm"] == "native" else fs.ON),
                ls=LS_CORPUS[g["corpus"]], lw=1.1, zorder=4,
                label="%s, %s (n = %s)" % (g["label"], g["corpus"], format(x.size, ",")))
    # The configured target, per corpus, from that corpus's own configuration. Both corpora
    # happen to configure 4 ms, so one line is drawn and the legend says it covers both.
    for c in sorted({g["target_c_ms"] for g in groups}):
        ax.axvline(c, color=fs.GREY, ls=(0, (4, 2)), lw=0.9, zorder=2)
    ax.set_xscale("log")
    ax.set_xlim(0.9, 110.0)
    ax.set_xticks(XTICKS_MS)
    ax.set_xticklabels([("%g" % t) for t in XTICKS_MS])
    ax.set_xlabel("CLRT $C_{\\rm obs}=m_r-m_a$ (ms, log scale)")
    ax.set_ylim(-0.02, 1.02)
    ax.set_yticks([0.0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("Cumulative fraction of transactions")
    ax.set_title("(a) measured CLRT distribution, READ", loc="left")
    handles, labels = ax.get_legend_handles_labels()
    handles.append(Line2D([], [], color=fs.GREY, ls=(0, (4, 2)), lw=0.9))
    labels.append("configured target $C$ = %g ms" % groups[0]["target_c_ms"])
    ax.legend(handles, labels, loc="upper left", fontsize=8, framealpha=0.95,
              borderpad=0.35, handlelength=2.0, labelspacing=0.28)
    _obfuscated_inset(ax, groups)


def _obfuscated_inset(ax, groups):
    """A linear zoom on the two Obfuscated curves, in microseconds either side of C.

    The main abscissa must span the full Timing OFF support, across which both Obfuscated
    curves rise within a hair of the target and read as one vertical step. The inset resolves
    that step. It sits in the lower right, where the ECDF axes are empty because every curve
    has already reached one. Samples outside the window are counted in the inset title, not
    dropped: the curve they belong to is drawn in full in the main axes.
    """
    win_us = 120.0
    ins = ax.inset_axes([0.575, 0.115, 0.395, 0.335])
    outside = 0
    for g in (groups[1], groups[3]):
        dev_us = (g["values"] - g["target_c_ms"]) * 1e3
        outside += int(np.count_nonzero(np.abs(dev_us) > win_us))
        x, y = svn.ecdf(dev_us)
        ins.step(x, y, where="post", color=fs.ON, ls=LS_CORPUS[g["corpus"]], lw=1.0, zorder=4)
    ins.axvline(0.0, color=fs.GREY, ls=(0, (4, 2)), lw=0.8, zorder=2)
    ins.set_xlim(-win_us, win_us)
    ins.set_xticks([-100, 0, 100])
    ins.set_ylim(-0.04, 1.04)
    ins.set_yticks([0.0, 0.5, 1.0])
    ins.tick_params(axis="both", labelsize=8, length=2, pad=1.5)
    ins.set_xlabel("$\\mu$s from $C$", fontsize=8, labelpad=1.0)
    ins.set_title("Obfuscated, zoom (%d of %s outside)"
                  % (outside, format(groups[1]["values"].size + groups[3]["values"].size, ",")),
                  fontsize=8, pad=2.5)
    fs.grid(ins)


def panel_variance(ax, groups, stats):
    """Sample variance of the same four distributions, n-1 denominator, on its own axis."""
    for x, g, s in zip(XPOS, groups, stats):
        col = fs.OFF if g["arm"] == "native" else fs.ON
        ax.bar([x], [s["sample_variance_ms2"]], width=0.78, color=col, edgecolor="black",
               lw=0.5, hatch=fs.HATCH[g["arm"]], alpha=0.80, zorder=3)
        ax.annotate("%.3g\nn = %s" % (s["sample_variance_ms2"], format(s["n"], ",")),
                    xy=(x, s["sample_variance_ms2"]), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8,
                    linespacing=1.25)
    ax.set_yscale("log")
    ax.set_ylabel("Sample variance of CLRT (ms$^2$), $n-1$")
    ax.set_title("(b) sample variance, per corpus and arm", loc="left")
    _decorate_categorical(ax, groups)
    lo = min(s["sample_variance_ms2"] for s in stats)
    hi = max(s["sample_variance_ms2"] for s in stats)
    ax.set_ylim(lo / 8.0, hi * 60.0)          # headroom for the two-line bar annotations
    # The ratio is formed within a corpus only; the two corpora are never pooled.
    for i in (0, 2):
        rho = stats[i + 1]["sample_variance_ms2"] / stats[i]["sample_variance_ms2"]
        ax.annotate("variance ratio %.3g" % rho, xy=((XPOS[i] + XPOS[i + 1]) / 2.0, 0.93),
                    xycoords=("data", "axes fraction"), ha="center", va="top", fontsize=8)


def make_figure(groups, stats, out, inputs, accounting):
    fs.use()
    fig, (a, b) = plt.subplots(1, 2, figsize=(fs.PAGE_W, 3.35))
    panel_distributions(a, groups)
    panel_variance(b, groups, stats)
    fs.grid([a, b])
    fig.tight_layout(pad=0.4, w_pad=1.6)
    cv1 = groups[0]["accounting"]
    frs = groups[2]["accounting"]
    caption = (
        "**Measured cross-layer response time for READ, with the timing mechanism disabled "
        "and enabled.** CLRT is the master-facing interval $C_{\\rm obs}=m_r-m_a$ between the "
        "acknowledgment and the application response at the master host NIC. (a) Empirical "
        "cumulative distribution of every READ transaction in each arm: colour separates the "
        "arms, line style separates the corpora, and each sample contributes one step, so "
        "nothing is binned, smoothed or clipped and the full support including the far tail is "
        "on the axes. The arms are separate capture blocks rather than repeated measurements "
        "of the same transaction, so there is no per-transaction correspondence to plot "
        "against a shared transaction number and the arms are compared as distributions. "
        "Because the two arms differ by roughly four orders of magnitude in variance, both "
        "Obfuscated curves read as one vertical step at this scale; the inset resolves them on "
        "a linear axis in microseconds either side of $C$. The dashed vertical line is the "
        "*configured* target $C$, read from each corpus's own configuration and not a measured "
        "value; both corpora configure 4 ms. (b) The sample variance of those same "
        "distributions, $n-1$ denominator, on its own axis, with the within-corpus ratio above "
        "each pair. Variance is never drawn on the CLRT axis, and the spread quoted around a "
        "mean is a standard deviation. In campaign_v1 the READ interval moves from a median of "
        "%.3f ms and a standard deviation of %.3f ms to a median of %.3f ms and a standard "
        "deviation of %.3f ms, a variance ratio of %.4f. Corpora and arms are never pooled. "
        "Sample counts are annotated in both panels. "
        "Nothing was excluded from campaign_v1, whose %s READ transactions all enter the "
        "figure; final_read_sbo excludes its %d cold-start rows and nothing else. Every "
        "completed transaction is included, the late ones among them: %d Obfuscated "
        "campaign_v1 transactions land farther than %g ms from $C$, the farthest at %.1f ms, "
        "and they are plotted rather than trimmed. Reduced variance is a property of the "
        "released interval and is not on its own evidence that transaction fingerprinting is "
        "mitigated."
        % (stats[0]["median_ms"], stats[0]["sample_sd_ms"], stats[1]["median_ms"],
           stats[1]["sample_sd_ms"],
           stats[1]["sample_variance_ms2"] / stats[0]["sample_variance_ms2"],
           format(cv1["read_rows"], ","), frs["cold_start_read"],
           stats[1]["n_farther_than_tol_from_C"], stats[1]["tol_ms"], stats[1]["max_ms"]))
    method = (
        "READ transactions only, from the frozen per-transaction tables. CLRT is "
        "clrt_ms = (t_resp - t_ack) * 1e3, the master-facing interval m_r - m_a, exactly as "
        "the extractor computes it; t_ack is the first payload-free outstation-to-master frame "
        "after the request and t_resp the response data frame. Panel (a) is an empirical "
        "cumulative distribution on a logarithmic abscissa, so the full support is on the "
        "axes without clipping. "
        "The samples are sorted and the k-th of n is plotted at k/n as a "
        "post-step, so there is no binning, no kernel, no bandwidth choice and no smoothing, "
        "and every observation including the extreme tail appears on the axes. An ECDF was "
        "chosen over a histogram, box or violin because the two arms differ by about four "
        "orders of magnitude in variance: a width-based summary renders the Obfuscated arm as "
        "a flat line on any shared CLRT axis, whereas an ECDF carries spread in the steepness "
        "of the curve. The inset applies the same construction to the Obfuscated deviation "
        "from C in microseconds. Every number in the figure-data CSV is computed from the raw "
        "millisecond samples: mean, median, quartiles, full range, sample variance and sample "
        "standard deviation. Sample variance uses the n-1 denominator and is reported in ms^2, "
        "standard deviation in ms. No pooling across corpora or arms, no resampling, no "
        "smoothing of the plotted statistics. The variance ratio annotated in panel (b) is "
        "formed within a corpus only; its confidence interval is not computed here, and the "
        "session-clustered bootstrap for campaign_v1 is in the constant-shift analysis.")
    limitations = (
        "Lower variance in the released interval does not by itself establish that transaction "
        "fingerprinting is mitigated: that claim rests on the classifier and mutual-information "
        "results, not on this figure. The two arms are separate capture blocks, so nothing here "
        "is a paired per-transaction effect and no transfer function between the arms can be "
        "read off it. All intervals are master-facing; the relay-facing release instants and "
        "the realized per-transaction jitter were not observed. final_read_sbo is a retired "
        "single-session dataset shown as a separate condition, never merged with campaign_v1. "
        "Nothing here concerns physical operation time or message size.")
    notes = [
        "READ only; SELECT and OPERATE are excluded by design and counted in the accounting.",
        "the configured target C is read per corpus from that corpus's configuration and is "
        "distinct from the measured interval",
        "cold-start rows in the retired corpus are excluded and counted; campaign_v1 excludes "
        "nothing",
        "sample variance, n-1 denominator; variance is never plotted on the CLRT axis",
    ]
    rows = [dict(s) for s in stats]
    pdf = emit(fig, out, STEM, caption, inputs, rows, method, limitations, notes)
    (Path(out) / "CLRT_BEFORE_AFTER.json").write_text(
        json.dumps({"groups": stats, "accounting": accounting}, indent=1) + "\n")
    return pdf


# ------------------------------------------------------------------ entry point

def main(argv):
    if len(argv) > 1 and argv[1] == "--check":
        out = argv[2] if len(argv) > 2 else str(DEFAULT_OUT)
        problems = svn.check_manifest(out)
        print("CLRT figure manifest: %d problems" % len(problems))
        for p in problems:
            print("  PROBLEM:", p)
        if not problems:
            print("  every generated artefact matches FIGURES.sha256")
        return 1 if problems else 0

    out = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    out.mkdir(parents=True, exist_ok=True)
    groups, inputs = build_groups()
    stats = [summarize(g) for g in groups]
    accounting = {"campaign_v1": groups[0]["accounting"],
                  "final_read_sbo": groups[2]["accounting"]}

    print("row accounting")
    for corpus, acc in accounting.items():
        print("  %-15s rows=%d READ=%d non-READ=%d excluded=%d"
              % (corpus, acc["rows"], acc["read_rows"], acc["non_read_rows"],
                 acc["excluded_from_plot"]))
        for k in ("cold_start_read", "non_finite", "non_positive",
                  "dataset_rollup_anomalies", "dataset_rollup_incomplete_sessions"):
            if k in acc:
                print("      %-34s %d" % (k, acc[k]))
    print()
    make_figure(groups, stats, out, inputs, accounting)
    svn.write_manifest(str(out))
    print()
    print("%-15s %-12s %8s %9s %9s %11s %9s %9s"
          % ("corpus", "arm", "n", "median", "mean", "variance", "sd", "max"))
    for s in stats:
        print("%-15s %-12s %8s %9.4f %9.4f %11.6f %9.4f %9.3f"
              % (s["corpus"], s["arm"], format(s["n"], ","), s["median_ms"], s["mean_ms"],
                 s["sample_variance_ms2"], s["sample_sd_ms"], s["max_ms"]))
    print()
    for i in (0, 2):
        print("%-15s variance ratio obfuscated/OFF = %.6f   (n=%s vs %s, target C=%g ms)"
              % (stats[i]["corpus"],
                 stats[i + 1]["sample_variance_ms2"] / stats[i]["sample_variance_ms2"],
                 format(stats[i + 1]["n"], ","), format(stats[i]["n"], ","),
                 stats[i]["configured_target_C_ms"]))
    for s in stats:
        if s["n_farther_than_tol_from_C"]:
            print("%-15s %-12s %d of %s transactions lie farther than %g ms from C "
                  "(included, not excluded)"
                  % (s["corpus"], s["arm"], s["n_farther_than_tol_from_C"],
                     format(s["n"], ","), s["tol_ms"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
