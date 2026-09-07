#!/usr/bin/env python3
"""Constant shift versus CLRT normalization, from verified transaction data.

Four things are computed and plotted, per operation and per corpus, and the two corpora are
never pooled:

  1. the measured native interval, an **analytical** constant-shift reference built from those
     same native samples, the measured defended interval, and the configured target C;
  2. the same distributions with their own sample mean removed, which changes neither sample
     variance nor shape and so isolates variability from location;
  3. the sample-variance ratio rho = var(defended)/var(native), n-1 denominator, with a
     cluster bootstrap over sessions where sessions exist;
  4. the target error, CLRT - C, with its offset, spread, RMSE, tails and tolerance coverage.

The analytical reference is

    X_shift = X_native + (C - median(X_native))

which aligns its median with C while preserving its variance and shape exactly. **It is not an
implemented hardware condition** and is not evidence that such a shift is realizable on this
switch: the loaded binary has no shifting mode at all
(`audit_current/SHIFT_VS_REPLACEMENT.md` §3).

    python3 shift_vs_normalization.py [OUT_DIR]        default: ../../figures/shift

Raw captures and frozen CSVs are inputs and are never written.
"""
from __future__ import annotations

import csv
import glob
import json
import os
import random
import statistics
import sys
from hashlib import sha256 as _sha256
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]
CV1 = TIMING / "evidence" / "campaign_v1"
FRS = TIMING / "evidence" / "final_read_sbo"
REPRO = CV1 / "repro"
sys.path.insert(0, str(REPRO))

import figstyle_ndss as fs                                                   # noqa: E402
import numpy as np                                                           # noqa: E402
import matplotlib.pyplot as plt                                              # noqa: E402

SEED = 20260907
# Configured target for the released interval, ms. Read lane: D_R. Control lane: R - A.
# Each corpus supplies its own target from its own documented configuration. The two happen to
# coincide at 4 ms, which is exactly why they must not be shared: taking the active campaign's
# policy and applying it to the retired dataset would look correct today and would silently
# mis-score the retired figures the moment either configuration changed.
CV1_POLICY_PATH = REPRO / "policy_config.json"
CV1_CONST_PATH = CV1 / "PROVENANCE_CONSTANTS.json"
FRS_MANIFEST_PATH = FRS / "CAPTURE_MANIFEST.csv"


def _targets_campaign_v1():
    """Read lane: D_R, the gap between the two deadlines armed from the one anchor.
    Control lane: the master-visible observable R - A."""
    pol = json.loads(CV1_POLICY_PATH.read_text())
    obf = json.loads(CV1_CONST_PATH.read_text())["config"]["obfuscated_arm"]
    c_read = float(pol["D_R_ms"])
    if abs(c_read - float(pol["scheduled_release_interval_ms"])) > 1e-9:
        raise SystemExit("campaign_v1: D_R_ms and scheduled_release_interval_ms disagree")
    return c_read, float(obf["R_ms"]) - float(obf["A_ms"]), [CV1_POLICY_PATH, CV1_CONST_PATH]


def _targets_final_read_sbo():
    """From the retired tree's own per-capture manifest, whose D_A/D_R/A/R fields carry their
    evidence string and status. Parsed from the first defended read-lane row."""
    import re as _re
    with open(FRS_MANIFEST_PATH) as fh:
        for row in csv.DictReader(fh):
            if row.get("condition_native_or_defended") != "defended":
                continue
            d_r = _re.match(r"\s*([0-9.]+)", row.get("D_R_ms", "") or "")
            a = _re.match(r"\s*([0-9.]+)", row.get("A_ms", "") or "")
            r = _re.match(r"\s*([0-9.]+)", row.get("R_ms", "") or "")
            if d_r and a and r:
                return float(d_r.group(1)), float(r.group(1)) - float(a.group(1)), \
                    [FRS_MANIFEST_PATH]
    raise SystemExit("final_read_sbo: no defended row carries D_R/A/R in CAPTURE_MANIFEST.csv")
# Tolerances, justified independently of the measured errors:
#   0.000256 ms is the deadline quantization grid, the finest placement the mechanism can make.
#   0.5 ms is half the smallest configured step in the policy sweep (D_R moves in 1 ms steps),
#   so it is the largest error that cannot be confused with a neighbouring policy setting.
TICK_GRID_MS = 256e-6
TOLERANCES_MS = (0.05, 0.5, 1.0)
PRIMARY_TOL_MS = 0.5
BOOT = 2000


# ------------------------------------------------------------------ data loading

def load_campaign_v1():
    """Per operation: native and defended CLRT, each tagged with its grouped run."""
    path = CV1 / "derived" / "transactions.csv"
    out = {c: {"native": [], "defended": []} for c in ("READ", "SELECT", "OPERATE")}
    with open(path) as fh:
        for r in csv.DictReader(fh):
            arm = "native" if r["arm"] == "native" else "defended"
            out[r["txn_class"]][arm].append((r["session"], float(r["clrt_ms"])))
    return out, [path]


def load_final_read_sbo():
    """The retired six-capture dataset. One session, so no session structure exists."""
    d = FRS / "derived_csv"
    out = {c: {"native": [], "defended": []} for c in ("READ", "SELECT", "OPERATE")}
    inputs = []
    for name, arm in (("native_txn", "native"), ("defended_read_txn", "defended"),
                      ("defended_txn", "defended")):
        p = d / (name + ".csv")
        inputs.append(p)
        with open(p) as fh:
            for r in csv.DictReader(fh):
                if r["cold"] == "1":
                    continue                      # cold-start rows carry cold=1 and are excluded
                cls = "READ" if r["req_func"] == "1" else "SELECT"
                out[cls][arm].append(("s1", float(r["clrt_ms"])))
    # OPERATE: response-to-acknowledgment interval, per configured J. Defended only; the
    # retired tree has no Timing OFF OPERATE arm, so no ratio can be formed for it.
    per_j = {}
    for j in (2, 6, 12):
        p = d / ("sbo_j%d.csv" % j)
        inputs.append(p)
        with open(p) as fh:
            per_j["J=%d ms" % j] = [float(r["echo_ack_ms"]) for r in csv.DictReader(fh)]
    return out, per_j, inputs


def load_campaign_v1_operate_by_j():
    """campaign_v1 records the codebook, not the realized draw, so J cannot be resolved."""
    return None


# ------------------------------------------------------------------ statistics

def sha256_file(path):
    h = _sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_entries(out):
    """The generated artefacts this manifest covers, as (name, sha256), sorted.

    Covered: the vector PDFs, the figure-data CSVs and the summary JSON, which are the
    artefacts a reader would check. Deliberately NOT covered: the `.provenance.json` sidecars,
    whose `source_commit` field changes with every commit by design, so hashing them would put
    the manifest permanently one commit behind; and the `.png` previews, which are not
    byte-reproducible across interpreter builds (`REPRODUCIBILITY_SCOPE.md`). Raw captures have
    their own DATASET.sha256 manifests and are not duplicated here.
    """
    names = [n for n in sorted(os.listdir(out))
             if (n.endswith(".pdf") or n.endswith("_data.csv")
                 or (n.endswith(".json") and not n.endswith(".provenance.json")))]
    return [(n, sha256_file(os.path.join(out, n))) for n in names]


def write_manifest(out):
    """Write FIGURES.sha256 from the same run that produced the artefacts.

    An earlier version was generated once by hand and then not updated when the data CSVs and
    the summary JSON changed, leaving three entries failing. Writing it here makes that
    impossible: the manifest cannot be older than the files it describes.
    """
    entries = manifest_entries(out)
    with open(os.path.join(out, "FIGURES.sha256"), "w") as fh:
        fh.write("\n".join("%s  %s" % (h, n) for n, h in entries) + "\n")
    print("wrote %s/FIGURES.sha256  (%d generated artefacts)" % (out, len(entries)))
    return entries


def check_manifest(out):
    """Verify FIGURES.sha256 against the files on disk. Returns a list of problems."""
    path = os.path.join(out, "FIGURES.sha256")
    if not os.path.exists(path):
        return ["FIGURES.sha256 is missing"]
    recorded = {}
    for line in open(path):
        line = line.strip()
        if line:
            h, n = line.split("  ", 1)
            recorded[n] = h
    actual = dict((n, h) for n, h in manifest_entries(out))
    problems = []
    for n in sorted(set(recorded) | set(actual)):
        if n not in recorded:
            problems.append("%s is a generated artefact but is not listed in FIGURES.sha256" % n)
        elif n not in actual:
            problems.append("%s is listed in FIGURES.sha256 but is not on disk" % n)
        elif recorded[n] != actual[n]:
            problems.append("%s: recorded %s, on disk %s"
                            % (n, recorded[n][:12], actual[n][:12]))
    return problems


def var_s(v):
    """Sample variance, n-1 denominator."""
    return statistics.variance(v) if len(v) > 1 else float("nan")


def ecdf(v):
    x = np.sort(np.asarray(v, dtype=float))
    return x, np.arange(1, x.size + 1) / x.size


def analytical_shift(native, c):
    """X_shift = X_native + (C - median(X_native)). Variance and shape preserved exactly."""
    a = np.asarray(native, dtype=float)
    return a + (c - float(np.median(a)))


def cluster_bootstrap_ratio(pairs_nat, pairs_def, rng, n_boot=BOOT):
    """Percentile CI for var(def)/var(nat), resampling whole sessions with replacement.

    Sessions are the sampling unit, so within-session dependence is preserved. Each bootstrap
    replicate recomputes both variances from the pooled transactions of the resampled sessions.
    Returns (lo, hi, n_sessions, n_valid_replicates). No bound is imposed on the interval.
    """
    by_s_nat, by_s_def = {}, {}
    for s, x in pairs_nat:
        by_s_nat.setdefault(s, []).append(x)
    for s, x in pairs_def:
        by_s_def.setdefault(s, []).append(x)
    sessions = sorted(set(by_s_nat) & set(by_s_def))
    if len(sessions) < 3:
        return None, None, len(sessions), 0
    reps = []
    for _ in range(n_boot):
        pick = [sessions[rng.randrange(len(sessions))] for _ in sessions]
        nat = [x for s in pick for x in by_s_nat[s]]
        dfd = [x for s in pick for x in by_s_def[s]]
        vn, vd = var_s(nat), var_s(dfd)
        if vn and vn > 0 and not np.isnan(vd):
            reps.append(vd / vn)
    if len(reps) < n_boot // 2:
        return None, None, len(sessions), len(reps)
    reps.sort()
    return reps[int(0.025 * len(reps))], reps[int(0.975 * len(reps))], len(sessions), len(reps)


def per_session_ratios(pairs_nat, pairs_def):
    by_s_nat, by_s_def = {}, {}
    for s, x in pairs_nat:
        by_s_nat.setdefault(s, []).append(x)
    for s, x in pairs_def:
        by_s_def.setdefault(s, []).append(x)
    out = {}
    for s in sorted(set(by_s_nat) & set(by_s_def)):
        vn, vd = var_s(by_s_nat[s]), var_s(by_s_def[s])
        if vn and vn > 0:
            out[s] = vd / vn
    return out


def target_error_stats(defended, c, tolerances=TOLERANCES_MS):
    e = np.asarray(defended, dtype=float) - c
    a = np.abs(e)
    q = lambda p: float(np.quantile(e, p))
    return dict(
        n=int(e.size), target_ms=c,
        mean_error_ms=float(e.mean()), median_error_ms=float(np.median(e)),
        error_sd_ms=float(e.std(ddof=1)) if e.size > 1 else float("nan"),
        rmse_ms=float(np.sqrt(float((e ** 2).mean()))),
        p001=q(0.001), p01=q(0.01), p50=q(0.5), p99=q(0.99), p999=q(0.999),
        min_error_ms=float(e.min()), max_error_ms=float(e.max()),
        max_abs_error_ms=float(a.max()),
        within={("%.3f" % t): int((a <= t).sum()) for t in tolerances},
        within_fraction={("%.3f" % t): float((a <= t).mean()) for t in tolerances},
        quantization_grid_ms=TICK_GRID_MS,
    )


# ------------------------------------------------------------------ figure 1

def fig_distributions(corpus_name, data, c_read, out, inputs, rows_out):
    """Per operation: full-range ECDF with a zoom, and the centered ECDF beside it."""
    classes = [k for k in ("READ", "SELECT") if data[k]["native"] and data[k]["defended"]]
    fs.use()
    fig, ax = plt.subplots(len(classes), 2, figsize=(fs.PAGE_W, 2.05 * len(classes)),
                           squeeze=False)
    rng = None
    for i, cls in enumerate(classes):
        nat = [x for _, x in data[cls]["native"]]
        dfd = [x for _, x in data[cls]["defended"]]
        shf = analytical_shift(nat, c_read)

        # ---- (left) full-range ECDF, log abscissa so the whole support is readable
        a = ax[i][0]
        for v, lab, col, ls in ((nat, "Measured native", fs.OFF, "-"),
                                (shf, "Analytical constant shift", fs.GREY, (0, (4, 2))),
                                (dfd, "Measured defended", fs.ON, "-")):
            x, y = ecdf(v)
            a.step(x, y, where="post", color=col, ls=ls, lw=1.1, label=lab, zorder=3)
        # C is marked by the dotted line here and labelled inside the zoom, where there is
        # room; repeating it in the main panel collided with the inset's tick labels.
        a.axvline(c_read, color=fs.C_OPERATE, ls=":", lw=1.0, zorder=2)
        a.set_xscale("log")
        lo = min(min(nat), min(shf), min(dfd)) * 0.8
        hi = max(max(nat), max(shf), max(dfd)) * 1.25
        a.set_xlim(max(lo, 1e-3), hi)
        a.set_ylim(0, 1.02)
        a.set_ylabel("%s\nECDF" % cls)
        fs.grid(a)
        if i == 0:
            a.legend(loc="upper left", frameon=False, fontsize=8, handlelength=1.8)
        if i == len(classes) - 1:
            a.set_xlabel("Observed interval (ms), log scale, full support")

        # ---- inset zoom on the defended concentration
        ins = a.inset_axes([0.56, 0.16, 0.41, 0.42])
        x, y = ecdf(dfd)
        ins.step(x, y, where="post", color=fs.ON, lw=1.0)
        ins.axvline(c_read, color=fs.C_OPERATE, ls=":", lw=0.9)
        ins.set_xlim(c_read - 0.12, c_read + 0.12)
        ins.set_ylim(0, 1.02)
        ins.tick_params(labelsize=8)
        ins.set_xticks([c_read - 0.1, c_read, c_read + 0.1])
        ins.set_title("defended, zoom on $C$=%g ms" % c_read, fontsize=8)
        fs.grid(ins)

        # ---- (right) centered ECDFs
        b = ax[i][1]
        cn = np.asarray(nat) - float(np.mean(nat))
        cd = np.asarray(dfd) - float(np.mean(dfd))
        for v, lab, col in ((cn, "Native, centered", fs.OFF), (cd, "Defended, centered", fs.ON)):
            x, y = ecdf(v)
            b.step(x, y, where="post", color=col, lw=1.1, label=lab, zorder=3)
        b.axvline(0.0, color="#999999", lw=0.7, zorder=2)
        b.set_xscale("symlog", linthresh=0.05)
        b.set_xticks([-10, -1, -0.1, 0, 0.1, 1, 10])
        b.set_xticklabels(["-10", "-1", "-0.1", "0", "0.1", "1", "10"])
        b.set_ylim(0, 1.02)
        fs.grid(b)
        if i == 0:
            b.legend(loc="upper left", frameon=False, fontsize=8, handlelength=1.8)
        if i == len(classes) - 1:
            b.set_xlabel("Deviation from own mean (ms), symlog, linear within $\\pm$0.05")
        b.set_ylabel("ECDF")

        for v, series in ((nat, "measured_native"), (shf, "analytical_constant_shift"),
                          (dfd, "measured_defended")):
            va = var_s(v)
            rows_out.append(dict(corpus=corpus_name, operation=cls, series=series,
                                 n=len(v), target_C_ms=c_read,
                                 median_ms=round(float(np.median(v)), 6),
                                 mean_ms=round(float(np.mean(v)), 6),
                                 sd_ms=round(float(np.sqrt(va)), 6),
                                 variance_ms2=round(va, 9),
                                 min_ms=round(float(np.min(v)), 6),
                                 max_ms=round(float(np.max(v)), 6)))
    fig.tight_layout(pad=0.4, h_pad=0.9, w_pad=1.0)
    stem = "fig_s1_shift_vs_normalization_%s" % corpus_name
    return fs.save(
        fig, out, stem,
        caption=(
            "DRAFT. **Constant shift against CLRT normalization, %s.** Left: empirical "
            "cumulative distributions of the master-observed interval $C_{\\rm obs}=m_r-m_a$ on "
            "a logarithmic abscissa spanning the full support, so no observation is clipped, "
            "with an inset linear zoom on $C\\pm0.12$ ms. Three curves: the measured native "
            "interval, the measured defended interval, and an **analytical constant-shift "
            "reference** $X_{\\rm shift}=X_{\\rm native}+[C-\\mathrm{median}(X_{\\rm "
            "native})]$ built from the same native samples, which aligns its median with the "
            "configured target while preserving the native variance and shape exactly. That "
            "reference is analytical: the loaded switch program has no shifting mode, so it is "
            "neither an implemented hardware condition nor evidence that such a shift is "
            "realizable here. Right: each measured distribution with its own sample mean "
            "removed. Centering changes neither the sample variance nor the shape, so this "
            "panel isolates variability from location; the analytical reference coincides "
            "exactly with the centered native curve by construction and is therefore not drawn "
            "again. Late and fail-open observations are included throughout."
            % corpus_name),
        inputs=inputs,
        notes=["the analytical constant shift is a reference, not an arm and not a hardware "
               "condition",
               "centering subtracts each distribution's own sample mean and does not "
               "standardize by its standard deviation, which would erase the difference under "
               "test",
               "every valid completed transaction is included, late and fail-open observations "
               "among them"],
        data_rows=rows_out, data_fields=list(rows_out[0].keys()),
        method_note=(
            "Empirical CDFs over every valid completed transaction; no resampling, smoothing or "
            "interpolation. The analytical reference is an additive translation of the native "
            "sample by the scalar C - median(native), so its sample variance equals the "
            "native sample variance identically. Centering subtracts each sample's own mean. "
            "Sample variances use the n-1 denominator; variances are reported in ms^2 and "
            "standard deviations in ms in the figure-data CSV."),
        limitation_note=(
            "The analytical constant shift is a construction from native samples and is not a "
            "measured condition; no fixed-shift mode exists in the loaded binary. Reduced "
            "variability is sufficient to reject a constant translation as the explanation, "
            "and is not sufficient to establish independence from the native interval, which "
            "would need paired ingress and egress measurement this evidence does not contain. "
            "All intervals are master-facing. Nothing here concerns physical operation time."),
        seed=None)


# ------------------------------------------------------------------ figure 2

# The S2 caption promises offsets, spreads, RMSE, tail quantiles, maxima and tolerance
# coverage in the figure-data CSV. Panel (a) contributes variance rows and panels (b) and (c)
# contribute target-error rows, so the CSV is long-form with a `panel` column rather than one
# table of a single shape.
_S2_FIELDS = ["panel", "corpus", "operation", "quantity", "value", "units", "note"]


def _s2_rows(ratio_rows, err_rows, have_j):
    out = []
    for r in ratio_rows:
        for q, v, u in (("n_native", r["n_native"], "count"),
                        ("n_defended", r["n_defended"], "count"),
                        ("var_native", r["var_native_ms2"], "ms^2"),
                        ("var_defended", r["var_defended_ms2"], "ms^2"),
                        ("sd_native", r["sd_native_ms"], "ms"),
                        ("sd_defended", r["sd_defended_ms"], "ms"),
                        ("rho", r["rho"], "ratio"),
                        ("rho_ci_lo", r["ci_lo"], "ratio"),
                        ("rho_ci_hi", r["ci_hi"], "ratio"),
                        ("n_sessions", r["n_sessions"], "count"),
                        ("per_session_rho_min", r["per_session_rho_min"], "ratio"),
                        ("per_session_rho_max", r["per_session_rho_max"], "ratio")):
            out.append(dict(panel="a", corpus=r["corpus"], operation=r["operation"],
                            quantity=q, value=v, units=u,
                            note=(r["ci_method"] if q.startswith("rho_ci") else "")))
    for e in err_rows:
        if e["operation"].startswith("OPERATE"):
            # Panel (c) exists only where the corpus fixed one J per capture. Where it does
            # not, the pooled OPERATE statistics are still reported, but the row says plainly
            # that no panel plots them rather than pointing at a panel that is not there.
            panel = "c" if have_j else "not plotted (no per-J panel for this corpus)"
        else:
            panel = "b"
        for q, v, u in (("n", e["n"], "count"),
                        ("target_C", e["target_ms"], "ms"),
                        ("mean_error", e["mean_error_ms"], "ms"),
                        ("median_error", e["median_error_ms"], "ms"),
                        ("error_sd", e["error_sd_ms"], "ms"),
                        ("rmse", e["rmse_ms"], "ms"),
                        ("error_p001", e["p001"], "ms"), ("error_p01", e["p01"], "ms"),
                        ("error_p50", e["p50"], "ms"), ("error_p99", e["p99"], "ms"),
                        ("error_p999", e["p999"], "ms"),
                        ("min_error", e["min_error_ms"], "ms"),
                        ("max_error", e["max_error_ms"], "ms"),
                        ("max_abs_error", e["max_abs_error_ms"], "ms"),
                        ("quantization_grid", e["quantization_grid_ms"], "ms")):
            out.append(dict(panel=panel, corpus=e["corpus"], operation=e["operation"],
                            quantity=q, value=round(v, 9) if isinstance(v, float) else v,
                            units=u, note=""))
        for tol, n in sorted(e["within"].items()):
            out.append(dict(panel=panel, corpus=e["corpus"], operation=e["operation"],
                            quantity="within_%s_ms_count" % tol, value=n, units="count",
                            note="tolerance fixed independently of the measured errors"))
            out.append(dict(panel=panel, corpus=e["corpus"], operation=e["operation"],
                            quantity="within_%s_ms_fraction" % tol,
                            value=round(e["within_fraction"][tol], 9), units="fraction",
                            note=""))
    return out

def fig_ratio_and_error(corpus_name, data, c_read, per_j, out, inputs, ratio_rows,
                        err_rows, c_control):
    classes = [k for k in ("READ", "SELECT") if data[k]["native"] and data[k]["defended"]]
    rng = random.Random(SEED)
    fs.use()
    have_j = bool(per_j)
    ncol = 3 if have_j else 2
    fig, ax = plt.subplots(1, ncol, figsize=(fs.PAGE_W, 2.35), squeeze=False)
    ax = ax[0]

    # ---- (a) variance ratio with a cluster bootstrap over sessions
    a = ax[0]
    ys, labels = [], []
    for k, cls in enumerate(classes):
        nat, dfd = data[cls]["native"], data[cls]["defended"]
        vn, vd = var_s([x for _, x in nat]), var_s([x for _, x in dfd])
        rho = vd / vn if vn and vn > 0 else float("nan")
        lo, hi, n_sess, n_rep = cluster_bootstrap_ratio(nat, dfd, rng)
        y = len(classes) - k
        ys.append(y); labels.append(cls)
        a.plot([rho], [y], marker=fs.MK[cls], ms=5, color=fs.ON, zorder=4)
        if lo is not None:
            a.plot([lo, hi], [y, y], color=fs.ON, lw=1.4, solid_capstyle="butt", zorder=3)
        else:
            a.annotate("no session interval\n(%d session%s)" % (n_sess, "" if n_sess == 1 else "s"),
                       xy=(rho, y), xytext=(rho * 2.2, y - 0.26), fontsize=8, color=fs.GREY,
                       va="center", ha="left")
        ps = per_session_ratios(nat, dfd)
        if len(ps) > 2:
            a.scatter(list(ps.values()), [y + 0.20] * len(ps), s=5, color=fs.GREY,
                      alpha=0.75, zorder=2, linewidths=0)
        ratio_rows.append(dict(
            corpus=corpus_name, operation=cls, target_C_ms=c_read,
            n_native=len(nat), n_defended=len(dfd),
            var_native_ms2=round(vn, 9), var_defended_ms2=round(vd, 9),
            sd_native_ms=round(float(np.sqrt(vn)), 6), sd_defended_ms=round(float(np.sqrt(vd)), 6),
            rho=round(rho, 9),
            ci_lo=(round(lo, 9) if lo is not None else ""),
            ci_hi=(round(hi, 9) if hi is not None else ""),
            ci_method=("cluster bootstrap over %d sessions, %d replicates, seed %d"
                       % (n_sess, n_rep, SEED) if lo is not None
                       else "none: %d session(s), a session-level interval cannot be formed"
                            % n_sess),
            per_session_rho_min=(round(min(ps.values()), 9) if ps else ""),
            per_session_rho_max=(round(max(ps.values()), 9) if ps else ""),
            n_sessions=n_sess))
    a.axvline(1.0, color=fs.C_OPERATE, ls="--", lw=1.0, zorder=2)
    a.text(0.92, 0.40, "$\\rho=1$: constant-shift prediction", fontsize=8,
           color=fs.C_OPERATE, va="center", ha="right")
    a.set_xscale("log")
    a.set_xlim(right=2.2)
    a.set_yticks(ys); a.set_yticklabels(labels)
    a.set_ylim(0.25, len(classes) + 0.62)
    a.set_xlabel("$\\rho=s^2_{\\rm def}/s^2_{\\rm nat}$, log scale")
    a.set_title("(a) sample-variance ratio", fontsize=9, loc="left")
    fs.grid(a)

    # ---- (b) target error
    b = ax[1]
    for cls in classes:
        dfd = np.asarray([x for _, x in data[cls]["defended"]])
        e = dfd - c_read
        x, y = ecdf(e)
        b.step(x, y, where="post", color=fs.C_READ if cls == "READ" else fs.C_SELECT,
               ls=fs.LS_CLASS[cls], lw=1.1, label=cls, zorder=3)
        err_rows.append(dict(corpus=corpus_name, operation=cls,
                             **target_error_stats(dfd.tolist(), c_read)))
    b.axvline(0.0, color=fs.C_OPERATE, ls=":", lw=1.0, zorder=2)
    b.set_xscale("symlog", linthresh=0.05)
    b.set_xticks([-1, -0.1, 0, 0.1, 1, 10])
    b.set_xticklabels(["-1", "-0.1", "0", "0.1", "1", "10"])
    b.set_ylim(0, 1.02)
    b.set_xlabel("$C_{\\rm obs}-C$ (ms), symlog, linear within $\\pm$0.05")
    b.set_ylabel("ECDF")
    b.set_title("(b) target error", fontsize=9, loc="left")
    b.legend(loc="upper left", frameon=False, fontsize=8, handlelength=1.8)
    fs.grid(b)
    ins = b.inset_axes([0.52, 0.14, 0.45, 0.40])
    for cls in classes:
        dfd = np.asarray([x for _, x in data[cls]["defended"]])
        x, y = ecdf(dfd - c_read)
        ins.step(x, y, where="post", color=fs.C_READ if cls == "READ" else fs.C_SELECT,
                 ls=fs.LS_CLASS[cls], lw=1.0)
    ins.axvline(0.0, color=fs.C_OPERATE, ls=":", lw=0.9)
    ins.set_xlim(-0.05, 0.05); ins.set_ylim(0, 1.02)
    ins.tick_params(labelsize=8); ins.set_title("zoom $\\pm$0.05 ms", fontsize=8)
    fs.grid(ins)

    # ---- (c) OPERATE per configured J, where the corpus resolves it
    if have_j:
        d = ax[2]
        for k, (lab, v) in enumerate(sorted(per_j.items(),
                                            key=lambda kv: int(kv[0].split("=")[1].split()[0]))):
            e = np.asarray(v) - c_control
            d.scatter(e, [k + 1] * len(e), s=7, color=fs.C_OPERATE, alpha=0.7, linewidths=0,
                      zorder=3)
            d.plot([float(np.median(e))], [k + 1], marker="|", ms=13, color="#222222", zorder=4)
            err_rows.append(dict(corpus=corpus_name, operation="OPERATE %s" % lab,
                                 **target_error_stats(v, c_control)))
        d.axvline(0.0, color=fs.C_OPERATE, ls=":", lw=1.0, zorder=2)
        d.set_yticks(range(1, len(per_j) + 1))
        d.set_yticklabels(sorted(per_j, key=lambda s: int(s.split("=")[1].split()[0])))
        d.set_ylim(0.4, len(per_j) + 0.6)
        d.set_xlabel("OPERATE $O-C$ (ms)")
        d.set_title("(c) OPERATE, per configured $J$", fontsize=9, loc="left")
        fs.grid(d)

    fig.tight_layout(pad=0.4, w_pad=1.0)
    stem = "fig_s2_variance_and_target_%s" % corpus_name
    j_txt = ("(c) The OPERATE response-to-acknowledgment interval, per configured $J$, as the "
             "error against its own target $C=R-A$. This is a protocol-response interval "
             "measured at the master, **not** a physical operation time. " if have_j else "")
    return fs.save(
        fig, out, stem,
        caption=(
            "DRAFT. **Variance ratio and target accuracy, %s.** (a) Sample-variance ratio "
            "$\\rho=s^2_{\\rm def}/s^2_{\\rm nat}$ per operation, $n-1$ denominator, on a "
            "logarithmic abscissa. The dashed line at $\\rho=1$ is what a constant translation "
            "predicts, since translating a sample leaves its variance unchanged. Bars are 95 "
            "per cent percentile intervals from a cluster bootstrap that resamples whole "
            "grouped runs, so within-run dependence is preserved; grey dots are the "
            "per-run ratios. No bound is imposed on the interval. (b) Distribution of the "
            "target error $C_{\\rm obs}-C$ over every defended observation, on a symmetric-log "
            "abscissa that is linear within $\\pm$0.05 ms, with an inset linear zoom; late and "
            "fail-open observations are included, which is why the upper tail is present. %s"
            "Offsets, spreads, RMSE, tail quantiles, maxima and tolerance coverage are in the "
            "figure-data CSV." % (corpus_name, j_txt)),
        inputs=inputs,
        notes=["sample variance uses the n-1 denominator; variance in ms^2, deviation in ms",
               "the interval resamples grouped runs, not transactions, so temporal dependence "
               "within a run is preserved",
               "no ratio and no interval bound is clipped at 1",
               "late and fail-open observations are included in the target-error distribution"],
        data_rows=_s2_rows(ratio_rows, err_rows, have_j), data_fields=_S2_FIELDS,
        method_note=(
            "rho is the ratio of sample variances with the n-1 denominator, computed on the "
            "pooled transactions of each arm. Its 95 per cent interval is a percentile cluster "
            "bootstrap with %d replicates, seed %d, resampling grouped runs with replacement "
            "and recomputing both variances from the pooled transactions of the resampled "
            "runs; runs are the sampling unit, so within-run dependence is preserved and "
            "transactions are not treated as independent. Where a corpus has fewer than three "
            "runs no interval is reported, because none can be formed at the level of the "
            "dependence. Target-error statistics are computed over every defended observation "
            "including late and fail-open ones; tolerance coverage is reported at 0.05, 0.5 "
            "and 1.0 ms, of which 0.5 ms is half the smallest configured step in the policy "
            "sweep and therefore fixed independently of the measured errors, and the 256 ns "
            "deadline quantization grid is recorded as the mechanism's own placement floor."
            % (BOOT, SEED)),
        limitation_note=(
            "rho below 1 shows reduced variability and rejects a constant translation as the "
            "explanation under comparable conditions. It does not establish independence from "
            "the native interval, does not bound leakage, and is not evidence that the queues "
            "behaved as designed. Operations and target settings are kept separate and are "
            "never pooled. For OPERATE the configured codebook is known but the realized "
            "per-transaction draw was never observed, so a per-J result exists only where the "
            "corpus fixed one J per capture. Nothing here is a physical-operation-time "
            "measurement."),
        seed=SEED)


# ------------------------------------------------------------------ main

def main(argv):
    if len(argv) > 1 and argv[1] == "--check":
        out = argv[2] if len(argv) > 2 else str(TIMING / "figures" / "shift")
        problems = check_manifest(out)
        print("shift-figure manifest: %d problems" % len(problems))
        for p in problems:
            print("  PROBLEM:", p)
        if not problems:
            print("  every generated artefact matches FIGURES.sha256")
        return 1 if problems else 0
    out = Path(argv[1]) if len(argv) > 1 else (TIMING / "figures" / "shift")
    out.mkdir(parents=True, exist_ok=True)
    summary = {}

    print("corpus: campaign_v1 (active authority)")
    cv1, cv1_inputs = load_campaign_v1()
    c_read, c_ctl, cfg_inputs = _targets_campaign_v1()
    cv1_inputs = cv1_inputs + cfg_inputs          # the configuration is a hashed input too
    print("  targets from configuration: read lane C=%g ms, control lane C=%g ms"
          % (c_read, c_ctl))
    dist_rows, ratio_rows, err_rows = [], [], []
    fig_distributions("campaign_v1", cv1, c_read, out, cv1_inputs, dist_rows)
    # OPERATE for campaign_v1: one pooled target-error row, because the realized per-transaction
    # J was never observed and cannot be resolved. Computed BEFORE the figure is emitted so it
    # reaches the figure-data CSV as well as the summary JSON.
    op = [x for _, x in cv1["OPERATE"]["defended"]]
    err_rows.append(dict(corpus="campaign_v1", operation="OPERATE (codebook {2,6,12} ms pooled)",
                         **target_error_stats(op, c_ctl)))
    fig_ratio_and_error("campaign_v1", cv1, c_read, load_campaign_v1_operate_by_j(),
                        out, cv1_inputs, ratio_rows, err_rows, c_ctl)
    summary["campaign_v1"] = dict(distributions=dist_rows, variance_ratio=ratio_rows,
                                  target_error=err_rows)

    print("corpus: final_read_sbo (retired, kept separate)")
    frs, frs_j, frs_inputs = load_final_read_sbo()
    f_read, f_ctl, f_cfg = _targets_final_read_sbo()
    frs_inputs = frs_inputs + f_cfg
    print("  targets from its own manifest: read lane C=%g ms, control lane C=%g ms"
          % (f_read, f_ctl))
    d2, r2, e2 = [], [], []
    fig_distributions("final_read_sbo", frs, f_read, out, frs_inputs, d2)
    fig_ratio_and_error("final_read_sbo", frs, f_read, frs_j, out, frs_inputs, r2, e2, f_ctl)
    summary["final_read_sbo"] = dict(distributions=d2, variance_ratio=r2, target_error=e2)

    (out / "SHIFT_VS_NORMALIZATION.json").write_text(json.dumps(summary, indent=1) + "\n")
    print("wrote %s" % (out / "SHIFT_VS_NORMALIZATION.json"))

    # The manifest is written HERE, by the same run that produces the artefacts, so it cannot
    # go stale the way a hand-run sha256sum can. An earlier version was generated once by hand
    # and then not updated when the data CSVs and the summary JSON changed, which left three
    # entries failing. Everything listed is a generated artefact; raw captures are covered by
    # their own DATASET.sha256 manifests and are not duplicated here.
    write_manifest(out)

    print()
    print("%-16s %-9s %10s %10s %10s %12s %s" %
          ("corpus", "op", "sd_nat", "sd_def", "rho", "95% CI", "sessions"))
    for corp in ("campaign_v1", "final_read_sbo"):
        for r in summary[corp]["variance_ratio"]:
            ci = ("[%.4g, %.4g]" % (r["ci_lo"], r["ci_hi"])) if r["ci_lo"] != "" else "none"
            print("%-16s %-9s %10.4f %10.4f %10.6f %12s %d"
                  % (corp, r["operation"], r["sd_native_ms"], r["sd_defended_ms"], r["rho"],
                     ci, r["n_sessions"]))
    print()
    print("%-16s %-34s %9s %9s %9s %9s %8s" %
          ("corpus", "operation", "mean err", "sd err", "RMSE", "max|err|", "<=0.5ms"))
    for corp in ("campaign_v1", "final_read_sbo"):
        for r in summary[corp]["target_error"]:
            print("%-16s %-34s %9.4f %9.4f %9.4f %9.3f %7.2f%%"
                  % (corp, r["operation"], r["mean_error_ms"], r["error_sd_ms"], r["rmse_ms"],
                     r["max_abs_error_ms"], 100 * r["within_fraction"]["0.500"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
