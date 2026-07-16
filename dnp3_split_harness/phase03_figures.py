"""phase03_figures.py -- Phase 03A figures (ACK-separation characterization).

Reads the committed Phase 03A tables (matrix + coarse/refined delay sweeps, already produced by
phase03_analyze.py from fresh PCAPs) and renders the plan-required figures:

    fig01 ack_mode_by_config          -- per matrix config, NON-FIRST combined/separate/other
    fig02 separation_probability_by_delay -- threshold S-curve + Wilson 95% band + transition band
    fig03 request_to_ack_cdf          -- ECDF of request->pure-ACK (separated non-first)
    fig04 ack_to_response_cdf         -- ECDF of pure-ACK->response (separated non-first)
    fig05 request_to_response_cdf     -- ECDF of request->response by ACK regime
    fig06 example_combined_timeline   -- one combined non-first transaction timeline
    fig07 example_separate_timeline   -- one separated non-first transaction timeline

Each figure carries a metadata sidecar (producing script + command + source table SHA-256 +
git commit + n + filters + transformation). Reads the COMMITTED tables so figures regenerate
from committed artifacts, not from git-ignored runs/.

    python3 phase03_figures.py --report-dir reports/phases/phase_03
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

CLS_COMBINED = "COMBINED_ACK_RESPONSE"
CLS_SEPARATE = "SEPARATE_ACK_RESPONSE"
CLS_OTHER = "OTHER_OR_AMBIGUOUS"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def _git():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE).stdout.decode().strip()
    except Exception:  # noqa: BLE001
        return None


def _rows(path):
    with open(path) as fh:
        return list(csv.DictReader(fh))


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _delay_of(cfg):
    return int(cfg.replace("delay_", "").replace("ms", ""))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report-dir", default="reports/phases/phase_03")
    args = ap.parse_args()
    tdir = os.path.join(args.report_dir, "tables")
    fdir = os.path.join(args.report_dir, "figures")
    os.makedirs(fdir, exist_ok=True)
    commit = _git()

    matrix_tx = os.path.join(tdir, "phase03_matrix_ack_transactions.csv")
    sweep_curve = os.path.join(tdir, "phase03_delay_sweep.csv")
    coarse_tx = os.path.join(tdir, "phase03_sweep_coarse_ack_transactions.csv")
    refined_tx = os.path.join(tdir, "phase03_sweep_refined_ack_transactions.csv")
    scope = ("Measured on the gambit loopback interface, Linux kernel 5.15.0-139-generic, "
             "in the tested socket and application configuration.")

    def meta(name, *, source_tables, filters, n, transformation):
        json.dump({
            "producing_script": "phase03_figures.py",
            "generation_command": "python3 phase03_figures.py --report-dir %s" % args.report_dir,
            "source_tables": {os.path.basename(s): _sha256(s) for s in source_tables},
            "git_commit": commit, "filters": filters, "n": n,
            "statistical_transformation": transformation, "scope_label": scope,
        }, open(os.path.join(fdir, name + ".metadata.json"), "w"), indent=2)

    def save(name):
        for e in ("png", "pdf"):
            plt.savefig(os.path.join(fdir, name + "." + e), dpi=200, bbox_inches="tight")
        plt.close()

    # ---- fig01: matrix ACK mode by config (NON-FIRST requests only) --------------------------
    mrows = [r for r in _rows(matrix_tx) if r["is_first_in_connection"] == "False"]
    configs = sorted({r["config"] for r in mrows})
    comb, sep, oth = [], [], []
    for cfg in configs:
        cr = [r for r in mrows if r["config"] == cfg]
        n = len(cr) or 1
        comb.append(sum(r["classification"] == CLS_COMBINED for r in cr) / n)
        sep.append(sum(r["classification"] == CLS_SEPARATE for r in cr) / n)
        oth.append(sum(r["classification"] == CLS_OTHER for r in cr) / n)
    x = np.arange(len(configs))
    plt.figure(figsize=(10, 4.8))
    plt.bar(x, comb, 0.6, label="COMBINED (ACK on response)", color="#5B8FF9", edgecolor="black")
    plt.bar(x, sep, 0.6, bottom=comb, label="SEPARATE (pure ACK first)", color="#F6BD16",
            edgecolor="black")
    plt.bar(x, oth, 0.6, bottom=np.array(comb) + np.array(sep), label="OTHER / ambiguous",
            color="#CDCDCD", edgecolor="black")
    plt.xticks(x, configs, rotation=30, ha="right", fontsize=8)
    plt.ylabel("fraction of NON-first requests"); plt.ylim(0, 1.05)
    plt.title("Phase 03A: ACK mode by config (non-first requests)\n"
              "fixed25 / bounded20-30 stay 100% COMBINED like native; crc-split chunking -> OTHER",
              fontsize=10)
    plt.legend(fontsize=8, loc="center right"); save("fig01_ack_mode_by_config")
    meta("fig01_ack_mode_by_config", source_tables=[matrix_tx],
         filters="matrix, is_first_in_connection==False", n=len(mrows),
         transformation="per-config class fractions (stacked)")

    # ---- fig02: separation probability vs app-write delay (threshold S-curve) -----------------
    cr = _rows(sweep_curve)
    coarse = [r for r in cr if r["source"] == "coarse"]
    refined = [r for r in cr if r["source"] == "refined"]

    def xyerr(rr):
        xs = [int(r["delay_ms"]) for r in rr]
        ys = [float(r["nonfirst_sep_frac"]) for r in rr]
        lo = [float(r["nonfirst_sep_frac"]) - float(r["wilson95_lo"]) for r in rr]
        hi = [float(r["wilson95_hi"]) - float(r["nonfirst_sep_frac"]) for r in rr]
        return xs, ys, [lo, hi]
    plt.figure(figsize=(8.2, 5))
    plt.axvspan(35, 40, color="#FFF1C9", label="transition region (35-40 ms)")
    cx, cy, ce = xyerr(coarse)
    plt.errorbar(cx, cy, yerr=ce, fmt="o-", color="#5B8FF9", capsize=3, ms=5,
                 label="coarse sweep (Wilson 95%)")
    rx, ry, re = xyerr(refined)
    plt.errorbar(rx, ry, yerr=re, fmt="s--", color="#CF1322", capsize=3, ms=5,
                 label="refined 1 ms sweep (Wilson 95%)")
    plt.axhline(0.5, ls=":", color="gray", lw=1)
    plt.xlabel("application-write delay (ms)")
    plt.ylabel("P(separate pure ACK | non-first request)")
    plt.title("Phase 03A: ACK-separation probability vs application-write delay\n"
              "graded (probabilistic) transition, ~36-40 ms; 50% near 39 ms", fontsize=10)
    plt.ylim(-0.03, 1.05); plt.legend(fontsize=8, loc="center left")
    save("fig02_separation_probability_by_delay")
    meta("fig02_separation_probability_by_delay", source_tables=[sweep_curve],
         filters="non-first requests; coarse + refined sweeps",
         n=sum(int(r["nonfirst_n"]) for r in cr),
         transformation="separation fraction with Wilson 95% CI vs delay")

    # ---- CDF helpers: separated non-first transactions from both sweeps -----------------------
    allsweep = _rows(coarse_tx) + _rows(refined_tx)
    sep_nf = [r for r in allsweep
              if r["is_first_in_connection"] == "False" and r["classification"] == CLS_SEPARATE]

    def ecdf(vals, xlabel, title, name, source_tables):
        vals = sorted(v for v in vals if v is not None)
        plt.figure(figsize=(7, 4.4))
        if vals:
            plt.step(vals, np.arange(1, len(vals) + 1) / len(vals), where="post", color="#5B8FF9")
        plt.xlabel(xlabel); plt.ylabel("ECDF"); plt.title(title, fontsize=10)
        plt.grid(alpha=0.3); save(name)
        return len(vals)

    n3 = ecdf([_f(r["req_to_pure_ack_ms"]) for r in sep_nf], "request -> pure ACK (ms)",
              "Phase 03A: request->pure-ACK CDF (separated non-first)\n"
              "pure ACK is emitted promptly (~0.01 ms), not at the response delay",
              "fig03_request_to_ack_cdf", [coarse_tx, refined_tx])
    meta("fig03_request_to_ack_cdf", source_tables=[coarse_tx, refined_tx],
         filters="non-first, SEPARATE_ACK_RESPONSE", n=n3, transformation="empirical CDF")

    n4 = ecdf([_f(r["pure_ack_to_resp_ms"]) for r in sep_nf], "pure ACK -> response (ms)",
              "Phase 03A: pure-ACK->response CDF (separated non-first)\n"
              "gap tracks the configured application-write delay (36-100 ms across sampled delays)",
              "fig04_ack_to_response_cdf", [coarse_tx, refined_tx])
    meta("fig04_ack_to_response_cdf", source_tables=[coarse_tx, refined_tx],
         filters="non-first, SEPARATE_ACK_RESPONSE", n=n4, transformation="empirical CDF")

    # ---- fig05: request->response CDF by ACK regime (combined vs separated), non-first --------
    nf = [r for r in allsweep if r["is_first_in_connection"] == "False"]
    comb_v = sorted(v for v in (_f(r["req_to_resp_ms"]) for r in nf
                                if r["classification"] == CLS_COMBINED) if v is not None)
    sep_v = sorted(v for v in (_f(r["req_to_resp_ms"]) for r in nf
                               if r["classification"] == CLS_SEPARATE) if v is not None)
    plt.figure(figsize=(7.4, 4.6))
    if comb_v:
        plt.step(comb_v, np.arange(1, len(comb_v) + 1) / len(comb_v), where="post",
                 label="COMBINED regime (n=%d)" % len(comb_v), color="#5B8FF9")
    if sep_v:
        plt.step(sep_v, np.arange(1, len(sep_v) + 1) / len(sep_v), where="post",
                 label="SEPARATE regime (n=%d)" % len(sep_v), color="#CF1322")
    plt.xlabel("request -> response (ms)"); plt.ylabel("ECDF")
    plt.title("Phase 03A: request->response CDF by ACK regime (non-first)", fontsize=10)
    plt.legend(fontsize=8); plt.grid(alpha=0.3); save("fig05_request_to_response_cdf")
    meta("fig05_request_to_response_cdf", source_tables=[coarse_tx, refined_tx],
         filters="non-first; split by classification", n=len(comb_v) + len(sep_v),
         transformation="empirical CDF per ACK regime")

    # ---- timeline helper ---------------------------------------------------------------------
    def timeline(row, name, title, has_ack):
        req = _f(row["req_to_first_rev_ms"])  # 0 reference is the request
        t_ack = _f(row["req_to_pure_ack_ms"]) if has_ack else None
        t_resp = _f(row["req_to_resp_ms"])
        plt.figure(figsize=(8.5, 2.6))
        plt.hlines(1, 0, max(t_resp, 1) * 1.05, color="#888", lw=1)
        plt.plot(0, 1, "o", color="#5B8FF9", ms=12)
        plt.annotate("request\n(frame %s, DNP3 func %s)" % (row["req_frame"], row["req_func"]),
                     (0, 1), textcoords="offset points", xytext=(0, 16), ha="left", fontsize=8)
        if has_ack and t_ack is not None:
            plt.plot(t_ack, 1, "s", color="#F6BD16", ms=12)
            plt.annotate("pure TCP ACK\n(frame %s, +%.3f ms)" % (row["pure_ack_frame"], t_ack),
                         (t_ack, 1), textcoords="offset points", xytext=(0, -30), ha="left",
                         fontsize=8)
        plt.plot(t_resp, 1, "D", color="#CF1322", ms=12)
        plt.annotate("DNP3 response%s\n(frame %s, +%.3f ms)" % (
            "" if has_ack else " (ACK on response)", row["resp_frame"], t_resp),
            (t_resp, 1), textcoords="offset points", xytext=(-10, 16), ha="right", fontsize=8)
        plt.yticks([]); plt.xlabel("time since request (ms)")
        plt.title(title, fontsize=10); plt.xlim(-max(t_resp, 1) * 0.08, max(t_resp, 1) * 1.15)
        save(name)

    def example_timeline(cfg, cls, name, title, has_ack):
        cand = next((r for r in _rows(coarse_tx)
                     if r["config"] == cfg and r["is_first_in_connection"] == "False"
                     and r["classification"] == cls and _f(r["req_to_resp_ms"]) is not None), None)
        if cand is None:
            print("skip %s: no matching %s non-first %s example in %s"
                  % (name, cfg, cls, os.path.basename(coarse_tx)))
            return
        timeline(cand, name, title, has_ack)
        meta(name, source_tables=[coarse_tx],
             filters="%s, non-first, %s (single example)" % (cfg, cls), n=1,
             transformation="single-transaction timeline")

    example_timeline("delay_025ms", CLS_COMBINED, "fig06_example_combined_timeline",
                     "Phase 03A: example COMBINED timeline (delay 25 ms, non-first)\n"
                     "no standalone ACK; the response packet carries the ACK", has_ack=False)
    example_timeline("delay_040ms", CLS_SEPARATE, "fig07_example_separate_timeline",
                     "Phase 03A: example SEPARATE timeline (delay 40 ms, non-first)\n"
                     "prompt pure ACK, then response after the app-write delay", has_ack=True)

    # ---- fig08: socket-option comparison (RQ3), non-first separation per variant x anchor -----
    socket_tbl = os.path.join(tdir, "phase03_socket_option_summary.csv")
    if os.path.exists(socket_tbl):
        srows = _rows(socket_tbl)
        variants = sorted({r["variant"] for r in srows})
        delays = sorted({int(r["delay_ms"]) for r in srows})
        x = np.arange(len(variants)); w = 0.8 / max(len(delays), 1)
        colors = {25: "#5B8FF9", 50: "#CF1322"}
        plt.figure(figsize=(8.5, 4.8))
        for i, dl in enumerate(delays):
            fr, err = [], [[], []]
            for v in variants:
                row = next((r for r in srows if r["variant"] == v and int(r["delay_ms"]) == dl), None)
                p = float(row["nonfirst_sep_frac"]) if row else 0.0
                fr.append(p)
                err[0].append(p - (float(row["wilson95_lo"]) if row else 0.0))
                err[1].append((float(row["wilson95_hi"]) if row else 0.0) - p)
            plt.bar(x + (i - (len(delays) - 1) / 2) * w, fr, w, yerr=err, capsize=3,
                    color=colors.get(dl, "#888"), edgecolor="black",
                    label="app-write delay %d ms (%s baseline)"
                          % (dl, "combined" if dl < 36 else "separate"))
        plt.xticks(x, variants); plt.ylim(0, 1.08)
        plt.ylabel("P(separate pure ACK | non-first request)")
        plt.title("Phase 03A: socket-option effect on ACK separation (RQ3)\n"
                  "one factor at a time; Wilson 95% CIs", fontsize=10)
        plt.legend(fontsize=8); save("fig08_socket_option_comparison")
        meta("fig08_socket_option_comparison", source_tables=[socket_tbl],
             filters="socket sweep, non-first requests, one factor at a time",
             n=sum(int(r["nonfirst_n"]) for r in srows),
             transformation="per-variant separation fraction with Wilson 95% CI")

    print("figures:", sorted(x for x in os.listdir(fdir) if x.endswith(".png")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
