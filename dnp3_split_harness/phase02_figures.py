"""phase02_figures.py -- Phase 02 figures (distribution-based, full metadata).

Replaces the earlier median-only bounded bar with distribution figures: the bounded
selected-target distribution, client-visible ECDF and box plots, target-vs-visible and
target-vs-size scatters, target-by-transaction-position (the defect check), and a BLOCKED
placeholder for the ACK-mode-after-normalization figure (needs a PCAP). Each figure carries a
full metadata sidecar (producing script + command + source table SHA-256 + run id + commit +
seed + filters + n + transformation).

    python3 phase02_figures.py --run-dir <phase02 run dir>
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


def _load(run_dir):
    with open(os.path.join(run_dir, "tables", "phase02_transaction_log.csv")) as fh:
        return list(csv.DictReader(fh))


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    run = args.run_dir
    rid = os.path.basename(run.rstrip("/"))
    fig = os.path.join(run, "figures"); os.makedirs(fig, exist_ok=True)
    src = os.path.join(run, "tables", "phase02_transaction_log.csv")
    src_sha = _sha256(src); commit = _git()
    seed = None
    mpath = os.path.join(run, "manifest.json")
    if os.path.exists(mpath):
        seed = json.load(open(mpath)).get("config", {}).get("run_seed")
    rows = _load(run)

    def meta(name, *, filters, n, transformation, subfig):
        json.dump({
            "producing_script": "phase02_figures.py", "subfigure": subfig,
            "generation_command": "python3 phase02_figures.py --run-dir %s" % rid,
            "source_table": "tables/phase02_transaction_log.csv", "source_table_sha256": src_sha,
            "run_id": rid, "git_commit": commit, "run_seed": seed,
            "filters": filters, "n": n, "statistical_transformation": transformation,
        }, open(os.path.join(fig, name + ".metadata.json"), "w"), indent=2)

    def save(name):
        for e in ("png", "pdf"):
            plt.savefig(os.path.join(fig, name + "." + e), dpi=200, bbox_inches="tight")
        plt.close()

    bounded = [r for r in rows if r["timing_mode"] == "bounded"]
    bfull = [r for r in bounded if r["delivery"] == "full"]

    # fig01: bounded selected-target distribution (should be ~uniform over [20,30])
    tg = [_f(r["selected_target_ms"]) for r in bounded if _f(r["selected_target_ms"]) is not None]
    plt.figure(figsize=(7, 4.2))
    plt.hist(tg, bins=20, range=(20, 30), color="#5B8FF9", edgecolor="black")
    plt.axhline(len(tg) / 20, ls="--", color="gray", label="uniform expectation")
    plt.xlabel("bounded selected target (ms)"); plt.ylabel("count")
    plt.title("Phase 02: bounded selected-target distribution (uniform 20-30 ms, n=%d)" % len(tg))
    plt.legend(); save("fig01_bounded_target_distribution")
    meta("fig01_bounded_target_distribution", filters="timing_mode==bounded",
         n=len(tg), transformation="histogram (20 bins over [20,30])", subfig="target distribution")

    # fig02: client-visible ECDF, native/fixed/bounded (full delivery, 2407B READ)
    plt.figure(figsize=(7, 4.4))
    for mode, color in (("native", "#5AD8A6"), ("fixed", "#F6BD16"), ("bounded", "#5B8FF9")):
        vs = sorted(_f(r["client_visible_ms"]) for r in rows
                    if r["timing_mode"] == mode and r["delivery"] == "full"
                    and r["response_size"] == "2407" and _f(r["client_visible_ms"]) is not None)
        if vs:
            plt.step(vs, np.arange(1, len(vs) + 1) / len(vs), where="post", label="%s (n=%d)" % (mode, len(vs)))
    plt.xlabel("client-visible request->response (ms)"); plt.ylabel("ECDF")
    plt.title("Phase 02: client-visible time ECDF (2407 B READ, full delivery)")
    plt.legend(); save("fig02_client_visible_ecdf")
    meta("fig02_client_visible_ecdf", filters="delivery==full, response_size==2407",
         n=sum(1 for r in rows if r["delivery"] == "full" and r["response_size"] == "2407"),
         transformation="empirical CDF", subfig="visible ECDF")

    # fig03: client-visible box plot per config (2407B READ)
    labels, data = [], []
    for cfg in sorted({r["config"] for r in rows}):
        vs = [_f(r["client_visible_ms"]) for r in rows if r["config"] == cfg
              and r["response_size"] == "2407" and _f(r["client_visible_ms"]) is not None]
        if vs:
            labels.append(cfg.split(" ")[0]); data.append(vs)
    plt.figure(figsize=(10, 4.6))
    plt.boxplot(data, labels=labels, showfliers=True)
    plt.axhline(25, ls="--", color="gray", lw=1, label="25 ms")
    plt.xticks(rotation=30, ha="right", fontsize=7); plt.ylabel("client-visible (ms)")
    plt.title("Phase 02: client-visible request->response by config (2407 B READ)")
    plt.legend(); save("fig03_client_visible_box")
    meta("fig03_client_visible_box", filters="response_size==2407", n=sum(len(d) for d in data),
         transformation="box plot", subfig="visible box")

    # fig04: bounded selected target vs client-visible (visible should track target)
    xs = [_f(r["selected_target_ms"]) for r in bfull]
    ys = [_f(r["client_visible_ms"]) for r in bfull]
    pts = [(a, b) for a, b in zip(xs, ys) if a is not None and b is not None]
    plt.figure(figsize=(5.5, 5))
    if pts:
        ax, ay = zip(*pts)
        plt.scatter(ax, ay, s=6, alpha=0.4, color="#5B8FF9")
        lim = [min(ax + ay), max(ax + ay)]; plt.plot(lim, lim, ls="--", color="gray", label="y=x")
    plt.xlabel("bounded selected target (ms)"); plt.ylabel("client-visible (ms)")
    plt.title("Phase 02 bounded: selected target vs client-visible"); plt.legend()
    save("fig04_target_vs_visible")
    meta("fig04_target_vs_visible", filters="timing_mode==bounded, delivery==full",
         n=len(pts), transformation="scatter", subfig="target vs visible")

    # fig05: bounded selected target vs response size (independence -> flat)
    xs = [_f(r["response_size"]) for r in bfull]
    ys = [_f(r["selected_target_ms"]) for r in bfull]
    pts = [(a, b) for a, b in zip(xs, ys) if a is not None and b is not None]
    plt.figure(figsize=(6, 4.4))
    if pts:
        ax, ay = zip(*pts); plt.scatter(ax, ay, s=6, alpha=0.4, color="#5AD8A6")
    plt.xlabel("response size (bytes)"); plt.ylabel("bounded selected target (ms)")
    plt.title("Phase 02 bounded: target independent of response size (flat)")
    save("fig05_target_vs_size")
    meta("fig05_target_vs_size", filters="timing_mode==bounded, delivery==full",
         n=len(pts), transformation="scatter", subfig="target vs size")

    # fig06: bounded target by transaction position (the defect check -> all ~U(20,30))
    pos_data, pos_labels = [], []
    for pos in sorted({r["txn"] for r in bfull}, key=lambda x: int(x)):
        vs = [_f(r["selected_target_ms"]) for r in bfull if r["txn"] == pos
              and _f(r["selected_target_ms"]) is not None]
        if vs:
            pos_labels.append("txn %s\n(%sB)" % (pos, next(r["response_size"] for r in bfull if r["txn"] == pos)))
            pos_data.append(vs)
    plt.figure(figsize=(8, 4.4))
    plt.boxplot(pos_data, labels=pos_labels)
    plt.ylabel("bounded selected target (ms)"); plt.xticks(fontsize=7)
    plt.title("Phase 02 bounded: target by transaction position (no position->target mapping after fix)")
    save("fig06_target_by_position")
    meta("fig06_target_by_position", filters="timing_mode==bounded, delivery==full",
         n=sum(len(d) for d in pos_data), transformation="box plot per position", subfig="target by position")

    # fig07: ACK-mode-after-normalization -- BLOCKED (no PCAP)
    plt.figure(figsize=(7, 3.4))
    plt.axis("off")
    plt.text(0.5, 0.5,
             "ACK-mode after normalization: BLOCKED\n\nRequires a packet capture (sniffer).\n"
             "dumpcap not group-executable on this host; two-host rig unavailable.\n"
             "Run on the rig: capture both endpoints, classify\n"
             "COMBINED_ACK_RESPONSE / SEPARATE_ACK_RESPONSE per config.",
             ha="center", va="center", fontsize=11,
             bbox=dict(boxstyle="round", fc="#FFF1F0", ec="#CF1322"))
    save("fig07_ack_mode_after_normalization_BLOCKED")
    meta("fig07_ack_mode_after_normalization_BLOCKED",
         filters="n/a", n=0, transformation="none (blocked placeholder)", subfig="ack-mode blocked")

    # fig08: projected size/native correlation (renamed, non-clipped title)
    ppath = os.path.join(run, "tables", "phase02_projected_leakage.json")
    if os.path.exists(ppath):
        p = json.load(open(ppath))["by_mode"]
        modes = list(p)
        cs = [abs(p[m]["corr_visible_vs_response_size"] or 0) for m in modes]
        cn = [abs(p[m]["corr_visible_vs_native_ready"] or 0) for m in modes]
        x = np.arange(len(modes)); w = 0.35
        plt.figure(figsize=(7.5, 4.6))
        plt.bar(x - w / 2, cs, w, label="|corr(visible, resp size)|", color="#5AD8A6", edgecolor="black")
        plt.bar(x + w / 2, cn, w, label="|corr(visible, native ready)|", color="#F6BD16", edgecolor="black")
        plt.xticks(x, modes); plt.ylabel("|correlation|"); plt.ylim(0, 1.05)
        plt.title("Projected normalization suppresses bulk timing variation\nwhile native tails retain residual correlation", fontsize=10)
        plt.legend(fontsize=8); save("fig08_projected_correlation")
        meta("fig08_projected_correlation",
             filters="projected shipped policy over real Phase 01 COMBINED transactions",
             n=json.load(open(ppath)).get("n_combined_transactions"),
             transformation="Pearson correlation (projected)", subfig="projected correlation")

    print("figures:", sorted(x for x in os.listdir(fig) if x.endswith(".png")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
