"""Exploratory figures for the offline leakage harness (not manuscript figures).

Fig 1: the quantised-grid privacy/overhead frontier (M3) with the permutation
       null band and the zero-leakage closure point.
Fig 2: cross-axis re-encoding (M4) -- I(timing ; response size) per composed
       condition, against each condition's own permutation-null p95.
"""

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT, FIGS = os.path.join(BASE, "out"), os.path.join(BASE, "figs")


def fig_frontier():
    F = pd.read_csv(os.path.join(OUT, "m3_grid_frontier.csv"))
    ad = F[F.policy == "adaptive"].sort_values("mean_added_bytes")
    fx = F[F.policy == "fixed"].sort_values("mean_added_bytes")
    j = json.load(open(os.path.join(OUT, "m3_grid_frontier.json")))["summary"]

    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    ax.plot(ad.mean_added_bytes, ad.MI_shape_vs_native_size_bits, "o",
            color="#1f77b4", label="quantised grid, adaptive K = ceil(L/c)")
    for _, r in ad.iterrows():
        ax.annotate("c=%d" % r["c"], (r.mean_added_bytes,
                                      r.MI_shape_vs_native_size_bits),
                    fontsize=7, xytext=(3, 3), textcoords="offset points")
    ax.plot(fx.mean_added_bytes, fx.MI_shape_vs_native_size_bits, "s",
            color="#d62728", label="quantised grid, fixed K (leakage 0 by design)")
    par = j["pareto_points"]
    ax.plot([p["overhead_B"] for p in par], [p["MI_bits"] for p in par],
            "-", color="#1f77b4", alpha=0.5)
    ax.fill_between([0, 230], 0, ad.MI_shape_vs_native_size_null_p95.max(),
                    color="grey", alpha=0.18,
                    label="permutation-null band (max p95 over c)")
    ax.axhline(j["H_native_size_bits"], ls="--", color="k", lw=0.8)
    ax.text(2, j["H_native_size_bits"] + 0.02,
            "H(response size) = %.3f bits (native leak)" % j["H_native_size_bits"],
            fontsize=8)
    kn = j["knee"]
    ax.annotate("knee c=%d\n%.1f B (%.0f%%), %.3f bits\nSTILL ABOVE NULL, k=1"
                % (kn["point"]["c"], kn["x_overhead"], 30.2, kn["y_leakage"]),
                (kn["x_overhead"], kn["y_leakage"]), xytext=(40, 0.55),
                textcoords="data", fontsize=8,
                arrowprops=dict(arrowstyle="->", lw=0.8))
    ax.annotate("closure only here\n135.8 B = 287%% overhead",
                (135.75, 0.0), xytext=(120, 0.28), fontsize=8,
                arrowprops=dict(arrowstyle="->", lw=0.8))
    ax.set_xlabel("mean added bytes per response")
    ax.set_ylabel("I(emitted shape ; native response size)  [bits]")
    ax.set_title("M3 -- quantised-grid frontier, n=11,494 transactions, 6 flows")
    ax.set_xlim(0, 230)
    ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout()
    fig.savefig(os.path.join(FIGS, "m3_frontier.png"), dpi=160)
    print("wrote figs/m3_frontier.png")


def fig_composition():
    d = json.load(open(os.path.join(OUT, "m4_composition.json")))
    keys = [k for k in d["conditions"] if k.startswith("P")]
    mi = [d["conditions"][k]["MI_timing_vs_size"]["mi"] for k in keys]
    p95 = [d["conditions"][k]["MI_timing_vs_size"]["null_p95"] for k in keys]
    H = d["conditions"][keys[0]]["H_native_size_bits"]

    fig, ax = plt.subplots(figsize=(7.6, 4.0))
    x = range(len(keys))
    ax.bar(x, mi, color=["#2ca02c" if m <= p else "#d62728"
                         for m, p in zip(mi, p95)])
    ax.plot(x, p95, "k_", markersize=22, label="permutation-null p95")
    ax.axhline(H, ls="--", color="k", lw=0.8)
    ax.text(0.05, H + 0.02, "H(response size) = %.3f bits" % H, fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels([k.replace("_PERFECT", "") for k in keys], rotation=20,
                       ha="right", fontsize=8)
    ax.set_ylabel("I(timing observables ; native response size) [bits]")
    ax.set_title("M4 -- size information re-encoded into the timing channel\n"
                 "under an IDEALISED perfect first-byte normaliser (n=11,494)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(FIGS, "m4_composition.png"), dpi=160)
    print("wrote figs/m4_composition.png")


if __name__ == "__main__":
    os.makedirs(FIGS, exist_ok=True)
    fig_frontier()
    fig_composition()
