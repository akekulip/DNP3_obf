#!/usr/bin/env python3
"""Clustering — before & after per case, each on the quantity that case controls.

  Case A (hold the ACK)      -> ACK-to-response gap   : before dev1~17 / dev2~35 ms  ->  after ~0
  Case B (hold the response) -> response time (req->resp): before dev1~17 / dev2~35 ms -> after ~107

Real per-transaction data (99 txns each), extracted from the rig captures:
  before : formby_eval/sel_native.pcap (dev1), dev2_native.pcap (dev2)
  Case A : formby_eval/sel_casea.pcap,          dev2_casea.pcap        (ACK-to-response gap)
  Case B : caseB_hardware/b_dev1.pcap,          b_dev2.pcap            (response time)
"""
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

D = json.load(open("/tmp/clrt_rt_arrays.json"))
def g(key, metric):                       # metric = "clrt" (ACK->resp gap) or "rt" (req->resp)
    return np.array([x for x in D[key][metric] if x is not None and x > -0.5])

# Case A row = ACK-to-response gap;  Case B row = response time
A_before1, A_before2 = g("dev1_native", "clrt"), g("dev2_native", "clrt")
A_after1,  A_after2  = g("dev1_caseA", "clrt"),  g("dev2_caseA", "clrt")
B_before1, B_before2 = g("dev1_native", "rt"),   g("dev2_native", "rt")
B_after1,  B_after2  = g("dev1_caseB", "rt"),    g("dev2_caseB", "rt")

BLUE, ORANGE = "#1f77b4", "#ff7f0e"
rng = np.random.default_rng(1)
def strip(ax, x, yc, c):
    ax.scatter(x, yc + rng.uniform(-0.16, 0.16, size=len(x)), s=22, c=c, alpha=0.65, edgecolors="none")

def row(ax, b1, b2, a1, a2, xlim, title, xlabel, after_note):
    strip(ax, b1, 1.0, BLUE); strip(ax, b2, 1.0, ORANGE)      # BEFORE lane
    strip(ax, a1, 0.0, BLUE); strip(ax, a2, 0.0, ORANGE)      # AFTER lane
    ax.axhline(0.5, color="#e2e7ea", lw=1)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["After", "Before"], fontsize=12)
    ax.set_ylim(-0.5, 1.5); ax.set_xlim(*xlim)
    ax.set_title(title, fontsize=13.5, weight="bold", loc="left", pad=8)
    ax.set_xlabel(xlabel, fontsize=12.5)
    ax.text(0.99, 0.90, "two separable groups", transform=ax.transAxes, ha="right", fontsize=10.5, color="#8a949a")
    ax.text(0.99, 0.28, after_note, transform=ax.transAxes, ha="right", fontsize=10.5, color="#2f8f6b")
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.tick_params(labelsize=11)

fig, axes = plt.subplots(2, 1, figsize=(11, 7.0))
row(axes[0], A_before1, A_before2, A_after1, A_after2, (-1, 45),
    "Case A — hold the ACK", "ACK-to-response gap (ms)", "one group at ≈ 0 ms")
row(axes[1], B_before1, B_before2, B_after1, B_after2, (-2, 115),
    "Case B — hold the response", "response time, request → response (ms)", "one group at ≈ 107 ms")

fig.legend(handles=[Line2D([0],[0],marker='o',color='w',markerfacecolor=BLUE,markersize=9,label='Device 1'),
                    Line2D([0],[0],marker='o',color='w',markerfacecolor=ORANGE,markersize=9,label='Device 2')],
           loc="upper right", frameon=False, fontsize=11.5, bbox_to_anchor=(0.995, 1.0))
fig.suptitle("Clustering — before and after each defense", fontsize=15, weight="bold", y=0.995)
fig.text(0.5, 0.005,
         "Each case shows the quantity IT controls, with its own BEFORE (two separable device profiles). "
         "Real per-transaction data, 99 transactions per profile.",
         ha="center", fontsize=9, color="#8a949a", style="italic")
fig.tight_layout(rect=[0, 0.03, 1, 0.95])
fig.savefig("evidence/visualization/clustering_before_after.png", dpi=150, bbox_inches="tight")
print("saved clustering_before_after.png")
for nm, a in [("A before dev1", A_before1), ("A before dev2", A_before2), ("A after", A_after1),
              ("B before dev1", B_before1), ("B before dev2", B_before2), ("B after", B_after1)]:
    print("  %-14s n=%3d median=%7.2f" % (nm, len(a), float(np.median(a))))
