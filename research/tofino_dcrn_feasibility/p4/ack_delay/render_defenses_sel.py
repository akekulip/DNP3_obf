#!/usr/bin/env python3
"""Case A = SEL-751 (separate-ACK). Two defenses, before -> after, on the ACK-to-response gap.

  Defense 1 (hold the ACK):      gap ~17 ms -> ~0 ms      (reduce)
  Defense 2 (hold the response): gap ~17 ms -> ~107 ms    (increase, fixed constant)

Data (rig, SEL-751 = dev1 profile, per evidence/caseB_hardware/RESULT.md):
  before   = sel_native.pcap  (dev1_native.clrt)
  Defense1 = sel_casea.pcap   (dev1_caseA.clrt)   -> hold ACK
  Defense2 = b_dev1.pcap      (dev1_caseB.clrt)   -> hold response
"""
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

J = json.load(open("/tmp/clrt_rt_arrays.json"))
def g(k): return np.array([x for x in J[k]["clrt"] if x > -0.5])
sel_before = g("dev1_native")     # SEL native gap ~17 ms
d1_after   = g("dev1_caseA")      # Defense 1 -> ~0 ms
d2_after   = g("dev1_caseB")      # Defense 2 -> ~107 ms

SEL = "#2f8f6b"
rng = np.random.default_rng(1)
def strip(ax, x, yc):
    ax.scatter(x, yc + rng.uniform(-0.16, 0.16, size=len(x)), s=22, c=SEL, alpha=0.6, edgecolors="none")

def fig(fname, after, xlim, title, before_note, after_note):
    f, ax = plt.subplots(figsize=(10, 3.4))
    strip(ax, sel_before, 1.0); strip(ax, after, 0.0)
    ax.axvline(float(np.median(sel_before)), color=SEL, lw=1, ls="--", alpha=0.4)
    ax.axvline(float(np.median(after)),      color=SEL, lw=1, ls="--", alpha=0.6)
    ax.axhline(0.5, color="#e2e7ea", lw=1)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["After", "Before"], fontsize=12)
    ax.set_ylim(-0.5, 1.5); ax.set_xlim(*xlim)
    ax.set_title(title, fontsize=14, weight="bold", loc="left", pad=10)
    ax.set_xlabel("ACK-to-response gap (ms)", fontsize=12.5)
    ax.text(0.99, 0.90, before_note, transform=ax.transAxes, ha="right", fontsize=11, color="#8a949a")
    ax.text(0.99, 0.28, after_note,  transform=ax.transAxes, ha="right", fontsize=11.5, color=SEL, weight="bold")
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.tick_params(labelsize=11)
    f.tight_layout()
    f.savefig(f"evidence/visualization/{fname}", dpi=150, bbox_inches="tight")
    plt.close(f)
    print("  %-26s before med=%.2f  after med=%.2f ms" % (fname, float(np.median(sel_before)), float(np.median(after))))

fig("defense1_hold_ack_SEL.png", d1_after, (-1, 22),
    "Case A · SEL-751 · Defense 1 — hold the ACK", "SEL gap ≈ 17 ms", "collapses to ≈ 0 ms")
fig("defense2_hold_response_SEL.png", d2_after, (-2, 115),
    "Case A · SEL-751 · Defense 2 — hold the response", "SEL gap ≈ 17 ms", "fixed at ≈ 107 ms")

# ---- combined 2-row figure for the deck (replaces the old clustering figure) ----
f2, ax2 = plt.subplots(2, 1, figsize=(11, 6.6))
def lane2(ax, after, xlim, title, after_note):
    strip(ax, sel_before, 1.0); strip(ax, after, 0.0)
    ax.axvline(float(np.median(sel_before)), color=SEL, lw=1, ls="--", alpha=0.4)
    ax.axvline(float(np.median(after)),      color=SEL, lw=1, ls="--", alpha=0.6)
    ax.axhline(0.5, color="#e2e7ea", lw=1)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["After", "Before"], fontsize=12)
    ax.set_ylim(-0.5, 1.5); ax.set_xlim(*xlim)
    ax.set_title(title, fontsize=13.5, weight="bold", loc="left", pad=8)
    ax.set_xlabel("ACK-to-response gap (ms)", fontsize=12.5)
    ax.text(0.99, 0.90, "SEL gap ≈ 17 ms", transform=ax.transAxes, ha="right", fontsize=10.5, color="#8a949a")
    ax.text(0.99, 0.28, after_note, transform=ax.transAxes, ha="right", fontsize=10.5, color=SEL, weight="bold")
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.tick_params(labelsize=11)
lane2(ax2[0], d1_after, (-1, 25),  "Defense 1 — hold the ACK",      "collapses to ≈ 0 ms")
lane2(ax2[1], d2_after, (-2, 115), "Defense 2 — hold the response", "fixed at ≈ 107 ms")
f2.suptitle("Case A · SEL-751 — both defenses normalise the ACK-to-response gap", fontsize=15, weight="bold", y=0.995)
f2.text(0.5, 0.005, "Real per-transaction data (SEL-751 separate-ACK profile). "
        "AB1400 / ION7550 are combined-ACK — no CLRT, bypassed by both defenses.",
        ha="center", fontsize=9, color="#8a949a", style="italic")
f2.tight_layout(rect=[0, 0.03, 1, 0.95])
f2.savefig("evidence/visualization/clustering_before_after.png", dpi=150, bbox_inches="tight")
plt.close(f2)
print("saved clustering_before_after.png (both defenses on SEL)")
print("done — both defenses on SEL-751")
