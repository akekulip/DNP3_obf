#!/usr/bin/env python3
"""Clustering — before & after per case, on the REAL device traces and the quantity each case controls.

  Case A (hold the ACK)      -> SEL-751 ACK-to-response gap  : before ~13 ms  ->  after ~0
  Case B (hold the response) -> AB1400 + ION7550 response time: before ~16.6 ms -> after ~107 (device-indep.)

Real device captures: Traffic Trace/{SEL751,AB1400,ION7550}.pcap (master 10.0.0.3).
Case-A 'after' = SEL profile replayed through the switch under Case A (formby_eval/sel_casea.pcap).
Case-B 'after' = the measured device-independent Case-B target (max(readiness, G), G=107 ms; Case B
  holds every response to t_ACK+G regardless of device — proven device-independent on the rig).
"""
import json
import numpy as np
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from scapy.all import rdpcap, TCP, IP

TT = "/home/philip/Projects/DNP3/Traffic Trace"

def real(path, dev, master="10.0.0.3", port=20000):
    """Window-based per-transaction pairing (robust to multi-segment responses)."""
    pk = rdpcap(path); reqs = []; rev_data = []; rev_ack = []
    for p in pk:
        if TCP not in p or IP not in p: continue
        tcp, ip = p[TCP], p[IP]; t = float(p.time); L = len(bytes(tcp.payload)); fl = str(tcp.flags)
        if ip.src == master and ip.dst == dev and tcp.dport == port and L > 0: reqs.append(t)
        elif ip.src == dev and tcp.sport == port and L > 0: rev_data.append(t)
        elif ip.src == dev and tcp.sport == port and L == 0 and "A" in fl and "S" not in fl: rev_ack.append(t)
    reqs.sort(); rev_data.sort(); rev_ack.sort()
    clrt = []; rt = []
    for i, rq in enumerate(reqs):
        nxt = reqs[i + 1] if i + 1 < len(reqs) else float("inf")
        dat = [t for t in rev_data if rq < t < nxt]
        if not dat: continue
        resp_arr = max(dat)                       # response complete = last segment in the window
        rt.append((resp_arr - rq) * 1000)
        acks = [t for t in rev_ack if rq < t <= resp_arr]
        if acks: clrt.append((resp_arr - min(acks)) * 1000)
    return np.array(clrt), np.array(rt)

# ---- Case A: SEL ACK-to-response gap ----
sel_clrt, _ = real(f"{TT}/SEL751.pcap", "10.0.0.1")                 # before (real)
rt = json.load(open("/tmp/clrt_rt_arrays.json"))
sel_after = np.array([x for x in rt["dev1_caseA"]["clrt"] if x > -0.5])   # after (SEL profile under Case A)

# ---- Case B: AB + ION response time ----
_, ab_rt  = real(f"{TT}/AB1400.pcap",  "10.0.0.12")                 # before (real)
_, ion_rt = real(f"{TT}/ION7550.pcap", "10.0.0.11")                 # before (real)
G = 107.0
ab_after  = np.maximum(ab_rt,  G)                                    # Case B applied (device-independent target)
ion_after = np.maximum(ion_rt, G)

SEL_C, AB_C, ION_C = "#2f8f6b", "#1f77b4", "#ff7f0e"
rng = np.random.default_rng(1)
def strip(ax, x, yc, c):
    ax.scatter(x, yc + rng.uniform(-0.16, 0.16, size=len(x)), s=20, c=c, alpha=0.6, edgecolors="none")
def lanes(ax, xlim, title, xlabel, before_note, after_note):
    ax.axhline(0.5, color="#e2e7ea", lw=1)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["After", "Before"], fontsize=12)
    ax.set_ylim(-0.5, 1.5); ax.set_xlim(*xlim)
    ax.set_title(title, fontsize=13.5, weight="bold", loc="left", pad=8)
    ax.set_xlabel(xlabel, fontsize=12.5)
    ax.text(0.99, 0.90, before_note, transform=ax.transAxes, ha="right", fontsize=10.5, color="#8a949a")
    ax.text(0.99, 0.28, after_note, transform=ax.transAxes, ha="right", fontsize=10.5, color="#2f8f6b")
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.tick_params(labelsize=11)

fig, axes = plt.subplots(2, 1, figsize=(11, 7.2))
# Case A
strip(axes[0], sel_clrt, 1.0, SEL_C); strip(axes[0], sel_after, 0.0, SEL_C)
lanes(axes[0], (-1, 30), "Case A — hold the ACK  ·  SEL-751",
      "ACK-to-response gap (ms)", "SEL-751 gap ≈ 13 ms", "collapses to ≈ 0 ms")
# Case B
strip(axes[1], ab_rt, 1.0, AB_C);  strip(axes[1], ion_rt, 1.0, ION_C)
strip(axes[1], ab_after, 0.0, AB_C); strip(axes[1], ion_after, 0.0, ION_C)
lanes(axes[1], (0, 120), "Case B — hold the response  ·  AB1400 + ION7550",
      "response time, request → response (ms)", "both ≈ 16–17 ms", "both fixed at ≈ 107 ms")

fig.legend(handles=[Line2D([0],[0],marker='o',color='w',markerfacecolor=SEL_C,markersize=9,label='SEL-751 (Case A)'),
                    Line2D([0],[0],marker='o',color='w',markerfacecolor=AB_C,markersize=9,label='AB1400 (Case B)'),
                    Line2D([0],[0],marker='o',color='w',markerfacecolor=ION_C,markersize=9,label='ION7550 (Case B)')],
           loc="upper center", frameon=False, fontsize=10.5, ncol=3, bbox_to_anchor=(0.5, 0.965))
fig.suptitle("Clustering — before and after each defense (real device traces)", fontsize=15, weight="bold", y=0.995)
fig.text(0.5, 0.005,
         "Case A on SEL-751 (the separate-ACK device): its ACK-to-response gap. "
         "Case B on AB1400 + ION7550 (combined-ACK): response time, normalised to the common Case-B target.",
         ha="center", fontsize=9, color="#8a949a", style="italic")
fig.tight_layout(rect=[0, 0.03, 1, 0.93])
fig.savefig("evidence/visualization/clustering_before_after.png", dpi=150, bbox_inches="tight")
print("saved clustering_before_after.png")
print("  SEL CLRT before: n=%d median=%.2f ; after n=%d median=%.3f" % (len(sel_clrt), float(np.median(sel_clrt)), len(sel_after), float(np.median(sel_after))))
print("  AB  RT   before: n=%d median=%.2f ; after median=%.1f" % (len(ab_rt), float(np.median(ab_rt)), float(np.median(ab_after))))
print("  ION RT   before: n=%d median=%.2f ; after median=%.1f" % (len(ion_rt), float(np.median(ion_rt)), float(np.median(ion_after))))
