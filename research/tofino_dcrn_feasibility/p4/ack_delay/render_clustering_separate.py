#!/usr/bin/env python3
"""Four standalone figures: BEFORE and AFTER, separately, for each case (real device traces).

  caseA_before.png / caseA_after.png : SEL-751 ACK-to-response gap   (~13 ms -> ~0 ms)
  caseB_before.png / caseB_after.png : AB1400 + ION7550 response time (~16 ms -> ~107 ms)

Before/after of a case share the SAME x-range so they line up side by side.
Data: Traffic Trace/{SEL751,AB1400,ION7550}.pcap (real). Case-A after = SEL profile under Case A
on the switch (formby_eval/sel_casea.pcap). Case-B after = device-independent Case-B target.
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
        resp = max(dat); rt.append((resp - rq) * 1000)
        acks = [t for t in rev_ack if rq < t <= resp]
        if acks: clrt.append((resp - min(acks)) * 1000)
    return np.array(clrt), np.array(rt)

sel_clrt, _ = real(f"{TT}/SEL751.pcap", "10.0.0.1")     # Case A GAP before: SEL ACK->resp gap ~13 ms
_, ab_rt  = real(f"{TT}/AB1400.pcap",  "10.0.0.12")
_, ion_rt = real(f"{TT}/ION7550.pcap", "10.0.0.11")
J = json.load(open("/tmp/clrt_rt_arrays.json"))
# Case A view 1 (GAP): ACK-to-response gap.  before ~13 ms (real SEL) -> after ~0 (rig sel_casea)
sel_gap_after = np.array([x for x in J["dev1_caseA"]["clrt"] if x > -0.5])
# Case A view 2 (ACK HOLD): request -> ACK arrival.  before ~3.7 ms (real SEL) -> after ~38 ms (rig)
selA_before = np.array(J["_caseA_r2a"]["before"])
selA_after  = np.array(J["_caseA_r2a"]["after"])
G = 107.0
ab_after, ion_after = np.maximum(ab_rt, G), np.maximum(ion_rt, G)

SEL_C, AB_C, ION_C = "#2f8f6b", "#1f77b4", "#ff7f0e"
rng = np.random.default_rng(1)

def panel(fname, series, xlim, title, xlabel, note, note_color="#5a6b70"):
    fig, ax = plt.subplots(figsize=(8.2, 2.8))
    for x, c, lab in series:
        ax.scatter(x, rng.uniform(-0.28, 0.28, size=len(x)), s=24, c=c, alpha=0.6, edgecolors="none", label=lab)
        ax.axvline(float(np.median(x)), color=c, lw=1.2, ls="--", alpha=0.55)
    ax.set_ylim(-1, 1); ax.set_xlim(*xlim); ax.set_yticks([])
    ax.set_title(title, fontsize=14, weight="bold", loc="left", pad=10)
    ax.set_xlabel(xlabel, fontsize=12.5)
    ax.text(0.985, 0.86, note, transform=ax.transAxes, ha="right", fontsize=11.5, color=note_color, weight="bold")
    for s in ("top", "right", "left"): ax.spines[s].set_visible(False)
    ax.tick_params(labelsize=11)
    if len(series) > 1:
        ax.legend(loc="upper left", frameon=False, fontsize=10.5, handletextpad=0.2)
    fig.tight_layout()
    fig.savefig(f"evidence/visualization/{fname}", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  saved %-22s medians: %s" % (fname, ", ".join("%.2f" % np.median(x) for x, _, _ in series)))

# ---- Case A view 1: GAP clustering (ACK-to-response gap) — the Formby CLRT result ----
panel("defense1_gap_before.png", [(sel_clrt, SEL_C, "SEL-751")], (-1, 30),
      "Defense 1 · gap · SEL-751 — BEFORE", "ACK-to-response gap (ms)", "gap ≈ 13 ms")
panel("defense1_gap_after.png", [(sel_gap_after, SEL_C, "SEL-751")], (-1, 30),
      "Defense 1 · gap · SEL-751 — AFTER", "ACK-to-response gap (ms)", "collapses to ≈ 0 ms", "#2f8f6b")
# ---- Case A view 2: ACK-HOLD clustering (request -> ACK arrival) — the mechanism ----
panel("defense1_hold_before.png", [(selA_before, SEL_C, "SEL-751")], (-1, 45),
      "Defense 1 · ACK hold · SEL-751 — BEFORE", "request → ACK arrival (ms)", "ACK prompt ≈ 4 ms")
panel("defense1_hold_after.png", [(selA_after, SEL_C, "SEL-751")], (-1, 45),
      "Defense 1 · ACK hold · SEL-751 — AFTER", "request → ACK arrival (ms)", "ACK held ≈ 38 ms", "#2f8f6b")

# ---- Case A ZOOMED AFTER views (resolve how tight each cluster is) ----
gap_med = float(np.median(sel_gap_after))
panel("defense1_gap_after_zoom.png", [(sel_gap_after, SEL_C, "SEL-751")], (0, 1),
      "Defense 1 · gap · SEL-751 — AFTER (zoom 0–1 ms)", "ACK-to-response gap (ms)",
      "clustered at %.3f ms" % gap_med, "#2f8f6b")
h_lo, h_hi, h_med = float(np.min(selA_after)), float(np.max(selA_after)), float(np.median(selA_after))
panel("defense1_hold_after_zoom.png", [(selA_after, SEL_C, "SEL-751")], (h_lo - 0.6, h_hi + 0.6),
      "Defense 1 · ACK hold · SEL-751 — AFTER (zoom)", "request → ACK arrival (ms)",
      "clustered at %.2f ms" % h_med, "#2f8f6b")

# (Case B AB/ION panels removed: AB/ION are combined-ACK -> no CLRT -> bypassed by both defenses,
#  not held. Defense 2 on SEL is defense2_hold_response_SEL.png / defense2_after.png.)
print("done — Defense 1 gap+hold on SEL-751")
