#!/usr/bin/env python3
"""make_figures.py -- two IEEE single-column figures from the RRC pcaps:
  fig_size.pdf   : observed response segmentation is identical for READ and SBO ([28,21] -> 49 B)
  fig_timing.pdf : the D4 hold normalizes response timing for READ and SBO (native spread -> tight ~22.6 ms)

Data comes straight from the captured pcaps (no synthetic numbers). Native = size-only bundle
(timing hold OFF); normalized = joint bundle (D4 hold ON). Run with $RESEARCH_PYTHON.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NP = HERE.parent                          # .../native_parity
sys.path.insert(0, str(NP))
from analyze_rrc_pcaps import load, latencies   # reuse the verified pcap parser

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP

MASTER, RELAY, RPORT = "192.168.10.1", "192.168.10.7", 20000

def load_all(pcap):
    """All TCP packets (incl. len=0 ACKs) as (t, src, plen) -- needed for the CLRT (ACK->response)."""
    out = []
    for p in rdpcap(str(pcap)):
        if p.haslayer(IP) and p.haslayer(TCP):
            plen = p[IP].len - p[IP].ihl * 4 - p[TCP].dataofs * 4
            out.append({"t": float(p.time), "src": p[IP].src, "len": plen})
    out.sort(key=lambda r: r["t"])
    return out

def clrt(pcap):
    """CLRT (ms) per transaction = t(response prefix, relay len=28) - t(held pure-ACK, relay len=0
    between the request and the response). Only carved (len=28) responses -> excludes state-reads."""
    pk = load_all(pcap)
    reqs = [r["t"] for r in pk if r["src"] == MASTER and r["len"] in (20, 45)]
    out = []
    for i, r in enumerate(pk):
        if not (r["src"] == RELAY and r["len"] == 28):
            continue
        t_resp = r["t"]
        prev_req = [t for t in reqs if t < t_resp]
        if not prev_req:
            continue
        t_req = max(prev_req)
        acks = [q["t"] for q in pk if q["src"] == RELAY and q["len"] == 0 and t_req < q["t"] < t_resp]
        if acks:
            out.append((t_resp - max(acks)) * 1000.0)
    return out

EV = NP / "evidence"
NATIVE = EV / "hw_rrc_readsbo_20260812T212234Z" / "captures"   # size-only (timing OFF)
JOINT  = EV / "hw_rrc_joint_20260812T223342Z" / "captures"     # joint (D4 hold ON)

# Okabe-Ito CVD-safe palette
C_READ, C_SBO, C_REF = "#0072B2", "#D55E00", "#999999"

def carved_lat(pcap):
    reqs, resps = load(str(pcap))
    return latencies(reqs, resps, only_lens={28})   # request -> carved (28 B) response, ms

def seg_sizes(pcap):
    _, resps = load(str(pcap))
    return [r["len"] for r in resps]

# ---- pull the data ---------------------------------------------------------
read_native = carved_lat(NATIVE / "read.pcap")
sbo_native  = carved_lat(NATIVE / "sbo.pcap")
read_joint  = carved_lat(JOINT / "read.pcap")
sbo_joint   = carved_lat(JOINT / "sbo.pcap")
read_seg    = seg_sizes(JOINT / "read.pcap")
sbo_seg     = seg_sizes(JOINT / "sbo.pcap")
print("n carved latencies: read_native=%d sbo_native=%d read_joint=%d sbo_joint=%d"
      % (len(read_native), len(sbo_native), len(read_joint), len(sbo_joint)))
print("read_seg hist:", {s: read_seg.count(s) for s in sorted(set(read_seg))})
print("sbo_seg  hist:", {s: sbo_seg.count(s) for s in sorted(set(sbo_seg))})
print("joint medians: read=%.3f ms  sbo=%.3f ms" % (np.median(read_joint), np.median(sbo_joint)))

# CLRT (ACK -> response) -- the separate-ACK fingerprint the defense collapses
read_clrt_n = clrt(NATIVE / "read.pcap")
sbo_clrt_n  = clrt(NATIVE / "sbo.pcap")
read_clrt_j = clrt(JOINT / "read.pcap")
sbo_clrt_j  = clrt(JOINT / "sbo.pcap")
print("CLRT native  : READ med=%.3f ms (n=%d)  SBO med=%.3f ms (n=%d)"
      % (np.median(read_clrt_n), len(read_clrt_n), np.median(sbo_clrt_n), len(sbo_clrt_n)))
print("CLRT normaliz: READ med=%.3f ms (n=%d)  SBO med=%.3f ms (n=%d)"
      % (np.median(read_clrt_j), len(read_clrt_j), np.median(sbo_clrt_j), len(sbo_clrt_j)))

utils_mpl.set_global()

# ===========================================================================
# Figure 1 -- response segmentation identical for READ and SBO
# stacked bar: each transaction's response = 28 B prefix + 21 B suffix = 49 B
# ===========================================================================
fig, ax = utils_mpl.get_fig(size=(3.5, 2.3))
x = [0, 1]
labels = ["READ", "SBO"]
prefix = [28, 28]      # first segment (no PSH)
suffix = [21, 21]      # second segment (PSH)
b1 = ax.bar(x, prefix, width=0.55, color=C_READ, edgecolor="black", linewidth=0.6, label="segment 1 (28 B)")
b2 = ax.bar(x, suffix, width=0.55, bottom=prefix, color=C_SBO, edgecolor="black", linewidth=0.6, label="segment 2 (21 B)")
for xi in x:
    ax.text(xi, 14, "28 B", ha="center", va="center", fontsize=8, color="white")
    ax.text(xi, 28 + 10.5, "21 B", ha="center", va="center", fontsize=8, color="white")
    ax.text(xi, 49 + 1.5, "49 B", ha="center", va="bottom", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels(labels)
ax.set_ylabel("Response payload (bytes)")
ax.set_ylim(0, 58)
ax.set_xlim(-0.6, 1.6)
ax.legend(loc="upper center", ncol=2, fontsize=7.5, columnspacing=1.0, handlelength=1.2,
          frameon=True, bbox_to_anchor=(0.5, 1.16))
utils_mpl.set_grid(fig, ax)
fig.savefig(str(HERE / "fig_size.pdf"), transparent=True)
plt.close(fig)

# ===========================================================================
# Figure 2 -- D4 hold normalizes response timing (ECDF)
# native (dashed) spread 2-22 ms; normalized (solid) tight at ~22.6 ms
# ===========================================================================
def ecdf(a):
    a = np.sort(np.asarray(a, float))
    return a, np.arange(1, len(a) + 1) / len(a)

fig, ax = utils_mpl.get_fig(size=(3.5, 2.3))
for data, c, ls, lab in [
    (read_native, C_READ, "--", "READ, native"),
    (sbo_native,  C_SBO,  "--", "SBO, native"),
    (read_joint,  C_READ, "-",  "READ, normalized"),
    (sbo_joint,   C_SBO,  "-",  "SBO, normalized"),
]:
    xs, ys = ecdf(data)
    ax.step(xs, ys, where="post", color=c, linestyle=ls, linewidth=1.4, label=lab)
ax.axvline(22.0, color=C_REF, linewidth=0.8, linestyle=":")
ax.annotate("D4 deadline\n(22 ms)", xy=(22.0, 0.55), xytext=(11.5, 0.55),
            fontsize=7, va="center", ha="center",
            arrowprops=dict(arrowstyle="->", lw=0.7, color=C_REF))
utils_mpl.set_x_axis(ax, bnd=[0, 32])
ax.set_ylim(0, 1.02)
ax.set_xlabel("Request$\\rightarrow$response latency (ms)")
ax.set_ylabel("Cumulative fraction")
ax.legend(loc="lower right", fontsize=7, handlelength=1.6, frameon=True)
utils_mpl.set_grid(fig, ax)
fig.savefig(str(HERE / "fig_timing.pdf"), transparent=True)
plt.close(fig)

# ===========================================================================
# Figure 3 -- CLRT (ACK->response), the separate-ACK fingerprint, confused by the defense
# native: READ (~2.1 ms) and SBO (~1.1 ms) form two separable clouds;
# normalized: both collapse onto ~20 ms -> the observer cannot tell them apart.
# ===========================================================================
from matplotlib.lines import Line2D
rng = np.random.default_rng(0)
fig, ax = utils_mpl.get_fig(size=(3.5, 2.4))

def strip(xc, data, color, marker):
    xs = xc + rng.uniform(-0.16, 0.16, len(data))
    ax.scatter(xs, data, s=11, color=color, marker=marker, alpha=0.7, linewidths=0, zorder=3)
    ax.plot([xc - 0.24, xc + 0.24], [np.median(data)] * 2, color=color, lw=1.4, zorder=4)

strip(0, read_clrt_n, C_READ, "o")
strip(0, sbo_clrt_n,  C_SBO,  "s")
strip(1, read_clrt_j, C_READ, "o")
strip(1, sbo_clrt_j,  C_SBO,  "s")
ax.set_yscale("log")
ax.set_ylim(0.6, 40)
ax.set_xlim(-0.55, 1.55)
ax.set_xticks([0, 1]); ax.set_xticklabels(["Native\n(no defense)", "Normalized\n(D4 hold)"])
ax.set_ylabel("CLRT: ACK$\\rightarrow$response (ms)")
ax.text(0.0, 0.72, "separable", ha="center", va="bottom", fontsize=7, style="italic", color="black")
ax.text(1.0, 27, "READ $\\equiv$ SBO", ha="center", va="bottom", fontsize=7, style="italic", color="black")
handles = [Line2D([0], [0], marker="o", linestyle="none", markerfacecolor=C_READ,
                  markeredgecolor="none", label="READ", markersize=5),
           Line2D([0], [0], marker="s", linestyle="none", markerfacecolor=C_SBO,
                  markeredgecolor="none", label="SBO", markersize=5)]
ax.legend(handles=handles, loc="center left", fontsize=8, frameon=True, handletextpad=0.3)
utils_mpl.set_grid(fig, ax)
fig.savefig(str(HERE / "fig_clrt.pdf"), transparent=True)
plt.close(fig)
print("wrote fig_size.pdf, fig_timing.pdf, fig_clrt.pdf in", HERE)
