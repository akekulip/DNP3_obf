#!/usr/bin/env python3
"""make_figures.py -- three IEEE single-column figures from the RRC pcaps (post-audit).

  fig_size.pdf   : response segmentation is identical for READ and SELECT ([28,21] -> 49 B)
  fig_timing.pdf : the D4 hold clamps request->response latency to the ~22 ms deadline for both
  fig_clrt.pdf   : the CLRT (ACK->response) fingerprint -- native READ/SELECT are separable,
                   the D4 hold collapses both onto ~20 ms

Data comes from analyze_rrc_pcaps.transactions() (TCP-ACK-based pairing, DNP3 function
classification) -- so only ADMITTED 20 B READ / 45 B SELECT profiles are used; the 18 B
all-points state-reads are excluded (they are not carved). Native = size-only bundle (hold OFF);
normalized = joint bundle (D4 hold ON). Labelled SELECT, not SBO: physical OPERATE was not run,
so this is per-response READ-vs-SELECT-echo parity. Run with $RESEARCH_PYTHON.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NP = HERE.parent
sys.path.insert(0, str(NP))
from analyze_rrc_pcaps import transactions

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

EV = NP / "evidence"
NATIVE = EV / "hw_rrc_readsbo_20260812T212234Z" / "captures"   # size-only (hold OFF)
JOINT  = EV / "hw_rrc_joint_20260812T223342Z" / "captures"     # joint (D4 hold ON)
C_READ, C_SEL, C_REF = "#0072B2", "#D55E00", "#999999"          # Okabe-Ito, CVD-safe

def series(pcap, klass, field):
    return [t[field] for t in transactions(str(pcap)) if t["klass"] == klass and t["admitted"]]

# request->response latency (ms)
read_native = series(NATIVE / "read.pcap", "READ",   "req_to_resp_ms")
sel_native  = series(NATIVE / "sbo.pcap",  "SELECT", "req_to_resp_ms")
read_joint  = series(JOINT / "read.pcap",  "READ",   "req_to_resp_ms")
sel_joint   = series(JOINT / "sbo.pcap",   "SELECT", "req_to_resp_ms")
# CLRT: pure-ACK -> response (ms)
read_clrt_n = series(NATIVE / "read.pcap", "READ",   "ack_to_resp_ms")
sel_clrt_n  = series(NATIVE / "sbo.pcap",  "SELECT", "ack_to_resp_ms")
read_clrt_j = series(JOINT / "read.pcap",  "READ",   "ack_to_resp_ms")
sel_clrt_j  = series(JOINT / "sbo.pcap",   "SELECT", "ack_to_resp_ms")
print("n(req->resp): read_n=%d sel_n=%d read_j=%d sel_j=%d" %
      (len(read_native), len(sel_native), len(read_joint), len(sel_joint)))
print("req->resp median: READ_j=%.3f SEL_j=%.3f ms" % (np.median(read_joint), np.median(sel_joint)))
print("CLRT median native : READ=%.3f SEL=%.3f ms" % (np.median(read_clrt_n), np.median(sel_clrt_n)))
print("CLRT median normaliz: READ=%.3f SEL=%.3f ms" % (np.median(read_clrt_j), np.median(sel_clrt_j)))

utils_mpl.set_global()

# === Figure 1 -- identical response segmentation ===========================
fig, ax = utils_mpl.get_fig(size=(3.5, 2.3))
x = [0, 1]
ax.bar(x, [28, 28], width=0.55, color=C_READ, edgecolor="black", linewidth=0.6, label="segment 1 (28 B)")
ax.bar(x, [21, 21], width=0.55, bottom=[28, 28], color=C_SEL, edgecolor="black", linewidth=0.6, label="segment 2 (21 B)")
for xi in x:
    ax.text(xi, 14, "28 B", ha="center", va="center", fontsize=8, color="white")
    ax.text(xi, 38.5, "21 B", ha="center", va="center", fontsize=8, color="white")
    ax.text(xi, 50.5, "49 B", ha="center", va="bottom", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels(["READ", "SELECT"])
ax.set_ylabel("Response payload (bytes)")
ax.set_ylim(0, 58); ax.set_xlim(-0.6, 1.6)
ax.legend(loc="upper center", ncol=2, fontsize=7.5, columnspacing=1.0, handlelength=1.2,
          frameon=True, bbox_to_anchor=(0.5, 1.16))
utils_mpl.set_grid(fig, ax)
fig.savefig(str(HERE / "fig_size.pdf"), transparent=True); plt.close(fig)

# === Figure 2 -- D4 hold clamps request->response latency ==================
def ecdf(a):
    a = np.sort(np.asarray(a, float))
    return a, np.arange(1, len(a) + 1) / len(a)

fig, ax = utils_mpl.get_fig(size=(3.5, 2.3))
for data, c, ls, lab in [
    (read_native, C_READ, "--", "READ, native"),
    (sel_native,  C_SEL,  "--", "SELECT, native"),
    (read_joint,  C_READ, "-",  "READ, normalized"),
    (sel_joint,   C_SEL,  "-",  "SELECT, normalized"),
]:
    xs, ys = ecdf(data)
    ax.step(xs, ys, where="post", color=c, linestyle=ls, linewidth=1.4, label=lab)
ax.axvline(22.0, color=C_REF, linewidth=0.8, linestyle=":")
ax.annotate("D4 deadline\n(22 ms)", xy=(22.0, 0.55), xytext=(11.5, 0.55),
            fontsize=7, va="center", ha="center",
            arrowprops=dict(arrowstyle="->", lw=0.7, color=C_REF))
utils_mpl.set_x_axis(ax, bnd=[0, 26])
ax.set_ylim(0, 1.02)
ax.set_xlabel("Request$\\rightarrow$response latency (ms)")
ax.set_ylabel("Cumulative fraction")
ax.legend(loc="lower right", fontsize=7, handlelength=1.6, frameon=True)
utils_mpl.set_grid(fig, ax)
fig.savefig(str(HERE / "fig_timing.pdf"), transparent=True); plt.close(fig)

# === Figure 3 -- CLRT (ACK->response) confused by the defense ==============
rng = np.random.default_rng(0)
fig, ax = utils_mpl.get_fig(size=(3.5, 2.4))
def strip(xc, data, color, marker):
    xs = xc + rng.uniform(-0.16, 0.16, len(data))
    ax.scatter(xs, data, s=11, color=color, marker=marker, alpha=0.7, linewidths=0, zorder=3)
    ax.plot([xc - 0.24, xc + 0.24], [np.median(data)] * 2, color=color, lw=1.4, zorder=4)
strip(0, read_clrt_n, C_READ, "o"); strip(0, sel_clrt_n, C_SEL, "s")
strip(1, read_clrt_j, C_READ, "o"); strip(1, sel_clrt_j, C_SEL, "s")
ax.set_yscale("log"); ax.set_ylim(0.6, 40); ax.set_xlim(-0.55, 1.55)
ax.set_xticks([0, 1]); ax.set_xticklabels(["Native\n(no defense)", "Normalized\n(D4 hold)"])
ax.set_ylabel("CLRT: ACK$\\rightarrow$response (ms)")
ax.text(0.0, 0.72, "separable", ha="center", va="bottom", fontsize=7, style="italic")
ax.text(1.0, 27, "READ $\\equiv$ SELECT", ha="center", va="bottom", fontsize=7, style="italic")
handles = [Line2D([0], [0], marker="o", linestyle="none", markerfacecolor=C_READ, markeredgecolor="none", label="READ", markersize=5),
           Line2D([0], [0], marker="s", linestyle="none", markerfacecolor=C_SEL, markeredgecolor="none", label="SELECT", markersize=5)]
ax.legend(handles=handles, loc="center left", fontsize=8, frameon=True, handletextpad=0.3)
utils_mpl.set_grid(fig, ax)
fig.savefig(str(HERE / "fig_clrt.pdf"), transparent=True); plt.close(fig)
print("wrote fig_size.pdf, fig_timing.pdf, fig_clrt.pdf in", HERE)
