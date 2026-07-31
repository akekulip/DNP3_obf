"""Figure 11 — the safe operating region for D.

The final control plane does not clamp D at a fixed value; it admits D only while the
reservoir can still be alive when the deadline arrives:

    to reach the deadline, the reservoir must survive  a_bound + D + t_detect + t_drain
    + t_tail + M  --- and that must stay below the fail-open horizon  H = B*K/rate.

Where that requirement line crosses H is D_max. Below it the delay is deadline-governed
(safe); above it the budget expires first and the trial would measure H, not D.
"""
import os
import sys

import numpy as np
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import d3_style as ds

# constants from control/parameter_policy.py (mirrored here so the figure is standalone)
H = 30.802                                   # fail-open horizon, ms  (B*K/rate)
A_BOUND = 3.0                                # conservative ACK-latency bound, ms
M = 3.0                                      # safety margin, ms
OVERHEAD = (1217.0 + 1736.0 + 1736.0) / 1e6  # t_detect+t_drain+t_tail, ms (~0.005)
RTO = 200.0                                  # master retransmission floor, ms
D_MAX = H - A_BOUND - OVERHEAD - M           # ~24.8 ms

fig, ax = ds.setup(size=(3.5, 2.6))

D = np.linspace(0, 44, 400)
req = A_BOUND + D + OVERHEAD + M              # time the reservoir must survive to hit deadline

# shade valid (req <= H) green and unsafe (req > H) red, under the H line
ax.fill_between(D, 0, np.minimum(req, H), where=(D <= D_MAX),
                color=ds.PASS, alpha=0.13, linewidth=0)
ax.fill_between(D, H, req, where=(D > D_MAX),
                color=ds.FAIL, alpha=0.13, linewidth=0)

# the requirement line (slope 1 in D) and the horizon
ax.plot(D, req, color=ds.NATIVE, lw=1.3,
        label=r"reservoir must survive: $a_{\mathrm{bound}}{+}D{+}\mathrm{oh}{+}M$")
ax.axhline(H, color=ds.ACK, lw=1.3, linestyle="-",
           label=r"fail-open horizon $H=30.8$ ms")

# markers: D=16 (admitted), D_max, D=40 (refused)
def mark(d, ok, txt, dy):
    y = A_BOUND + d + OVERHEAD + M
    c = ds.PASS if ok else ds.FAIL
    ax.plot([d], [min(y, H) if ok else H], marker="o", ms=5, color=c,
            markeredgecolor="black", markeredgewidth=0.5, zorder=5)
    ax.annotate(txt, (d, (min(y, H) if ok else H)), textcoords="offset points",
                xytext=(0, dy), ha="center", fontsize=7.5, color=c)

mark(16, True, "D = 16 ms\nadmitted", 8)
ax.axvline(D_MAX, color=ds.PASS, lw=0.9, linestyle=":", zorder=1)
ax.annotate(r"$D_{\max}\approx24.8$ ms", (D_MAX, 6), rotation=90,
            va="bottom", ha="right", fontsize=7.5, color=ds.PASS)
mark(40, False, "D = 40 ms\nREFUSED", 6)

ax.set_xlabel("configured D (ms)")
ax.set_ylabel("timing horizon (ms)")
ax.set_title("Safe operating region for D", fontsize=9)
ax.set_xlim(0, 44)
ax.set_ylim(0, 44)
ax.legend(loc="upper left", fontsize=7, framealpha=0.9)

# label the two regions in-plot
ax.text(11, 33, "SAFE\ndeadline-governed", color=ds.PASS, fontsize=7.5,
        ha="center", va="center", weight="bold")
ax.text(37, 18, "UNSAFE\nfail-open pre-empts", color=ds.FAIL, fontsize=7.5,
        ha="center", va="center", weight="bold")

ds.grid(fig, ax)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out")
w = os.environ.get("D3_FIG_W")
sub = "report" if w else ""
dest = os.path.join(out, sub, "fig11_safe_d.pdf")
os.makedirs(os.path.dirname(dest), exist_ok=True)
fig.savefig(dest, transparent=True)
fig.savefig(dest.replace(".pdf", ".png"), dpi=300, transparent=True)
print("wrote", dest, "| D_max = %.3f ms" % D_MAX)
