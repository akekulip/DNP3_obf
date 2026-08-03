"""Native CLRT and response latency of the two physical devices, per transaction.

100 native Class 0 polls per device (4 interleaved blocks x 25, single-segment reads --
NOTHING here is the induced split-read observable), 2026-08-03,
evidence/20260803_native/.

The left panel is the quantity Defense 3 conceals, and it is the point of the figure:
the SEL-751 has a CLRT to show; the ION7550 has none to show, because it never emits a
separate acknowledgement. That absence is drawn as an absence -- an empty column with its
0-of-100 count -- rather than filled with a substitute number.

The right panel is the quantity that DOES exist for both devices, so the two are actually
comparable somewhere: the total read-to-response turnaround. Note it is nearly the same
for both (~2.9 ms), which is what makes the left panel a statement about acknowledgement
BEHAVIOUR and not about device speed.

Devices are encoded by x position, so colour would be redundant; it is therefore not used
to distinguish them, and no colour here carries the d3_style packet semantics.
"""
import glob
import json
import os
import statistics as st
import sys
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parents[2] / "defense3/figures/src"))
import utils_mpl
import d3_style as ds

ds.setup_only()
rng = np.random.default_rng(7)                      # jitter only; no data is randomised

EV = Path(__file__).parent / "evidence/20260803_native"
DEV = [("sel751", "SEL-751\n(separate ACK)"), ("ion7550", "ION7550\n(combined ACK)")]

data = {}
for key, _ in DEV:
    clrt, r2r, n_tx = [], [], 0
    for f in sorted(glob.glob(str(EV / ("%s_r*.json" % key)))):
        d = json.loads(open(f).read().split("ACKMODE ", 1)[1])
        for row in d["rows"]:
            n_tx += 1
            if row.get("clrt_ms") is not None:
                clrt.append(row["clrt_ms"])
            if row.get("read_to_resp_ms") is not None:
                r2r.append(row["read_to_resp_ms"])
    data[key] = {"clrt": clrt, "r2r": r2r, "n": n_tx}

fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.6))


def strip(ax, xi, vals, color):
    """One device's measurements as a jittered cluster with a median bar."""
    if not vals:
        return
    x = xi + rng.uniform(-0.13, 0.13, len(vals))
    ax.plot(x, vals, "o", ms=2.6, mfc=color, mec="black", mew=0.25, alpha=0.75,
            ls="none", zorder=3)
    m = st.median(vals)
    ax.plot([xi - 0.26, xi + 0.26], [m, m], "-", color="black", lw=1.4, zorder=5)
    ax.annotate("%.2f" % m, (xi + 0.28, m), fontsize=6.4, va="center", ha="left",
                zorder=6)


# ---- (a) the CLRT: exists for one device, does not exist for the other ---------------
ax = axes[0]
strip(ax, 0, data["sel751"]["clrt"], ds.ACK)
ax.axvspan(0.45, 1.55, color="0.93", zorder=0)
ax.text(1.0, 3.0, "no separate ACK,\nso no CLRT exists\n(0 of %d transactions)"
        % data["ion7550"]["n"], fontsize=6.8, ha="center", va="center",
        color=ds.FAIL, zorder=4)
ax.set_xlim(-0.55, 1.55)
ax.set_ylim(1.0, 30)
ax.set_yscale("log")
ax.set_xticks([0, 1])
ax.set_xticklabels([d[1] for d in DEV], fontsize=7.2)
ax.set_ylabel("native CLRT (ms)", fontweight="bold")
ax.set_title("(a) the leak Defense 3 conceals", fontsize=8.4, pad=3)

# ---- (b) read->response: the quantity both devices actually have ---------------------
ax = axes[1]
for xi, (key, _) in enumerate(DEV):
    strip(ax, xi, data[key]["r2r"], ds.ACK if xi == 0 else ds.RESPONSE)
ax.set_xlim(-0.55, 1.55)
ax.set_ylim(1.0, 30)
ax.set_yscale("log")
ax.set_xticks([0, 1])
ax.set_xticklabels([d[1] for d in DEV], fontsize=7.2)
ax.set_ylabel("native READ $\\rightarrow$ RESPONSE (ms)", fontweight="bold")
ax.set_title("(b) the quantity both devices have", fontsize=8.4, pad=3)

for a in axes:
    utils_mpl.set_grid(fig, a)
    a.set_axisbelow(True)
    a.xaxis.grid(False)
fig.tight_layout(pad=0.4)

out = Path(__file__).parent / "out"
out.mkdir(exist_ok=True)
fig.savefig(out / "fig_native_clrt.pdf", transparent=True)
fig.savefig(out / "fig_native_clrt.png", dpi=300)

for key, label in DEV:
    d = data[key]
    def q(v, p):
        return np.percentile(v, p) if v else float("nan")
    print("%-8s n_tx=%3d | CLRT n=%3d %s | R2R n=%3d med %.3f p05 %.3f p95 %.3f"
          % (key, d["n"], len(d["clrt"]),
             ("med %.3f min %.3f max %.3f" % (st.median(d["clrt"]), min(d["clrt"]),
                                              max(d["clrt"]))) if d["clrt"] else "NONE",
             len(d["r2r"]), st.median(d["r2r"]), q(d["r2r"], 5), q(d["r2r"], 95)))
