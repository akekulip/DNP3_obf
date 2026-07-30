"""Figure 7 (double column) — the requested direct comparison: every measured CLRT,
native and under Defense 3, as points rather than summaries. (b) shows WHERE the
information went: out of the vertical axis and into the horizontal one."""
import sys, json
from pathlib import Path
import numpy as np, matplotlib.pyplot as plt
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl, paper_palettes as pp
utils_mpl.set_global(); C = pp.get("alessandretti-nature")

DATA = Path(__file__).parents[2] / "evidence/physical/dsweep_blocks.jsonl"
by = {}
for line in open(DATA):
    r = json.loads(line)
    by.setdefault(r["arm"], []).extend(r["block"]["rows"])
ARMS = ["native", "d1", "d2", "d4", "d8", "d16"]
LAB  = ["native", "$D$=1", "$D$=2", "$D$=4", "$D$=8", "$D$=16"]
FLOOR = 0.006                     # where a below-resolution 0 is drawn
RES   = 0.001                     # 1 us libpcap timestamp resolution

rng = np.random.default_rng(7)    # jitter only; no data is randomised
fig = plt.figure(figsize=(7.16, 2.75))
gs  = fig.add_gridspec(1, 2, width_ratios=[1.15, 1.0], wspace=0.26)

# ---------------- (a) every CLRT, native and protected ----------------
ax = fig.add_subplot(gs[0])
ax.axhspan(FLOOR/2.4, FLOOR*1.9, color="0.88", zorder=0)
ax.text(-0.50, FLOOR*2.4, "CLRT measured as 0: below the 1 $\\mu$s capture resolution",
        fontsize=6.0, va="bottom", ha="left", color="0.15", zorder=6)
nz = {}
for i, a in enumerate(ARMS):
    c = np.array([x["clrt_ms"] for x in by[a]])
    nz[a] = int((c == 0).sum())
    y = np.where(c == 0, FLOOR, c)
    x = i + rng.uniform(-0.26, 0.26, size=y.size)
    col = C[0] if a == "native" else C[1]
    ax.scatter(x, y, s=5.5, fc=col, ec="none", alpha=0.62, zorder=3,
               label=("native, $n$=80" if i == 0 else ("Defense 3, $n$=80 each"
                      if i == 1 else None)))
    m = float(np.median(y))
    ax.plot([i-0.34, i+0.34], [m, m], color="black", lw=1.5, zorder=5,
            solid_capstyle="butt")
ax.set_yscale("log")
ax.set_ylim(FLOOR/2.4, 40)
ax.set_xlim(-0.62, len(ARMS) - 0.38)
ax.set_xticks(range(len(ARMS))); ax.set_xticklabels(LAB, fontsize=7.4)
ax.set_ylabel("observed CLRT (ms)", fontweight="bold")
ax.set_xlabel("the chosen ACK hold $D$ (ms)", fontweight="bold")
ax.set_title("(a) every measured CLRT; black bars are medians", fontsize=8.6, pad=3)
ax.legend(fontsize=6.6, loc="upper right", framealpha=0.97, handlelength=0.9,
          borderpad=0.32, labelspacing=0.22, scatterpoints=1, markerscale=1.9)
utils_mpl.set_grid(fig, ax)

# ---------------- (b) where the information moved ----------------
ax = fig.add_subplot(gs[1])
for a, col, mk, lab in (("native", C[0], "o", "native"),
                        ("d2",     C[1], "s", "$D$ = 2 ms"),
                        ("d16",    C[2], "^", "$D$ = 16 ms")):
    k = np.array([x["read_to_ack_ms"] for x in by[a]])
    c = np.array([x["clrt_ms"]       for x in by[a]])
    ax.scatter(k, np.where(c == 0, FLOOR, c), s=8, marker=mk, fc=col, ec="none",
               alpha=0.66, label=lab, zorder=3)
ax.set_yscale("log"); ax.set_xscale("log")
ax.set_ylim(FLOOR/2.4, 40); ax.set_xlim(0.24, 40)
ax.set_xlabel("READ $\\rightarrow$ ACK (ms)  —  what the defense creates",
              fontweight="bold")
ax.set_ylabel("CLRT (ms)  —  what it hides", fontweight="bold")
ax.set_title("(b) the leak is moved, not destroyed", fontsize=8.6, pad=3)
ax.annotate("", xy=(16.0, 0.082), xytext=(6.3, 7.4),
            arrowprops=dict(arrowstyle="-|>", lw=1.0, color="0.35"))
ax.text(25.0, 0.42, "increasing $D$", fontsize=6.8, color="0.28", ha="center")
ax.legend(fontsize=6.8, loc="lower left", framealpha=0.97, handlelength=0.9,
          borderpad=0.32, labelspacing=0.22, scatterpoints=1, markerscale=1.7)
utils_mpl.set_grid(fig, ax)

fig.subplots_adjust(left=0.085, right=0.988, top=0.885, bottom=0.235)
out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig7_scatter.pdf", transparent=True)
fig.savefig(out / "fig7_scatter.png", dpi=300)
print("fig7 ok  zeros per arm:", {a: nz[a] for a in ARMS})
