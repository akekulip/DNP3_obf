"""Figure 14 (single column) — the MEASURED hold-continuity floor (silicon, 2026-08-03).

An OUTCOME GRID, the plainest encoding for a binary result: one row per
requested deadline D, one cell per tested reservoir size K, three trials per
cell — green if all three held the ACK for the full D, red-hatched if all three
let it escape (~1 us hold). Every row flips red -> green between K = 40 and 44,
so the floor is K = 44 and it does not depend on D. Blank = combination not
tested. Cell colors reuse the fig9 semantics (PASS green / FAIL red + hatch,
CVD-safe). All 32 tested cells were unanimous 3/3; absolute hold times and the
mechanism live in evidence/ksweep_hold/20260803T175912Z/RESULTS.md.
"""
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Patch, Rectangle

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
import utils_mpl
import d3_style as ds

ds.setup_only()
plt.rcParams["hatch.linewidth"] = 0.5

EV = Path(__file__).parents[2] / "evidence/ksweep_hold/20260803T175912Z/summary.json"
summary = json.load(open(EV))["summary"]

KS = [1, 2, 4, 8, 12, 16, 20, 24, 32, 36, 40, 44, 48, 64]
DS = [2, 8, 16]
cell = {}                                   # (d, k) -> True held / False escaped
mixed = []
for s in summary:
    held = s["n_clean"] == s["n"]
    if 0 < s["n_clean"] < s["n"]:
        mixed.append((s["d_ms"], s["k"]))
    cell[(s["d_ms"], s["k"])] = held
assert not mixed, "non-unanimous cells need a third color: %s" % mixed

fig, ax = ds.setup(size=(3.5, 1.75))

for yi, d in enumerate(DS):
    for xi, k in enumerate(KS):
        if (d, k) not in cell:
            continue                        # blank: not tested
        held = cell[(d, k)]
        ax.add_patch(Rectangle((xi + 0.06, yi + 0.08), 0.88, 0.84,
                     facecolor=ds.PASS if held else ds.FAIL,
                     hatch=None if held else "//",
                     edgecolor="black", linewidth=0.5))
# the floor: every row flips at the same column boundary
ax.axvline(11.0, color="black", ls="--", lw=1.0)

ax.set_xlim(0, len(KS))
ax.set_ylim(len(DS), 0)                     # D = 2 ms on the top row
ax.set_xticks([i + 0.5 for i in range(len(KS))])
ax.set_xticklabels([str(k) for k in KS], fontsize=7)
ax.set_yticks([i + 0.5 for i in range(len(DS))])
ax.set_yticklabels([r"$D$ = %d ms" % d for d in DS], fontsize=7.5)
ax.set_xlabel("reservoir size $K$ (tokens)", fontweight="bold")
ax.tick_params(length=0)
for s in ax.spines.values():
    s.set_visible(False)

ax.legend([Patch(facecolor=ds.PASS, edgecolor="black", lw=0.5),
           Patch(facecolor=ds.FAIL, edgecolor="black", lw=0.5, hatch="//"),
           plt.Line2D([], [], color="black", ls="--", lw=1.0)],
          ["ACK held the full $D$ (3/3)", "ACK escaped (3/3)", "floor: $K$ = 44"],
          fontsize=6.6, ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.0),
          framealpha=1.0, handlelength=1.1, borderpad=0.35, columnspacing=0.9,
          handletextpad=0.5)
ax.set_title("44 tokens are required to sustain the hold — at every $D$",
             fontsize=8.0, pad=24)
fig.tight_layout(pad=0.4)

out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig14_ksweep_hold.pdf", transparent=True)
fig.savefig(out / "fig14_ksweep_hold.png", dpi=300)
print("fig14 outcome grid: %d tested cells, all unanimous (from %s)"
      % (len(cell), EV.parent.name))
