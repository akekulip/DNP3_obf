"""Figure 13 (single column) — how many tokens a hold of D needs.

The reservoir size K must satisfy two independent bounds, and the requirement at
each D is their maximum:

  coverage  K >= ceil(RTT_loop * rate)  = 44 tokens        (D-INDEPENDENT)
      while a token is in flight around the loop the queue must still hold
      others, or Q_HOLD is served and the held packet escapes early. MEASURED
      on silicon 2026-08-03 (evidence/ksweep_hold/20260803T175912Z, fig14):
      floor = 44 at D = 2, 8 and 16 ms; implied RTT_loop in (1036, 1176] ns.
      (The earlier ~16 estimate borrowed the Part-12 build's 408 ns RTT, which
      does not transfer to this pipeline.)

  survival  B * K / rate >= D + c                          (GROWS WITH D)
      the fail-open budget must outlive the deadline plus cleanup;
      c = a_bound + t_detect + t_drain + t_tail + M ~= 6.0 ms. This is the same
      inequality parameter_policy.evaluate() enforces as D <= D_max, inverted
      for K. At the deployed B = 18000 each token buys B/rate = 0.481 ms of
      horizon; B is the cheap substitute knob (registers), K the structural one
      (pktgen batch).

  K_req(D) = max(coverage, ceil((D + c) * rate / B))

Upper context (not plotted, off-scale): the RTO floor H < RTO_min - margin caps
K <= 373 at B = 18000; the generation-wrap bound is not binding. Validation of
the coverage floor between K = 2 and K = 63 is a lab-blocked hold-integrity
sweep (early-release/gap events per K, B scaled to keep H constant).
"""
import math
import sys
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "control"))
import utils_mpl
import d3_style as ds
import parameter_policy as pp

ds.setup_only()

# ---- the two bounds, from the single admissibility authority ----------------
K_COV = 44                 # MEASURED continuity floor (ksweep_hold 2026-08-03, fig14)
SUB_MS = (pp.T_DETECT_NS + pp.T_DRAIN_NS + pp.T_TAIL_NS) / 1e6
C_MS = pp.ACK_BOUND_MS_DEFAULT + SUB_MS + pp.SAFETY_MARGIN_MS_DEFAULT
TAU_MS = pp.BUDGET_DEFAULT / pp.RATE_DP8_PPS * 1e3                 # horizon per token, ms


def k_surv(d_ms):
    return (d_ms + C_MS) / TAU_MS


def k_req(d_ms):
    return max(K_COV, math.ceil(k_surv(d_ms)))


# D_max at the deployed K = 64 (must reproduce the report's ~24.8 ms)
D_MAX_64 = pp.d_max_ms(pp.horizon_ms(pp.BUDGET_DEFAULT), pp.ACK_BOUND_MS_DEFAULT,
                       pp.SAFETY_MARGIN_MS_DEFAULT)

D_SWEEP = [1, 2, 4, 8, 16]
REQ = [k_req(d) for d in D_SWEEP]

fig, ax = ds.setup(size=(3.5, 2.5))
d = np.linspace(0, 28, 400)

ax.plot(d, np.maximum(K_COV, k_surv(d)), color=ds.NATIVE, lw=1.6, zorder=4,
        label=r"$K$ required = max(coverage, budget)")
ax.plot(d, k_surv(d), color=ds.ACK, lw=0.9, zorder=3,
        label="budget bound: 0.481 ms per token ($B$ = 18 000)")
ax.axhline(K_COV, color="0.45", ls="--", lw=0.9, zorder=2,
           label="coverage floor = 44 (measured, fig14)")
ax.axhline(64, color=ds.PASS, ls="-", lw=1.1, zorder=2,
           label="deployed $K$ = 64 ($D_{max}$ = %.1f ms)" % D_MAX_64)

ax.plot(D_SWEEP, REQ, "o", color=ds.NATIVE, ms=3.4, zorder=5)
prev = None
for x, y in zip(D_SWEEP, REQ):          # label the first point of each value run
    if y != prev:
        ax.annotate(str(y), (x, y), xytext=(0, 6), textcoords="offset points",
                    ha="center", fontsize=6.6, zorder=6)
    prev = y
ax.plot([D_MAX_64], [64], "s", color=ds.PASS, ms=3.8, zorder=5)
ax.annotate("%.1f" % D_MAX_64, (D_MAX_64, 64), xytext=(0, -9),
            textcoords="offset points", ha="center", fontsize=6.6,
            color=ds.PASS, zorder=6)

ax.set_xlim(0, 28)
ax.set_ylim(0, 80)
ax.set_xticks([0, 4, 8, 12, 16, 20, 24, 28])
ax.set_xlabel(r"$D$ (ms) — the chosen ACK hold", fontweight="bold")
ax.set_ylabel(r"tokens $K$", fontweight="bold")
ax.legend(fontsize=6.2, loc="lower right", framealpha=1.0, handlelength=1.6,
          borderpad=0.35, labelspacing=0.3)
utils_mpl.set_grid(fig, ax)
ax.set_axisbelow(True)

out = Path(__file__).parents[1] / "out"
fig.savefig(out / "fig13_k_required.pdf", transparent=True)
fig.savefig(out / "fig13_k_required.png", dpi=300)
print("fig13: c = %.4f ms, tau = %.4f ms/token, K_cov = %d" % (C_MS, TAU_MS, K_COV))
print("fig13: K_req at D=%s -> %s" % (D_SWEEP, REQ))
print("fig13: D_max(K=64) = %.2f ms | RTO cap K <= %d"
      % (D_MAX_64, math.floor((pp.RTO_MIN_MS_DEFAULT - pp.RTO_MARGIN_MS_DEFAULT)
                              / TAU_MS)))
