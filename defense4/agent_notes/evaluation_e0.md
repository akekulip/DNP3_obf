# Agent note — evaluation design + E0 gate (wave 1)

**research-scientist, 2026-08-04. E0 RUN on the 480-transaction canonical set (reproduces
`dsweep_analysis.json` exactly); script captured at `defense4/analysis/e0.py` and re-run from the
repo copy this session. No hardware touched.**

## E0 result — native vs D16 (pure Defense 3), the operating point

| observable | folded AUROC | grouped-CV bal-acc | MI (bits, corr / null-95) | residual sd native→D16 | residual H native→D16 |
|---|---|---|---|---|---|
| **CLRT (ACK→resp)** | 1.000 | 1.000 | 0.95 / 0.09 | 2.836 → **0.012 ms** | 4.33 → **0.00 b** |
| **READ→ACK** | 1.000 | 1.000 | 0.97 / 0.06 | 0.820 → **0.585 ms** | 2.19 → **0.65 b** |
| **inter-arrival** | 1.000 | 1.000 | 0.94 / 0.11 | 2.935 → 0.587 ms | 4.52 → 1.47 b |
| **response size** | 0.50 (floor) | — | **0.00** | 0 → 0 | **0.00 → 0.00 b** |

Drift floor (VERIFIED): native-vs-native folded AUROC = **0.5303**; permutation bal-acc 95th ≈ 0.60.
Acceptance band [0.50, 0.60].

## The four findings that scope Defense 4

1. **CLRT device content ERASED, not merely detectable.** AUROC 1.000 = collapse-detectability ("the
   defense is on"), NOT residual device leak — the fingerprinting content is destroyed (4.33 → 0.00 b).
2. **READ→ACK is the ONE surviving real target.** D3 holds the ACK to t_ACK+D so `a` survives
   additively: **0.65 bits, sd 0.585 ms.** This is §12.4's relocation, quantified. **Defense 4's
   marginal timing win = drive this residual toward the drift floor with the switch-clock grid.**
3. **Inter-arrival is a HARNESS CONFOUND, not a device leak.** It appears only for D≥4 and tracks D
   (+D shift, tightens) because the pydnp3 test master is response-paced. A wall-clock SCADA poller
   would not show it. **Exclude from discriminative features; report with/without.**
4. **Size has NO within-READ target on this device** (single class over 300 polls, 0 bits). Size
   shaping is UNTESTABLE until a real SBO corpus exists; the size axis only becomes a target for
   cross-operation READ-vs-SBO discrimination.

**E0 verdict:** timing (READ→ACK residual) is the only axis with a live real-data target now; size has
none within-READ and is BLOCKED for cross-operation until SBO traffic is captured.

## Joint-attack design

Tasks in priority order: T1 {READ vs SBO} (arch target), T2 {device A vs B} (BLOCKED, k=1 → run vs the
synthetic population), T3 {CROB count} (needs SBO corpus). Features: per-slot sizes, direction
sequence, counts, timing (READ→ACK, CLRT, SELECT-resp→OPERATE, duration, jitter), TCP flags;
inter-arrival ONLY as a conditioning covariate. Model: XGBoost (primary, gives per-feature gain for
ablation attribution) + L2 logistic (interpretable). **Split by connection, never transaction.**
Statistics: bal-acc, ROC-AUC, PR-AUC (rare SBO class), MI with Miller-Madow + shuffle null,
block-bootstrap 95% CIs, permutation p. Headline = AUROC distance above the 0.53 floor.

## Ablation ladder (8 rungs, falsifiable per-feature predictions)

unprotected / size-only / D1-only / D2-only / D3-only(=E0 measured row) / unified-timing-only(grid) /
D4-without-filler / full-bounded-D4. **The load-bearing prediction:** rung 5→6, READ→ACK AUROC must
fall from 1.000 (0.65 b residual) to ≤0.60; if the switch-clock grid does NOT drop it, the
anchor-relocation-fix claim is refuted — the single most important comparison in the paper. Rung 6 vs
7: unified timing closes all timing axes but count/direction still leak READ-vs-SBO; if rung 7 already
closes count/direction, filler is unnecessary and Profile B is over-engineered. Rung 7→8: filler must
close count/direction at a stated overhead.

## Acceptance (two-tier)

- **Strong ("Obs(READ)≈Obs(SBO)"):** every implemented feature's joint-attacker AUROC 95%-CI upper ≤
  0.60, cross-run AND vs the synthetic population. Only rung 8, only on shape axes; plaintext →
  "shape-indistinguishable" not "semantically indistinguishable."
- **Honest ("reduces the differences"):** CI-separated AUROC drop from unprotected, but ≥1 feature
  stays >0.60. **The claim the current single-device evidence supports.**
- **Slip-rate residual metric:** P(|obs − grid_slot| > ε); pre-register a ≤1% budget. The honest
  complement to mean AUROC — a defense can hit floor on average while leaking on a 5% tail.

## The falsifier for device-independence

Synthetic device-population run: drive the SAME grid with programmed (a,c) emitters (a-med ∈ {0.2,
0.45, 1.5, 3.0} ms, c-med ∈ {0.5, 2.8, 8, 13} ms + cold-poll tail); run the joint classifier on
{device_i vs device_j}. Falsified if any feature's between-profile AUROC > 0.60. E0 predicts where it
breaks if it breaks: READ→ACK, if the slot tolerance ε < spread(a). **SUFFICIENT FALSIFIER, NOT a
sufficient confirmation** — a real device B is still required for any positive anonymity claim (k=1).

## Threats to validity (carry with every number)

n=4 effective rounds (not 480 — block by connection); k=1 device (surviving variance is necessary not
sufficient for fingerprinting); inter-arrival harness confound; CROB-size regression n=1-per-N; NO real
SBO corpus (blocks the whole size half); plaintext ceiling (shape- not semantic-indistinguishability).

## Recommended next (no-hardware): E0-replication on `physical_repaired/` (2×960) + the synthetic
falsifier. The one experiment that unblocks the rest — the real SBO corpus from a controlled OpenDNP3
outstation — should run in parallel.
