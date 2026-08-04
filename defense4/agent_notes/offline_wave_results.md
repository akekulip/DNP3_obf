# Offline evidence wave — results (per the directive)

**2026-08-04. Executed the first offline evidence wave (`DEFENSE4_DIRECTIVE.md` §4). No switch touched,
no SEL-751 actuation. The stripped-D2 + MB-1 compiles are running in a delegated offline pass; this
note records the corpus, the Part-12 unit settlement, and the E0 reproduction.**

## 1. Emulator full SBO corpus — CAPTURED (directive §4.2)

`run_multicrob_sweep.py --points 1,2,4,8,16` (plus the pre-existing N=17/32/64/128 captures), Vision
master ↔ **Hulk simulated `--control-test` outstation**, management network — **no SEL-751, no Tofino
data-plane path.** Captures preserved under `defense4/evidence/sbo_corpus/`.

**Harness caveat (honest):** the sweep's pass-gate returned `pass=False` (`task_completion=None`,
`out_match=False`) — a master-reporting fidelity issue, NOT a corpus failure. The **wire captures are
clean and complete** (SELECT/OPERATE/responses all present); the *semantic* success (did the control
apply) is unconfirmed and needs the harness fixed before any functional-correctness claim. For the
**size envelope** (what the size plane needs) the wire sizes are authoritative and solid.

### The SBO size envelope — VERIFIED, full N=1..16 sweep (16 points, linear)

| unit | direction | TCP payload (B) | slope |
|---|---|---|---|
| SELECT request (func 3) | M→O | 35 (N=1) → 254 (N=16) | **14.6 B/CROB** |
| OPERATE request (func 4) | M→O | identical to SELECT (35→254) | 14.6 B/CROB |
| SELECT-RESPONSE (func 129) | O→M | 37 (N=1) → 256 (N=16) | **14.6 B/CROB** |
| OPERATE-RESPONSE (func 129) | O→M | identical (37→256) | 14.6 B/CROB |

Slope = (254−35)/(16−1) = **14.6 B/CROB**, both directions (the outstation echoes the CROBs with
status). **This supersedes the "n=1-per-N" caveat: the 14.6 B/CROB channel is now a full 16-point
linear fit.** Rejection boundary: **N ≥ 17 → only a SELECT frame, no OPERATE** (TOO_MANY_OPS,
`maxControlsPerRequest`); the successful SBO envelope is N = 1..16.

### ★ Correction to the E0 "size has no target" finding

E0 correctly found the **Class-0 READ response** is a single constant size (0 bits). But the **SBO CROB
count is a strong, real size channel in BOTH directions (14.6 B/CROB, N=1..16)**. So the size plane
has a genuine target — the CROB count — which is exactly why Defense 4 keeps the size substrate as a
first-class work package (per the directive), not future work. My adversarial-review-driven "size = no
target / future work" framing was over-broad: it applied to the READ response, not to SBO.

Emulator ACK behaviour: piggybacked (Case B, PSH+ACK on the data frames) — the emulator has no separate
CLRT, so it cannot exercise the separate-ACK timing Defenses 1/2/3 shape (that stays a physical-SEL
READ-only measurement). Consistent with prior findings.

## 2. Part 12 release-tail — UNIT SETTLED: ~1.72 µs (directive §4.4)

From the raw 100-rep campaign (`research/ibspg_hold_response/evidence/part12/rep_campaign_100/campaignA_summary.json`,
G = 20 ms = 20,000,000 ns):
- `deadline_error_ns`: min **1720**, mean **1734.53**, median **1735** ns
- `c2_block_term_to_release_ns`: min 1717, mean 1720.13, median **1720** ns
- `g_observed_ns`: mean 20,001,734.53 ns (= G + the tail)

**The release tail is ~1.72 µs (1720–1735 ns), NOT 1.72 ms.** VERIFIED from raw timestamps. The HOLD is
ms-scale (the deadline G/D); the release TAIL after the deadline is microseconds. The feasibility
prompt's "1.72 ms" was a units slip. The evidence ledger's flag is confirmed.

## 3. E0 timing analysis — REPRODUCED (directive §4.5)

`defense4/analysis/e0.py` re-run from the repo copy this session: CLRT residual sd 2.836→**0.012 ms**
(4.33→0.00 bits, device content ERASED), READ→ACK sd 0.820→**0.585 ms** (2.19→**0.65 bits**, the surviving
relocation target), response size **0 bits** (constant). The synthetic-population run is a **falsifier**
for the grid's device-independence, **not** cross-device anonymity evidence (k=1). Full detail in
`agent_notes/evaluation_e0.md`.

## 4. Still running

- **Stripped Defense 2 core** — offline compile for the REAL resource baseline (do not retain the "7–8
  stage" estimate unless the compiler proves it).
- **MB-1** — the decisive combined ingress compile INCLUDING the full size-control surface (`size_profile`
  select, per-slot size lookup, outer-header fields, real/filler tagging) + the timing predicates + SBO
  linkage. Decision rule: ≤12 → single-pass GO; >12 → two-pass / ingress-egress redistribution; still
  infeasible → NO-GO for that profile (scope the profile, do not drop the size axis).

## 5. Still needed for the size half

Comparable **READ traces with varying response sizes** on the same emulator stack (directive §4.3) — the
`--control-test` outstation is control-only; a general-READ emulator config (multiple object groups) is
needed to give the READ size envelope the template must match against the SBO envelope above.
