# IBSPG physical-dp8 rate-bounded experiment — report (2026-07-24)

Switch **10.10.54.81** (`ufispace`, SDE 9.13.2). Branch `research/queue-resident-transaction-release`,
commit at run time `6484b17` (+ this report). P4 artifact: `p4/ibspg_mb_physL.p4`
sha256 `e630b43daf089c37174c961f8858d838fb632e8432efc80d8fe148c1ad7fa350` (program `ibspg_mb_physL`,
on-switch bf-p4c 9.13.2, 7/12 ingress stages, 0 egress). Switch **restored** to
`queue_microbench_abs.conf` after the run (1 bf_switchd, ASIC attached, hosts reachable).

## Status ladder (mandate Phase 11)
| Stage | Result |
|---|---|
| compiled (local 9.13.1 + on-switch 9.13.2) | **PASS** — 7 stages, 0 errors, sha match |
| loaded on silicon (ASIC attached) | **PASS** — after authorized `bf_kdrv` load (host had rebooted) |
| dp8 physical loopback link-validated | **PASS** — preflight exact, 0 loss |
| pass-budget safety validated | **PASS** — ring self-terminates at N×budget, no storm |
| drain / generation / release scheduler-tested | **PASS** — 4/4 reps clean |
| token isolation (dp9/dp11) | **PASS (switch-counter proof)** — dp11 tx=0; dp9 tx==releases exactly |
| strict-priority HOLD (the primitive) | **NOT ACHIEVED in the safe/shaped envelope; clean unshaped test NOT PERFORMABLE within the 50k-pps ceiling** |

## Pre-run event (recorded honestly)
The switch host had rebooted (new mgmt IP 10.10.54.81) and the Tofino kernel driver `bf_kdrv` was not
loaded → `/dev/bf0` missing, no bf_switchd could attach the ASIC (the earlier "microbench restored"
was process-up-only). The mandate forbids autonomous driver reloads; **the user explicitly authorized
the kernel reload**, after which `bf_kdrv` loaded, `/dev/bf0` appeared, and bf_switchd reached
"Operational mode set to ASIC". Only then did the experiment run.

## TM configuration (readback-verified)
- Loopback L = **dp8 physical**, `BF_LPBK_MAC_NEAR` (`mac_loopback_L: 8`). pg_id=2, pg_port_nr=0.
- **Q_BLOCK qid7 = HIGH** (`min_priority` readback `7`), **Q_HOLD qid1 = LOW** (`LOW`);
  `strict_priority_verified: true`.
- Safety shapers: Q_BLOCK 20 000 pps, Q_HOLD 50 000 pps (PPS/UPPER). (Enabling recirc on dp8 errors
  benignly — dp8 is not the recirc port; the MAC-near loopback is the path.)
- **HARD pass-budget** in the P4: blocker token's `seq` = pass budget; decremented each loop; dropped
  at 0 (`ctr_safety_expiry`). Caps total ring passes to N×budget regardless of rate.

## Phase 1 — physical dp8 loopback preflight: PASS
budget=1 tokens (exactly one loop then self-expire), injected from Hulk/dp11:
- 10 tokens → `blk_loop=10, safety_expiry=10, dp8 tx=10, dp8 rx=10`, 0 drops.
- 100 tokens ×3 → cumulative 110/210/310 on all four counters, **each burst exactly +100**, egress
  drop 0, queue drop 0. The MAC-near loopback forwards **losslessly and exactly**. NOT physical-path-blocked.

## Phase 4/5 — strict-priority hold (bounded shaped ring): HOLD NOT ACHIEVED (with a confound)
Ring N=8, budget=10 000, Q_BLOCK shaped 20k pps. Verbatim trajectory:
```
t1_ring   held_enq=0       blk_loop=45942  Q_BLOCK use=7/7  Q_HOLD use=0
t2_held+  held_enq=64546   blk_loop=73806  Q_BLOCK use=6/7  Q_HOLD use=1   (1 HELD injected)
t3_+1s    held_enq=165166  blk_loop=80310  Q_BLOCK use=0/7  Q_HOLD use=1
t4_+2s    held_enq=265786  blk_loop=80310  Q_BLOCK use=0/7  Q_HOLD use=1
t5_drain  held_enq=287286  held_rel=1  dp9 tx=1  Q_HOLD use=0             (DRAIN_MATCH)
```
- **Safety proven:** blk_loop rose 310→80310 = exactly 8×10 000 loops, then 8 expiries; ring
  self-terminated (blk_loop froze). No storm; switch healthy throughout. dp8 tx==rx=367 596 exact.
- **Hold NOT achieved:** HELD was serviced (`held_enq` climbed ~100–130k/s) while Q_BLOCK was
  backlogged (use 6–7). HELD did not sit resident.
- **Confound (critical):** Q_BLOCK is **shaped** to 20k pps to keep the ring bounded/safe. A shaped
  high-priority queue is *ineligible* between shaper credits, so strict priority correctly serves
  Q_HOLD in those windows — the observed service is at least partly the shaping, not proof that
  strict priority fails. A clean test needs an **unshaped, continuously-eligible** Q_BLOCK, i.e. a
  saturated line-rate ring — which requires >50 000 pps and is **forbidden by this experiment's
  ceiling** (and is exactly the unbounded ring that hung the switch previously).

## Phase 6/7 — drain / generation / release: PASS (4/4 reps)
Per rep (ARM reset → HELD → wrong-gen drain → matched drain):
```
rep1 unrel  held_rel=1 dp9tx=1 reg_drain=[0,0] Q_HOLD_use=1   (wrong gen: NOT released, HELD held)
rep1 match  held_rel=2 dp9tx=2 reg_drain=[1,0] Q_HOLD_use=0   (right gen: released to dp9)
... reps 2–4 identical pattern (held_rel/dp9tx 2→5) ...
```
- Unrelated (wrong-generation) drain **never** released HELD and never set `reg_drain`.
- Matched drain **always** released HELD; `dp9 tx` incremented exactly with releases (1→5).
- Byte path: HELD released to dp9 only, no internal header added (deparser emits eth+ibspg only).

## Phase 8 — internal-token visibility: PASS (switch-counter proof)
- `dp11 tx = 0` for the entire run — **no blocker token (0x88C1) egressed toward Hulk**.
- `dp9 tx` == number of releases exactly (1→5) — dp9 carried only released HELD packets, no tokens.
- All token traffic stayed on the internal dp8 loopback (dp8 tx==rx, 0 drops).
- (A host-side pcap on dp9/dp11 was not additionally captured; the switch-side per-port TX counts
  provide the escape proof. A pcap belt-and-suspenders is a remaining nicety, not a gap in the result.)

## Phase 10 — classification: **PARTIAL / hold-not-achievable-within-safe-bounds**
- **PASS** sub-mechanisms (silicon): physical loopback, pass-budget safety, drain, generation check,
  release, token isolation, clean teardown/restore.
- **NOT ACHIEVED:** the strict-priority HOLD. In every safely-bounded (≤50k pps ⇒ shaped) configuration,
  the shaping that bounds the ring creates scheduler-eligibility gaps that serve the low queue, so the
  HELD packet is not held resident. The one configuration that might hold — an **unshaped, saturated,
  continuously-eligible** high queue — is a line-rate ring the safety ceiling forbids.
- **NOT** PHYSICAL-PATH BLOCKED (path proven exact).
- **NOT** a blanket family-impossibility from one variant — but note the convergent evidence:
  **recirc result #1** (unshaped, saturated, use=126/127) already showed Q_HOLD serviced at 1.3–5.3M/s
  (strict priority not absolute); **dp8** (safely shaped) is defeated by the shaping. Together: on
  Tofino-1, a strict-priority blocker does not hold a low-priority packet resident either unshaped
  (recirc: fails) or safely-shaped (dp8: shaping serves the low queue) — the hold is not achievable
  within safe operating bounds.

## Exact next experiment
Two mutually-exclusive options, a genuine choice for Philip:
1. **Authorize a bounded but higher-rate unshaped ring on dp8** (e.g. N=16, budget set for ~1–2M total
   passes ≈ 1 s at ~2M pps — still self-terminating via the proven pass-budget, but exceeding the
   50k-pps ceiling). This is the ONLY way to test whether an unshaped continuously-eligible Q_BLOCK on
   a physical port holds Q_HOLD. Risk: higher internal load (~5% of dp8 line rate; bounded, not the
   unbounded storm that hung it before, but above the current ceiling — hence needs explicit authorization).
2. **Accept the convergent negative** (recirc unshaped fails + dp8 safe-shaped is defeated by shaping)
   and pivot to the already-identified **two-stage / backpressure** alternatives (Part 10 tail), or
   revisit whether a queue-resident hold is the right primitive at all.
