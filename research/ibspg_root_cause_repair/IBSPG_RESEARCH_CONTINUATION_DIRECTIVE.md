# IBSPG research continuation — record correction (dated addendum, 2026-07-24)

This is a **dated addendum**, not a rewrite. All prior reports (`IBSPG_MICROBENCH_FINAL_REPORT.md`,
`EXPERIMENT_RESULT_recirc_L.md`, `IBSPG_PHYSICAL_DP8_RATE_BOUNDED_REPORT.md`,
`TOFINO_INTERNAL_BACKPRESSURE_AUDIT.md`, `TWO_STAGE_QUEUE_RELEASE_ALTERNATIVES.md`,
`NEXT_QUEUE_PRIMITIVE_EXPERIMENT.md`, `PSCHED_MICROBENCH_RESULT.md`) stand unaltered as evidence.
Branch `research/ibspg-root-cause-repair` off `38d02c8`; the endpoint-timing pivot commit (`48caef2`)
is left on `research/queue-backpressure-release` and is **not carried forward** — the pivot is withdrawn.

## What was actually implemented (verified)
- `p4/ibspg_microbench/p4/ibspg_mb.p4` (recirc L=dp68) and `ibspg_mb_physL.p4` (physical L=dp8), TNA,
  6–7 ingress stages; roles BLOCKER/HELD/DRAIN_M/DRAIN_U/ARM; drain-gated release; **hard pass-budget**
  on the blocker token (seq decrement, drop at 0). Compiled local 9.13.1 + on-switch 9.13.2.
- Control plane `control/ibspg_setup.py`: host ports up; recirc/mac-loopback; `tf1.tm.queue.sched_cfg`
  `scheduling_enable=true` + `min_priority` HIGH/LOW; optional Q_BLOCK / Q_HOLD PPS shapers. Readers
  `harness/ibspg_read.py`, `control/psched_ctl.py`; host generator `harness/ibspg_gen.py`.

## What was actually tested (two silicon runs + P-SCHED)
1. **Recirc L=dp68**, self-looping ring, **unshaped**, N∈{1,8,64,256}; host-injected from Hulk/dp11.
2. **Physical L=dp8** MAC-near loopback, self-looping ring, **Q_BLOCK SHAPED to 20k pps** (+ Q_HOLD
   50k safety cap), N=8 budget=10000; drain-logic reps ×4.
3. **P-SCHED** on dp8: control-plane `scheduling_enable=false` hold.

## What passed (remains valid, scoped)
- Physical dp8 MAC-near loopback is reliable for the tested bursts (preflight exact, 0 loss).
- Pass-budget termination exact (N×budget loops then self-terminate; no storm).
- Generation-safe drain: wrong-gen never released; matched-gen released; `dp9 tx` == releases exactly.
- Internal-token isolation: `dp11 tx=0`; blocker (0x88C1) never on a protected port.
- P-SCHED: `scheduling_enable=false` holds a packet queue-resident (usage=1, 0 drops, 2s), not
  recirculating; a control-plane re-enable releases it. **This isolates the direct-TM-actuation limit
  only.**

## What FAILED (scoped to the tested configuration)
The tested IBSPG configurations did not achieve a reliable bounded strict-priority hold: HELD received
service while Q_BLOCK was reported nonempty. **Scoped to the tested queue mappings, token populations,
shaping settings, loopback paths, and safety ceilings.**

## Claims that were TOO BROAD (withdrawn during this campaign)
- "IBSPG is refuted" / "strict-priority occupancy gating is universally refuted" — **withdrawn.**
- "in-network holding is systematically infeasible" — **withdrawn.**
- "the negative result is the contribution" / "endpoint timing is the proven path" — **withdrawn.**
- The convergence of the shaped-dp8 confound + the recirc result into an architecture-limit conclusion
  was premature: causes A–E (below) were not excluded first.

## What remains UNRESOLVED (the actual open questions)
1. **Scheduler semantics unproven (Part 4):** is `min_priority` even the field that produces strict
   (absolute) priority arbitration, or is it a *minimum-bandwidth* priority while strict/excess uses
   `max_priority` or a different mechanism? Never verified against SDE docs — inferred from the field
   name, which the directive forbids.
2. **Queue/priority placement unproven (Part 5):** Q_BLOCK (qid7) and Q_HOLD (qid1) were assumed to
   share one arbitration domain (same dev_port). L1-node attachment / scheduler parent never read back.
3. **No clean finite-backlog control (Part 6):** the recirc test was unshaped but on the recirc port
   (possibly a different scheduler domain) with a self-looping ring (loopback-gap confound + coarse
   occupancy sampling); the dp8 test SHAPED Q_BLOCK (self-inflicted eligibility-gap confound). Neither
   answers the clean question "does the scheduler serve Q_HOLD while Q_BLOCK holds a real, finite,
   UNSHAPED backlog in a proven-same domain?"
4. **Empty-gap never measured directly (Part 7):** loopback round-trip vs service interval, token
   phasing, and the minimum safe N were never instrumented per-token.
5. **Measurement resolution (Part 3-D):** occupancy reads were polled (coarse); sub-µs Q_BLOCK-empty
   intervals are invisible — "reported nonempty" ≠ "continuously eligible."

## Why further root-cause work is required
An architecture-limit conclusion is permitted only after configuration, scheduler-domain, priority-
semantics, measurement, and physical-path causes are excluded and a targeted silicon experiment
confirms the predicted behavior with no unresolved confound. **None of A–E were excluded.** The
campaign (Parts 2–17) will reconstruct the runs forensically, prove the scheduler semantics and queue
placement, run the clean finite-backlog oracle, measure the loop dynamics, and correct the mechanism.

## Language discipline for this phase
Only "the tested configuration failed", "the current root cause is…", "this correction was
evaluated…", "this mechanism remains unvalidated", "scoped to the tested configuration". No
impossibility/refutation/endpoint-pivot language. Memory updated only with tested config + measured
result + identified cause + correction + corrected result.
