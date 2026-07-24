# IBSPG root-cause tree (Part 3)

**Observed failure (scoped):** in the tested configurations, HELD_REAL in Q_HOLD received service while
Q_BLOCK was *reported* nonempty. Causes A–E must be excluded before F (architecture limit) is permitted.
Each node: **predicted observation if this is the cause · distinguishing experiment · required evidence
· correction if confirmed.**

## A. CONFIGURATION ERROR
- **A1 wrong strict-priority field** (set `min_priority` when strict/absolute arbitration uses
  `max_priority` or a `bf_tm_sched_q_priority` call): *predicted* — readback shows `max_priority` unset/
  default while only `min_priority` was written; the scheduler never had a strict pass configured.
  *Experiment* — Part 4 semantics audit + Part 5 readback dump of BOTH priority fields. *Evidence* —
  full `sched_cfg` dict for both queues. *Correction* — set the correct field/API; re-run Part 6.
- **A2 reversed priority numbering** (HIGH/LOW map opposite to intent): *predicted* — Q_HOLD readback ≥
  Q_BLOCK. *Experiment* — Part 5 readback. *Correction* — swap.
- **A3 DWRR still active / min-rate/max-rate inadvertently enabled**: *predicted* — `dwrr_weight`≠0 or
  `*_rate_enable`=true on Q_BLOCK/Q_HOLD in readback → DWRR/rate arbitration instead of strict.
  *Experiment* — Part 5 readback. *Correction* — clear DWRR/rate; re-run Part 6.
- **A4 shaping on the wrong object / Q_BLOCK shaped** (dp8 run shaped Q_BLOCK to 20k): *predicted* —
  the eligibility gap is a shaping artifact, not a priority failure. *Experiment* — Part 6 with
  shaping DISABLED; Part 9 shaping-placement study. *Correction* — no Q_BLOCK shaping in the control.
- **A5 Q_BLOCK & Q_HOLD not in the same arbitration domain**: *predicted* — readback/port.cfg shows
  different pg_id / L1 parent / dev_port. *Experiment* — Part 5 domain check. *Correction* — remap to
  one domain.
- **A6 stale bfrt state / program-setup mismatch**: *predicted* — readback ≠ intended; wrong program
  bound. *Experiment* — Part 5 fail-loud checks + cold reload before the control. *Correction* — reload.

## B. SCHEDULER-SEMANTICS ERROR
- **B1 "strict priority" not absolute in the tested hierarchy** (min-service/anti-starvation floor):
  *predicted* — even with a correct, unshaped, finite Q_BLOCK backlog in one domain, Q_HOLD still gets
  a small guaranteed service. *Experiment* — Part 4 (is there a documented floor?) + Part 6 finite-
  backlog oracle. *Evidence* — SDE doc citation + Q_HOLD dequeue-count while Q_BLOCK nonempty.
  *Correction* — if a floor exists, use the field that disables it, else this is a genuine semantics
  limit (scoped, not global).
- **B2 min_priority vs max_priority are separate stages**: *predicted* — Part 4 shows min governs the
  min-rate pass and max governs the excess/strict pass; setting only min gives no strict pass.
  *Experiment* — Part 4. *Correction* — configure the strict (max/excess) stage.
- **B3 shaping changes eligibility before priority arbitration**: *predicted* — Part 4 confirms a
  credit-exhausted shaped queue is ineligible and a lower queue is served. *Experiment* — Part 4 + Part
  9. *Correction* — never shape Q_BLOCK; pace the source instead (Part 8-E).
- **B4 recirc-port scheduling differs from physical-port**: *predicted* — Part 4 doc + Part 10 shows
  different behavior on dp68 vs dp8. *Experiment* — Part 10 same-program comparison. *Correction* —
  use the port type with correct strict-priority semantics.

## C. BLOCKER-REPLENISHMENT ERROR (only relevant to the ring, not the finite-backlog control)
- **C1 Q_BLOCK momentarily empty (loopback RTT > service interval); C2 N too small; C3 tokens
  bursty/synchronized; C4 shaping empty periods; C5 token loss; C6 pass-budget-expiry gap; C7 ring
  established too late**: *predicted* — Part 6 (finite backlog, no ring) shows strict priority WORKS,
  but the ring fails → the gap is replenishment, not priority. *Experiment* — Part 7 per-token loop
  instrumentation (RTT, service interval, min/max gap, N sweep). *Evidence* — measured
  N_required > RTT/service_interval + jitter margin. *Correction* — Part 8 constructions (phased,
  reservoir, dual-bank, upstream-paced).

## D. MEASUREMENT ERROR
- **D1 coarse occupancy sampling hides sub-µs Q_BLOCK-empty**: *predicted* — "reported nonempty" but
  actually gapping; finer evidence (watermark deltas, per-packet event counts, held-packet enqueue/
  dequeue counts) reveals gaps. *Experiment* — Part 6/7 use exact enqueue/dequeue COUNTS and watermark,
  not polled usage; repeated-trial premature-release statistics. *Correction* — count-based evidence.
- **D2 wrong-queue read / D3 stale counters / D4 capture not on protected egress / D5 held packet
  dropped-not-held / D6 clock-domain**: *Experiment* — Part 5 readback confirms the queue identity;
  Part 6 confirms drop=0 and held-packet enqueue==dequeue accounting; captures on dp9 AND dp11.
  *Correction* — fix the instrument.

## E. PHYSICAL-PATH ERROR
- **E1 dp8 intermittent / E2 FEC-PCS / E3 loopback-path mismatch / E4 MAC-near vs physical / E5 flap /
  E6 wrong port-role mapping**: *predicted* — preflight loss/flap or role inversion. *Experiment* —
  Part 6/10 preflight (exact tx==rx, 0 error/flap) before the control; Part 10 port-type comparison.
  *Evidence* — port error/flap counters, exact loopback tx==rx. *Correction* — use a verified path.
  (Note: dp8 MAC-near loopback preflight was already exact in the prior run — E is currently low-prior.)

## F. ARCHITECTURE LIMIT — permitted ONLY after A–E excluded
- **F1 Q_HOLD receives service while Q_BLOCK is continuously nonempty AND eligible** in a proven-same
  domain, correct strict-priority config, no shaping, count-based evidence, no unresolved confound.
  *Experiment* — Part 6 finite-backlog oracle is the decider. *Evidence* — Q_HOLD dequeue-count > 0
  while Q_BLOCK enqueue−dequeue > 0 and eligible, across repeats. *Correction* — if F1 holds under all
  the above, the strict-priority hold is a scoped Tofino-1 limit → escalate to Part 8-E/8-C/8-D and the
  two-stage alternatives; still NOT a global impossibility claim without Philip's closure review.

## Priority of investigation
1. **Part 5 readback** (excludes/confirms A1–A6, D2) — do FIRST; cheap, decisive for config errors.
2. **Part 4 semantics** (B1–B4, and tells us the correct field for A1) — in flight.
3. **Part 6 finite-backlog oracle, UNSHAPED, correct config, proven domain** (separates B/F from C, and
   D via counts) — the load-bearing control.
4. Only if Part 6 = STRICT-PRIORITY CONFIRMED do the ring/empty-gap parts (7–8) become the failure locus.
