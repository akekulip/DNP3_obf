# IBSPG root-cause and repair report (Part 17)

Evidence tags: [INF]=inferred · [DOC]=documentation-supported · [OBS]=observed on silicon ·
[REP]=repeated · [FIX]=corrected/applied · [OPEN]=unresolved.

## 1. Research question
Does the IBSPG "strict-priority does not hold Q_HOLD" failure have a correctable root cause (config /
scheduler-semantics / measurement), or is it an architecture limit? A limit is permitted only after
A–E are excluded.

## 2. Prior implementation [OBS]
`tf1.tm.queue.sched_cfg` written with `scheduling_enable=true` + **`min_priority`** HIGH(7)/LOW(0) only,
via `ibspg_setup.py:set_pri`. `strict_priority_verified` asserted purely from the `min_priority` readback.

## 3. Prior failure [OBS/REP]
Q_HOLD (the held real packet's queue) received service while Q_BLOCK was reported non-empty, on both
recirc (unshaped, saturated use=126) and dp8 (shaped). Concluded — prematurely — "strict priority not
absolute."

## 4. Forensic reconstruction [OBS] — `IBSPG_EXPERIMENT_FORENSIC_LEDGER.md`
`max_priority` **never set on any queue in any run** (0 hits repo-wide); DWRR weight never set; `min_rate`
never enabled. Both silicon runs used the identical (min_priority-only) priority config.

## 5. Root-cause hypotheses — `IBSPG_ROOT_CAUSE_TREE.md`
A config · B scheduler-semantics · C blocker-replenishment · D measurement · E physical · F architecture.

## 6. Scheduler-semantics audit [DOC] — `TOFINO1_STRICT_PRIORITY_SEMANTICS_AUDIT.md` (3 SDE sources)
`tf1.tm.queue.sched_cfg` has TWO priority enums for TWO passes: **`min_priority`**
(`bf_tm_sched_q_priority_set`) orders the **guaranteed-bandwidth** pass — active only when
`min_rate_enable=true`, which **defaults false** → the HIGH/LOW set was **inert**. **`max_priority`**
(`bf_tm_sched_q_remaining_bw_priority_set`) orders the **remaining/excess** pass where two merely-
backlogged queues actually compete. `dwrr_weight` is a tie-break among *equal* priority. So both queues
fell through to the remaining pass at **equal `max_priority` + equal `dwrr_weight=1023` → a fair split**,
producing exactly the Q_HOLD service measured.

## 7. Queue-placement proof [OBS] — `ibspg_tm_readback.py`, PLACEMENT-OK
Both queues on one domain (dp8: pg_id 2; recirc: pg_id 17). Full `sched_cfg` dump before the fix:
Q_BLOCK `{min_priority:"7", max_priority:"LOW", dwrr_weight:1023, min_rate_enable:false}`; Q_HOLD
`{min_priority:"LOW", max_priority:"LOW", dwrr_weight:1023}`. **max_priority = LOW on BOTH (default);
DWRR = 1023 on BOTH (default)** — the config error, on silicon.

## 8. Finite-backlog control [OPEN — measurement limit]
Could NOT be run cleanly: a strict-priority-high queue that is eligible drains at **line rate**, so any
*finite* Q_BLOCK backlog empties in microseconds — far below the ~0.15 s ssh-read sampling resolution.
The finite-backlog oracle is not observable with counter polling; it needs on-chip µs instrumentation.

## 9. Token-loop measurements [OBS]
The blocker ring runs at ~29 M loops/s on dp8 (measured `dBLK≈4.4M`/0.15 s sample). N=8 sustains only
Q_BLOCK use=1–2 (shallow); N=128/256 peak the queue (wm≈94/126) but overflow-drop and dissipate before
sampling, or self-terminate via the pass-budget. The ring cannot be held as a clean, deep, continuously-
non-empty backlog for a measurable window.

## 10. Empty-gap analysis [OBS]
With the shallow ring (use=1–2), during the live-ring samples Q_HOLD was served at ~540k/sample (~11% of
the ~4.9M total) — the **empty-gap duty cycle** (Q_BLOCK oscillating to 0), and **identical for max HIGH
and max LOW**. The shallow ring's result is dominated by the empty-gap, not by the priority field.

## 11. Shaping-placement [OBS/DOC]
The `max_burst_size=16384`-cell default makes the PPS shaper **inert** for a small ring (ran at ~110k/s
under a "20k" shaper). And [DOC] a working max-shaper makes Q_BLOCK *ineligible* between credits (serving
Q_HOLD in the gaps) — so shaping Q_BLOCK can never demonstrate the hold; the blocker must stay unshaped
and eligible.

## 12. Internal-port comparison [OBS]
Recirc dp68 sustains a deeper backlog (use=126) than dp8 MAC-near (use≈1–2 at N=8), but the on-switch
recirc binary (`build_9132`) was the **pre-budget** build — a 5-token seed looped unbounded at ~23 M/s
(the original hang mode); drained safely with DRAIN_MATCH, then rebuilt WITH the pass-budget.

## 13. CONFIRMED ROOT CAUSE — Part-12 decision gate
**CONFIGURATION / PRIORITY-SEMANTICS ROOT CAUSE CONFIRMED** (causes A1 "wrong strict-priority field" +
A3 "DWRR still active" + B2 "min vs max are separate stages"). The prior "architecture limit" conclusion
is **withdrawn** — it rested on a scheduler in which strict (remaining-bw) arbitration was never
configured. Documentation + forensic + silicon readback all agree.

## 14. Corrective design [FIX]
`ibspg_setup.py:set_pri` now writes **`max_priority`** (HIGH on Q_BLOCK, LOW on Q_HOLD) in addition to
`min_priority`, and **verifies the `max_priority` readback** (the strict field). Q_BLOCK max-shaper left
disabled (must stay eligible). Recirc binary rebuilt WITH the pass-budget (safe).

## 15. Corrected silicon results [OBS/FIX]
The fix is applied and **verified on silicon**: readback after the corrected config shows Q_BLOCK
`max_priority=7 (HIGH)`, Q_HOLD `max_priority=LOW`, on both dp8 (pg2) and recirc (pg17). Budget-safe
recirc binary confirmed (5 tokens budget=1 → blk_loop=5, safety_expiry=5, stable). **End-to-end
demonstration that the corrected config drives Q_HOLD service to zero is NOT yet obtained** — every A/B
was confounded by §8–§10 (finite backlog unobservable; ring empty-gap/token-loss). Under the corrected
config the shallow ring still showed Q_HOLD served at the empty-gap duty cycle (same as wrong config),
because the empty-gap — not the priority field — dominates a shallow/short backlog.

## 16. Remaining limitations [OPEN]
1. The finite-backlog oracle is unobservable with counter polling (line-rate drain « sampling period).
2. The blocker ring cannot sustain a clean, deep, continuously-non-empty Q_BLOCK (empty-gap at low N,
   overflow/dissipation at high N, self-termination via budget) — this is the **blocker-replenishment /
   empty-gap problem** (cause C), now the load-bearing sub-problem, and is DISTINCT from the priority
   config (now fixed).
3. Cleanly proving strict-priority starvation therefore needs either on-chip µs instrumentation
   (per-packet timestamps/digests for dequeue ordering) or a solved empty-gap that yields a naturally
   sustained deep backlog.

## 17. Exact next experiment
Two independent tracks, either of which closes the demonstration:
- **(a) Empty-gap first (Parts 7–8):** build a blocker construction that sustains Q_BLOCK continuously
  non-empty at a bounded rate — phased multi-token, preloaded reservoir with just-in-time replenish, or
  dual-bank — measured by watermark never reaching 0; THEN re-run the corrected-`max_priority` A/B and
  expect Q_HOLD service → 0.
- **(b) Instrument the oracle:** add an egress digest carrying (queue, dequeue-timestamp) so the
  finite-backlog dequeue ORDER is captured at µs resolution; preload Q_BLOCK=N + 1 HELD (both scheduling-
  disabled), enable both, and verify all N Q_BLOCK packets dequeue before HELD under corrected
  `max_priority` and interleave under the old config.

**Status: root cause FOUND and CORRECTED (configuration); the corrected priority is verified on silicon;
the end-to-end hold demonstration is gated on the empty-gap sub-problem, not on any architecture limit.**
