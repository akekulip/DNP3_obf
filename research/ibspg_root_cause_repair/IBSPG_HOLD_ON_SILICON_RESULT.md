# Parts 6/8 — the corrected IBSPG hold WORKS on silicon (queue-resident hold-then-release)

**Headline:** with the corrected `max_priority` (Part 3 fix), a self-replenishing blocker ring holds
co-queued packets in Q_HOLD with **zero leakage** while it runs, and **releases every held packet
intact** when it stops. Demonstrated on Tofino-1 silicon with the dequeue-order oracle. This resolves
the empty-gap question **positively** for the tested regime and overturns the pessimistic counting
model of Part 5. [OBS/REP]

## The instrument and why the first readings were misleading (honest trail)
The oracle records every packet that loops back through dp8 (role, seq, ts) into a 512-deep trace.
Three confounds had to be removed before the hold could be read correctly — each was chased down, not
assumed:
1. **`H=0` during active blocking is ambiguous** — a held HELD does not loop back, so it is simply
   *absent* from the trace; absence is not proof of holding.
2. **Trace overflow ≠ ring death.** Watching `reg_overflow` settled this: for a K=1 blocker with
   pass-budget 100 000, `reg_overflow` climbed to 99 489 (= 100 000 − 512) and *froze* — the overflow
   path **skips recording but keeps looping**, so the blocker ran its full budget (~40 ms at 408 ns/
   loop) then expired. It did **not** die at trace-fill.
3. **Consequence:** with a large budget the HELD drain *after* the trace is already full, so their
   release is unrecorded → a false `H=0`. Releasing via `mode=FINITE` or a mid-run priority flip also
   perturbed recording. All three are **measurement artifacts**, not packet loss.

## The clean test — read the dequeue ORDER, budget sized so the trace never fills
Size the blocker pass-budget so total blocker loops + 32 HELD < 512 (no overflow). Then the whole
episode is captured in index order, and the question becomes a pure ordering test:
- **all 32 HELD after the last blocker loop** ⇒ held-then-released (hold worked, 0 leak);
- **any HELD interleaved among the blocker loops** ⇒ leak during blocking.

| Config (Q_BLOCK strict HIGH) | B loops | H released | HELD leaked during hold | order transitions | verdict |
|---|---|---|---|---|---|
| K=1, budget 400 | 401 | 32/32 | **0** | 1 | HELD-THEN-RELEASED |
| K=4, budget 100 | 404 | 32/32 | **0** | 1 | HELD-THEN-RELEASED |
| K=8, budget 50  | 408 | 32/32 | **0** | 1 | HELD-THEN-RELEASED |

**Reproducibility (K=1, budget 400, 32 HELD): 15/15 reps identical — B=401, H=32, leak=0, PASS.**
Deterministic: exactly one B→H transition, first HELD at index 401, last blocker at index 400.

## Controls that make it a result, not a coincidence
- **K=0 (no blocker):** H=32, HELD drain freely from the first index (n=32, no B) — proves the HELD
  path works and that **the blocker is what holds them**. The only difference between K=0 (drain) and
  K≥1 (hold-then-release) is the blocker.
- **Held-then-released order** (transitions=1, all H after last B) rules out "served-then-lost": the
  releases occur in one clean burst *after* the blocker stops, i.e. the packets were resident and
  fail-open on blocker expiry.

## What this establishes (and the exact scope)
1. **Strict-priority hold with 0 leak, from a SINGLE recirculating token.** The Part 4/5 RTT-scale
   `dt` gaps between blocker dequeues do **not** open a service window for Q_HOLD — across ~400
   blocker loops (K=1) not one of 32 HELD escaped, 15/15. One token is sufficient; the multi-token
   reservoir the counting model called for is **not needed** in this regime.
2. **Byte/count-preserving release (fail-open).** All 32 held packets are released intact when the
   blocker stops — none dropped, none duplicated.
3. **ACK-before-response is the same primitive:** strict priority releases Q_HOLD only after the
   higher-priority stream stops — the ordering guarantee IBSPG needs.

## Honest limits — what is NOT yet shown (feeds Parts 9–13)
- **Release here is pass-budget expiry, not a deliberate drain event.** A *controlled* release (a
  data-plane drain fired at the chosen instant — Part 9/10) is the next step; budget-expiry only
  proves the hold+fail-open primitive, not timed release.
- **Hold duration = budget × RTT** (≈163 µs at budget 400). A DNP3 CLRT hold (~12.9 ms, Case A) needs
  budget ≈ 31 600 loops or, better, a controlled drain decoupled from budget.
- **Synthetic oracle packets on a MAC-near dp8 loopback**, not real DNP3 frames or the final port
  topology (Part 13 = DNP3 integration, replay first).
- **Single depth/rate point per K**, one HELD population (32). Parts 8–11 widen this (durations,
  30–100 trials, paired ACK+response).

## Bottom line
The corrected strict priority does not merely order preloaded backlogs (Part 3) — it sustains a
**live queue-resident hold**: a recirculating blocker starves Q_HOLD with zero leakage and releases
every packet intact on stop, reproducibly, with a single token. The empty-gap concern, as a leak
mechanism, does **not** materialize on silicon with the corrected configuration.
