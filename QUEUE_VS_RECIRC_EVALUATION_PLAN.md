# QUEUE_VS_RECIRC_EVALUATION_PLAN.md — Recirculation vs queue evaluation (Phase 8)

_Master direction Phase 8. Produced 2026-07-21 on `research/caseA-ditto-queue`. This is a **plan**
(off-switch); **execution is gated** on a hardware window and on Phase-4 (microbenchmark) and
Phase-6/7 (queue Defense 1/2) being in place. Feeds paper §VII (`PAPER_OUTLINE.md`) and the
selection deferred in `CASE_A_QUEUE_DESIGN.md`._

> **Purpose (master direction Phase 8).** Directly compare the **recirculation** timing mechanism
> (frozen feasibility baseline) against the **queue/hybrid** mechanism for **both** Case-A defenses,
> under load, and answer which is more **stable, lower-overhead, more defensible, cheaper in
> resources, and better-scaling — and whether either creates a NEW timing fingerprint.** **Do not
> claim the queue is better before this comparison is complete** (master direction Phase 4/8).

---

## 1. Arms to compare (master direction Phase 8)
1. **Native** (no defense) — the SEL-751 capture-replay baseline (and physical, once Phase 5 lands).
2. **Defense 1 — recirculation** (frozen `dcrn_defense1.p4`; the proven baseline).
3. **Defense 1 — queue / hybrid** (the D1-A/B/C mapping selected by Phase 4).
4. **Defense 2 — recirculation** (frozen `dcrn_defense2.p4`).
5. **Defense 2 — queue scheduling** (the P-A…P-E policy selected by Phase 4/5).

## 2. Conditions (master direction Phase 8)
`idle · low · moderate · high` background load × `mixed packet sizes` × `long continuous operation`.
Reuse the Phase-4 background-load generator; the long-continuous run checks drift/occupancy and the
"no cold reload / zero stale state" invariant.

## 3. Metrics (master direction Phase 8 — measure all, per arm × condition)
**Timing:** ACK→response (CLRT) · request→ACK · request→response · added response latency · jitter ·
deadline/slot error (realized − target).
**Transport safety:** retransmissions · resets · packet loss · duplicates · reordering · payload
byte-identity.
**Mechanism cost:** queue occupancy · recirculation passes · internal (recirc/loopback) bandwidth.
**Switch resources:** ingress+egress stages · SRAM · TCAM · stateful ALUs · parser rows · port
consumption · power estimate where available.

Report mean/median/std/p50/p90/p99/worst-case for the timing metrics with confidence intervals and
**independent hardware runs** (do not resample one run).

## 4. Questions the result must answer (master direction Phase 8)
- Which mechanism is **more stable under load**? (recirc drain offset is load-dependent —
  `ASSUMPTIONS_AND_UNKNOWNS.md` #4/#5; Ditto shaper is "correct on average" — S10.)
- Which adds **less operational latency**?
- Which is **easier to justify** as a predictable timing policy? (Dr. Lin's core concern, meeting §6.)
- Which uses **fewer switch resources** and **scales better** (more protected flows/ports)?
- **Does either mechanism create a NEW timing fingerprint?** (constant-gap / pass-count / slot-cadence
  artifacts — ties to the Phase-9 adaptive attacker, `ASSUMPTIONS_AND_UNKNOWNS.md` #17.)

## 5. Fairness / validity controls
- Same replayed SEL-751 input (and same physical device, once Phase 5 lands) across all arms.
- **Grouped** comparison by hardware run / connection / session (no cross-session leakage) — mirrors
  the Phase-9 split discipline and the Formby window semantics (`FORMBY_SOURCE_MAP.md` cautions 1–2).
- Recirc and queue arms measured on the **same** shared-chip conditions and background load.
- Every number tagged physical vs **"capture-derived live-TCP replay"** (master direction §12).

## 6. Honest-reporting rules (master direction §13)
Report failed conditions, packet loss, resource overuse, and any timing offset — do **not** hide them.
Never treat MAX_PASS as normal release or a cold reload as continuous operation. A recirc "constant"
that is actually `G_i + drain-offset` must be reported as such (#4/#5). If the queue is NOT better on
some axis, say so — the comparison, not a preferred conclusion, is the deliverable.

## 7. Output
`QUEUE_VS_RECIRC_RESULT.md` + `tab:queue_vs_recirc` (paper §VII) + a one-paragraph verdict per
Phase-8 question, each backed by measured numbers with CIs.

**Status: PLAN COMPLETE. Execution NOT_STARTED — gated on a hardware window and on Phases 4/6/7.**
