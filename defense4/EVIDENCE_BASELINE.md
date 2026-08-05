# Defense 4 — evidence baseline (frozen sources reused)

The timing core is grounded in these frozen, already-validated sources. They are **referenced in place**
(not copied into `defense4/`) and must **not be modified**.

| # | mechanism | source (do not modify) | status / what it proves |
|---|---|---|---|
| 1 | Defense 1 — event-governed ACK release | `research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense1_hardened_dp9_dp11.p4` | ACK held on a recirc loop until the matching RESPONSE event; ordering by register-visibility. Proves the **event-release** mode primitive. |
| 2 | Defense 1 — ACK-before-RESPONSE ordering | `research/ibspg_paired/` (IBSPG Part 11) | 3-level strict priority (Q_BLOCK>Q_ACK>Q_RESP) enforces ACK before RESPONSE; **100/100** both injection orders. Proves the ordering primitive on the strict-priority reservoir. |
| 3 | Defense 2 — queue-resident RESPONSE deadline | `research/ibspg_hold_response/` (IBSPG Part 12) | ACK forwarded immediately; RESPONSE held to a **data-plane deadline `t_ack + G`**; reservoir drains at expiry. **Part 12 completed 200/200 releases at commit `f00a5fd`.** Proves queue-resident deadline release. |
| 4 | Defense 3 — delayed ACK deadline | `defense3/p4/case_a_defense3.p4` | ACK held to a **predetermined `t_ACK + D`**, RESPONSE released after the ACK; K-token reservoir; R1/R2/R3 repairs unconditional. Validated on Tofino-1 vs the physical SEL-751. Proves the ACK-deadline mode. |
| 5 | four-level strict priority | `research/case_a_read_anchored_dual_release/reports/FOUR_QUEUE_ORACLE_CLOSED.md` | **Closed at commit `6ffd5e5`** — four-level strict-priority ordering proven on silicon (finite backlog). |

## What the four-queue oracle does and does NOT prove

**Do not re-run the closed four-queue oracle.** It proves **finite-backlog priority ordering** of the
four queues. It does **NOT** prove:
- dual-reservoir readiness (both `Q_ACK_BLOCK` and `Q_RESP_BLOCK` established before the earliest ACK);
- recirculation continuity (no pre-deadline empty gap in either reservoir);
- deadline correctness (release at `T_A` / `T_RESP`);
- DNP3 transaction correctness (matching, generation, cleanup).

Those are the new obligations of the Defense 4 timing core (Gate 3 offline; hardware phase on silicon).

## Use of the READ-anchored research directory

`research/case_a_read_anchored_dual_release/` is reused **only** for its verified **queue, compiler,
pktgen, and failure evidence**. Its **READ-relative policy is NOT revived** as the governing Defense 4
design (Defense 4 is ACK/RESPONSE-deadline based per `TIMING_SPEC.md`).

## Deleted MB-1 programs

`mb1_unified_skeleton.p4`, `mb1_v2_unified_core.p4`, `mb1_v3_unified_core.p4` were removed from the active
tree (recoverable from git history, commits `92cb620`…`0155e0`). They are **historical compile probes**
only. None is copied wholesale or renamed into the new core; `defense4_timing.p4` is written to this spec.
