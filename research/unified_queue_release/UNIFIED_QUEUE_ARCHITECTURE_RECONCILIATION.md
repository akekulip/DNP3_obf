# Unified queue architecture — reconciliation (Part A)

Read-only reconciliation of the existing GridCloak/Case-A queue and timing documents against the task's
queue-resident target: hold real ACK/response packets in TM queues, released by a response event or a
deadline, **without** a controller in the fast path, **without** external chaff, and **without**
continuously recirculating the original packet. All documents named in the task EXIST (paths below);
nothing was edited, compiled, or sent to hardware.

## The load-bearing finding

**The queue-resident-without-recirculation target, as literally stated, was already tested and REFUTED on
silicon by the earlier `queue_microbench`.** Two independent silicon results:

1. `queue_microbench/QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md:22-26,563-571` — all four TM mechanisms
   (pktgen metronome, max-rate shaper, min-rate/guaranteed, DWRR) were run on live Tofino-1; every TM
   scheduler is a **backlog discipline** and **cannot pace a sparse ~5 Hz flow**. "The
   'round-robin/min-rate could pace cheaply without chaff' idea is **refuted on silicon**."
2. `GRIDCLOAK_TM_QUEUE_AUDIT.md:184-196` — the Tofino-1 TM **PPS shaper starves below ~1200 pps** (0
   dequeue at 100/200 pps); GridCloak abandoned TM shaping for a pktgen-as-clock for exactly this reason.

The project has therefore already converged back onto **recirculation-hold-to-event/deadline** as the
sparse-flow pacer — i.e. the frozen `dcrn_defense1/2` mechanism (`CASE_A_QUEUE_DESIGN.md:79-82`). And the
**pktgen metronome is a chaff construct**: without chaff there are no empty slots to fill, so the τ-grid
"only adds latency" (`CASE_A_QUEUE_DESIGN.md:72-75`, `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md:71-76`).

Corroborated by Ditto (`DITTO_QUEUE_RELEASE_RELEVANCE.md`): Ditto has no event-driven release and requires
chaff because the Tofino TM cannot inject a packet when it tries to service an empty queue (the paper
states that feature "does not exist"). So the constraint set the task poses is exactly the combination the
prior work found unsatisfiable for a sparse flow — a fresh primitive-level audit (Part B) confirms whether
this holds at the API level, not just empirically.

## Per-document mechanism (condensed; full cites in Part-A agent log)

| Doc | Hold/release mechanism | recirc / TM / chaff / pktgen | Key capability claim |
|---|---|---|---|
| `CASE_A_QUEUE_DESIGN.md` | §0 (2026-07-22) overrides the locked §1a: default (cover=OFF) = **recirc-hold to event/deadline** = the frozen dcrn mechanism; metronome+slot-grid only in cover modes | recirc=delay in every mode; pktgen metronome = chaff construct (cover only) | TM cannot pace a sparse ~5 Hz flow (:20-25); on-switch splitting infeasible (:238-245) |
| `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md` | ran 4 TM mechanisms on silicon; default now dcrn_defense2-style **absolute-deadline recirc-hold** | recirc=HOLD; metronome+slot-grid=chaff construct (cover only) | TM = backlog discipline, can't pace sparse (REFUTED); deadline recirc-hold scales w/ NO ceiling (:703-717) |
| `GRIDCLOAK_TM_QUEUE_AUDIT.md` | shipped GridCloak = recirc loop hold + pktgen periodic-timer clock | pktgen=clock, recirc dp68=hold buffer, TM shaper = rate CAP only | **TM PPS shaper starves <~1200 pps** (:184-196) |
| `DITTO_QUEUE_RECONSTRUCTION.md` / `_TO_DNP3_MAPPING.md` | Ditto = schedule/round-robin-driven, **no event release**; Defense-1 (hold-ACK) does NOT map | requires chaff (empty-queue-skip); 2-pass loopback | "correct only on average, worst for small packets" = DNP3 regime; must be measured |
| `END_TO_END_{PLAN,CHARTER}.md` | charter §E: **recirc is the sparse hold primitive; TM is not the clock**; cover OFF → pktgen OFF, no filler | recirc hold; TM = priority/occupancy only | joint size+time single-program **infeasible** (D1 12/12 full) → platform split |
| `dcrn_defense1.p4` / `dcrn_defense2.p4` | D1 event-governed ACK hold (recirc, release@resp_seen); D2 response hold to ACK-relative deadline (recirc) | recirc-hold only; no pktgen/chaff; TM = shared FIFO egress | byte-preserving; zero-inversion; D2 reads egress-rewritten clock |
| `GATE1_COMPLETE_HARDENED.md` / `txncore/*` | no hold (passive classifier); txncore = generation-safe recirc-hold lifecycle | none / recirc | Vision=dp9=dir0, Hulk=dp11=dir1; gen-ENFORCED doesn't fit 12/12 |

## Contradictions to resolve (from the reconciliation; most-consequential first)

- **C1 — The queue-resident-without-recirc target is refuted on silicon.** TM (max/min-rate, DWRR) cannot
  pace a sparse flow (`QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md:22-26,563-571`); the shipped answer IS
  recirculation-hold (`CASE_A_QUEUE_DESIGN.md:69-71`). The task's "without continuously recirculating the
  original packet" collides with the only proven sparse-flow pacer.
- **C2 — The "new" default pacer is the OLD dcrn recirc baseline** (`CASE_A_QUEUE_DESIGN.md:79-82`) — for
  the no-chaff ICS mode the queue-resident and recirc mechanisms were unified into pre-existing recirc-hold.
- **C3 — No-external-chaff vs Ditto's queue mechanism structurally REQUIRING chaff**
  (`DITTO_QUEUE_RECONSTRUCTION.md:76-87`); removing chaff removes the property (no empty-queue-skip) that
  made the queue mechanism attractive.
- **C4 — The pktgen metronome is itself a chaff construct** (`CASE_A_QUEUE_DESIGN.md:72-75`), so it cannot
  be the chaff-free timing primitive the target wants.
- **C5 — Locked "one joint size-and-time pattern" vs "joint single-program INFEASIBLE → platform split"**
  (`CASE_A_QUEUE_DESIGN.md:8-10` vs `END_TO_END_IMPLEMENTATION_PLAN.md:52,100-106,131`).
- **C6 — Locked §1a "the TM scheduler determines output time" is contradicted by the same file's §0 and by
  silicon** (`CASE_A_QUEUE_DESIGN.md:157` vs `:20-25`) — §1a step 8 is false for the sparse regime; treat
  as superseded.
- **C7 — No-chaff vs "chaff REQUIRED for SBO/CROB hiding"** in the same locked doc
  (`CASE_A_QUEUE_DESIGN.md:29` vs `:189-194`) — the no-chaff target delivers CLRT/timing but NOT the
  SBO/READ-indistinguishability claim.
- **C8 — Splitting listed as a joint component vs splitting infeasible on the Tofino path**
  (`CASE_A_QUEUE_DESIGN.md:106-109` vs `:238-245`).
- **C9 — Ditto "predictable line-rate" vs measured "correct only on average, worst for small packets"**
  (DNP3 regime).
- **C10 — Defense-2 deadline scaling: two opposite silicon results on record** — hardware "constant ~107 ms,
  bounded distribution does NOT manifest, offset dominates" (`END_TO_END_IMPLEMENTATION_PLAN.md:48`) vs
  microbench "NO ceiling, passes==hold_passes exactly" (`QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md:703-717`);
  the qid-not-set/burst-mispair reconciliation is not reflected in the Defense-2 gap row.
- **C11 — "PASS_MEASURED_ON_TOFINO" overstates** what the current on-disk files show (earlier shas,
  single-host replay, pre-rename program; current files re-verified only by off-switch compile —
  `END_TO_END_IMPLEMENTATION_PLAN.md:16-33`).
- **C12 — Three conflicting port↔host↔role/direction mappings** feed a direction-dependent classifier:
  GATE-1 dp9/dp11 vs plan silicon-box dp8/dp9 vs microbench dp9/dp8
  (`GATE1_COMPLETE_HARDENED.md:8-10`, `END_TO_END_IMPLEMENTATION_PLAN.md:118`,
  `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md:187-194`) — the accepted current truth is **Vision=dp9=dir0,
  Hulk=dp11=dir1** (GATE-1, silicon-validated); the others are stale.

## Reconciled position going into Parts B/F

- The TM queue is, on Tofino-1, a priority/contention/occupancy mechanism and (at best) a coarse rate CAP —
  **not** a clock for a sparse packet. This is silicon-established, not assumed.
- Recirculation-hold-to-deadline/event is the only proven sparse-flow hold, but it makes the original
  packet spin many passes (30000–40000 for 135–236 ms) — which the task explicitly forbids ("must not spin
  through ingress thousands of times").
- The internal pktgen metronome is a chaff construct and adds nothing without chaff.
- Therefore the task's four constraints (event/deadline release + no controller-in-fastpath + no external
  chaff + no continuous original-packet recirc) are, on the current evidence, **jointly unsatisfiable for a
  sparse DNP3 flow** — Part B confirms this at the primitive level and Part F scores each candidate against
  it, and if no candidate qualifies, that is reported honestly rather than weakening the criteria.
