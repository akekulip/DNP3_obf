# Defense 4 — feasibility report (regenerated)

**2026-08-04, regenerated after the first offline evidence wave per `DEFENSE4_DIRECTIVE.md` §6. This
supersedes the earlier draft. Governing authority: the directive. Analysis + two offline compiles +
the E0 gate + the emulator SBO corpus; no switch, no TM config, no SEL-751 actuation. Evidence:
`DEFENSE4_EVIDENCE_LEDGER.md`, `agent_notes/`. Every load-bearing number is compiler- or trace-verified
this session.**

---

## Executive summary

Defense 4 is the **integrated size-and-timing** obfuscation primitive Dr. Lin specified: one
configurable engine reproducing Defenses 1/2/3 plus the combined scheduled (grid) mode (the timing
substrate), a size substrate (finite outer-size states, byte-preserving encap/decap, overflow
fail-open, no arbitrary splitting), a READ/SBO transaction template, and the integration in which a
real READ and an emulator full SBO pass through the same implementation and produce the same declared
shape within a bounded envelope.

**The decisive question is answered, and favourably.** The combined ingress core — including the
*complete size-control surface* the directive forbade excluding — compiles at **10 ingress stages,
critical path 9, 0 egress, 75 tables** on one Tofino-1 pipeline (bf-p4c 9.13.1, verified). 10 ≤ 12, so
**single-pass integrated Defense 4 is feasible**, with 2 empty ingress stages and the entire egress
pipe (0/12) free for the physical padding action (~2–4 egress stages). The earlier "coin-flip at 11–12"
is resolved by measurement; the estimated stripped-D2 baseline of "7–8 stages" was disproven (the
compiler proves **9**).

**The size substrate has a real target,** correcting an over-broad earlier claim. The E0 gate found the
constant Class-0 READ *response* carries 0 bits of size entropy — true, but that is the READ response
only. The emulator SBO sweep (N=1..16, verified this session) shows the **CROB count is a strong size
channel in BOTH directions at 14.6 B/CROB** (SELECT/OPERATE requests 35→254 B, their responses 37→256 B,
because the outstation echoes the CROBs). Normalizing that channel is exactly what the size substrate is
for. Size stays a first-class work package, per the directive.

**What is buildable vs what may be claimed are different questions.** The mechanism is buildable
single-pass. The *strong* target `Obs(READ)≈Obs(SBO)` — semantic indistinguishability — is capped on a
plaintext link by the DNP3 function code (one byte at a fixed offset, an O(1) READ-vs-SBO classifier the
chip cannot hide). On plaintext, Defense 4 **reduces** the size/timing/count/direction differences; the
*strong* claim additionally needs an external link-confidentiality boundary (the same envelope Ditto
assumes) and a genuine two-edge deployment. These are claim boundaries to state, not build blockers.

### Overall verdict: **GO — single-pass integrated size-and-timing Defense 4 is feasible on one Tofino-1 (10 ingress + 2–4 egress, compiler-proven), within stated claim boundaries.**

Build the integrated system (all four work packages). Scope the *plaintext* claim to difference
reduction; treat the *strong* `Obs(READ)≈Obs(SBO)` claim as conditional on an external crypto boundary
and a two-edge deployment. Benchmark against **Ditto/NetShaper** (Ditto is the main comparison; it does
**not** subsume Defense 4 — see §Positioning).

### Verdict by work package

| work package | verdict | basis (verified) |
|---|---|---|
| **1. Timing substrate** (unified D1/D2/D3 + grid engine) | **GO** | all five release predicates compile in MB-1; 4-queue = 4-level extension of proven 3-level strict priority; stripped-D2 hold core = 9 ingress |
| **2. Size substrate** (finite outer states, prepend encap/decap, overflow fail-open, no splitting) | **GO — real target, fits the budget** | SBO CROB-count size channel = 14.6 B/CROB both directions (verified); full size-CONTROL surface fits in the 10-stage MB-1 ingress; padding APPLICATION is egress (0/12 free) |
| **3. READ/SBO transaction template** | **GO for the mechanism; template to be fixed from the corpus** | SBO corpus captured (N=1..16 + rejection boundary N≥17); READ envelope needs a general-READ emulator config (open item) |
| **4. Integrated Defense 4** (same impl, READ + full SBO, same declared shape) | **GO to build; not yet demonstrated** | no combined program run end-to-end yet; MB-1 proves it fits |
| Strong claim `Obs(READ)≈Obs(SBO)` on plaintext / single-switch | **NO — claim boundary** | plaintext function code = O(1) classifier; single-box loop shares registers + one epoch clock (two real edges do not) |
| Strong claim WITH external crypto + two-edge deployment | **plausible (external assumption + future two-switch work)** | same mechanism + confidentiality boundary + cross-switch epoch sync |
| Cellization of oversized READs | **NO for v1** | not demonstrable on TF1; declare a bounded READ envelope, fail open outside it |
| Multi-transaction concurrency | **v1 = one active transaction per scheduler domain** | shared FIFO cannot mid-release |

### Minimum viable Defense 4 (build order)

The integrated single-transaction, plaintext primitive: live DNP3 classify → bidirectional READ+SBO
transaction/phase state (SELECT↔OPERATE linked by state+generation, never app-seq) → **unified release
engine** (D1/D2/D3 + grid, one binary) → **finite outer-size states** with prepend encap/decap,
byte-identical restore, and overflow fail-open → **READ/SBO template** with outer filler for unused
slots → integrated on the one-switch external-loop topology. It normalizes CLRT (proven), the READ→ACK
relocation residual (the 0.65-bit timing target, via the switch-clock grid), the SBO CROB-count size
channel (14.6 B/CROB, via outer size states), and the READ-vs-SBO count/direction shape (via filler).
**Size concealment is outer-encapsulation only — no decoy CROBs, no DNP3-object manipulation** (directive
rule; the earlier decoy-CROB line is retired, and its safety hazard with it).

### What must NOT be claimed yet

- That Defense 4 exists as a demonstrated system (no combined program run end-to-end; MB-1 proves it
  *fits*, not that it *works*).
- Semantic READ/SBO indistinguishability on plaintext (function code); even under crypto it is
  *shape*-, not *semantic*-, indistinguishability.
- Any two-edge / distance-link result from the single-switch topology (shared registers + one epoch
  clock; two real switches share neither — cross-switch epoch sync is unanswered).
- Device anonymity (k=1).
- SBO *semantic* correctness from the current corpus (the sweep pass-gate failed on master reporting;
  wire sizes are solid, the "did the control apply" claim needs the harness fixed).
- Cellization.

---

## Positioning (directive §3): Ditto is the comparison, not the subsumer

Ditto (NDSS'22) provides programmable-switch padding, buffering, fixed patterns, and chaff — it is the
main comparison. But it is an **oblivious link shaper**; it has none of Defense 4's contribution:
the **DNP3 transaction-aware mechanism**, **event/deadline configurability**, **ACK-before-response
gating**, **SBO causality and timeout safety**, **exact matching**, and **bounded fail-open**. NetShaper
(USENIX Sec'24) is a privacy middlebox baseline, not a Tofino/DNP3 substitute. The honest framing:
**encryption (802.1AE) is porous to size/timing/count/direction, so shaping complements encryption** —
and Defense 4's delta over Ditto is the transaction-aware, safety-bounded control it exercises that an
oblivious shaper cannot.

---

## The 14 feasibility decisions (updated with the compile result)

1. **Two trusted boundaries on one Tofino?** YES for the mechanism, over an external front-panel loop
   (not internal recirc). Single-box shares registers + one epoch clock, so it is a lab stand-in, not a
   deployment — two-edge claims need two switches + cross-switch epoch sync (future work).
2. **Add/remove the outer representation, byte-exact?** YES — prepend encap; decode `setInvalid` → inner
   byte-identical, no inner-checksum recompute. (MB-1 carries the outer-header field computation; the
   byte-append is the excluded egress action, ~free.)
3. **Max READ/SBO size for a no-splitting v1?** Single-frame unit ≤ (MTU − outer). SEL response 134 B,
   SBO ≤16 CROBs = 254 B request / 256 B response — all fit. Multi-frame READ = out of v1 (#4).
4. **Cellization feasible?** Future work; declare a bounded READ envelope, fail open outside it.
5. **Is filler necessary?** For the READ-vs-SBO count/direction match (template WP3), yes; for
   within-operation size (WP2), no. Both are in the integrated system.
6. **Safe transaction-bound filler without a fast-path controller?** YES — pktgen (the internal slot
   clock) generates filler + grid tick, input-independent; filler carries {direction, txn_tag, slot_id}
   and is dropped at the decode pass. Controller installs policy only.
7. **One queue bank for READ/SELECT/OPERATE sequentially?** YES within the one-transaction limit; reverse
   4-queue on the master port, forward gate on the outstation port — per-port, no contention.
8. **Concurrency / fail-open?** One active protected transaction per scheduler domain (v1); concurrent
   attempt bypasses (fails open unshaped). Fail-open = bounded absolute-deadline release.
9. **One binary reproduces D1/D2/D3?** YES — MB-1 compiles all five release predicates over `tbl_params`;
   reproducing each defence individually is a P4 exit criterion.
10. **RESPONSE anchor when the ACK is also delayed?** `T_R = A_ref + G_R`, `A_ref` = scheduled ACK-release
    point + characterized drain correction (NOT native ACK arrival except in D2 compat mode). Grid:
    `A_ref` = the ACK's grid slot.
11. **True ACK dequeue or logical reference?** Logical `ack_gone` / scheduled-release + the **~1.72 µs**
    release-tail correction (settled from raw Part-12 timestamps this session).
12. **Resources after the stripped baseline?** Stripped-D2 = **9 ingress / CP 7 / 50 tables** (verified;
    NOT the estimated 7–8). MB-1 full-control skeleton = **10 ingress / CP 9 / 75 tables**, +2 empty
    ingress, egress 0/12 free.
13. **Proven / needs-microbench / infeasible?** Proven now: the ingress fit (MB-1), the stripped-D2
    baseline, the SBO size envelope, the Part-12 unit, the E0 residual. Needs a switch microbench: the
    4-level priority (100/100 causality, gated), encap/decap byte-identity, the grid device-independence
    falsifier. Infeasible v1: cellization, in-band opacity (needs external crypto), concurrency.
14. **Smallest defensible Defense 4 on this testbed?** **The integrated single-transaction primitive that
    passes a real READ and an emulator full SBO through the same binary and produces the same declared
    size+timing+count+direction shape within a bounded envelope** — with CLRT + READ→ACK-residual
    normalization (timing), CROB-count normalization via outer size states (size), and READ-vs-SBO shape
    match via filler. The strong `Obs(READ)≈Obs(SBO)` semantic claim and anonymity are future work.

---

## The three hardest remaining items (no longer the ingress budget)

1. **The plaintext function-code wall** — a claim boundary, not a build blocker; the strong claim needs
   external crypto.
2. **The two-edge deployment gap** — the single-box loop shares a register and one epoch clock; a real
   two-switch deployment needs cross-switch grid epoch sync (unanswered).
3. **k=1 + SBO semantic-success corpus** — no second device (no anonymity claim); the SBO sweep's
   pass-gate needs fixing before any "the control applied" claim (wire sizes are already solid).

## The three next experiments, in order

1. **Build the unified engine (P4)** — MB-1 proves it fits; now reproduce D1/D2/D3 individually from one
   binary and add the grid, then **measure** the rung 5→6 result (READ→ACK 0.65 bits → floor). This turns
   the load-bearing prediction into a result.
2. **The 4-level priority microbenchmark** (first gated hardware step) — 100/100 causality + BF-RT
   readback, synthetic packets only; SEL-751 READ-only, SELECT/OPERATE emulator-only.
3. **Fix the SBO harness pass-gate + capture the READ size envelope** — gives functional-correctness for
   SBO and the READ side of the template.

## Strongest claim the current evidence supports

*The integrated size-and-timing core — unified D1/D2/D3 release engine, grid, per-slot size lookup,
outer-header construction, real/filler tagging, SBO SELECT→OPERATE linkage, fail-open — compiles on one
Tofino-1 pipeline at 10 ingress stages (CP 9), with the entire egress pipe free for padding. Defense 3
erases the CLRT device fingerprint and leaves a measured 0.65-bit READ→ACK residual; the SBO CROB count
is a 14.6-B/CROB size channel in both directions. Defense 4 has a real target on both axes and fits.*
The grid's *closing* of the residual and the end-to-end shaping remain to be built and measured.
