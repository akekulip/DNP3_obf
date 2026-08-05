# Defense 4 — feasibility report (regenerated)

> **⛔ SUPERSEDED on the size/topology axes by [`DEFENSE4_CHECKPOINT_2026-08-04.md`](DEFENSE4_CHECKPOINT_2026-08-04.md) (2026-08-04).**
> The size plane is now **master-inserted real-plus-decoy CROBs (K = R + D)**, not outer encapsulation;
> the topology is a **single Tofino-1 at the outstation**, not a two-edge tunnel; Candidate A/A2/A3 and
> MB-8 are retired. **Carries forward:** the D1/D2/D3 timing results, the emulator SBO/CROB corpus, and
> the MB-1 v3 compile as *timing-core* feasibility evidence (its outer-header parts are superseded).
> **Corrected claim:** complete Defense 4 is **NOT demonstrated** — the unified core is not implemented
> and the K=R+D size plane is not yet verified even on the emulator. Read the checkpoint first; this
> report is preserved as historical feasibility evidence.

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

**The decisive question is answered — on the DEFECT-FREE complete core, and the answer is a QUALIFIED
fit.** Two reviews drove this: the first found the skeleton stubbed several semantics (→ MB-1 v2); the
second found v2 itself carried ten fatal logic defects (directional flow key, dead pktgen blocker,
generation-parity validity, missing response reservoir, incomplete cleanup, wildcard slot-occupancy,
6-byte header, missing MODE_FAIL_OPEN release, uninitialized metadata). **MB-1 v3**
(`mb1_v3_unified_core.p4`) fixes all ten — canonical bidirectional flow key with a collision-guarded
fingerprint (fail-open on collision), corrected pktgen ordering, explicit generation validity, BOTH
blocker reservoirs, full state retirement on completion/fail-open/FIN, full-mask slot-occupancy +
expected-slot enforcement, an 8-byte D4 header carrying the true inner length, the MODE_FAIL_OPEN release
entry, and safe parser init. It **compiles at 12/12 ingress, critical path 11** (0 egress, 122 tables;
bf-p4c 9.13.1; independently verified, raw evidence in `p4/evidence_mb1v3/`) — it **FITS, but exactly at
the ceiling with zero ingress headroom**; the ten fixes cost +2 stages over the defective v2. Any further
ingress logic needs an egress move or 2-pass. This is a COMPILE/resource result, not a silicon
validation. The controlling stripped-D2 baseline is 9 ingress (the "7–8" estimate retired).

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

### Overall verdict — three separate labels (directive §2)

The single word "GO" is deliberately **not** used for the whole system. The evidence supports three
distinct verdicts at three distinct scopes, and they must not be collapsed:

| scope | verdict | what it rests on |
|---|---|---|
| **Unified ingress control core** | **GO — QUALIFIED (fits at the ceiling, zero headroom)** | The **defect-free** complete core (MB-1 v3, `mb1_v3_unified_core.p4`) compiles at **12/12 ingress, critical path 11** — it FITS, but **exactly at the ceiling: 0 empty ingress stages, 0 margin** (raw evidence committed in `p4/evidence_mb1v3/`; independently verified). The ten review-found defects in v2 (directional flow key, dead pktgen blocker, generation-parity validity, missing response reservoir, incomplete cleanup, wildcard slot-occupancy, 6-byte header, missing MODE_FAIL_OPEN release, uninitialized metadata) are all fixed — costing +2 stages over the defective v2's 10/12. **Any further ingress logic needs an egress move or 2-pass.** COMPILE/resource result, not silicon. |
| **Complete bounded Defense 4** | **GO WITH CONSTRAINTS** | Buildable single-pass within the bounds — one active transaction per scheduler domain, a bounded READ/SBO size envelope (no cellization), outer-encapsulation size control only (no decoy CROBs, no DNP3-object edits), fail-open outside the envelope, and — for the *strong* `Obs(READ)≈Obs(SBO)` claim — an external link-confidentiality boundary plus a genuine two-edge deployment. The egress padding action, four-level TM behaviour on silicon, and byte-identical decap are designed but not yet proven. |
| **End-to-end Defense 4** | **NOT YET DEMONSTRATED** | No combined program has been run end-to-end. MB-1 v2 proves the complete ingress *fits*; it does not prove the system *works*. Physical padding emission, exact observer-visible frame lengths, decode/restore, four-level priority causality on silicon, and same-device `Obs(READ)≈Obs(SBO)` co-measurement are all unproven. |

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
~~**Size concealment is outer-encapsulation only — no decoy CROBs**~~ **⛔ REVERSED by the 2026-08-04
checkpoint:** size is now **master-inserted real-plus-decoy CROBs (K = R + D)**; the outer-encapsulation
plane, the one-switch external-loop topology, the READ/SBO template, and the filler are all retired. The
decoy safety hazard (R8) is LIVE again. See `DEFENSE4_CHECKPOINT_2026-08-04.md`.

### What must NOT be claimed yet

- That Defense 4 exists as a demonstrated system (no combined program run end-to-end; MB-1 proves it
  *fits*, not that it *works*).
- Semantic READ/SBO indistinguishability on plaintext (function code); even under crypto it is
  *shape*-, not *semantic*-, indistinguishability.
- Any two-edge / distance-link result from the single-switch topology (shared registers + one epoch
  clock; two real switches share neither — cross-switch epoch sync is unanswered).
- Device anonymity (k=1).
- Cellization.

*(Update: the SBO sweep pass-gate is now REPAIRED — the failure was a harness rsync/`--mkpath` plumbing
bug, not a DNP3 fault; N=1..16 are wire-verified all-SUCCESS and N≥17 rejects on `maxControlsPerRequest
=16`. See `evidence/sbo_corpus/FINDINGS.md`. SBO semantic correctness for N=1..16 is now supported.)*

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
3. **k=1 + same-device co-measurement** — no second device (no anonymity claim). The SBO pass-gate is
   now fixed and N=1..16 are wire-verified; the remaining gap is that READ (Case-A physical relay) and
   SBO (Case-B emulator) were measured on *different* devices, so a defensible `Obs(READ)≈Obs(SBO)` still
   needs both operations on one device/path (or an explicit device-independence argument).

## The next experiments, in order

0. **Offline transaction oracle — DONE + CORRECTED (this session).** `analysis/txn_oracle.py` (v2)
   parses the corpus into complete bidirectional wire sequences with the six promised per-unit fields
   (txn_id, phase, ack_assoc, fragment, outer_len, expected_slot); `evidence/oracle/annotated_corpus.json`
   = 78 txns (60 READ, all now correctly 4-unit after the transaction-closure fix; 16 SBO success;
   2 rejected). READ = Case-A 4 units, D=16 ms hold + 32 µs residual CLRT; SBO = Case-B 6 units,
   14.6 B/CROB across the FULL N=1..16. Output: **corrected Candidate A2** in
   `PROVISIONAL_SLOT_CANDIDATES.md` (READ→slots 0/1/4/5 + filler 2/3; slot 1 exposes one public size for
   both the READ separate-ACK and the SBO SELECT-response; frozen format (b); provisional τ) — NOT
   frozen, awaiting the pick (directive §7/§8).
0b. **MB-1 v3 — DONE, VERIFIED (v2 superseded for defects).** The defect-free complete core compiles at
   **12/12 ingress, CP 11 — it FITS, exactly at the ceiling (0 headroom)**; all ten v2 logic defects
   fixed, raw compiler evidence committed (`p4/evidence_mb1v3/`). Resource feasibility of the correct
   complete core is closed with the caveat that there is no ingress margin. `p4/MB1_EVIDENCE_FREEZE.md`.
1. **The size-data-path offline gate (MB-8)** — before any switch size work: exact outer format, real
   padding bytes, exact observer-visible frame lengths, encoder/decoder ports, padding removal,
   byte-identical restoration, hidden real/filler discrimination, MTU/unsupported-size handling. MB-1's
   PHV overlay proved the outer-field *assignment* is cheap; MB-8 proves the *mechanism* (directive §9).
2. **First switch experiment = synthetic four-level priority microbenchmark** (directive §11) — 100/100
   causal ordering in both injection orders, BF-RT readback, no premature release, no blocker escape,
   bounded fail-open. **Synthetic packets only; no SEL-751, no SELECT/OPERATE on the relay.**
3. **Build the unified engine (P4)** — MB-1 proves it fits; reproduce D1/D2/D3 individually from one
   binary, add the grid, then **measure** the rung 5→6 result (READ→ACK 0.65 bits → floor), turning the
   load-bearing prediction into a result.
4. **Fix the SBO harness pass-gate + capture the READ size envelope** — gives functional-correctness for
   SBO (the oracle already gives the wire template) and the same-device READ side needed for a defensible
   `Obs(READ) ≈ Obs(SBO)` co-measurement.

## Strongest claim the current evidence supports

*The **defect-free semantically complete** integrated size-and-timing ingress core — unified D1/D2/D3
release engine, grid, per-slot size lookup, 8-byte outer header with true inner_len, real/filler tagging
with full-mask occupancy + expected-slot enforcement, canonical bidirectional flow-keyed state with a
collision-guarded fingerprint, internal-generation SELECT→OPERATE linkage, ack_gone, universal fail-open,
epoch cleanup, both blocker reservoirs, and full state retirement — compiles on one Tofino-1 pipeline at
12 ingress stages (CP 11), with the entire egress pipe free for padding (MB-1 v3, verified, raw evidence
committed). It fits, but exactly at the ceiling — zero ingress headroom. Defense 3 erases the CLRT device
fingerprint and leaves a measured 0.65-bit READ→ACK residual; the SBO CROB count is a 14.6-B/CROB size
channel in both directions; and (persistent connection) both READ and SBO expose a real slot-5 terminal
ACK. Defense 4 has a real target on both axes and its complete ingress core fits at the ceiling — a
resource result, with the egress size data path (MB-8), silicon TM behaviour (MB-3), and end-to-end
operation still to be built and measured.*
The grid's *closing* of the residual and the end-to-end shaping remain to be built and measured.
