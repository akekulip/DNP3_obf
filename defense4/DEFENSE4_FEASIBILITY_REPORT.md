# Defense 4 — feasibility report

**2026-08-04. Lead synthesis of a four-specialist wave (Tofino/P4, DNP3/SBO safety, size/topology,
evaluation) over `defense4_arch.md` and the ADTA feasibility prompt. Analysis only; no P4 loaded, no
switch or TM config touched, no OPERATE issued. Two READ-ONLY offline compiles and the E0 gate were
run. Evidence base: `DEFENSE4_EVIDENCE_LEDGER.md`; expert detail: `agent_notes/`.**

---

## Executive summary (two pages)

Defense 4, as Dr. Lin framed it, is a transaction-level obfuscation primitive that unifies the timing
behaviours of Defenses 1/2/3 in one configurable release engine, adds a size plane, and shapes a DNP3
READ poll and a full SELECT-Before-Operate control so they present the same observable size, timing,
packet count, and direction pattern — target `Obs(READ) ≈ Obs(SBO)`.

The study reaches a clear, defensible position: **the shaping *mechanism* is buildable on the existing
Tofino-1 testbed, but the *strong claim* `Obs(READ)≈Obs(SBO)` is not reachable on Tofino-1 alone.** It
is blocked by one byte — the plaintext DNP3 function code at a fixed offset, which is a perfect O(1)
READ-vs-SBO classifier the chip structurally cannot hide (Tofino-1 cannot encrypt the payload; the
DNP3 bytes are the unparsed deparser residual and never enter the PHV). Closing the strong claim
requires an *external* link-confidentiality assumption (MACsec on the protected segment) that sits
outside the Tofino data-plane primitive. Without it, the honest, defensible claim is difference
reduction — Profile A.

Three empirical facts, established this session, decide scope:

1. **After Defense 3, the only surviving real per-transaction device signature is READ→ACK** — a
   residual of **0.65 bits / sd 0.585 ms** (the §12.4 relocation, quantified by the E0 gate). CLRT's
   device content is *erased* (4.33 → 0.00 bits). So Defense 4's marginal timing contribution over
   Defense 3 is precisely to drive the READ→ACK residual to the drift floor with a **switch-clock
   grid** that anchors release on the switch's own clock rather than on `t_ACK`.
2. **The size axis has no within-READ target on this device** — the SEL-751 Class-0 response is one
   constant size over 300 polls (0 bits). Size shaping is only meaningful for *cross-operation*
   READ-vs-SBO discrimination, which is unmeasurable until a real SBO corpus exists.
3. **The size plane is essentially free on Tofino-1** — it lives in egress (Defense 3's egress is
   0/12 empty; the PHV exhaustion is ingress-only). The whole feasibility question therefore reduces
   to **one ingress-stage compile**: whether the combined timing+state core clears 12 stages on a
   pipeline already at 10/10 dependency-bound. Bounded estimate 11–12 — a coin-flip, resolvable
   offline with no hardware.

Two grounding results reshape the roadmap: **emulator SBO already exists** (`multi_crob_sbo.pcap`
decodes to a real SELECT→SELECT-RESP→OPERATE→OPERATE-RESP), so Phase 1 shrinks from "build SBO
generation" to "run the existing sweep and characterise sizes"; and **SBO imposes a select-timeout
coupling** READ does not have — a reverse-path hold on the SELECT response consumes the outstation's
select-arm budget, so phase-specific parameters are mandatory and no live SELECT is admissible until
the SEL-751's device select timeout is read.

### Overall verdict: **GO WITH CONSTRAINTS**

Build the mechanism; scope the claim to Profile A (difference reduction) on plaintext; treat the strong
`Obs(READ)≈Obs(SBO)` claim as conditional on an explicit, stated MACsec deployment assumption.

### Verdict by subsystem

| subsystem | verdict | basis |
|---|---|---|
| Unified D1/D2/D3 release engine (one binary, selectable predicates) | **GO** | D1/D2/D3 primitives silicon-proven; 4-queue = 4-level extension of proven 3-level strict priority; TM side free |
| Four-queue reverse-path construction | **GO (needs the decisive compile)** | Part-11 3-level proven; 4th level = independently-terminable RESPONSE blocker; cost is dual-blocker *control* in ingress |
| Size plane (finite egress size states, prepend encap/decap, byte-identical restore) | **GO** | egress 0/12 empty, prepend proven on GridCloak, inner rides as residual (no checksum recompute) |
| Combined ingress core clearing 12 stages | **CONDITIONAL — one offline compile** | D3 already 10/10 dependency-bound; bounded 11–12; ≤12 → GO, >12 → drop a mode / egress-bridge the SBO key / 2-pass |
| One-switch two-edge topology over an external physical loop | **GO for the mechanism** | dp-loop must be an *external* front-panel cable (tapped), not internal recirc; port table in the arch spec |
| Strong claim `Obs(READ)≈Obs(SBO)` on Tofino-1 alone | **NO-GO** | plaintext function code = O(1) classifier; TF1 cannot make the inner opaque |
| Strong claim WITH external MACsec on the loop | **GO (external assumption)** | same mechanism + stated confidentiality boundary |
| Cellization / reassembly of oversized READs | **NO-GO for v1** | not demonstrable on TF1 without dedicated feasibility work; declare a bounded READ envelope instead |
| Multi-transaction concurrency | **OUTSIDE MINIMUM CONTRACT** | shared FIFO cannot mid-release; one active protected transaction per scheduler domain for v1 |

### Minimum viable Defense 4 (what to build first)

A single-transaction, plaintext, **Profile-A** primitive: live DNP3 classify → bidirectional
transaction/phase state (READ + SBO, SELECT↔OPERATE linked by state+generation, not app-seq) →
**unified release engine** reproducing D1/D2/D3 and the switch-clock grid from one binary → **finite
egress size states** with prepend encap/decap and byte-identical restore → **one-switch external-loop
topology**. It delivers: CLRT normalization (proven), the READ→ACK relocation fix (the measured 0.65-bit
target), within-operation size normalization for READ and SBO, and CROB-count concealment via
master-side decoy padding. It does **not** attempt cross-operation READ≈SBO indistinguishability, filler
templates, cellization, continuous cover, or concurrency.

### Larger forward-looking profile

Profile B (cross-operation READ≈SBO with count/direction filler) + the external MACsec assumption for
the strong claim; Profile C (continuous cover, hides transaction frequency) as a further, opacity- and
safety-gated extension. Both require the real SBO size corpus and, for any anonymity claim, a second
separate-ACK device.

### What must NOT be claimed yet

- That Defense 4 exists (no combined program, no real physical SELECT→OPERATE SBO corpus).
- That an observer "cannot distinguish READ from SBO" on the plaintext testbed — on plaintext the
  honest claim is *difference reduction*, and even the strong claim is *shape*- not
  *semantic*-indistinguishability.
- Live-DNP3 size normalization (the Level-1 128-B result was synthetic, pad-only).
- Any combined ingress-stage total before the decisive compile.
- Device anonymity of any kind (k=1; the single relay is an anonymity set of one).
- A CROB-count size-leak magnitude beyond the n=1-per-N regression.

---

## The 14 required feasibility decisions

1. **Can one Tofino-1 implement the two trusted boundaries for an outer padded representation on the
   current testbed?** YES for the mechanism, over an *external front-panel loopback* (not internal
   recirc, which the observer cannot see). Ports dp10 (FP15/2) ⇄ dp65 (FP33/1), both pipe-0, both free;
   observer taps the loop cable. PROPOSED (topology), corroborated by Ditto.
2. **Can the pipeline add and later remove the outer representation, restoring bytes exactly?** YES.
   Encap = **prepend** (deparser emits headers then the residual; DNP3-over-TCP self-delimiting;
   GridCloak-proven). Decode `setInvalid` the outer → inner bit-identical, no inner-checksum recompute.
3. **Max READ/SBO size a no-splitting v1 supports?** Any inner unit ≤ (MTU − outer header), i.e. a
   single-frame DNP3 unit ≤ ~1400 B. The SEL Class-0 response (134 B payload) and bounded SBO (≤16
   CROBs ≈ 256 B) fit trivially. A multi-fragment READ larger than one frame is out of v1 (see #4).
4. **Is cellization/reassembly feasible on TF1, or future work?** **Future work.** Not demonstrable
   without dedicated feasibility work; v1 declares a bounded READ envelope and fails open outside it.
5. **Is bounded filler necessary for the agreed contract?** NO for Profile A (the MVP). Filler is
   required only for Profile B (cross-operation count/direction match), which is gated on opacity.
6. **Can pktgen/clone/recirc produce safe transaction-bound filler without a controller fast path?**
   YES — pktgen (dp68) generates filler cells and the grid tick, input-independent (measured 100 pps
   ±1); filler carries {direction, txn_tag, slot_id} and is dropped at the decode pass. Controller
   installs policy only. PROPOSED for Defense 4, mechanism proven in Defense 2/3.
7. **Can one queue bank support READ, SELECT, and OPERATE sequentially?** YES within the
   one-active-transaction limit — the reverse-path 4-queue bank on the master port is reused across
   phases; the forward gate is a single-blocker D3-style gate on the outstation port. Queues are
   per-port, so reverse (4) and forward (≤3) do not contend.
8. **Exact concurrency limit and fail-open behaviour?** **One active protected transaction per
   scheduler domain** for v1 (shared FIFO cannot mid-release); a concurrent attempt bypasses (fails
   open, unshaped) until the bank frees. Fail-open is a bounded absolute-deadline release of any held
   packet.
9. **Can one P4 binary reproduce D1/D2/D3 by configuration?** YES (PROPOSED) — a common gate with
   selectable predicates {IMMEDIATE, MATCHING_RESPONSE_EVENT, ABSOLUTE_DEADLINE, PREDECESSOR_PLUS_OFFSET,
   bounded FAIL_OPEN} over the existing `tbl_params`. Reproducing each defence from the same binary is
   Phase-4 exit criterion.
10. **What anchor for RESPONSE release when the ACK is also delayed?** `T_R = A_ref + G_R`, with
    `A_ref` = the **scheduled ACK-release point plus a characterized drain correction** (NOT the native
    ACK arrival, which is only valid in Defense-2 compatibility mode where the ACK is forwarded
    immediately). For the grid, `A_ref` = the ACK's grid slot.
11. **Can the system observe true ACK dequeue, or must it use a logical reference?** Use the
    **scheduled-release / `ack_gone` logical reference plus the characterized ~1.72 µs release-tail
    correction** — observing the true physical dequeue economically on TF1 is an open item, not a
    dependency. INFERRED.
12. **What compiler/TM resources remain after the stripped baseline?** Stripped-D2 core ≈ **7–8
    ingress stages** (fresh read-only compile: D2 pktgen core 10 ing / CP 8 / 70 tables; strip
    telemetry tail + microbench + A/B toggles). Headroom to the 12-stage ceiling ≈ 4–5 dependency
    levels for the timing+state additions; egress is wide open (0/12) for the size plane.
13. **Which requirements are proven / need microbenchmarks / infeasible?** Proven: CLRT hold,
    queue-resident release, 3-level strict priority, prepend encap, egress size states, emulator SBO.
    Need a microbenchmark: the 4-level queue, the unified engine's stage count (the decisive compile),
    encap/decap byte-identity round-trip, the grid device-independence falsifier. Infeasible v1:
    cellization, in-band opacity (needs external crypto), concurrency.
14. **Smallest publishable, defensible Defense 4 on this testbed?** **A single-transaction Profile-A
    primitive that shapes a real READ and a real (emulator) SBO through one binary, preserves endpoint
    behaviour, normalizes CLRT and the READ→ACK relocation to the drift floor, normalizes within-operation
    size, and states the plaintext claim boundary honestly.** The strong `Obs(READ)≈Obs(SBO)` result is
    a separate, opacity-conditional contribution.

---

## The three hardest blockers

1. **The plaintext function-code wall.** No Tofino-1 mechanism makes READ and SBO semantically
   indistinguishable; the strong claim needs external crypto. This is a *claim* limit, not a build
   limit — but it must be stated in the threat model or the paper overclaims.
2. **The combined ingress core clearing 12 stages.** D3 is already 10/10 dependency-bound; the unified
   engine + SBO key is bounded at 11–12. Resolved only by the offline skeleton compile.
3. **The missing real SBO size corpus + k=1.** The whole size/READ-vs-SBO half is unevaluable until a
   controlled-outstation SBO sweep exists, and no anonymity claim is reachable with one device.

## The three next experiments, in order

1. **E1 — the decisive ingress compile (offline, no switch).** Unified release-engine skeleton (D3 core
   + D2 response-deadline + mode-select + SBO SELECT↔OPERATE key + slot bitmap), size plane excluded,
   telemetry excluded. Rule: ≤12 ingress → GO; >12 → drop a mode / egress-bridge the SBO key / accept
   2-pass. This converts the coin-flip into a number and gates all P4 work.
2. **E2 — the real SBO size corpus (emulator, no relay).** Run `run_multicrob_sweep.py` at N ∈ {1,2,4,8,16},
   plus rejected-SELECT and valid-but-unwired paths; extract the per-N size envelope; fixes the public
   size pattern P and the phase deadlines. Unblocks the entire size half.
3. **E3 — E0 replication + the synthetic device-population falsifier (offline).** Re-run E0 on
   `physical_repaired/` (2×960) to confirm the 0.65-bit READ→ACK residual at 2×n; drive the grid model
   with programmed (a,c) profiles and test between-profile classifier accuracy — the only
   device-discrimination evidence obtainable without a second relay.

## Strongest claim the current evidence supports

*Defense 3 erases the CLRT device fingerprint (4.33 → 0.00 bits) and relocates the device's ACK-latency
jitter into READ→ACK (0.65-bit residual); a switch-clock grid that anchors release on the defender's
clock is the mechanism that closes that residual, and it composes on one Tofino-1 with an egress size
plane and a unified D1/D2/D3 engine — reducing the size, timing, packet-count, and direction differences
between a READ and an SBO on a plaintext link.*

## The claim that must not yet appear

*"Defense 4 makes a DNP3 READ and a SELECT-Before-Operate control indistinguishable to an on-path
observer."* — void on plaintext (function code), and even under external opacity it is
shape-indistinguishability, evaluable only after the real SBO corpus and against a second device.
