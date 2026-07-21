# Case B (Combined-ACK) Defense — Design Synthesis

**Status: DESIGN / scoping only. No switch touched. `next_phase_allowed=false`.**
Multi-expert study (2026-07-21): principal-investigator scoping + p4-dataplane-engineer,
power-systems-expert, research-scientist, sdn-networks-expert. Locked taxonomy:
**Case B = COMBINED-ACK devices** (AB1400 `10.0.0.12`, ION7550 `10.0.0.11`) — the ACK is
piggybacked on the single DNP3 response, so **CLRT is undefined**. (Case A = separate-ACK / SEL-751,
already has Defense 1 hold-ACK + Defense 2 hold-response proven on silicon.)

---

## 0. The reframe — a Case-B defense is NOT a CLRT defense

A combined device has no separate ACK, so there is no CLRT sub-channel to reduce or increase. A
passive observer instead keys on three axes, in order of strength:

| Signal a combined device leaks | Discriminative power | Closed by |
|---|---|---|
| **Response SIZE / segmentation** (AB 37/54 B; ION 37/**61** B, multi-segment) | **DOMINANT** — ION's 61 B is uniquely identifying | **B-SIZE** (byte-modifying) |
| **request→response TIME** (AB 16.6 ms, ION 16.1 ms) | **weak** between the two combined devices (Δmean 0.5 ms); tail/jitter may leak more | **B-E5** (byte-preserving) |
| **ACK MODE** (combined) | separates the *population* (vs SEL-751); gives 0 bits *between* the two combined devices | **B-MODE** (population) |

The defense is therefore a **composition of three orthogonal primitives — B-E5 ⊕ B-SIZE ⊕ B-MODE** —
not any single one. E5 alone is not a Case-B contribution (means differ by 0.5 ms); the publishable
unit is the composition.

---

## 1. B-E5 — request-anchored response hold (byte-preserving) — *p4-dataplane-engineer*

`dcrn_ackB.p4` anchors its deadline on the pure ACK (`reg_deadline = t_ACK + G_i`) — which does not
exist for a combined device. **B-E5 re-anchors it on the request:** `reg_deadline = t_req + G_i`,
written in the ARM branch; hold the one reverse response frame until `now ≥ deadline`. This is
`dcrn.p4`'s proven write-deadline-at-arm pattern, minus the dual-hold FIFO — **strictly simpler than
both predecessors.**

**Register delta vs `dcrn_ackB.p4`:** DELETE `reg_expected_ack`/`reg_ack_seen` (+ their actions, the
`exp_ack` add, the pure-ACK flag test — the whole ACK-qualification path); MOVE `next_txn` +
`bounded_target` + `arm_deadline` from the ACK path to the ARM path; REPURPOSE `reg_armed`'s
read-and-clear to the first-arrival response; KEEP `reg_deadline`/`check_deadline`, `reg_txn`,
`reg_held_count`. Net: **6 registers → 4**, ~11 RegisterActions → 7, arm-time 32-bit add removed.

**Compile-realistic estimate: 7–9 ingress stages** (7–8 realistic, 9 honest ceiling per the M1
"estimates ran ~2 low" lesson) — comfortably inside 12; egress near-empty. **qid=5 (M2 fix)
inherited** — every `PORT_RECIRC` assignment sets `QID_HOLD` so the dp68 shaper paces the lone held
frame. **Byte-preserving, no `Checksum()` extern, no ACK synthesis** — the piggybacked ACK rides
inside the held frame; only *when* it egresses changes.

**The one NEW risk B-E5 carries** (the price of not synthesizing an ACK): holding the combined
response also **holds the request's TCP ACK** (it's piggybacked), so request→ACK latency becomes
`G_i`. If `G_i > RTO`, the master retransmits the request. **`G_i < RTO` is a hard design bound** →
prefer **BOUNDED** (~38 ms) over FIXED; measured Vision RTO ≈ 211 ms.

---

## 2. Grid-safety envelope for holding a combined response — *power-systems-expert*

**Classify-and-hold gate** (data plane reads AC / FC / IIN at fixed DNP3 offsets it already parses):
**HOLD only** a solicited **single-fragment** (FIR=FIN=1), **CON=0**, **UNS=0** Class-0 integrity
poll response (armed on FC `0x01` READ, g60 v1), with IIN event/restart/overflow flags clear.
**NEVER hold → fail-open bypass:** unsolicited (`0x82`), control confirmations (SELECT/OPERATE/
DIRECT_OPERATE/freeze), restart/mode-change, **time-sync** (holding a `RECORD_CURRENT_TIME`/
`DELAY_MEASURE` response injects clock skew — forbidden), multi-fragment, confirm-requiring,
event-class reads, IIN-flagged, and all transport ambiguity.

**The tighter ceiling (the key new constraint):** because the combined packet carries the request's
ACK, holding it withholds the master's *request* acknowledgment — clock started ~16 ms *earlier*
than the response — so the binding limit is the **master request-RTO (~207–211 ms), tighter than
Case A/B.** DNP3 application timers are seconds-scale (master `responseTimeout` 5 s, verified in
opendnp3 source — ~24× the TCP RTO), so **TCP request-RTO is the only timer in play**. Recommended
target ≈ **40–60 ms** req→resp; the **hard invariant is fail-open on request retransmit** (release
unchanged), which makes the design safe even where RTO is unknown.

**Size-filler legality:** the prepended **black-hole data-link frame** (foreign DEST address,
discarded at the data-link layer before the app parser) is **master-agnostic** (IEEE 1815 §9) —
**recommended default**; the Group-110 octet-string is rig-master-confirmed inert but master-
dependent (**fallback**). The production master paired with AB1400/ION7550 is unverifiable here → a
per-deployment probe is mandatory.

---

## 3. B-SIZE + co-residency — *p4-dataplane-engineer + sdn-networks-expert*

**B-SIZE compile gate (make-or-break):** the per-flow TCP seq-space translator (`seq+=Δ`/`ack−=Δ`)
is line-rate-proven (NetWarden), but its **runtime, cumulative-Δ RFC-1624 checksum carry** is exactly
the Class-6 **silent-ICE** pattern (`1 error generated`, no text). Whether it lowers to a native
`bit<16>` ALU is unknowable until the first `bf-p4c` pass — this is Probe B / S3, run it first.

**Co-residency verdict:** two separate programs **do not fit** (Defense-2 ~10/12 + B-SIZE ~5–6/12 ≫
12 ingress). An integrated single program almost certainly needs an ingress(timing)/egress(pad+
checksum+seq-translate) split and still faces the Class-6 gate — high risk. **The clean answer:**

| Architecture | Fits? | Verdict |
|---|---|---|
| **A. Tofino-only, all three** | **No** | timing+size overflow the 12-stage wall; ACK-drop is cheap but can't rescue it |
| **B. Tofino (timing + ACK-mode) + DPU (size)** | **Yes** | clean functional split; timing/ACK on proven silicon, size on a run-to-completion element. **Recommended, staged.** |
| **C. Netronome NFP-4000, all three** | design-feasible, **not runnable today** | no 12-stage wall, but Agilio P4C/Micro-C SDK **absent**; host-CPU over the NFP wire is the runnable surrogate |

**Recommendation: adopt B, staged, with C as end-state.** Now: co-locate **request-anchored timing
hold + ACK-drop as one Tofino program** (both primitives already exist in `dcrn_ackB` form; ACK-drop
reuses the already-computed classifier — near-zero incremental stages). Then: size on a DPU / the
Vision host (already on the master-facing path over the NFP DAC). End-state: all three on the NFP
once the SDK is acquired (do **not** swap the NFP firmware meanwhile — drops the live rig link).

---

## 4. B-MODE — population ACK-mode homogenization — *sdn-networks-expert*

**The load-bearing asymmetry:** ACK-mode normalization is only achievable in ONE direction — **toward
combined** — because you can only *remove* an existing packet (byte-preserving), never *insert* one
non-cooperatively. So it is a **population** property: the combined devices are already at the target
and need **no transform**; only **SEL-751 (separate)** is touched — suppress its redundant pure ACK
(owned socket: coalesce, proven Phase-05; un-owned: Tofino `mark_to_drop` of the exact-qualified ACK).
The categorical `mode_only` channel then goes non-discriminating (**Phase-05 measured 0.667 → 0.333**).

**Composition insight:** dropping the ACK deletes the very event `dcrn_ackB` anchors on → downstream
there is only request + response → the timing normalization **must** re-anchor to the request. B-E5
and B-MODE are *coupled*; the clean composed rule is **hold every monitored response to
`max(t_ready, t_req + G)`; independently drop any exact-qualified redundant pure ACK** — actually
simpler than `dcrn_ackB` (retires the separate/combined branch).

**Topology / "morphing" assumption:** the passive attacker is **downstream of the switch**
(switch→master / dp8 side); the protected region begins at the master-facing egress; the short
device↔switch (dp9) segment is native and assumed inside the trusted perimeter — state this plainly.

---

## 5. THE FAKE-ACK VERDICT — technically possible, but the wrong move (all four experts converge)

Idea: fabricate a synthetic pure ACK so a COMBINED device presents as SEPARATE-ACK (the deliberate
opposite of B-E5's "never synthesize"). Its real target is the categorical ACK-MODE residual.

**Feasibility (p4-dataplane-engineer): FEASIBLE-to-HARD on Tofino-1.**
- *Cheap parts:* clone the request (`clone_i2e`) → rewrite in egress to a 40-B pure ACK (all fields
  derivable from the request); `ack = exp_ack` (request end-seq) is **free** (already computed);
  **sequence-neutral** (a pure ACK consumes 0 seq space → **no Δ translator, no runtime-Δ checksum** —
  fundamentally simpler than B-SIZE); the header-only checksum is the **Class-6-safe** wholesale case
  on the **egress** pipe (which B-E5 leaves nearly empty → plausibly co-resident with B-E5).
- *But it is **byte-GENERATING**, not byte-preserving* — it needs a `Checksum()` extern and fabricates
  a packet the outstation never sent. State that plainly.
- *The genuinely hard part is forgery FIDELITY:* on a TCP-timestamp-negotiated connection (the common
  Linux case) the fake ACK must carry a plausible **TSval** or the master's **PAWS silently drops it**
  (the mode-flip fails invisibly); it also needs a correct advertised **window, TTL, IP-ID
  progression**, or a sophisticated observer distinguishes synthetic from real. That needs extra
  per-flow outstation-state registers. Easier off-ASIC (NFP/host, DRAM state, C checksum).

**Direction (sdn-networks-expert): make-all-separate LOSES to make-all-combined on every axis** —
additive (adds fingerprint surface: the synthetic ACK's own timing + header must *themselves* be
homogenized) vs subtractive; transforms **2** devices vs **1**; breaks byte-preservation vs keeps it;
its one merit (keeps the request acked early during the hold) is marginal since `G ≪ RTO`. Its only
clean home is an **owned** socket (native `TCP_QUICKACK` — no fabrication); never inline on a live
device.

**Grid-safety (power-systems-expert): do NOT inject on a live CIP path.** A synthetic ACK is
**TCP-correct** (it's *not* a duplicate-ACK — the real response carries data, so it never counts
toward fast-retransmit) and application-neutral — **but** it makes a NERC-CIP asset **fabricate a
segment and source-spoof a protected IED**; the mechanics are identical to an on-path injection
attack. It corrupts incident forensics (CIP-008), trips least-functionality/detectability (CIP-007,
IEC 62443-3-3), and weakens fail-open (a fabricated packet already on the wire cannot be recalled).

**Effectiveness (research-scientist): worse than relocating — it CREATES a fingerprint from nothing.**
A combined device has **no CLRT at all**; injecting a fake ACK *manufactures* a CLRT (fake-ACK→
response gap) that did not previously exist, then must hold it constant — a near-zero-variance gap is
itself a machine-generated tell. An adaptive attacker builds a `synthetic_ack` detector ("separate
ACK with suspiciously-constant CLRT / machine-regular spacing ⇒ defended"); evading it requires
replicating a *real* device's native kernel-ACK timing — which **reintroduces the very device-specific
CLRT the defense was hiding** (a Catch-22). In the pre-registered two-number eval, the INJECT
full-stack (C5′) floors **higher** than the COALESCE stack (C5) — it adds an `R-synthetic_ack`
residual and is predicted to **regress, not improve**. Contrast with make-all-combined, which is a
no-op on the two combined devices (they're already at the target) and touches only SEL-751.

**VERDICT:** Keep the fake-ACK as a **documented, rejected alternative**. Homogenize ACK mode **toward
combined** (drop, not fabricate). If ever required, confine it to **owned-socket coalescing / an
isolated testbed**, place it on the **DPU/host** (never the Tofino), label it explicitly as
active-injection outside byte-preservation, and **prototype PAWS/master-tolerance on the Vision host
first** before any Checksum-extern P4 is written.

---

## 6. Attacker evaluation design — *research-scientist*

**Two nested problems:** **P3** {SEL751, AB1400, ION7550}, chance 0.333 (the Phase-05-anchored
number); **P2** {AB1400, ION7550}, chance 0.5 — the **acid test**, where `is_combined` is constant so
ACK-mode gives the attacker nothing and **B-E5 + B-SIZE must do all the work**. Feature families named
exactly: **mode** (`is_combined`), **timing** (`req→resp` mean + higher moments + tail/jitter — the
0.5 ms mean gap is a trap; success is defined on KS D / Cliff's δ over the *whole distribution*),
**size** (`resp_size`), **segment_count**. Joint classifier = max-over-{RF, GBM, LogReg}.

**Attribution:** a **2³ factorial** (8 conditions, add-one-in from NATIVE and leave-one-out from
FULL; condition C6 = the P2 acid test). **Metrics:** balanced-accuracy + **Miller–Madow MI** (with
permutation-null band + bootstrap CI) + **effect sizes** (Cliff's δ, KS D, paired Δ) — **no bare
p-values** (fold-level tests prohibited; only a run-level sign test on R≥5 independent runs).
**Leakage-safe:** grouped CV with the **capture run as the group**; frozen calibration fold for
B-SIZE buckets.

**The honest two-number pre-registration:** (i) the `{timing_size}` subset → **approaches chance**
(both closeable axes shut); (ii) the `{all}` set → **floors above chance** at the declared residual =
bucket-occupancy (at B>1) ⊕ TCP-timestamp clock-skew (Kohno) ⊕ ACK-mode-population (when B-MODE
scoped out). **Phase-05 trajectory anchor:** native 1.000 → +B-MODE 0.756 → +B-E5 0.681 → size floor
0.667 → **B-SIZE is the lever** that takes it toward chance.

**Pre-registered projections (before any data):**

| Problem (chance) | full-stack `{timing_size}` | full-stack `{all}` |
|---|---|---|
| **P-pair** — AB1400 vs ION7550 (0.500) | CI covers **0.500** | floors **0.55–0.65** (occupancy ⊕ skew) |
| **P-pop** — 3-class (0.333) | **0.333** | floors **0.40–0.48** (occupancy ⊕ skew ⊕ mode-residual) |

The two numbers **diverging** is the honesty: the closeable axes reach chance while `{all}` stays
above it by the named residuals. The **fake-ACK direction enters only as condition C6 — a documented
negative**: its `{all}` is pre-registered **≥** the coalesce stack's, because it adds a
`synthetic_ack`-regularity residual (a fixed-offset injected ACK has near-zero CLRT jitter where a
real kernel ACK has p10–p90 = 11.6–15.9 ms of natural jitter — the tell). Factorial is
B-E5{off,on} × B-SIZE{off,on} × B-MODE{off, combine, separate=fake-ACK}; C0–C7.

---

## 7. Honest hard limits (state up front)

1. CLRT is undefined for a combined device — every timing defense re-anchors to `t_req` and must be
   reported as **req→resp shaping (E5), never CLRT**.
2. ACK-mode is changeable **only toward combined** non-cooperatively (make-separate needs forbidden
   synthesis).
3. Holding a combined response **tightens the safety envelope** (request-RTO, ~207 ms) — fail-open on
   request retransmit is mandatory.
4. **Size is byte-modifying and the dominant residual**; occupancy floor at B>1; the size claim must
   not be folded into the byte-preserving timing claim.
5. Between AB1400 and ION7550, **timing is a weak separator (0.5 ms)** — E5 alone ≠ combined-device
   anonymity; size is the separator.
6. **Netronome is design-feasible, not runnable today** (Agilio SDK absent); co-residency is
   architectural, host-CPU is the runnable fallback.
7. **n=1 per profile** — the eval characterizes a device *configuration*, not a device *family*;
   replay not live devices; clock-skew an un-ruled-out residual. More hardware is Philip-gated.

---

## 8. Recommended build order (all gated; nothing runs without PI authorization)

1. **B-E5 request-anchored hold + B-MODE ACK-drop as ONE Tofino program** — design → local
   `bf-p4c 9.13.1` compile-fit → gated hardware window. Byte-preserving; closes the timing +
   ACK-mode axes on proven silicon. (S-caseB-1)
2. **B-SIZE on a DPU / Vision-host surrogate** — separate byte-MODIFYING line; first task = the
   Class-6 runtime-Δ checksum compile probe. (S-caseB-2, gated like the size-study S1–S3)
3. **Evaluation** per §6 (P2/P3, 2³ factorial, two-number pre-registration, grouped-CV). (S-caseB-3)
4. **Fake-ACK:** rejected for the live path; owned-socket / isolated-testbed only, host-prototype
   PAWS tolerance first if ever pursued.

**Recommended FIRST step (unprivileged, no switch, no P4):** the offline byte-transform smoke test
(size-study S0) restricted to the **pairwise AB1400-vs-ION7550** problem — it produces the first real
`{timing_size}` pairwise number and immediately surfaces any heavy-tail `k=1` occupancy residual,
before any hardware window is requested. This is the cheapest way to test the core Case-B hypothesis
(does closing timing+size drive AB-vs-ION to coin-flip) and it de-risks everything downstream.

## Provenance
PI scoping + four specialists (p4-dataplane-engineer, power-systems-expert, research-scientist,
sdn-networks-expert), 2026-07-21, grounded in: `ACK_DELAY_POLICY.md`, `dcrn_ackB.p4`,
`ACK_DELAY_STATE_MACHINE.md`, `ACK_DELAY_CASE_B_DESIGN.md`, `dnp3_split_harness/reports/phases/
phase_05_ack_mode_normalization/`, `research/inline_dnp3_size_normalization/research_design.md`,
`netronome_vision_onbox_inspection.md`, and opendnp3 `MasterParams.h`. See [[dnp3-clrt-case-taxonomy]].
