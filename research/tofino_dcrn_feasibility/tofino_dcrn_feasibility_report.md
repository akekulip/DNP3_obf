# Tofino-1 / P4 Implementation Feasibility — DCRN Response-Timing Normalization

*Synthesized feasibility study, 2026-07-18. Consolidates three independent specialist contributions
(principal-investigator framing; p4-dataplane-engineer on-ASIC feasibility; sdn-networks-expert
deployment architecture + SOTA). Research/design only — no P4 written, compiled, or loaded. Governing
spec: `corrective.md` (DCRN). Plan: `acj_delay2.md` Phase 07 (P4-readiness). Prior art:
`research/split_pad_timing_policy/tofino_design.md`. Raw contributions in `agent_contributions/`.*

*Evidence labels: [M] measured on the two-host rig · [V] vendor/standard doc · [P] paper-reported ·
[I] inference on an unbuilt design · [H] hypothesis · [unverified].*

---

## 1. Executive verdict

**Realize DCRN's millisecond timing hold at the EDGE, not on the Tofino-1 ASIC.** The switch's
defensible, in-network contribution is **line-rate classification, per-flow timing/size telemetry, and
config-time policy distribution** — not the hold. All three specialists converge on this from
independent angles.

Two sub-findings frame the whole study:

1. **On-switch feasibility (the recirc-hold, "option B"): FEASIBLE WITH CONSTRAINTS, but UNBUILT and
   DNP3-rate-bound.** A ~16–42 ms per-flow absolute hold is reachable on Tofino-1 *only* via an
   unbuilt self-clocked recirculation loop, and *only* because DNP3's ~1 s request spacing is 20–60×
   the hold. It is a trick, not a primitive, and it is dominated for the timing purpose by a trivial
   edge buffer.
2. **The deciding constraint is traffic rate, not any chip resource.** Recirc load for DNP3 is ≈0.4–1.5
   Gbps (<0.1% of the ~1.6 Tbps on-chip budget [P]) and the 42 ms hold sits ~3.5× under the RTO-safe
   cap. The verdict flips to *infeasible on-switch* only when inter-request spacing falls toward the
   hold time — which for DNP3 is ~20–60× away.

**The honest, defensible landing: hold at the edge (host qdisc-EDT where we own the outstation; an
inline SmartNIC/DPU where we don't), Tofino as the instrument panel.** The on-switch recirc-hold is
retained as the "if the hold must live on the ASIC" contingency — the more novel but riskier claim,
unproven until something compiles.

---

## 2. Problem, threat model, and what DCRN already proved

**Threat.** A passive on-path observer fingerprints the DNP3 outstation *model* from its response
timing (cross-layer response time — Formby et al., NDSS 2016 [P]). The defense must be
**byte-preserving**: no CRC recompute, no DNP3 field/length edits, no padding, no packet synthesis, no
proxy, no control commands.

**DCRN (proven in software, Phase 04B, PASS_MEASURED on the two-host Vision↔Hulk rig, 2026-07-18).**
For each transaction it records the request arrival `t0` at ingress, selects a **class-independent**
absolute deadline `T = t0 + D`, and at egress sets the outbound packet's earliest-departure-time
(`skb->tstamp`, enforced by the `fq` qdisc) to `T` — delaying *when* the byte-identical packet leaves.
Rig result [M]: native req→resp median 16.8 ms → FIXED 32.7 ms → BOUNDED 37.8 ms; attacker pure-timing
balanced accuracy 0.731 → 0.740 → **0.289** (chance 0.333). **Use BOUNDED** — FIXED leaves a
device-correlated ~0.19 ms scheduler guard residual that survived real-path jitter. Transport clean
(0 retrans/reset/dup-ack/reorder), byte-identical. **DCRN normalizes TIMING only; the categorical ACK
MODE and the response SIZE are untouched and remain device fingerprints.**

---

## 3. The mechanism gap (the spine of the study)

DCRN's controlled quantity is a **per-flow, cross-direction, size-independent, absolute wall-clock
interval**: `response_departure − request_arrival = D`. A host/NIC qdisc buffers a 16–42 ms packet
against an earliest-departure-time trivially — which is exactly what passed on the rig. A commodity RMT
switch has **no primitive that sets an absolute per-packet departure time**:

- The Traffic Manager shapes **rate** (bps/pps via token/leaky bucket), not per-packet latency [V].
  A lone response arriving to an idle, token-replenished queue — which every ~1 s-spaced DNP3 poll
  does — leaves **immediately** (added delay = 0). This is proven from shaper structure, not asserted.
- Programmable schedulers (PIFO/SP-PIFO/PIEO) release in **relative** deadline order, not on an
  absolute wall clock [P]. Time-Aware Shaping (802.1Qbv) gives **cyclic, time-quantized** release, and
  P4-TAS is demonstrated on **Tofino-2**, not Tofino-1 [P].

**The two DCRN constructs with no TNA equivalent — `skb->tstamp` (EDT) and `fq` — are precisely DCRN's
release engine** [p4 §4]. Everything DCRN does *before* release (arm `t0`, classify pure-ACK vs
combined, per-flow state, deadline math, fail-open) maps directly to TNA. The *release itself* has no
primitive, and that single gap is the entire reason an on-switch hold has to abuse recirculation.

---

## 4. On-switch feasibility — the recirculation-hold (option B), quantified

The **only** on-switch route to an absolute hold is to keep the frame in flight by recirculating it and
checking a clock each lap. Two prior-art docs in this repo took opposite tones; the study reconciles
them:

- `phase_04/ack_control_feasibility.md` §Q7 (pessimistic, correct): **bare** recirc needs tens of
  thousands of passes per packet (per-pass ≈ 0.3–1 µs) → destroys line rate.
- `split_pad_timing_policy/tofino_design.md` §6 (optimistic, correct): a **shaped/self-clocked**
  loopback port (~100 µs/pass) cuts a 42 ms hold to ~420 passes.

**Both are right.** Bare recirc is prohibitive; self-clocked recirc is affordable **only because DNP3's
request spacing (~1 s) is 20–60× the hold (~42 ms)** — "the affordability inversion." [p4 §2.4]

**Quantified feasibility (all [I] on an unbuilt design):**

| Dimension | Finding |
|---|---|
| Incremental on-switch hold | 16–21 ms (median device) up to ~42 ms (fast device / pure ACK) [M-derived] |
| Passes for a 42 ms hold | ~420 at 100 µs/pass (vs ~42,000 bare) |
| Recirc BW per held frame (~300 B) | ≈24 Mbps at 100 µs/pass |
| Peak concurrency (8–32 outstation substation) | ~16–64 held frames → **≈0.4–1.5 Gbps** |
| vs on-chip recirc budget (~1.6 Tbps [P]) | **<0.1%** |
| Worst hold (42 ms) vs RTO-safe cap (~150 ms; Vision RTO ≈211 ms [M]) | ~3.5× headroom |
| MAU stages (classify+arm+deadline+guards) | ~5–7 of 12 [I] — standalone fits; **cannot co-reside** with a 12-stage sibling |

**Two new requirements the prior split-pacing design did not cover, and their resolution:**

- **Dual-case ordering (separate pure-ACK then response).** Two frames to one deadline, ACK must
  egress first. `fq` gives this free on the host; recirc does not. **Resolution:** DCRN's own
  guard-delta (`response deadline = target + guard_delta`) maps to "≥ one recirc pass (~100 µs)" and
  enforces FIFO by construction. The measured host guard-delta (~0.19 ms) exceeds one pass — so the
  **same ~0.19 ms residual that made FIXED leak on the host reappears as recirc quantization on Tofino,
  and the "use BOUNDED" verdict carries over to the switch.** [p4 §2.5]
- **BOUNDED sampling with a deterministic seed.** On-chip `Random<>` cannot reproduce the host seed.
  **Resolution:** the controller installs a small pre-sampled distribution table (64–256 values, drawn
  host-side with the deterministic seed), indexed by the transaction counter — reproducibility
  preserved off-chip, device-independence intact. [p4 §2.6]

**bf-p4c constraints that bite** (skill-verified this session): the deadline compare `now >= deadline`
must be a **32-bit SALU predicate** on a pre-sliced tick (`global_tstamp[47:16]`, 65.5 µs resolution) —
it will not fit a gateway (≤44-bit predicate, Class 1) or a TCAM range key (≤20-bit, Class 2); flags
widened to `bit<8>` (Class 3); **no in-SALU `v==0` sentinel** (Class 8 — seed registers from the
controller). Fail-open is five cheap guards (RTO cap, watermark, max-pass, wrap, policy-absent),
default action **forwards, never drops** — a dropped or RTO-overshot response is the loudest tell and
trips a Zeek `dnp3` IDS. [p4 §2.3, §2.7]

**Non-recirc alternatives — none gives an absolute per-flow deadline** [p4 §3]: TM shaper/meter (rate
only; lone frame leaves immediately), 802.1Qbv TAS (cyclic only, Tofino-2), deflect-on-drop (uncontrolled),
packet-generator (emits *new* packets — synthesis, forbidden), TM buffer (transient, not addressable
storage), PFC/pause (whole-link, unsafe on an ICS conduit), PIFO/SP-PIFO (relative order only). PIFO is
a companion release discipline *once frames are held*, not a hold.

---

## 5. Deployment architecture — where the hold lives

Three re-expressions were evaluated; the recommendation is (c), with one important nuance.

**(a) Pure on-switch rate-shaping — REJECTED (tight proof, not assertion).** A max-rate shaper is
work-conserving below its cap: it delays a packet only when standing backlog already queued ahead of it
pushes its drain turn later. At ≥1 s poll spacing every response hits an idle, token-replenished queue
→ added delay = **0**. Forcing a lone frame to wait requires setting the rate so low that
`frame_bytes/r = D`, which (i) makes the delay a **function of size** — re-injecting the exact
CROB/point-count size fingerprint DCRN removes; (ii) is **cross-direction blind** — the shaper has no
representation of `t0`; (iii) **shatters** the 12 kB / 49-frame large-READ response. Rate-shaping
normalizes inter-packet *gaps within a burst* (a segmentation-axis tool), never first-response absolute
latency. [sdn §3a]

**(b) Hybrid "decide-on-switch, hold-at-edge" — DOMINATED except one narrow case.** The sdn agent's
**fatal-redundancy** argument: any edge element able to buffer the *response* is on the response path,
therefore on-path for the connection, therefore **sees the request too** — so it can compute `t0` and
`D` locally with the same information the switch would use. The switch's deadline computation is
duplicated work, and shipping the deadline downstream either **adds wire bytes** (violating
byte-preservation unless re-stripped) or needs out-of-band plumbing. The hybrid pays off **only** when
the holder is an egress-only tap that genuinely cannot see the reverse request — **not** the lab
topology (a bump-in-the-wire SmartNIC/DPU sees both directions). [sdn §3b]

> **Reconciliation of a real disagreement.** The p4 and PI framings phrase the recommendation as
> "Tofino does the decision, edge holds." The sdn "fatal-redundancy" argument refines this: for an
> **inline** edge holder the switch's per-transaction *decision* is also redundant, leaving the switch
> a **classification + telemetry** role rather than a per-flow deadline role. All three agree the
> **hold** is edge-bound; the residual disagreement is only about whether the switch usefully computes
> the deadline, and it resolves cleanly by topology: inline holder → switch does classify/telemetry;
> egress-only holder → switch also computes the deadline. For this testbed (inline), the switch is the
> instrument panel.

**(c) Full edge-only hold, Tofino = classify/telemetry — RECOMMENDED.**
- **c1 — owned outstation edge (the current rig):** run DCRN exactly as it passed (host tc + eBPF +
  `fq` in the response path) [M]. Tofino contributes classification and telemetry only.
- **c2 — unowned real OT asset (deployment-realistic):** cannot install eBPF on a vendor PLC/RTU/relay,
  so the holder is an **inline bump-in-the-wire SmartNIC/DPU** (BlueField-class: Arm + DDR + EDT NIC)
  running the same eBPF-EDT logic, or `SO_TXTIME`/ETF with hardware LaunchTime [V]. It is inline → sees
  both directions → computes `t0`/`D` locally → **still no switch in the timing path.**
  **[unverified] whether a BlueField-class DPU or ETF-offload NIC is present on Hulk/Vision — c2 is
  contingent on procuring one.**

**Recommended component split:**

| Function | Owner |
|---|---|
| Hold the packet(s) to `T` (the ms buffer) | **Edge** — host qdisc-EDT (owned) or inline SmartNIC/DPU (unowned) |
| Select the class-independent absolute deadline | Edge holder (inline, sees the request) |
| Dual-case release, fail-open guards | Edge holder |
| Line-rate classify / per-flow timing+size telemetry / attacker sampling | **Tofino-1** |
| Fabric-wide policy distribution (config-time) | Tofino control plane |
| ACK-mode split / response-size change | **Out of byte-preserving scope** (socket owner / off-ASIC DPU) |

---

## 6. SOTA positioning and the honest novelty boundary

**Closest in-network systems, and how DCRN differs** (all verified from sources this session [P]):
- **NetWarden** (USENIX Sec 2020, on Tofino) mitigates timing channels by "holding a burst in a cache
  and sending back-to-back when a timer fires" — but that buffering lives in the **software slowpath**
  (control-plane CPU / co-located server), **not** the ASIC datapath, and it **synthesizes** ACKs and
  **proxies/caches** data. It forbids exactly what DCRN forbids, and **independently corroborates**
  that the ms-hold is not an ASIC-datapath operation.
- **ditto** (NDSS 2022, on Tofino, 100 G line-rate) obfuscates by **padding to fixed size + injecting
  chaff** — genuinely in-network, but **not byte-preserving**, and targets aggregate uniformity, not
  per-flow device-fingerprint timing under a no-synthesis constraint.
- **NetShaper** (USENIX Sec 2024): DP side-channel shaping via a **buffered host/middlebox** mechanism.
- **Askarov/Zhang/Myers predictive mitigation of timing channels** (CCS 2010/2011): the theoretical
  backbone — bound leakage by releasing at predetermined/quantized times. DCRN's
  `release = max(ready, t0 + D)` with a class-independent `D` is a predictive-mitigation bounded
  schedule for DNP3 — a citable formal grounding.

**Novelty boundary (state it plainly):**
- **NOT novel:** in-network / line-rate obfuscation on a switch (NetWarden, ditto own this); that the
  ms-hold lives off the ASIC fastpath (corroborates our verdict, cite it); shaping via padding+dummies.
- **NOVEL:** a **byte-preserving, no-synthesis** timing normalizer (delays only *when* existing packets
  leave); the **dual-case** (separate + combined) class-independent **absolute-deadline** release
  against a **device-fingerprint** attacker on a real **OT/DNP3** protocol; and the rigorously argued
  **feasibility result** that on a commodity RMT switch the hold is **edge-bound** and the switch's role
  is classify/telemetry — a systematization-and-feasibility contribution that *corrects* the natural but
  wrong "programmable switch ⇒ do the whole defense in the data plane."
- **Caps:** single-device-per-profile traces → device-**configuration** discrimination, not a proven
  device-**family** fingerprint; **timing-axis only**; the on-switch hold is **unbuilt / inference**
  until compiled P4 + hardware evidence exists.

---

## 7. Risk / residual ledger

| Item | Severity | Disposition |
|---|---|---|
| **Response-size fingerprint** (~0.99 classifier; 14.6 B/CROB [M]) | **High to any anonymity claim** | **Scope out** — outside byte-preserving phase; padding is a proven dead end (invalid-index CROB → OUT_OF_RANGE, not insertable). Never claim DCRN/Tofino touches size. |
| **ACK-mode fingerprint** (mode_only ~0.667 [M]) | Medium | **Scope out** — a passive switch cannot synthesize the split; owned by the separate socket-coalescing primitive. |
| **Recirc-load ceiling** | Low for DNP3, High if generalized | The duty-cycle argument makes it negligible for slow SCADA; **explicitly flag it does not generalize.** |
| **RTO / latency margin** | Medium | RTO-cap guard set below the **measured** Vision RTO (~211 ms; ~200 ms is a Linux floor, not universal — re-measure per deployment). |
| **Fail-open safety** | **High** | Never drop, never overshoot RTO, clean revert. The five guards must be **demonstrated in hardware**, not asserted — a spurious retransmit is the loudest tell and trips a Zeek `dnp3` IDS. |
| **Guard-delta residual** (~0.19 ms, device-correlated) | Medium | Operate **BOUNDED**; the on-switch mechanism must realize the class-independent target without re-introducing a deterministic per-mode delta. |
| **Reproduction caveats** | Medium to external validity | Config-not-family; every Tofino number is **inference until compiled P4** — the plan forbids stating stage/SALU/queue/line-rate counts without a compile. |
| **SmartNIC/DPU availability (c2)** | Medium | [unverified] on Hulk/Vision — c2 is contingent on procurement. |

---

## 8. Verdict rubric applied (P4-readiness)

Per-sub-capability, in the Phase-07 "likely feasible vs. potentially difficult" format:

| DCRN sub-capability | On Tofino-1 | Evidence that would upgrade it |
|---|---|---|
| Classify direction / ACK-bearing / FC | **Likely feasible** (shallow parse, native) | A `bf-p4c` compile of the Stage-1 classifier |
| Pure-ACK vs combined (`payload_len==0`) | **Likely feasible** (exact discriminator) | same |
| Per-flow state (arm `t0`, deadline, flags) | **Likely feasible** (registers + SALU) | compile + resource report showing the 32-bit compare fits an SALU predicate |
| Per-flow / size telemetry | **Likely feasible** (SALU counters, mirror/INT) | compile + hardware counter read |
| **Absolute ms-deadline hold** | **Feasible with constraints, UNBUILT** (recirc-hold; DNP3-rate-bound) | compile + hardware capture: timing flattens to target, byte-identical, 0 spurious retransmits, measured recirc load |
| BOUNDED sampling (seed-reproducible) | **Indirect** (controller distribution table) | rig validation of the table-indexed target |
| Release engine (`skb->tstamp` / `fq`) | **No equivalent** | — (this is the edge's job) |

**Landing:** the study lands on **edge-bound hold + switch classify/telemetry** as the defensible-today
architecture, with the **on-switch recirc-hold (B) as a feasible-but-unbuilt, DNP3-rate-bound
contingency** reserved for the case where the hold must be on the ASIC. Native TM shaping (A) is ruled
out; DPU/FPGA relegation (E) is the fallback if a future compile shows the deadline compare or fail-open
cannot be guaranteed on-chip.

---

## 9. Recommended next step (gated) and the decisions that are Philip's

**Recommended next experiment:** a **compile-only Stage-1 probe** — classify + arm + deadline-compute,
**no hold built** — to upgrade the "likely feasible" classify/telemetry claims from inference to a
`bf-p4c` resource report. This is the minimal step that produces real hardware evidence, and it stays
inside the byte-preserving, no-synthesis constraint.

**Per the plan's final gate (`acj_delay2.md`) and the one-primitive-at-a-time rule, that probe is NOT
started automatically. Three decisions are Philip's alone:**

1. **Headline framing / venue fit.** Edge-bound-hold + switch-classify/telemetry (defensible today,
   security/grid venue) vs. the on-switch recirc-hold (more novel, P4/systems venue, but riskier and
   contingent on the compile succeeding).
2. **Authorize even the compile-only Stage-1 P4 probe?** It touches P4, so it needs an explicit
   go/no-go despite building no hold.
3. **External-validity ceiling.** A device-*family* claim (vs. device-*configuration*) needs additional
   physical devices — a separate data-collection line that only Philip can green-light.

**Further specialists available on request** (from the PI delegation map): `research-scientist` +
statistical-analysis for a re-expressed-release equivalence eval; `literature-reviewer` for a full SOTA
matrix; `ieee-journal-reviewer` for an adversarial pre-submission pass; `power-systems-expert` for the
DNP3-correctness lens (RTO-binding, fail-open, protection-traffic allowlist).

---

## 10. Provenance and integrity

- **Nothing was compiled, loaded, or run on the switch this session** — this is a design/feasibility
  study under the research-only constraint. Every Tofino resource/latency/buffer number is relayed from
  prior-art vendor/paper citations or is inference on an unbuilt design; a `bf-p4c` compile on the
  testbed remains the only real proof of the stage/SALU fit.
- Measured facts [M] are from the Phase-04B rig result, `corrective.md`, `GROUNDING.md`, and
  `phase_04/ack_control_feasibility.md`.
- Raw specialist contributions: `agent_contributions/p4_tofino_hardware_feasibility.md` (219 lines),
  `agent_contributions/sdn_architecture_sota.md`, and the PI framing (scratch).
