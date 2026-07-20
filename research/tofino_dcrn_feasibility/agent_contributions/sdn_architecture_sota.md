# Deployment Architecture & SOTA Positioning for In-Network DCRN Timing Normalization

*Contribution from sdn-networks-expert (feasibility study, 2026-07-18). Network-architecture + SOTA half. Research/design only. Evidence labels: [M] measured on rig · [V] vendor/standard doc · [P] paper-reported · [I] inference · [H] hypothesis · [unverified].*

## 1. Verdict (lead)
**Realize DCRN's timing hold at the EDGE, not on the Tofino-1 ASIC.** Recommended split: **FULL edge-only hold (option c)**, Tofino demoted to classification / telemetry / policy-distribution. The "decide-on-switch, hold-at-edge" hybrid (option b) is **dominated** and rejected except one narrow deployment; pure on-switch rate-shaping (option a) **cannot** reproduce DCRN semantics — rejected outright.

Structural reason: DCRN's controlled quantity is a per-flow, cross-direction, size-independent, absolute wall-clock interval `response_departure − request_arrival = D`. A host/NIC qdisc holds 16–42 ms against EDT trivially (what passed on the rig: tc+eBPF+fq [M]). A commodity RMT switch has no primitive for absolute per-packet departure — TM shapes RATE not latency [V]; only route to absolute ms-hold is recirculation (thousands–100k pipeline re-entries/frame), affordable for DNP3 only because traffic is trivially slow, yet strictly worse than the edge buffer it avoids [I per tofino_design.md §6]. The switch adds nothing to the timing hold that the on-path edge lacks, because the edge holder is itself on-path and observes the request directly.

### Component-responsibility table (recommended)
| Function | Owner | Evidence |
|---|---|---|
| Observe request, learn t0, classify flow | Edge holder AND/OR Tofino ingress (both on-path) | [M]/[V] |
| Select class-INDEPENDENT deadline D / T=t0+D | Edge holder (needs only public class+seed+counter) | [M] |
| **Hold packet(s) to T (the ms buffer)** | **Edge: host qdisc-EDT (owned) OR inline SmartNIC/DPU (unowned OT)** | [M] host; [I] DPU |
| Dual-case release (separate: ACK+resp FIFO; combined: one pkt) | Edge holder (per-pkt EDT + per-flow FIFO = fq property) | [M] |
| Fail-open guards (RTO cap, watermark, dead-man) | Edge holder (where the hold sits) | [M] |
| Line-rate classify / per-flow timing+size telemetry / attacker sampling | **Tofino-1 (its genuine job)** | [V]/[I] |
| Fabric-wide policy distribution | Tofino control plane (config-time) | [I] |
| ACK-mode split / size change | **Out of byte-preserving scope** (socket owner / off-ASIC DPU) | [M] |

## 2. Dominating tension (precise)
DCRN sets response departure T_i = t0 + D: t0 = REQUEST arrival (different packet, opposite direction); D = class-independent, D ≥ p99.9 slowest-device readiness + guard, D < effective_RTO − guard [M]; interval independent of response size (size-dependent delay re-encodes the fingerprint). Rig: native 16.8 → FIXED 32.7 → BOUNDED 37.8 ms; attacker 0.731→0.740→0.289 (chance 0.333); BOUNDED closes, FIXED leaves ~0.19 ms device-correlated residual [M]. Tofino TM = rate regulator, ~20–22 MB transient egress buffer [V], ~650 ns port-to-port [P]; not architected to park a frame tens of ms against an absolute deadline.

## 3. Three re-expressions
### (a) Pure on-switch rate-shaping/scheduled dequeue — REJECTED (tight proof)
Rate shaper is work-conserving below cap: added delay = max(0, backlog_drain_time); packet to empty token-replenished queue → added delay = 0. DNP3 poll ≥1 s vs hold ≤42 ms → every response hits idle queue → shaper delay = 0 (= tofino_design §5.3 "chunk 1 leaves immediately", from first principles). Forcing delay of a lone frame needs (i) manufactured backlog (doesn't exist) or (ii) r so low that frame_bytes/r = D — fails 3 ways: SIZE-COUPLING (delay ∝ size re-injects CROB/point size fingerprint 14.6 B/CROB, 5.7 B/pt [M]); CROSS-DIRECTION BLINDNESS (shaper has no t0 representation, can't compute t0+D); COLLATERAL THROTTLING (r≈27 kbps for 30 ms on ~100 B shatters 12 kB/49-frame large READ [M], breaks RTO). Rate-shaping CAN normalize inter-packet gaps within an already-backlogged burst (chunks 2..N) — segmentation-axis tool, NOT first-response-latency tool. PIFO/SP-PIFO/PIEO = relative rank not absolute hold [P]; TAS = cyclic quantized not per-flow deadline, and P4-TAS is Tofino-2 [P arXiv 2511.10249]. **Verdict (a): NO.**

### (b) Hybrid decide-on-switch + hold-at-edge — DOMINATED (reject except 1 case)
FATAL REDUNDANCY: any edge holder able to buffer the response is on the response path → on-path for the connection → sees the request too → computes t0 and D locally with the same info. Switch deadline computation = duplicated work, not added value. Communication cost is strictly NEGATIVE for byte-preservation: shipping the deadline either (i) writes it into a header/metadata field = adds wire bytes unless stripped (violates invariant or needs 2nd rewrite) or (ii) out-of-band mirror/digest = extra plumbing for a locally-computable value. NARROW justified case: hold hardware sees egress ONLY and genuinely can't observe the reverse request (NIC on a one-way tap downstream) → switch is the only both-directions element. NOT the lab topology (bump-in-the-wire SmartNIC/DPU sees both directions). **Verdict (b): dominated by (c).**

### (c) Full edge-only hold, Tofino = classify/telemetry — RECOMMENDED
- c1 OWNED outstation edge (current rig): run DCRN as passed — tc+eBPF (ingress arms, egress EDT) + fq on host in response path [M]. Tofino not needed for hold; contributes classify+telemetry.
- c2 UNOWNED real OT asset (deployment-realistic): can't install eBPF on vendor PLC/RTU/relay → holder = inline bump-in-the-wire SmartNIC/DPU (BlueField-class: Arm+DDR+EDT NIC) running same eBPF-EDT on Arm Linux, or SO_TXTIME/ETF hardware LaunchTime [V Intel i210/TSN ETF]. Inline → sees both directions → computes t0/D locally → no switch in timing. **SmartNIC/DPU presence on Hulk/Vision = [unverified]; c2 contingent on procuring BlueField-class DPU or ETF-offload NIC.**
Tofino role in both: shallow-parse direction/ACK-bearing/FC classification, per-flow ns-timestamp + size/gap telemetry via SALU counters, mirror/INT sampling to feed attacker-model eval at 100 G — instrument panel, not the hold.

## 4. Literature positioning
- THREAT: Formby et al. "Who's in Control of Your Control System?" NDSS 2016 — CLRT cross-layer response-time device fingerprinting [P] = direct motivation. DeviceRadar (arXiv 2404.12738) runs IoT fingerprinting IN a P4 data plane [P] → observer can be a switch.
- NetWarden (Xing/Kang/Chen, USENIX Sec 2020, on Tofino Wedge 100BF-32X): timing mitigation "temporarily holds a burst in a cache, sends back-to-back when a timer fires" — buffering in SOFTWARE SLOWPATH (control-plane CPU / co-located server) NOT ASIC fastpath; ACK-boosting SYNTHESIZES ACKs; PROXIES/caches data [P verified]. Corroborates our verdict: the hold is not an ASIC-datapath op. DCRN forbids exactly its two moves (synthesize, cache).
- ditto (Meier/Lenders/Vanbever, NDSS 2022): 100 G line-rate on Tofino by PADDING to fixed size + injecting CHAFF at constant rate [P verified]. In-network + line-rate, but NOT byte-preserving; targets aggregate uniformity not per-flow device-fingerprint timing under no-synthesis.
- NetShaper (USENIX Sec 2024): DP side-channel shaping via BUFFERED host/middlebox mechanism [P].
- PayloadPark (CoNEXT 2020): parks payloads in-switch by recirculation [P] — temporary storage, not absolute-deadline timed release.
- WF lineage (BuFLO/CS-BuFLO/Tamaraw/FRONT/RegulaTor/Surakav): privacy goal, host-side, padding+dummies [P].
- Askarov/Zhang/Myers predictive mitigation of timing channels (CCS 2010/2011): THEORETICAL BACKBONE — bound leakage via predetermined/quantized release times [P]. DCRN's release=max(ready,t0+D) with class-independent D = predictive-mitigation bounded schedule for DNP3 — citable formal grounding.
- Scheduled/timed release: Linux EDT (SO_TXTIME+ETF/fq), hw LaunchTime (i210, TSN) [V] = EDGE precedent for per-packet absolute departure (why hold belongs there). Carousel SIGCOMM 2017 end-host timing-wheel [P]. 802.1Qbv TAS [V] + P4-TAS Tofino-2 [P] = cyclic gated not per-flow absolute. PIFO/SP-PIFO/PIEO/Loom [P] = relative ordering not absolute hold.

Novelty table (survives NSDI/CCS/TNSM reviewer):
| Aspect | Precedent | Verdict |
|---|---|---|
| In-network/line-rate obfuscation on a switch | NetWarden, ditto | NOT novel |
| ms-hold lives off ASIC fastpath | NetWarden slowpath, NetShaper, EDT/Carousel | NOT novel — corroborates our verdict |
| Shaping via padding+dummies | BuFLO family, ditto | Not novel; DCRN does NOT do this |
| **Byte-preserving timing normalization (no synth/pad/CRC edits; delay only WHEN existing pkts leave)** | — | **NOVEL point in design space** |
| **Dual-case (separate+combined) class-independent absolute-deadline release vs device-fingerprint attacker on real OT/DNP3** | — | **NOVEL combination** |
| **Hold is edge-bound on commodity RMT; switch role = classify/telemetry** | NetWarden hints; not stated as a design law | **NOVEL as rigorously-argued feasibility result** |

Delta that survives review: NOT "an in-network obfuscation system" (NetWarden/ditto own that), but (i) byte-preserving no-synthesis OT timing normalizer formalized as predictive-mitigation bounded schedule; (ii) dual-case absolute-deadline mechanism; (iii) honest first-principles demo that on commodity RMT the ms-hold is edge-bound and the switch contributes classify/telemetry — a systematization+feasibility contribution that corrects "programmable switch ⇒ do the whole defense in the data plane."

## 5. Residual-handling map
ACK-mode split: passive switch CANNOT create it — needs synthesizing a new TCP segment / rewriting seq-ack / owning the socket [M Phase-04 §3a]; bump-in-the-wire can delay not manufacture; Zeek dnp3 IDS would flag. Handled ONLY at socket owner (Phase-05 coalescing normalizes toward combined). In front of unowned device → out of scope. Cost: mode_only ~0.667 persists [M].
Response SIZE: switch CANNOT conceal within byte-preserving scope — shrink/pad changes DNP3 object bytes/lengths → CRC + TCP/IP length+checksum recompute (forbidden); DNP3 padding tested = NEGATIVE (invalid-index CROB → OUT_OF_RANGE, not insertable) [M]; split preserves total bytes (no help). Handled off-ASIC protocol-modifying out of phase (encap/tunnel or synthetic padding on DPU/FPGA Stage-4) or declared out of scope. Cost: size ~0.99 accuracy [M] = dominant stable residual; joint identity never reaches chance on timing alone — paper must say so, must NOT claim device anonymity.
NET: perfect DCRN timing hold still leaves ACK mode + size intact. Timing = 1 of 3 axes; DCRN closes it, NECESSARY BUT NOT SUFFICIENT.

## 6. Research-contribution framing
Defensible claim: byte-preserving DNP3 device-fingerprint timing normalization (no-synthesis, no-padding, delays only WHEN existing packets depart; formalized as predictive-mitigation bounded release with class-independent absolute deadline) closes response-timing channel to chance (0.731→0.289, chance 0.333), preserving byte identity + transport health; AND establishes from RMT rate-shaping+recirc structure that on commodity Tofino-1 the ms-hold is NOT a data-plane primitive (rate-shaping normalizes gaps but provably can't set first-response absolute latency; absolute hold only via recirc loop dominated by a trivial edge buffer); switch's defensible role = line-rate classify+telemetry; hold belongs at edge (owned host qdisc-EDT or inline SmartNIC/DPU for unowned OT). ACK mode + size = out-of-scope residual channels.
DO NOT claim: novel in-network buffering primitive; full device anonymity; ACK-mode/size removal by DCRN; physical-device result unless tested; any Tofino result until something compiles on the testbed.

## Sources
NetWarden USENIX Sec 2020 (cs.rice.edu/~angchen/papers/netwarden-sec2020.pdf; github jiarong0907/NetWarden) · ditto NDSS 2022 (ndss-symposium.org 2022-56B; github nsg-ethz/ditto) · NetShaper USENIX Sec 2024 · Formby NDSS 2016 · DeviceRadar arXiv 2404.12738 · Askarov/Zhang/Myers CCS 2010/2011 · PayloadPark CoNEXT 2020 (dl.acm.org 10.1145/3386367.3431295) · P4-TAS arXiv 2511.10249 (Tofino-2) · Tofino latency profiling (sciencedirect S0140366424000094); Open-Tofino TNA public spec · Linux EDT/ETF/SO_TXTIME/LaunchTime (man7 tc-etf.8; AVnu tsn-doc qdiscs) · WF lineage + programmable schedulers + 802.1Qbv (research/ack_timing_normalization/paper_matrix.csv).
Repo files read: research/split_pad_timing_policy/tofino_design.md · GROUNDING.md · corrective.md · dnp3_split_harness/reports/phases/phase_04/ack_control_feasibility.md · phase_04b_dual_case_timing/phase_status.json.
[unverified]: BlueField-class DPU / ETF-offload NIC presence on Hulk/Vision (needed for c2).
