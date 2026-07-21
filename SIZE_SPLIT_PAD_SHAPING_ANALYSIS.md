# Splitting vs. Padding vs. Ditto-style shaping — security properties & Tofino feasibility

_Research note, 2026-07-21 (rev. per Dr. Lin), `research/caseA-ditto-queue`. Consolidates a
security-property / related-work review, an SDN/P4 feasibility review, and a wire-overhead
quantification on the project's real numbers. Grounded in the Ditto PDF (read directly), the Formby
PDF, and the literature cited at the end. Feeds the paper's Design + Related-Work + the size-vs-timing
split._

## Roles of the three primitives — components of ONE joint mechanism (LOCKED)
**These are NOT alternative defenses.** The DNP3 obfuscation mechanism is a single **joint
size-and-time pattern** (locked per Dr. Lin 2026-07-21; authoritative architecture in
`CASE_A_QUEUE_DESIGN.md`). This note analyzes each **component's** individual contribution; the
matrix below is a *component-contribution* analysis, not a menu to choose from.
- **Padding** maps packets **smaller** than a pattern state up to a common size state — including pure
  ACKs, DNP3 requests, and **CROB / Select / Operate / confirmation** control packets, so different
  operations occupy the same visible size class.
- **Splitting** maps **selected large/distinctive** responses (e.g. one 2407 B response → `S1 S1 S2 S1`)
  into a predefined sequence of smaller size states — the transformation for response classes that do
  not fit a state efficiently. It is one transformation, not the size defense.
- **Queue + scheduler** is the **central enforcement**: pattern states are target sizes; size-labelled
  queues hold each state; the scheduler sets state order, release time, inter-packet gap, and
  protocol ordering. It therefore provides **size obfuscation** (enforces a predefined visible sequence
  of size states) **and timing obfuscation** (transmits them on a predefined schedule, not native
  device timing) **together**.
- **CROB / SBO is IN SCOPE** for this joint size-and-time analysis: SELECT→OPERATE→confirmation
  sequences map into common padded size states on the same public schedule, so a passive observer
  cannot easily distinguish a READ from an SBO by size/timing. No unique control-specific schedule.

**Claim scope (current work):** the system *jointly* reshapes packet **size, segmentation, and
timing** (incl. ACK-to-response CLRT and SBO/CROB patterns) by mapping DNP3 packets to predefined
size states transmitted through a scheduled Traffic-Manager pattern. **Do NOT claim complete
traffic-volume independence** — without continuous chaff, a passive observer may still see whether
traffic exists, total transaction duration, packet count in some cases, and unused pattern periods.
Chaff (and volume-independence claims) are deferred until chaff is implemented and evaluated.

## Bottom line
The three security claims (splitting ≠ volume-hiding; padding ≠ count/volume-hiding; only
fixed-rate+chaff makes the pattern independent of real traffic) are **correct** under the stated
threat model. Two refinements:
1. **Feasibility — checksum is NOT the splitting blocker.** Tofino can recompute checksums (`Checksum`
   extern; `p4_decoy` and GridCloak already recompute IP+TCP on a DNP3 response on-chip). The real
   obstacle is that transparent DNP3/TCP resegmentation needs **proxy-grade stream reassembly,
   resegmentation, and retransmission state that is impractical on the current Tofino** — plus payload
   opacity and non-constant-time cutting (§3).
2. **Security — splitting is volume-*adverse*, not neutral.** It **redistributes** the response-size
   secret into segment **count** (monotone in size) and, if paced, intra-response **timing**, and it
   **increases** wire bytes 2–4× (§2). As a standalone size defense it is, by the field's coarse-feature
   yardstick (Dyer et al., S&P 2012), close to useless.

---

## 1. Feature matrix (precise terms, stated threat model)

**Threat model for this matrix:** a passive on-path observer of a **single, isolated, attributable**
encrypted DNP3/TCP transaction (one poll → response), **no cover traffic and no mixing** across
transactions or flows. (Cover traffic / mixing changes several cells — noted in §4.)

Cell vocabulary (not binary):
- **preserved** — observable passes through unchanged (secret still visible as before).
- **increased** — the mechanism actively adds to this observable.
- **coarsened** — observable made less granular (partially obscured, not independent).
- **redistributed** — the secret is moved into a *different* observable channel.
- **controlled** — observable forced to a chosen value/policy (deterministic, but that value may
  itself be a fingerprint — e.g. "defended" vs "native").
- **hidden** — observable made **independent of the secret** under this threat model (true obfuscation).

| Mechanism | TCP vol | wire bytes | pkt count | per-pkt size | segmentation | timing / CLRT | ACK mode | dir |
|---|---|---|---|---|---|---|---|---|
| **SPLITTING** (byte-preserving) | preserved | increased | increased (redistributed from size) | coarsened (redistributed) | controlled (+ split signature) | controlled (only if paced) | preserved | preserved |
| **PADDING** (per-pkt → target) | increased | increased | preserved | controlled→hidden (common target) | preserved | preserved | preserved | preserved |
| **DITTO** (states + rate + chaff) | hidden | controlled→hidden | hidden | controlled→hidden | controlled | hidden | controlled→hidden | hidden |
| **TIMING queue** (byte-preserving hold/release) | preserved | preserved | preserved | preserved | preserved | controlled (→hidden only if a common, device-independent target) | preserved | preserved |

**Reading:** only **Ditto** reaches **hidden** across the row — and only because it spends **chaff + a
fixed schedule**, which add cover traffic and modify bytes. The two byte-preserving mechanisms
(**splitting**, **timing queue**) each **control** at most one channel and **preserve** the rest;
**splitting** is the only one that **increases** three observables (wire bytes, count, and — via
redistribution — the size signal).

## 2. Wire-overhead quantification (project's real numbers)
Byte-preserving CRC-split into `N` segments adds `(N−1)×54 B` of Eth+IP+TCP headers **plus** `N−1`
packets; total payload is exactly recoverable (Σ segment payloads = original, by construction).

| Response | → N chunks | wire footprint | extra packets |
|---|---|---|---|
| SEL-751 54 B | 3 | **2.0×** (108→216 B) | +2 |
| mid 292 B | 16 | **3.3×** (346→1156 B) | +15 |
| large 2407 B | 141 | **4.1×** (2461→10021 B) | +140 |

Against a volume/count observer, splitting makes an isolated transaction **more** distinguishable
(more wire bytes, more packets — both fingerprint features); its only genuine effect is **controlling
the fine-grained segmentation** of a *particular* response.

## 3. Transparent in-network resegmentation on Tofino-1 (feasibility)
Requirement-by-requirement (Ditto §III p3; TNA/bf-p4c):

| Requirement | Tofino-1? | Why |
|---|---|---|
| Generate N packets from 1 | Partial | clone/mirror/recirc make **identical copies**, not different payload slices |
| **Partition arbitrary payload at a runtime offset** | **NO — blocker** | Ditto §III: payload "cannot be modified"; the pipeline can't address byte *k* of the payload |
| **Variable segment count / data-dependent cut** | **NO — blocker** | Ditto §III: "loops, splitting or merging packets" are "not possible"; fn2: "fragmentation is often not available on switches" |
| Rewrite TCP seq/len per segment | arithmetic OK, unusable | seq rewrite runs at line rate, but the value depends on the (impossible) cut offset |
| Recompute TCP/IP checksum | **YES — not a blocker** | `Checksum` extern + Class-6 guarded add; `p4_decoy`/GridCloak already do it on a DNP3 response |
| **Proxy-grade stream reassembly / resegmentation / retransmission state** | **NO — decisive** | preserving DNP3/TCP stream semantics under retransmit/SACK across switch-invented boundaries needs buffering/reassembly the RMT ASIC lacks |

**We do not claim splitting requires full TCP termination.** It requires **proxy-grade stream
reassembly, resegmentation, and retransmission state** — impractical on the current Tofino.

**Padding↔splitting asymmetry (key structural result).** *Padding* adds a **compile-time-constant**
filler — another header the deparser already emits, real payload untouched (byte-identical residual);
the only runtime unknown is a cumulative seq-space Δ (`seq+=Δ`/`ack−=Δ`). Because DNP3 is a stream of
self-delimiting link frames, a constant filler **prepended** is equivalent to a trailer, dissolving
the "can't emit after payload" crux. *Splitting* must **read, cut, and redistribute the variable,
opaque, runtime payload** at runtime-chosen offsets into a runtime-variable number of packets, then
carry proxy-grade retransmission/reassembly state. **Padding leans on the deparser; splitting leans on
proxy-grade stream state the ASIC lacks.** That is why the Tofino normalizes size by **padding** and
controls timing by **queue scheduling**.

**Prior work — narrowed claim.** Published **P4 packet aggregation/disaggregation** work does exist
(coarse-grained packet merging/splitting for telemetry/IoT/ML aggregation) — we do **not** claim no
in-network packet splitting exists. What we could not find, and what is impractical on the current
Tofino, is **transparent DNP3/TCP resegmentation preserving full TCP stream semantics** (arbitrary
payload boundaries, per-flow retransmission consistency). The traffic-analysis segmentation-obfuscation
work (Random Segmentation, arXiv 2309.05941; Adaptive Segmentation, IEEE 2024) does its splitting at
the **endpoint's TCP socket**, which owns the stream state; Ditto/PINOT/SPINE only pad or rewrite
headers. _[Specific P4 aggregation/disaggregation citations to be added; not yet independently verified
this session.]_ In-network MSS clamping can coarsely cap *future* segment sizes but cannot re-segment a
*specific* response.

## 4. The independence boundary — scope of the impossibility
Making the observable pattern **independent of the real traffic** requires **adding dummy/cover
traffic**. Ditto states it verbatim: the transmitted volume is *"static and independent from the real
traffic"* (§VII-A p6), and the **chaff** is what makes it work — round-robin "skips an empty queue,"
which would break the pattern, so every state gets a real (high-prio) queue **and** a chaff-flooded
(low-prio) queue so it is "never empty" (§VI p6). Fixed-rate scheduling alone decouples **timing** from
availability; **chaff** additionally decouples **volume and count**. Every defense that reaches this —
BuFLO, CS-BuFLO, TARANET, Walkie-Talkie, Ditto — adds bytes/dummies (Dyer et al., S&P 2012: coarse
total-volume/count features defeat all padding-only defenses).

**Scope (as instructed):** the "no byte-preserving mechanism can hide it" statement applies to an
**isolated, attributable transaction with no cover traffic or mixing.** With cover traffic, cross-flow
mixing, aggregation, or a shared-link pattern, total volume/count can be decoupled from a single
transaction — that is precisely the regime Ditto (and BuFLO/TARANET) operate in. So: for a lone
attributable DNP3 transaction and byte-preservation, the **timing** channel is closable (timing queue)
but the **size** channel is not; introducing padding (byte-modifying) closes per-packet/total size, and
introducing chaff/mixing closes volume/count.

## 5. Timing-release policies — three distinct options (do not conflate)
For the timing queue, "release the response at a controlled time" is not one policy. Distinguish:

1. **Native + fixed offset:** release = native_readiness + δ. Adds a constant to every CLRT →
   **shifts the mean but preserves the distribution shape** (variance, tail). Since the Formby attacker
   classifies the CLRT *distribution over a window*, the shape still separates devices. Weak — this is
   *controlled*, not *hidden*.
2. **Release at a common absolute deadline:** release = t_ack + G, one **common, device-independent
   absolute** target G. CLRT collapses to ~G for covered transactions (fail-open tail), so the covered
   mass becomes **device-independent** → *hidden* for that mass, but it creates a new constant
   "defended" signature and the fail-open tail leaks.
3. **Release according to a common schedule:** the response takes the next slot of a **common repeating
   schedule** (Ditto-style). CLRT follows the schedule independent of device readiness → looks like
   generic shaping; strongest, but needs slot machinery and empty-slot handling (idle or chaff).

Policies 2 and 3 (common, device-independent) are the defensible directions; policy 1 is not. The
final choice is deferred to Phase 4.5/5.5 (microbench precision + physical-device distribution).

## 6. Provenance of the 17 ms / 25 ms numbers (candidates, NOT final policy)
- **Data:** pooled native SEL-751 CLRT over `Traffic Trace/SEL751.pcap` (n=299) + `SEL751L.pcap`
  (n=3999) = **n=4298** separate-ACK transactions with a defined CLRT.
- **Per-transaction CLRT:** `CLRT_i = t(DNP3 response_i) − t(pure TCP ACK_i)`, extracted by
  `sel751_extract.py` (the pure ACK is matched to `req.seq + req.payload_len`, then the next
  outstation→master response; `research/tofino_dcrn_feasibility/p4/ack_delay/sel751_extract.py:48-76`).
- **Calculation:** `p95 = numpy.percentile(sorted(CLRT), 95) = 17.15 ms`; `p99 = percentile(…,99) =
  25.11 ms` (`determine_queue_pattern.py`; pooled median 12.21 ms, max 165.98 ms). These are **coverage
  points** — 95 % / 99 % of native transactions have CLRT ≤ this value.
- **Status:** **trace-derived candidates only, NOT the final policy.** A final target must be justified
  by (a) the **physical** SEL-751 distribution (Phase 5), (b) the microbench's measured slot precision
  (Phase 4), (c) a **common device-independent** principle (policy 2 or 3 above), and (d) the TCP-RTO
  and latency-budget constraints. **Not locked.**

## 7. Implications for our design (the LOCKED joint architecture)
- **The design is ONE joint size-and-time pattern** (`CASE_A_QUEUE_DESIGN.md`), not a timing queue plus
  a separate size step: pattern states = target sizes; **padding** maps small packets (ACK, request,
  CROB/Select/Operate/confirmation) to states; **splitting** maps selected large responses to a
  size-state sequence; **size-labelled queues + scheduler** enforce the state order and timing —
  obfuscating size, segmentation, inter-packet timing, and CLRT **together**.
- **Case A Defense 1:** retain the ACK until the response event, then map ACK and response into
  **consecutive scheduled size states** (padded ACK in slot *n*, response segment(s) in *n+1, n+2…*).
- **Case A Defense 2:** forward the ACK per the defense definition; map the **response** into the
  selected size-state sequence and release it on the **common schedule** (not native device timing).
- **CROB/SBO in scope:** SELECT/OPERATE/confirmation fitted into common size states on the same public
  schedule — **no operation-specific schedule** — so READ vs SBO is not distinguishable by size/timing.
- **Timing target not locked** — a **common, device-independent** policy (deadline or schedule, §5),
  chosen at Phase 4.5/5.5 from the physical distribution + microbench precision.
- **Chaff deferred:** the current claim is joint size/segmentation/timing obfuscation (§Roles);
  complete volume/count independence needs continuous chaff (§4) and is out of the current claim until
  chaff is implemented and evaluated.
- **Do NOT implement a timing-only queue that ignores the size pattern.** The queue is size-labelled.

## Citations
Formby et al., *Who's in Control of Your Control System?*, NDSS 2016 [repo PDF]. Meier, Lenders,
Vanbever, *ditto*, NDSS 2022 [repo PDF, §VI/§VII-A p6]. Dyer, Coull, Ristenpart, Shrimpton, *Peek-a-Boo,
I Still See You*, IEEE S&P 2012. Cai, Nithyanand, Johnson, *CS-BuFLO*, ACM WPES 2014 [3rd author from
memory]. Chen, Asoni, Perrig, Barrera, Danezis, Troncoso, *TARANET*, IEEE EuroS&P 2018. Chen, Asoni,
Barrera, Danezis, Perrig, *HORNET*, ACM CCS 2015 [not re-verified]. Wang, Goldberg, *Walkie-Talkie*,
USENIX Sec 2017. Meier, Gugelmann, Vanbever, *iTAP*, ACM SOSR 2017 [positioning, not a size/timing
baseline]. Meier, Tsankov, Lenders, Vanbever, Vechev, *NetHide*, USENIX Sec 2018 [positioning]. Wright,
Coull, Monrose, *Traffic Morphing*, NDSS 2009 [NOT re-verified]. Endpoint segmentation: Random
Segmentation (arXiv 2309.05941), Adaptive Segmentation (IEEE 2024). Header rewriting: PINOT (arXiv
2006.00097), SPINE. _P4 packet aggregation/disaggregation citations: to be added. Unverified flags:
NetWarden line-rate seq/ack and on-chip checksum recompute cited from repo docs; padding's runtime-Δ
checksum carry sits in the bf-p4c Class-6 zone, unproven until first compile._
