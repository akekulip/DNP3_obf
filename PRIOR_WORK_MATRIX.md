# Prior-Work Matrix — DNP3 Fixed-Transcript Defense

**Question under study.** Can an in-network defense make the observable wire transcript
`O = [(direction, size, release_time, outer_header)_i], i = 1..K` *independent of the protected
device / response*, i.e. `P(O | X=x, C=c) = P(O | X=x', C=c)`? Leading hypothesis to beat: a
Ditto-style repeating pattern. Deployment constraint: **one Tofino-1 at the outstation edge**,
**plaintext DNP3/TCP**, **unmodifiable outstation**, **separate-ACK Case-A CLRT**, **exact byte
recovery required**.

This document positions that problem against the closest primary works. It states, per work,
exactly what is already solved and where it stops. **Novelty is argued as a specific technical
recombination, never from keyword absence.**

> **Reconciliation banner (added by the lead after the transport analysis and the skeptical review).**
> Two of the novelty pillars proposed in this document's "Novelty candidate" section are **superseded**
> and must not be carried into the paper: **Z.1 "plaintext-safe CRC-valid chaff"** and **Z.2
> "single-edge, endpoint-preserving."** The transport safety analysis (`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`
> §2) and risk R14 show that plaintext CRC-valid chaff is either detectable (bad CRC / illegal frame)
> or dangerous (the master's DNP3 stack runs `ProcessIIN` even on rejected frames; a fabricated CONFIRM
> can delete relay SOE records), and that a single-edge, no-encryption design provably cannot reach a
> fixed transcript. The sound, reconciled novelty position is stated in `DECISION_MEMO.md` §4: the
> defensible contributions are the impossibility boundary, the measured Architecture-5 floor, and a
> silicon-confirmed TSval/TSecr closure, plus (conditionally) a measured switch-versus-software cadence
> delta. The Ditto/IP-TFS nearest-neighbor analysis below stands unchanged and is correct.

Access level for every source (full-text vs abstract-only) is recorded in
`references/README.md`. Reading depth: Ditto, NetShaper, Formby, and RFC 9347/IP-TFS were read at
the design/mechanism/evaluation level; USENIX-hosted PDFs (Securitas, Minos, Pacer) 403'd and are
represented at abstract + author-summary + artifact-repo fidelity.

---

## Legend

- **Fixes** column uses `{C,S,T,D,H}` = does the mechanism regularize **C**ount, **S**ize,
  **T**iming (release time), **D**irection, **H**eaders? `✓` full / `~` partial or statistical /
  `✗` no / `enc` = made unobservable by encryption rather than by shaping.
- **Op** = Continuous constant-rate (`cont`) vs Event-triggered (`trig`).
- Work IDs (used across both tables): **DIT** Ditto · **SEC** Securitas · **MIN** Minos ·
  **PIN** PINOT · **NSH** NetShaper · **PAC** Pacer · **TFS** IP-TFS/RFC 9347 ·
  **FOR** Formby (attack) · **SNP** ICS-Sniper (attack) · **HU** Hu SmartGridComm P4-DNP3 ·
  **NTO** NTOS-IIoT · **SYN** Synchrophasor-P4 · **WFD** WF/link-padding family ·
  **IOT** IoT smart-home shaping · **TSN** 802.1Qbv time-aware shaper ·
  **TS7** RFC 7323 TCP timestamps (+Kohno clock-skew).

---

## Table 1 — Adversary, endpoints, encryption, what is fixed, operation

| ID | Adversary & protected secret | Endpoint assumption | Enc? | Fixes C/S/T/D/H | Op |
|----|------------------------------|---------------------|------|-----------------|----|
| **DIT** | Passive WAN eavesdropper on one/many links; secret = real per-link traffic (sizes, inter-packet time, volume, flow membership, path) | **No host changes**; runs on 2 switches bracketing a protected link (per-link, not per-flow) | **Yes** (MACsec at line rate) | C✓ S✓ T✓ D✓ H:enc | cont |
| **SEC** | Passive traffic-analysis classifier on encrypted flows; secret = website/app activity | Proxy switch near sender; **real server must reassemble fragments**; downstream Internet nodes drop small-TTL fakes | Yes | C~ S✓ T~ D✗ H✗ | trig (per-packet, learning-guided) |
| **MIN** | Traffic-analysis + identity linking on encrypted flows; secret = identity + flow shape | Gateway/proxy switch; no host change | Yes | C~ S✓ T~ D~ H:enc(header re-encrypt) | trig/dynamic |
| **PIN** | Downstream ASes / destination servers; secret = client **identity (IPv4 address)** — not shape | Gateway switch in campus net; no host change | n/a (address encryption) | C✗ S✗ T✗ D✗ H✓(src-IP only) | trig |
| **NSH** | On-path ISP that records size/timing/direction; secret = app content/activity (video, web). Non-goals: type, protocol, identity | **Middlebox tunnel endpoints** (2), app must connect to local endpoint; QUIC/UDP userspace | Yes (QUIC) | C~ S✓(DP) T✓(interval) D✓(per-dir) H:enc | cont (per interval T) |
| **PAC** | Cloud co-tenant / network side channel; secret = guest response size/timing | **Hypervisor + guest-kernel changes** (paravirtualizing) | Yes | C✓ S✓ T✓ D~ H:enc | cont (scheduled) |
| **TFS** | Passive observer of an IPsec tunnel; secret = inner IP flow sizes/rate (traffic-flow confidentiality) | **Two IPsec tunnel endpoints**; inner hosts unaware | Yes (ESP) | C✓ S✓ T✓ D✓ H:enc(inner)/SPI+seq observable | cont (const-rate) or cong-controlled |
| **FOR** | *Attack.* Passive on-path observer; infers **device type / software config / spoofing** via CLRT (DNP3 app-response − TCP-ACK gap) | Observes real DNP3 traffic; no defense proposed | Plaintext | — (measures, does not fix) | — |
| **SNP** | *Attack.* Internet adversary on encrypted ICS traffic; infers **which message is critical** from size/timing, then blackholes it | On-path; encryption present but leaks shape | Yes | — (measures, does not fix) | — |
| **HU** | DNP3 protocol attacks: malformed/length-overflow, event-buffer DoS, config-corrupt MITM; secret/goal = **integrity, availability, confidentiality of DNP3 messages** (NOT shape) | P4 switch in DNP3 path; DPI parser; no host change | adds encryption/hashing as a feature | C✗ S✗ T✗ D✗ H✗ (does not shape) | trig (inspection) |
| **NTO** | Passive analyst of IIoT-cloud control traffic; secret = control communication pattern | Host/agent + split server ("non-receiving agents" emit timed dummies); packet scrambling | pad+encrypt option | C~ S~ T~ D✗ H~ | trig (dummy on response) |
| **SYN** | Spoofed/malformed synchrophasor (C37.118/61850-90-5) traffic; goal = integrity + anomaly detection (NOT shape) | P4 switch; no host change | no | C✗ S✗ T✗ D✗ H✗ | trig (validation) |
| **WFD** | Tor/WF classifier; secret = visited site. Family: BuFLO, CS-BuFLO, Tamaraw, Walkie-Talkie, WTF-PAD, FRONT, Traffic-Morphing | **Endpoint/proxy (client + bridge)**; both ends cooperate | Yes | C~ S✓ T✓ D~ H:enc | cont (BuFLO/Tamaraw) or trig (adaptive) |
| **IOT** | Passive observer of home ISP link; secret = smart-home **device activity**. Apthorpe ILP / Stochastic Traffic Padding | Home router / hub shaping; no device change | Yes | C~ S✓ T✓(ILP) D~ H:enc | cont (ILP) or trig (STP) |
| **TSN** | *Not privacy.* 802.1Qbv time-aware shaper; goal = deterministic latency; secret = none | Bridges with synchronized gate-control lists | n/a | C✗ S✗ T✓(gated) D✗ H✗ | cont (schedule) |
| **TS7** | *Header side channel.* RFC 7323 TCP Timestamps (TSval/TSecr) + Kohno 2005 remote clock-skew fingerprinting; secret = device clock / identity via outer header | End hosts set timestamps; observer reads them | — | reveals H (per-packet) | — |

---

## Table 2 — Chaff generation, scheduler/queues, overload, loss handling, hardware, eval

| ID | Chaff / dummy generation | Scheduler & queue architecture | Overload behavior | Loss / retransmission | Hardware | Eval scale |
|----|--------------------------|--------------------------------|-------------------|-----------------------|----------|-----------|
| **DIT** | Continuous **recirculate-and-clone** chaff into low-prio queues; 1 switch port for recirc; no traffic generator | **2-level hierarchical**: per pattern-state pair {high=real, low=chaff}; round-robin across states; realized by 2 passes via loopback ports; padding by stacked 32/16/8/4/2/1-B custom Ethernet headers, ≤254 B/pass, recirc for more | **Drops rather than violate the pattern**; near-zero loss ≤60–70 Gbps (CAIDA)/70–80 (interactive) | TCP retx works end-to-end (Ditto transparent); non-interactive traces replayed | Intel Tofino; 32×100G; needs **2 switches** (add vs remove padding); MACsec | 100 Gbps line rate; patterns L=3–6; 1 MB buffer covers 99% BW; 92% order preserved |
| **SEC** | **Insert fake packets with small TTL** (default p=0.3) discarded by Internet nodes before the real server; **fragment** real packets | Learning-guided policy (policy-gradient agent trained vs a NN attacker, ISCX VPN data) chooses which/how to obfuscate; flexible per-packet | not detailed publicly | Fragments **reassembled at the real server**; fakes never reach it | **Tofino + AMD/Xilinx FPGA + eBPF + BMv2** | ↓ attack acc up to **95.89%**; **42.69× less bandwidth** vs prior; +0.15 s page-load |
| **MIN** | Dummy insertion + padding via **priority dummy queues**; flow **interleaving** "simulates" dummies without extra BW | Proxy + Traffic-Morphing + Schedule modules; header encryption via round-compression in match-action pipeline | minimize BW/delay overhead (claimed) | not detailed publicly | Programmable switch (Tofino-class) | overhead + attack-accuracy numbers in paper |
| **PIN** | none (no chaff; identity only) | Match-action encryption of client IPv4 | n/a | transparent | Barefoot Tofino, campus deploy | DNS/NTP/WireGuard tests |
| **NSH** | **DP noise** sets #dummy bytes; dummy = QUIC **STREAM** frames (not PADDING frames, which are distinguishable) sent through shared transport | Per-flow buffering queue Q; DShaper/UShaper userspace; periodic DP query on queue length L → shaped buffer of R payload + D dummy bytes; split to MTU packets | Buffering queue **TTL**; drops bytes older than W (Assumption 1) | QUIC reliability/congestion/loss; avoids TCP-over-TCP meltdown | **Middlebox** (userspace, not a switch ASIC) | video streaming + web; DP (ε,δ) tunable; defeats SOTA classifiers |
| **PAC** | Hypervisor emits **dummy packets when guest payload not ready**; secret-independent by design | Traffic shaped **outside the guest** to a schedule; cloaked-tunnel abstraction; respects flow/congestion/loss signals | schedule fixed; dummies fill | preserves guest TCP flow/congestion/loss recovery | **Hypervisor extension + guest-kernel** changes | IaaS cloud; end-to-end NSC elimination |
| **TFS** | **All-pad AGGFRAG payloads** emitted only when no inner data at send time | Constant send-rate = bandwidth / fixed-cell-size; **aggregation + fragmentation** packs partial/whole/multiple inner packets into fixed cells; **BlockOffset + monotonic ESP seq** drive reassembly; reorder sliding window | const-rate mode ignores congestion (needs path control); cong-controlled mode lowers rate (RFC 5348) | Reorder window; **fragment loss loses only that inner packet**; fragments must use consecutive ESP seq / same SA | IPsec software (e.g., strongSwan); tunnel endpoints | RFC-level spec; efficiency vs RFC 4303 all-pad |
| **FOR** | — | — | — | — | Passive taps on live DNP3 substation | ~130 devices, DNP3, 5 mo + 2nd substation ~80; **93% acc at 5-min slices**; CLRT tens–hundreds ms |
| **SNP** | — | — | — | selective **blackhole** of critical packets | Internet path; SWaT-plant emulation | infers critical messages from size/timing on encrypted ICS |
| **HU** | none (security features, not shaping): hashing, encryption, header/payload inspection, custom filtering; **P4 DNP3 parser** for DPI | match-action pipeline; per-packet or multi-packet-aggregated inspection | rejects malformed / rate-limits DoS | not a shaping concern | **P4 switch** (bmv2/Tofino-class) | 3 case studies: length-overflow, event-buffer-flood DoS, config-corrupt MITM |
| **NTO** | Timed **dummy packets** matched to real response timing + **packet scrambling**; split server | rule-based obfuscation (rule known only to legitimate device) | maintains response-time budget (safety-aware) | not detailed | Host/agent software | IIoT-cloud control; scrambling + dummies |
| **SYN** | none | stateful P4 validation / anomaly rules | reject anomalies | n/a | P4 switch | synchrophasor integrity/resilience |
| **WFD** | BuFLO/Tamaraw: **constant-rate dummy packets** in fixed cells at fixed intervals; adaptive (WTF-PAD/FRONT): burst-gap dummies from a distribution | Endpoint/proxy pacers; Traffic-Morphing (Wright) matches a target size distribution | Tamaraw pads tail; overhead vs anonymity tradeoff | TCP at endpoints | Host software / Tor bridge | Tor traces; bandwidth/latency overhead vs accuracy |
| **IOT** | Independent Link Padding: **device-independent constant traffic**; STP: dummy shaping around real activity windows | Router/hub shaper | ILP is fixed-rate regardless of activity | preserves app TCP | Home router / hub | smart-home devices; activity-inference reduction |
| **TSN** | none | **Gate-control lists** open/close queues on a time schedule (time-triggered) | deterministic; frames wait for gate | standard Ethernet | TSN bridges | latency/jitter bounds (not privacy) |
| **TS7** | — | — | — | — | any TCP stack | TSval monotonic per-connection reveals clock; Kohno: skew fingerprints a device remotely |

---

## Nearest-neighbor analysis

Two works are closest, on two different axes. The DNP3 fixed-transcript design inherits heavily
from both and must add a specific, non-trivial delta to each.

### Nearest neighbor #1 — **Ditto (NDSS 2022)** — the *mechanism* twin (the hypothesis to beat)

Ditto is the leading hypothesis made concrete: shape traffic into a **repeating pattern of
pre-defined (size, timing) packets**, on a **Tofino**, with **in-switch chaff** and no host
changes. Its internals map almost one-to-one onto what a DNP3 fixed-transcript engine would want.

**What a DNP3 design inherits from Ditto:**
- The repeating obfuscation pattern `P = [P_0..P_{L-1}]` of fixed sizes emitted at a fixed rate —
  the direct ancestor of a fixed transcript `O` of length `K`.
- In-switch chaff without a traffic generator: **recirculate a chaff packet and clone it** into a
  low-priority queue.
- **Two-level queueing**: per transcript slot a pair {high-priority = real, low-priority = chaff},
  fed to a round-robin scheduler so a slot is *never empty* — realized as a **two-pass / loopback**
  design on Tofino. This is exactly the four-queue / loopback scheduler the project already has.
- **Drop-rather-than-violate** overload semantics, and padding via **stacked custom headers**
  removed at the far end.

**Where Ditto stops — the delta a DNP3 design must add:**
1. **Ditto requires encryption (MACsec).** Its entire security argument ("attacker cannot
   distinguish real from chaff, cannot read padding") rests on the payload being ciphertext. DNP3
   Case-A is **plaintext, CRC-framed, self-describing**: a passive parser reads function codes,
   IIN bits, object headers, and *validates CRCs*. Therefore chaff cannot be arbitrary bytes — it
   must be **CRC-valid, master-plausible DNP3 framing**, and padding cannot be a strippable extra
   header the observer can trivially ignore.
2. **Ditto needs two switches** (one adds padding, the peer removes it before the unprotected
   link). The project has **one Tofino** and an **unmodifiable outstation** that will not
   de-encapsulate anything. The transcript must be recoverable by the *real master with no
   endpoint change*.
3. **Ditto is continuous, per-link, direction-symmetric.** DNP3 is **event-triggered
   request→ACK→response** with a **separate-ACK Case-A CLRT** (the Formby feature) that must be
   normalized — a timing problem Ditto never addresses because it drowns everything in constant
   chaff.
4. **Ditto cannot split packets** ("fragmentation is often not available on switches"); it only
   pads to the next-larger pattern size. DNP3 responses are **variable and can far exceed one
   packet** (the repo's 12,204-byte READ breaks any small fixed-K size bound), so the design needs
   **fragmentation/aggregation with exact recovery**, which Ditto lacks.

### Nearest neighbor #2 — **IP-TFS / RFC 9347 (2023)** — the *exact-recovery-under-fixed-framing* twin

IP-TFS is the closest thing in the literature to "carry a **variable** payload inside a **fixed-size,
constant-rate** outer transcript and recover **exact bytes**." It is the missing piece Ditto lacks.

**What a DNP3 design inherits from IP-TFS (conceptually):**
- **Constant-rate, fixed-size outer cells whose rate/size are independent of the inner traffic** —
  literally the `P(O|inner)=P(O)` transcript-independence goal, already specified and analyzed.
- **Aggregation + fragmentation**: pack partial / whole / multiple inner units into fixed cells,
  filling with all-pad cells when idle.
- **Exact reassembly** via an explicit **offset pointer (BlockOffset) + monotonically increasing
  sequence numbers**, with a **reorder window**; a lost fragment damages only its own inner unit.
  This is the template for recovering a segmented DNP3 response byte-for-byte.

**Where IP-TFS stops — the delta a DNP3 design must add:**
- IP-TFS reassembles at the **far IPsec endpoint under ESP encryption**. DNP3 has **no second
  cooperating endpoint** and **no encryption**: reassembly cannot happen at the outstation
  (unmodifiable) and ideally not at the master (unmodified), and the framing must be **CRC-valid
  DNP3 over a live TCP connection** (correct seq/ack space, checksums) rather than opaque ESP
  cells. So the aggregation/fragmentation must be done **switch-side on plaintext DNP3** (closer to
  **Securitas**'s switch-side fragmentation, but Securitas still relies on the *real server* to
  reassemble and on *downstream nodes* to drop small-TTL fakes — neither exists on a point-to-point
  outstation link).

---

## The single sharpest "what remains different for DNP3"

**Every close system buys transcript-independence with one of two resources the DNP3 Case-A
setting denies it:**

- **(a) Encryption cover** — Ditto (MACsec), NetShaper (QUIC), Pacer, IP-TFS (ESP), Minos, the
  WF/IoT families all assume the payload is ciphertext, so chaff is indistinguishable from real
  and outer headers are hidden/rewritten under the crypto boundary; **or**
- **(b) A cooperating second endpoint** — a peer switch that strips padding (Ditto), a tunnel
  egress that reassembles (IP-TFS), a real server that reassembles fragments and downstream nodes
  that discard fakes (Securitas), tunnel endpoints/hypervisor/guest-kernel (NetShaper, Pacer).

**DNP3 Case-A provides neither.** The observer parses *plaintext, CRC-checked* DNP3 and reads the
*live TCP/IP outer header per packet*, and there is exactly **one Tofino** with an **unmodifiable
outstation** and an ideally **unmodified master**. Consequently the fixed transcript must be built
from **CRC-valid, master-parseable DNP3 frames on a live TCP connection**, be **recovered with zero
endpoint change**, **normalize the separate-ACK CLRT** (kill the Formby fingerprint), **and rewrite
the per-packet TCP/IP outer-header fields** (seq/ack, IP-ID, window, and especially the RFC-7323
TCP **timestamp**, a per-packet clock-skew fingerprint à la Kohno) so that even `outer_header_i` is
device-independent — all while keeping the real TCP connection correct. **No prior system fixes a
plaintext, self-describing, correctness-critical protocol's full transcript under a single-sided,
endpoint-preserving deployment.** That intersection is empty in the literature; that is where the
contribution lives.

A secondary, ICS-specific hard constraint absent from all networking works: **safety-bounded
timing.** NTOS-IIoT and the community note it explicitly — pacing an ICS message beyond a tolerable
threshold is itself a fault. The transcript's fixed release schedule must respect a DNP3 latency
budget, unlike Ditto/IP-TFS which optimize purely for privacy/throughput.

---

## Novelty candidate — the exact minimal novel combination

> **X from Ditto + Y from IP-TFS (switch-side à la Securitas) + Z DNP3-specific.**

- **X (Ditto):** a repeating fixed-`(size, timing)` transcript emitted at a fixed schedule on **one
  Tofino**, kept slot-full by **in-switch recirculate-and-clone chaff** and a **two-level
  priority + round-robin (loopback) scheduler**, with drop-rather-than-violate overload.
- **Y (IP-TFS, executed switch-side):** **aggregation + fragmentation of the variable DNP3 response
  into the fixed transcript slots with exact byte recovery** (offset + monotonic sequence,
  reorder-tolerant), performed on **plaintext CRC-boundary DNP3 framing** rather than encrypted
  cells — i.e., Securitas-style in-switch fragmentation but recovered without a cooperating server
  or downstream discard.
- **Z (DNP3-specific, the genuinely new part):**
  1. **Plaintext-safe chaff & padding** — transcript slots are **CRC-valid, master-plausible DNP3
     frames**, not opaque ciphertext or strippable headers (no encryption to hide behind);
  2. **Single-edge, endpoint-preserving deployment** — one Tofino at the outstation edge, an
     **unmodifiable outstation** and unmodified master, so the transcript is recovered with **no
     second de-shaping switch and no endpoint code**;
  3. **Separate-ACK CLRT normalization** — the release times of ACK and RESPONSE are made
     independent of the device's real processing time, closing the **Formby (NDSS 2016)** and
     **ICS-Sniper**-style size/timing fingerprints;
  4. **Live outer-header synthesis** — per-packet TCP/IP header fields, including the **RFC-7323
     timestamp / clock-skew** channel, are rewritten to a device-independent template while the
     real TCP connection stays correct — the `outer_header_i` component that Ditto/IP-TFS get "for
     free" from encryption but which is fully exposed here;
  5. **Safety-bounded fixed schedule** — the transcript's timing is constrained by a DNP3 latency
     budget, not chosen purely to minimize overhead.

**What is NOT claimed as novel** (to keep the claim honest): in-network shaping to a fixed pattern
(**Ditto/Minos/Securitas**), fixed-rate aggregation/fragmentation with exact reassembly
(**IP-TFS**), differentially-private shape independence (**NetShaper**), shaping outside an
untrusted endpoint (**Pacer**), or P4 on DNP3 at all (**Hu et al., SmartGridComm 2023**, who were
"first to explore P4 switches to bolster DNP3 security" — but for *integrity/DPI/DoS-filtering*,
explicitly **not** traffic-shape/fingerprint obfuscation). The contribution is the **intersection**
of these under the plaintext, single-edge, unmodifiable-outstation, CLRT-bearing, exact-recovery
constraints — not any single ingredient, and never "no one has done DNP3."
