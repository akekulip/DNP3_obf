# Annotated Bibliography — DNP3 Fixed-Transcript Prior Work

Primary sources for `../PRIOR_WORK_MATRIX.md`. Each entry: authors, venue, year, DOI/URL, the
section(s) actually read, and the relevance. **Access level** is marked honestly:
`[FULL-TEXT]` = design/mechanism/eval sections read this session; `[PARTIAL]` = abstract + intro +
selected sections; `[ABSTRACT+]` = abstract + author summary + artifact repo / talk page (primary
PDF was paywalled or 403'd); `[BACKGROUND]` = stable, well-established work cited from standing
knowledge, not re-fetched this session.

---

## A. In-network / programmable-switch traffic shaping (closest mechanism)

### [FULL-TEXT] Ditto — WAN Traffic Obfuscation at Line Rate
- **Authors:** Roland Meier, Vincent Lenders, Laurent Vanbever.
- **Venue / year:** NDSS 2022.
- **URL:** https://roland-meier.ch/files/roland-meier_ditto_ndss22.pdf · code https://github.com/nsg-ethz/ditto
- **Read:** §II threat model, §III–VI design (pattern computation, hierarchical queueing, chaff via
  recirculate-and-clone, padding via stacked custom headers), §VII security/limitations, §VIII
  implementation (Tofino, loopback two-pass), §IX evaluation.
- **Relevance:** The leading hypothesis to beat. Repeating fixed-(size,timing) pattern, in-switch
  chaff, priority+round-robin queues on Tofino, drop-rather-than-violate — the mechanism twin.
  Critically depends on **MACsec encryption** and **two switches**, which the DNP3 setting denies.

### [ABSTRACT+] Securitas — Defending against Traffic Analysis Attacks with Flexible In-Network Obfuscation
- **Authors:** Guorui Xie et al. (Peng Cheng Lab / Tsinghua).
- **Venue / year:** USENIX NSDI 2026.
- **URL:** https://www.usenix.org/conference/nsdi26/presentation/xie-guorui · PDF
  https://www.usenix.org/system/files/nsdi26-xie-guorui.pdf (403 on fetch) · code
  https://github.com/xgr19/Securitas
- **Read:** USENIX abstract, author summary, GitHub repo structure (policy-gradient agent
  `train_securitas.py` vs an APP-Net NN attacker on ISCX VPN data; small-TTL insertion p=0.3).
- **Relevance:** Nearest to **switch-side fragmentation of real packets + fake-packet insertion**
  with exact recovery. But recovery needs the **real server** to reassemble and **downstream
  Internet nodes** to drop small-TTL fakes — neither exists on a point-to-point outstation link.
  Multi-dataplane (Tofino/FPGA/eBPF/BMv2); ↓attack acc up to 95.89%, 42.69× less bandwidth.

### [ABSTRACT+] Minos — A Lightweight and Dynamic Defense against Traffic Analysis in Programmable Data Planes
- **Authors:** Zihao Wang et al.
- **Venue / year:** USENIX ATC 2025.
- **URL:** https://www.usenix.org/conference/atc25/presentation/wang-zihao · PDF
  https://www.usenix.org/system/files/atc25-wang-zihao.pdf (403 on fetch)
- **Read:** USENIX abstract + session summary (Proxy, Traffic-Morphing, Schedule modules;
  header-encryption round-compression; priority dummy queues; flow interleaving to "simulate"
  dummies).
- **Relevance:** Recent switch-based shaping providing identity + traffic anonymity on **encrypted**
  flows; low-overhead dummy scheduling. Same encryption/anonymity framing as Ditto; not a fixed
  transcript, no plaintext/ICS constraints.

### [ABSTRACT+] PINOT — Programmable In-Network Obfuscation of Traffic
- **Authors:** Liang Wang, Hyojoon Kim, Prateek Mittal, Jennifer Rexford.
- **Venue / year:** arXiv 2020 (cs.NI) — in-network identity work by the Princeton group.
- **URL:** https://arxiv.org/abs/2006.00097
- **Read:** abstract.
- **Relevance:** Line-rate in-network privacy on Tofino **without host changes** — but the secret is
  the **client IPv4 address (identity)**, obfuscated by address encryption, *not* traffic shape.
  Establishes the "Tofino, no endpoint change" deployment shape only.

---

## B. Formal / tunnel-based traffic shaping (independence guarantees, exact recovery)

### [FULL-TEXT] NetShaper — A Differentially Private Network Side-Channel Mitigation System
- **Authors:** Amir Sabzi, Rut Vora, Swati Goswami, Margo Seltzer, Mathias Lécuyer, Aastha Mehta.
- **Venue / year:** USENIX Security 2024.
- **DOI/URL:** ACM 10.5555/3698900.3699090 · PDF https://arxiv.org/pdf/2310.06293 · code
  https://github.com/ubc-systopia/netshaper
- **Read:** §2.2–2.4 key ideas + threat model + DP primer, §3 DP traffic shaping (periodic interval
  T, DP query on buffer length, Gaussian noise, Props 1–2, Corollary 1), §4 tunnel/middlebox design
  (QUIC STREAM dummies, UShaper/DShaper).
- **Relevance:** The **formal-guarantee twin**: `P(O|S)≈P(O|S')` via differential privacy — the exact
  transcript-independence objective, stated with tunable (ε,δ). But it is a **middlebox QUIC tunnel
  (two endpoints, encryption)**, gives *probabilistic* not *fixed* shape, and needs app cooperation.

### [ABSTRACT+] Pacer — Comprehensive Network Side-Channel Mitigation in the Cloud
- **Authors:** Aastha Mehta, Mohamed Alzayat, Roberta De Viti, Björn Brandenburg, Peter Druschel, Deepak Garg.
- **Venue / year:** USENIX Security 2022.
- **URL:** https://www.usenix.org/conference/usenixsecurity22/presentation/mehta · TR
  https://arxiv.org/abs/1908.11568
- **Read:** abstract + USENIX summary + arXiv abstract (cloaked-tunnel abstraction; shape guest
  traffic **outside** the guest; dummy packets when payload not ready; respects flow/congestion/loss).
- **Relevance:** Canonical "shape outside an untrusted endpoint so shape is **secret-independent by
  design**." But it needs **hypervisor + guest-kernel changes**; not a switch; encrypted.

### [FULL-TEXT] RFC 9347 — Aggregation and Fragmentation Mode for ESP (IP-TFS)
- **Authors:** C. Hopps (IETF ipsecme).
- **Venue / year:** IETF RFC 9347, January 2023.
- **DOI/URL:** 10.17487/RFC9347 · https://www.rfc-editor.org/rfc/rfc9347.html
- **Read:** AGGFRAG payload structure, constant-rate/fixed-size framing, aggregation+fragmentation,
  **BlockOffset + monotonic ESP sequence** reassembly, reorder window / loss handling,
  non-congestion vs congestion-controlled modes, observable outer fields (SPI, seq).
- **Relevance:** The **exact-recovery-under-fixed-framing twin** — how to carry a *variable* payload
  in a *fixed-size, constant-rate* transcript independent of inner traffic, with byte-exact
  reassembly. The piece Ditto lacks. But it runs between **two IPsec endpoints under ESP**, not on
  plaintext DNP3 with an unmodifiable outstation.

### [BACKGROUND] RFC 4303 — IP Encapsulating Security Payload (ESP), Traffic Flow Confidentiality padding
- **Author:** S. Kent. IETF RFC 4303, 2005. https://www.rfc-editor.org/rfc/rfc4303
- **Relevance:** The baseline TFC mechanism (append padding, allow all-pad packets) that IP-TFS
  improves on; the "pad each packet, waste bandwidth" ancestor of fixed-size framing.

---

## C. The DNP3/ICS threat being defended (why a fixed transcript is needed)

### [FULL-TEXT] Formby et al. — Who's in Control of Your Control System? Device Fingerprinting for CPS
- **Authors:** David Formby, Preethi Srinivasan, Andrew Leonard, Jonathan Rogers, Raheem Beyah.
- **Venue / year:** NDSS 2016.
- **DOI/URL:** dblp FormbySLRB16 ·
  https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf
- **Read:** §III threat model + §IV Method 1 (Cross-Layer Response Time). CLRT = time between the
  DNP3 application-layer response and the device's TCP ACK (Fig 3, IED processing time *m*);
  independent of RTT; histogram signature. §IV results.
- **Relevance:** **This is the attack the fixed-transcript defeats.** CLRT is stable and unique per
  device type + software config (93% classification at 5-min slices; real substation ~130 DNP3
  devices, 5 months). Directly names the **separate-ACK Case-A timing feature** the project must
  normalize. Also cites Kohno 2005 clock-skew fingerprinting (see §E).

### [ABSTRACT+] ICS-Sniper — A Targeted Blackhole Attack on Encrypted ICS Traffic
- **Authors:** (Purdue/collab.) — see arXiv.
- **Venue / year:** 2023 (arXiv 2312.06140).
- **URL:** https://arxiv.org/abs/2312.06140
- **Read:** abstract.
- **Relevance:** Motivation that **encryption is not enough**: packet **sizes and timing** still
  identify critical ICS messages (SWaT emulation), enabling selective blackholing. Justifies fixing
  size *and* timing, not just adding crypto.

---

## D. Programmable switches / in-network security for ICS (nearest platform+protocol)

### [PARTIAL] Hu et al. — Industrial Network Protocol Security Enhancement Using Programmable Switches
- **Authors:** Zheng Hu, Hui Lin, Luke Waind, Yanfeng Qu, Gong Chen, Dong Jin.
- **Venue / year:** IEEE SmartGridComm 2023, Glasgow.
- **URL:** https://web.uri.edu/decps/wp-content/uploads/sites/1880/2023_SmartGridComm_Industrial_Network_Protocol_Security_Enhancement_Using_Programmable_Switches.pdf
- **Read:** abstract, §I intro, Table I (21-attack DNP3 taxonomy).
- **Relevance:** **The nearest "P4 + DNP3" work — and the reason the novelty claim must be precise.**
  They build a **P4 DNP3 parser** and add **hashing, encryption, header/payload inspection,
  filtering** against length-overflow, event-buffer-flood DoS, and config-corrupt MITM; "to the best
  of our knowledge, first to explore P4 to bolster DNP3 security." **Goal = integrity / availability
  / confidentiality via DPI + crypto — explicitly NOT traffic-shape / fingerprint obfuscation and NOT
  CLRT normalization.** So "P4+DNP3" is occupied; "P4+DNP3 *fixed transcript*" is not.

### [ABSTRACT+] Towards Secure and Resilient Synchrophasor Networks Using P4 Programmable Switches
- **Authors:** URI DECPS lab.
- **Venue / year:** IEEE GreenTech 2024.
- **URL:** https://web.uri.edu/decps/wp-content/uploads/sites/1880/2024_GreenTech_Towards-Secure-and-Resilient-Synchrophasor-Networks-Using-P4-Programmable-Switches.pdf
- **Read:** fetched summary.
- **Relevance:** P4 in-network **integrity + anomaly detection** for synchrophasor (C37.118 /
  61850-90-5); explicitly does **not** modify packet size/timing (no fingerprint obfuscation).
  Reinforces that ICS+P4 has been about integrity/detection, not transcript shaping.

### [ABSTRACT+] Network Traffic Obfuscation System (NTOS) for IIoT-Cloud Control Systems
- **Venue / year:** 2022 (ScienceDirect / researchgate).
- **URL:** https://www.sciencedirect.com/org/science/article/pii/S1546221822009249
- **Read:** abstract/summary snippets.
- **Relevance:** The closest **ICS-specific obfuscation** system: rule-based **packet scrambling +
  timed dummy packets** matched to legitimate response timing, via host/agents + split server.
  Statistical/host-side, not a switch, not byte-exact. **Names the ICS-specific hard constraint the
  networking papers ignore: pacing a critical message beyond a tolerable threshold harms operational
  safety** — a bound the fixed schedule must respect.

---

## E. Header / timing side channels (the `outer_header_i` component of O)

### [BACKGROUND] RFC 7323 — TCP Extensions for High Performance (TCP Timestamps)
- **Authors:** D. Borman, B. Braden, V. Jacobson, R. Scheffenegger. IETF RFC 7323, 2014 (obsoletes RFC 1323). https://www.rfc-editor.org/rfc/rfc7323
- **Relevance:** Defines the TCP **Timestamps option** (Kind 8, TSval/TSecr) for RTTM and PAWS. On a
  plaintext DNP3/TCP connection the **per-packet TSval is exposed in `outer_header_i`** and advances
  with the sender's clock — a device fingerprint that a fixed-size/fixed-timing scheme does **not**
  close. The transcript design must normalize/synthesize it.

### [BACKGROUND] Kohno, Broido, Claffy — Remote Physical Device Fingerprinting
- **Venue / year:** IEEE S&P 2005 (also cited as [13] in Formby).
- **Relevance:** Fingerprints a remote device via **TCP-timestamp clock skew**. Concrete evidence
  that the outer TCP header alone identifies a device — directly motivates outer-header normalization
  as a distinct requirement beyond size/timing.

---

## F. Endpoint/proxy shape defenses — the ancestors (grouped, background)

### [BACKGROUND] Website-fingerprinting / link-padding defenses
- **BuFLO** — Dyer, Coull, Ristenpart, Shrimpton, "Peek-a-Boo, I Still See You," IEEE S&P 2012
  (constant-rate fixed-size cells). **CS-BuFLO** — Cai et al. 2014. **Tamaraw** — Cai, Nithyanand,
  Johnson, Goldberg, CCS 2014 (rate-adaptive constant padding). **Walkie-Talkie** — Wang & Goldberg,
  USENIX Security 2017 (half-duplex burst molding). **WTF-PAD** — Juarez, Imani, Perry, Diaz,
  Wright, ESORICS 2016 (adaptive padding, fill inter-burst gaps). **FRONT/GLUE** — Gong & Wang,
  USENIX Security 2020 (trace-front obfuscation). **Traffic Morphing** — Wright, Coull, Monrose,
  NDSS 2009 (morph one size distribution into another).
- **Relevance:** These are the conceptual ancestors of "fix size and timing." All operate at
  **cooperating endpoints/proxies over encrypted (Tor) traffic**; constant-rate variants (BuFLO,
  Tamaraw) are the endpoint analog of Ditto's fixed pattern. None are in-network, plaintext, or
  byte-exact for a legacy protocol.

### [BACKGROUND] IoT smart-home traffic shaping — Apthorpe et al.
- Apthorpe, Reisman, Sundaresan, Narayanan, Feamster, "Spying on the Smart Home" (2017) +
  "Keeping the Smart Home Private with Independent Link Padding" (2019). **Independent Link
  Padding (ILP)** = device-independent constant traffic; **Stochastic Traffic Padding (STP)**.
- **Relevance:** Closest *device-activity* fingerprint analog to CLRT (infer device state from
  traffic shape) and closest use of **device-independent** shaping — but router/hub-side,
  statistical, over encrypted flows; not byte-exact, not a legacy plaintext protocol.

### [BACKGROUND] TSN — IEEE 802.1Qbv Time-Aware Shaper
- IEEE 802.1Qbv (Enhancements for Scheduled Traffic), gate-control lists / time-triggered queues.
- **Relevance:** The deterministic-scheduling analog for fixing `release_time` on a fixed schedule.
  Goal is bounded latency/jitter, **not** privacy, and it has no chaff/size/header notion — but its
  gated, time-triggered dequeue model is the scheduling primitive a fixed-transcript release engine
  resembles.

---

## Coverage note

Nearest neighbors (Ditto, IP-TFS) and the defining attack (Formby CLRT) were read at full-text /
mechanism depth; NetShaper and the Hu P4-DNP3 platform work were read at design/section depth. The
three USENIX-hosted PDFs (Securitas, Minos, Pacer) returned HTTP 403 to automated fetch and are
represented from their official abstracts, author/session summaries, and (for Securitas) the public
artifact repository — sufficient for mechanism-level positioning, and flagged as such above. Grouped
`[BACKGROUND]` families (WF/link-padding, IoT shaping, TSN, RFC 4303/7323, Kohno) are cited from
standing knowledge of stable, well-established results, not re-fetched this session.
