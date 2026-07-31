# Related Work Map — Defense 3 (In-Network CLRT ACK-Delay Normalizer)

**What Defense 3 is (one line).** An Intel Tofino / P4 in-network defense that hides a
DNP3 outstation's *cross-layer response time* (CLRT) device-timing fingerprint by holding the
device's pure TCP ACK on the switch for a predetermined delay `D` and releasing it independently
of the RESPONSE, validated on a physical SEL-751 relay. The transform is byte-preserving (no DNP3
field or CRC edits, no host changes) and touches a single observable (the ACK release time).

**How to read this map.** Five themes. Within each, prior work is listed first and **Defense 3 is
positioned last** with an explicit "relates / differs" line. Every citekey resolves to an entry in
`references.bib`; provenance (anchor PDF / arXiv MCP / web) is recorded there.

---

## Theme 1 — ICS/SCADA device & protocol fingerprinting; passive OT reconnaissance (the threat)

- **[kohno2005remote]** Kohno, Broido & Claffy, *IEEE TDSC* 2005 — Seminal *remote* device fingerprinting via microscopic clock-skew timing; establishes that transport-layer timing leaks stable per-device identity. Defense 3 attacks the same class of leak but for the ICS CLRT feature.
- **[shu2006fingerprint]** Shu & Lee, *IEEE INFOCOM* 2006 — Formal protocol-state-machine fingerprinting; identifies protocol implementations from observed message/timing behavior. Defense 3 removes the timing dimension of such signatures for DNP3.
- **[radhakrishnan2014gtid]** Radhakrishnan, Uluagac & Beyah, *IEEE TDSC* 2014 — GTID: inter-arrival-time distributions fingerprint both device and device *type*, including on constrained/embedded devices. Same Beyah-group lineage as the CLRT attack; Defense 3 denies the inter-packet-timing feature at the switch.
- **[jeon2016passive]** Jeon, Yun, Choi & Kim, arXiv 2016 — Passive SCADA fingerprinting *without* DPI, using intrinsic SCADA traffic structure; confirms OT devices are fingerprintable from metadata alone on real critical-infrastructure captures. Motivates a metadata-level (not payload) defense.
- **[formby2016control]** Formby, Srinivasan, Leonard, Rogers & Beyah, *NDSS* 2016 — **THE threat model.** Defines CLRT (the ACK→RESPONSE cross-layer interval capturing IED processing time) as a stable, hard-to-forge per-device fingerprint on DNP3/Modbus/IEC-61850, 92–99% classification on a live substation.
  - **→ Defense 3:** directly neutralizes Formby's CLRT channel. By releasing the pure ACK at a predetermined `t_ACK + D` independent of the RESPONSE, the device's processing time no longer appears in any observable inter-packet interval, collapsing the CLRT distribution the classifier depends on — the first *defense* against this attack.

## Theme 2 — In-network / programmable-dataplane (P4/Tofino) obfuscation at line rate (mechanism class)

- **[kfoury2021p4survey]** Kfoury, Crichigno & Bou-Harb, arXiv/IEEE Access 2021 — Survey of P4 programmable-switch applications; frames the capability envelope (match-action stages, TM queues, recirculation) that Defense 3 works within. Establishes feasibility grounding.
- **[chen2015hornet]** Chen, Asoni, Barrera, Danezis & Perrig, *ACM CCS* 2015 — HORNET: onion routing *at the network layer*, ~93 Gb/s, per-packet padding to uniform size. Hides identity/volume in the core; Defense 3 instead hides a device's timing fingerprint and requires no per-flow cryptographic state.
- **[chen2018taranet]** Chen, Asoni, Perrig, Barrera, Danezis & Troncoso, *IEEE EuroS&P* 2018 — TARANET: constant-rate traffic shaping via packet splitting at the network layer, >50 Gb/s. Constant-rate is the heavy-handed timing defense; Defense 3 achieves timing-fingerprint removal by delaying *one* packet rather than reshaping the whole flow, and needs no end-host support (TARANET does).
- **[wang2020pinot]** Wang, Kim, Mittal & Rexford, arXiv 2020 — PINOT: line-rate in-network anonymity on a Barefoot Tofino (encrypts client IP). Demonstrates a *targeted, single-field* in-switch privacy transform with no host cooperation — the same deployment philosophy as Defense 3, but for addressing rather than timing.
- **[ding2021inddos]** Ding, Savi, Pederzolli, Campanella & Siracusa, arXiv 2021 — INDDoS: security *monitoring* (volumetric DDoS victim ID) entirely in a Tofino P4 pipeline at line rate. Precedent that non-trivial security logic fits the Tofino; Defense 3 is an in-Tofino *countermeasure* rather than a detector.
- **[meier2022ditto]** Meier, Lenders & Vanbever, *NDSS* 2022 — **Closest prior work.** Ditto shapes WAN traffic to a fixed size/timing pattern in the switch data plane (padding + chaff + delay), 100 Gb/s, no host changes, using priority queues + round-robin scheduling + recirculation.
  - **→ Defense 3:** shares Ditto's line-rate, host-transparent, programmable-switch stance and even its queue/recirculation toolkit, but differs in target and cost. Ditto obfuscates *aggregate* packet size, volume and inter-packet timing of a whole link by adding padding and dummy packets; Defense 3 leaves every DNP3 byte and packet untouched and normalizes exactly one *device-specific* observable — the ACK-relative-to-RESPONSE cross-layer interval — for far lower overhead (one held ACK, no chaff, no per-packet padding).

## Theme 3 — Network-flow & website fingerprinting defenses (padding / morphing / constant-rate)

- **[wright2009morphing]** Wright, Coull & Monrose, *NDSS* 2009 — Traffic morphing: reshape a flow's packet-size distribution toward a target class at minimum overhead. Size-centric; Defense 3 targets a timing interval and is byte-exact.
- **[dyer2012peekaboo]** Dyer, Coull, Ristenpart & Shrimpton, *IEEE S&P* 2012 — BuFLO: shows per-packet/timing tweaks fail and only rigid constant packet-size + fixed inter-packet time resists analysis — at large overhead. Defense 3 gets fingerprint removal without constant-rate cost by acting on one packet.
- **[cai2014csbuflo]** Cai, Nithyanand & Johnson, *WPES* 2014 — CS-BuFLO: congestion-sensitive BuFLO; still high overhead and per-flow. Contrast: Defense 3 is per-device and in-network.
- **[juarez2016wtfpad]** Juarez, Imani, Perry, Diaz & Wright, *ESORICS* 2016 — WTF-PAD: adaptive dummy-packet padding to fill statistically revealing gaps at zero added latency. Defense 3 *adds* a bounded latency but *removes* rather than fills the leaking interval, and injects no dummy packets.
- **[wang2017walkietalkie]** Wang & Goldberg, *USENIX Security* 2017 — Walkie-Talkie: half-duplex + burst molding to make traces collide across pages. Requires browser/protocol cooperation; Defense 3 is transparent to the DNP3 endpoints.
- **[sirinam2018df]** Sirinam, Imani, Juarez & Wright, *ACM CCS* 2018 — Deep Fingerprinting: CNN attack defeating WTF-PAD; shows padding-only defenses that *leave the underlying feature present* are brittle. Motivates Defense 3's choice to *eliminate* the CLRT feature rather than mask it.
  - **→ Defense 3:** the website-fingerprinting line is host/proxy-based, per-flow, dominated by packet *size/volume* obfuscation, and repeatedly broken when the true feature survives under padding. Defense 3 differs on all three axes: it runs in-network at the switch, operates on a single device-timing observable, and *structurally removes* that observable (the processing time never enters a measurable interval) rather than statistically hiding it.

## Theme 4 — Timing side channels & timing-analysis defenses in networked/embedded systems

- **[song2001timing]** Song, Wagner & Tian, *USENIX Security* 2001 — Foundational: inter-packet timing of SSH keystrokes leaks secret content; timing is a first-class network side channel. Defense 3 closes an analogous device-processing timing channel in DNP3.
- **[wang2008dependent]** Wang, Motani & Srinivasan, *ACM CCS* 2008 — Dependent link padding: provably bounds timing leakage by transmitting on a schedule independent of real arrivals. Defense 3 borrows the *release-independent-of-content* principle but applies it to a single ACK against a deadline rather than padding a whole link.
- **[feghhi2016timing]** Feghhi & Leith, *IEEE TIFS* 2016 — A traffic-analysis attack using *only* timing (no size/volume); proves timing alone suffices to fingerprint. Establishes that a timing-only defense is a necessary, non-redundant contribution — exactly Defense 3's scope.
- **[apthorpe2017spying]** Apthorpe, Reisman, Sundaresan, Narayanan & Feamster, arXiv 2017 — Encrypted smart-home traffic *rates/timing* reveal in-home activity; evaluates blocking/tunneling/rate-shaping defenses. Same leakage family (device behavior via timing) one domain over.
- **[apthorpe2019stp]** Apthorpe, Huang, Reisman, Narayanan & Feamster, *PoPETs* 2019 — Stochastic Traffic Padding: makes genuine device events statistically indistinguishable from cover traffic, with a formal bound. Defense 3, by contrast, removes the timing feature deterministically for the CLRT case rather than probabilistically masking event timing.
  - **→ Defense 3:** it is fundamentally a *timing-channel normalizer*. Where prior timing defenses pay a continuous cost (constant-rate schedules, cover traffic, per-link padding), Defense 3 exploits the specific structure of the CLRT leak — that it lives in a single cross-layer interval — to neutralize it by scheduling one packet's release, at roughly one held-ACK of overhead and zero injected traffic.

## Theme 5 — DNP3 / ICS intrusion detection & the defensive landscape (why a new defense)

- **[east2009taxonomy]** East, Butts, Papa & Shenoi, *IFIP CIP III* 2009 — Canonical taxonomy of ~30 DNP3 attacks incl. reconnaissance/interception; situates device fingerprinting as an early-stage reconnaissance capability worth denying.
- **[fovino2010modbus]** Nai Fovino, Carcano, De Lacheze Murel, Trombetta & Masera, *AINA* 2010 — State-based IDS for Modbus/DNP3 (detects illegitimate protocol states). Detection, not prevention; Defense 3 denies the attacker's reconnaissance input upstream of any IDS.
- **[cardenas2011attacks]** Cárdenas, Amin, Lin, Huang, Huang & Sastry, *ASIACCS* 2011 — Risk assessment / detection / response for process-control attacks; frames the CPS threat lifecycle Defense 3 intervenes in (reconnaissance).
- **[sridhar2012cyber]** Sridhar, Hahn & Govindarasu, *Proc. IEEE* 2012 — Survey of CPS security for the power grid; notes crypto/patching are often infeasible on legacy field devices — the exact gap Defense 3 fills without touching the relay.
- **[lin2013bro]** Lin, Slagell, Di Martino, Kalbarczyk & Iyer, *CSIIRW* 2013 — Specification-based DNP3 IDS built on Bro; the same "augment IDS" deployment context Formby targets. Defense 3 complements such IDS by removing a passive-recon fingerprint they cannot address.
  - **→ Defense 3:** existing ICS defenses are either *detective* (protocol/state IDS) or *cryptographic* (DNP3-SA / TLS), the latter widely infeasible on deployed legacy relays. Defense 3 is a *proactive, transparent, in-network* countermeasure that removes a specific passive-fingerprint leak with no device firmware change, no DNP3 byte modification, and no key management — occupying a gap none of the above fills.

---

## Coverage summary

| Theme | # prior papers | Anchor / MCP-verified |
|---|---|---|
| 1. ICS/SCADA device & protocol fingerprinting | 5 | Formby (anchor, read); Jeon (arXiv); Kohno/Shu/Radhakrishnan (Formby bib) |
| 2. In-network / P4 obfuscation at line rate | 6 | Ditto (anchor, read); HORNET/TARANET/PINOT/INDDoS/P4-survey (arXiv MCP) |
| 3. Website / flow fingerprinting defenses | 6 | WTF-PAD/CS-BuFLO/DF (arXiv MCP); BuFLO/morphing/Walkie-Talkie (Ditto bib) |
| 4. Timing side channels & timing defenses | 5 | Apthorpe×2 (arXiv MCP); dependent-link-padding/Feghhi (Ditto bib); Song (web) |
| 5. DNP3 / ICS IDS & defensive landscape | 5 | Fovino/Cárdenas/Sridhar/Lin (Formby bib); East (web) |

**Total: 27 real, verified papers.** No citation, DOI, or author list was fabricated.
