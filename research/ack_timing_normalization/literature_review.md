# Literature Review — Timing Normalization of ACK-Bearing DNP3 Responses

_Synthesis of the evidence gathered by Agents A (traffic-analysis/privacy), B (TCP/transport),
C (DNP3/SCADA), D (software), E (hardware), F (evaluation methodology), 2026-07-13. Organized by
the four relevance tiers in the study spec. Every work here was verified this session at the
**title / authors / year / venue / DOI-or-stable-URL / abstract** level; **no full texts were
read** — paper-reported results are drawn from abstracts and landing pages and are labeled as
such. Two ICS items (Jeon 2016, Ahmed 2024) are arXiv preprints with no confirmed peer-reviewed
version. The complete, per-paper matrix (101 works, 21 columns) is `paper_matrix.csv`; verified
BibTeX is `bibliography.bib`. Counts: Tier 1 = 10, Tier 2 = 42, Tier 3 = 33, Tier 4 = 16._

---

## Tier 1 — Directly relevant (DNP3/SCADA/ICS fingerprinting, ICS timing/deception)

The defining Tier-1 result is **Formby et al., "Who's in Control of Your Control System?"
(NDSS 2016)**: it establishes **Cross-Layer Response Time (CLRT)** fingerprinting — the
request→response processing-time distribution is a stable device-type fingerprint on
read/response ICS protocols including DNP3. This is precisely the attack our defense exists to
defeat, and it is the published proof that our measured processing-time leak (below) is a *fielded*
fingerprint, not a lab curiosity. **We close the loop Formby opened**: they showed the CLRT leak
is an attack; no published work provides the byte-preserving in-network defense that removes it.

Corroborating that processing-time fingerprints ICS *hardware* (not only software stacks):
**Xiang & Han, TIDF (NPC 2025)** fingerprints PLCs from communication processing time + clock
period on a 13-PLC testbed (Siemens, Xinje); **Radhakrishnan et al., GTID (IEEE TDSC 2015)** and
**Kohno et al. (IEEE TDSC 2005, clock-skew)** establish inter-arrival/clock-timing as strong
device-ID features generally. **Barbosa et al. (IJCIP 2016)** and **Barbosa et al. (PAM 2012)**
show ICS/SCADA traffic is highly periodic and predictable — which is *why* the timing leak is
exploitable (an attacker gets many clean repeated samples) and *why* a bounded fixed pad is
tolerable to supervisory control.

The mandatory differentiation anchor is **RAINCOAT (Lin, Kalbarczyk, Iyer, IEEE TSG 2019,
DOI 10.1109/TSG.2018.2870362)** — the advisor's own work. RAINCOAT **randomizes** the control
center's acquisition schedule and spoofs offline-device measurements to **misdirect** an attacker
about grid state. Our work **normalizes** an outstation's per-exchange response latency to make
devices **indistinguishable** and suppress a **device-identity** leak. The two differ on all
three structural axes — mechanism (randomization/misdirection vs normalization/anonymity-set),
leaked quantity (grid content vs device identity), and locus (cooperating endpoints vs in-network
byte-preserving pass-through). Same-lab deception neighbors round out the tier: **DefRec (NDSS
2020)**, **DecIED (CPSS@AsiaCCS 2020, k-anonymous IED decoys)**, and **HoneyPLC (CCS 2020)** —
all deception/decoy systems whose *k-anonymity/indistinguishability* framing maps to our
normalization goal but which do not normalize a real device's release timing.

_Plain-language: prior ICS work proved that how long a device takes to answer is a reliable
fingerprint, and the advisor's own defense hides grid data by faking it. Our niche is different:
hide the device's identity by making every device answer on the same clock, without changing a
single byte._

## Tier 2 — Closely adjacent (WF defenses, timing-channel defenses, in-network shaping, methodology)

Three lineages matter here.

**(a) The timing-channel / latency-padding lineage is the closest mechanism match.** It
manipulates *when* an output is released to bound information leakage — exactly our lever.
- **Predictive mitigation** (Askarov, Zhang, Myers, CCS 2010; Zhang, Askarov, Myers, CCS 2011)
  delays outputs to a *predicted schedule* so leakage grows only logarithmically in run time.
  This is the **formal backbone of our candidate policy** `release = max(ready, deadline)`.
- **Köpf–Dürmuth bucketing** (CSF 2009) quantizes response time into k buckets with a provable
  |O|·log(n+1)-bit bound — a low-overhead instantiation of our size-decorrelation policy.
- **The NRL Pump / Network Pump** (Kang & Moskowitz, CCS 1993; Kang, Moskowitz, Lee, IEEE TSE
  1996) is the **closest prior mechanism that manipulates ACK timing to bound a leak**: it
  releases ACKs on a *moving average* of service times, decoupling ACK timing from true
  processing time. Different threat (colluding-process covert channel) but the identical lever.
- **Giles & Hajek (IEEE T-IT 2002)** gives the timing-channel capacity under a delay-jammer
  budget — the theory for how much timing information survives a normalization budget (RQ4).
- **Hu, Fuzzy Time (S&P 1991)**, **Shmatikov & Wang adaptive padding (ESORICS 2006)**, and the
  mix-network schedulers **Loopix (USENIX 2017)**, **Stop-and-Go (IH 1998)**, **dependent link
  padding (CCS 2008)**, **Levine et al. (FC 2004)** supply the randomized-release and
  bounded-delay-indistinguishability framings.

**(b) The website-fingerprinting (WF) lineage** is the reference literature for shape/timing
defenses but is **mechanism-incompatible** with our phase rule: every WF defense reshapes by
**adding dummy packets or padding sizes**, which breaks DNP3 CRCs/lengths. BuFLO/Peek-a-Boo
(S&P 2012), Tamaraw (CCS 2014), CS-BuFLO (WPES 2014), WTF-PAD (ESORICS 2016), Walkie-Talkie
(USENIX 2017), FRONT (USENIX 2020), RegulaTor (PoPETs 2022), and Surakav (S&P 2022) are all
[C]-conceptual-only. The *objectives* transfer (declare a target distribution and match it;
build an anonymity set; Surakav's GAN-generated decoy trace ≈ our decoy-match policy); the
*mechanisms* do not. The WF **attacks** set our adversary bar: Deep Fingerprinting (CCS 2018,
the deep-classifier attacker), k-fingerprinting (USENIX 2016, the RF baseline), and Tik-Tok
(PoPETs 2020) — the last proving *packet timing* alone is a strong feature, which is exactly why
the timing axis must be normalized.

**(c) The in-network / systems-shaping neighbors** are the systems-axis comparison a reviewer
will demand: **ditto (NDSS 2022)** — WAN obfuscation at 100 Gbps on **Intel Tofino**, our
closest platform precedent, but *not byte-preserving* (adds padding+chaff) and targeting WAN
volume, not a device-identity processing-time leak; **NetWarden (USENIX 2020)** — in-network
covert-channel mitigation on Tofino, the closest in-network-IPD-normalization precedent;
**Pacer (USENIX 2022)** and **NetShaper (USENIX 2024, differential-privacy shaping)** — whose
"shape independent of the secret" objective and privacy-vs-overhead formalization are directly
reusable for our Pareto analysis. **Alyami et al., Random Segmentation (Electronics 2023)** is a
byte-preserving *size*-axis obfuscator — the direct analog of our existing CRC-boundary split.

**(d) Statistical-methodology sources** (from Agent F) anchor the evaluation: the **KSG
mutual-information estimator (Kraskov et al. 2004)**, **McNemar (1947)** and **DeLong et al.
(1988)** for classifier/AUC significance, **Benjamini–Hochberg (1995)** FDR control, the
**bootstrap (Efron & Tibshirani 1993)**, **Cohen (1988)** power analysis, optimal-transport
(**Peyré & Cuturi 2019**) for Wasserstein, and **Carlini et al. (2019)** for the defense-aware
adversary discipline.

_Plain-language: the closest existing tricks come from covert-channel research (release outputs
on a fixed schedule) and web-privacy research (make traffic look alike). We borrow the schedules
and the goals but not the padding, because padding would corrupt DNP3._

## Tier 3 — Enabling implementation work (software schedulers, programmable data planes)

**Software (Agent D).** Because the replay server *generates* its bytes, the correct mechanism is
an application-layer absolute-deadline scheduler; the systems literature is cited mostly **to
reject** heavier machinery as over-engineered for DNP3's single-digit-kbps rate: **Carousel**
(Saeed et al., SIGCOMM 2017), **Eiffel** (Saeed et al., NSDI 2019), **hashed/hierarchical timing
wheels** (Varghese & Lauck 1997), and **calendar queues** (Brown 1988) scale timed release to
millions/sec — we need one timer or a small heap. Kernel/dataplane paths (**Linux `tc`/netem**,
**tc-etf** earliest-txtime, **AF_XDP**, DPDK) exist to delay *live* packets and are the right
tools only if the defense later moves to an in-path proxy.

**Programmable hardware (Agent E).** Pacing and inter-packet-gap normalization are native on
Tofino via the Traffic Manager and are grounded in the programmable-scheduler literature —
**PIFO/programmable scheduling** (Sivaraman et al., SIGCOMM 2016), **SP-PIFO** (Alcoz et al.,
NSDI 2020), **Loom** (Stephens et al., NSDI 2019), **Nimble** (Thapeta et al. 2021), and the
RMT/Tofino architecture itself (**Bosshart et al., SIGCOMM 2013**; Open-Tofino). But the decisive
first-packet **absolute** delay is native only on **BlueField** (Accurate Send Scheduling — PTP
transmit time) and **FPGA** (calendar-queue schedulers; Corundum, NetFPGA-SUME); on Tofino it is
reachable only via a recirculation + timestamp-deadline loop (register/SALU state per NetVRM/TEA;
precise in-dataplane time per Kannan et al. 2019). The closest *published* in-network timing-
normalization precedent is **NetWarden**; the closest Tofino-obfuscation systems paper is
**ditto**. Time-aware shaping (**P4-TAS**, IEEE 802.1Qbv, IEEE 1588) is the TSN analog. Every
hardware capability claim is tied to a vendor doc (NVIDIA DOCA/BlueField datasheets, Open-Tofino)
or a peer-reviewed paper; the Tofino recirc-hold remains **design, not measured on our chip**.

_Plain-language: in software one timer is enough — the fancy schedulers exist for traffic
millions of times faster than DNP3. In hardware, "hold a packet until a wall-clock time" is easy
on a BlueField NIC or an FPGA, hard on a Tofino switch (only via a recirculation trick), and that
trick is affordable only because DNP3 is so slow._

## Tier 4 — Standards & operational constraints (TCP, DNP3, Linux, protection timing)

**Transport (Agent B).** The delay budget is bound by the master's **effective TCP RTO**, not any
DNP3 timer. Primary sources: **RFC 6298** (Paxson et al., RTO computation), **RFC 9293** (TCP),
**RFC 1122** (host requirements / delayed-ACK), **RFC 5681** (congestion control / dup-ACK
fast-retransmit threshold = 3), **RFC 7323** (TCP timestamps), and Jacobson (SIGCOMM 1988). The
200 ms floor is **Linux `TCP_RTO_MIN` = HZ/5**, verified in `include/net/tcp.h`; it is a **rig
consequence, not universal** — `rto_min` is tunable per route (`ip route … rto_min`), so the
effective RTO must be measured on Vision via `sysctl net.ipv4.tcp_retries2` plus the observed
request→first-retransmit delta in a capture. ACK-pacing/ACK-thinning context: Aggarwal et al.
(2000), Zhang et al. (1991), Balakrishnan et al. (RFC 3449). Holding an ACK-*bearing* segment
(vs a pure ACK) leaves the master's *request* unacknowledged → spurious retransmit — the loudest
tell to both a passive observer and a Zeek `dnp3` correctness IDS.

**DNP3 / power (Agent C).** **IEEE 1815-2012 (DNP3)** defines SELECT/OPERATE (SBO), the
application CONFIRM handshake, and function codes, and imposes **no minimum-latency requirement**
— so a bounded sub-RTO hold violates no clause. Every OpenDNP3 timer was re-verified in the
community-fork source (file:line): outstation select timeout 10 s, solicited-confirm/app-response
5 s, keepalive 60 s; link service is **unconfirmed only** (no `SEC_ACK` to delay — the confirmed
formatter has zero callers). **IEC 61850-5** is cited only to scope protection tripping (sub-cycle,
GOOSE/hardwired, ~3 ms performance classes) *out* of the DNP3 supervisory path — a shaping element
on a DNP3 link is architecturally upstream of any protection loop. **Lin et al. "Adapting Bro into
SCADA" (CSIIRW 2013)** confirms a specification/correctness DNP3 IDS validates semantics/CRCs and
is blind to timing-only manipulation while flagging malformed frames.

_Plain-language: the real limit is not any DNP3 clock (those are 5–60 seconds) but the master's
TCP retransmit timer (~200 ms on this rig, but measure it). Stay well under it and nothing breaks
and nobody sees retransmits. DNP3 itself has no speed requirement, and true protection tripping
does not travel over this link._

---

## What the literature does NOT contain (the gap, developed in `research_gaps_and_novelty.md`)

No verified work combines all four of our defining properties: (i) target = a measured
**device-configuration processing-time** leak in an OT protocol (device *identification* — telling
two devices apart — is a future ≥2-stack claim, not what one outstation shows), (ii) mechanism =
**release-timing-only and byte-preserving** (no padding/chaff/CRC recompute), (iii) medium =
**live TCP/DNP3** with an RTO/handshake correctness bound, (iv) deployment = **in-network
pass-through**. **NetWarden (USENIX 2020)** already occupies "in-network, timing-only Tofino
shaping," so byte-preservation alone is not the wedge; the unoccupied point is the *combination*
above, anchored on a **measured OT leak**. The byte-preserving constraint — forced by DNP3's CRCs
and live-master transparency, which forbid the padding every WF defense relies on — is what makes
timing the only reshapeable axis here.
