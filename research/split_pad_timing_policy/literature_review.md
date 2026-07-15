# Literature Review — Split / Pad / Timing for DNP3 Obfuscation

_Organized by the nine categories in the study spec. The **verified base is the 102-paper matrix +
101-entry bibliography from `../ack_timing_normalization/`** (deep 4-tier review there); this study
**adds 14 verified works** (in this dir's `paper_matrix.csv`, new 21-column schema, and the merged
`bibliography.bib` = 115 entries). All verification is at title/authors/year/venue/DOI-or-URL/abstract
level — **no full texts read**; two ICS items are flagged preprints. Evidence tags as elsewhere._

## 1. DNP3 / ICS
The attack we counter: **Formby et al., NDSS 2016** (Cross-Layer Response Time fingerprinting) —
processing time is a stable device fingerprint on read/response ICS protocols. **TIDF (NPC 2025)** and
**GTID (TDSC 2015)** corroborate timing/inter-arrival device fingerprints on real hardware.
**RAINCOAT (Lin et al., IEEE TSG 2019)** is the differentiation anchor (randomize/misdirect grid
content vs our normalize/indistinguish device configuration). Deception neighbors: **DefRec (NDSS
2020)**, **DecIED (CPSS@AsiaCCS 2020, k-anonymous IED decoys)**, **HoneyPLC (CCS 2020)**. **Barbosa et
al. (PAM 2012 / IJCIP 2016)** establish that SCADA polling is periodic/predictable. **Lin et al.
"Adapting Bro into SCADA" (CSIIRW 2013)** shows a spec/correctness DNP3 IDS validates semantics/CRCs
and is blind to timing-only shaping but flags malformed frames (relevant to why byte-preservation and
CRC-clean splits stay invisible). Governing standards: **IEEE 1815-2012** (DNP3; no minimum-latency
requirement) and **IEC 61850-5** (protection performance classes, cited only to scope protection out
of the DNP3 path). No DNP3/ICS-specific byte-preserving padding or cover-traffic defense exists in the
verified corpus — the study's gap.

## 2. Traffic analysis / fingerprinting
Attacks that set the adversary bar: **Deep Fingerprinting (CCS 2018)**, **k-fingerprinting (USENIX
2016)**, **Tik-Tok (PoPETs 2020)** (timing alone is a strong feature). Base-rate honesty: **Juarez et
al. "A Critical Evaluation of WF Attacks" (CCS 2014, new)** — closed-world accuracy overstates
open-world; SCADA's near-closed-world makes the attacker *stronger* here, not weaker. Obfuscation is
itself detectable: **Wang et al. "Seeing through Network-Protocol Obfuscation" (CCS 2015, new)** — the
formal basis for the "a lone shaped device is a beacon" finding. Remote timing attacks average out
noise: **Crosby (TISSEC 2009)**, **Brumley–Boneh (2005)** — the basis for "jitter is averageable,
normalization is not."

## 3. Splitting / segmentation
**Random Segmentation (Alyami et al., Electronics 2023)** is the direct analog of CRC-boundary split:
byte-preserving segmentation that reshapes the size *distribution* but **cannot hide total bytes** —
the sharpest lesson for this study. TCP segmentation/reassembly and offload behavior grounded in the
new transport primary sources: **RFC 896 (Nagle)**, **tcp(7)**, and the **Linux segmentation-offloads
kernel doc** (GSO/TSO/GRO) — establishing that split survives the wire only with pacing and that the
mid-path vantage is ground truth.

## 4. Padding / cover traffic
Constant-shape ceiling (provably closes total size, byte-adding): **BuFLO/Peek-a-Boo (S&P 2012)**,
**Tamaraw (CCS 2014)**, **CS-BuFLO (WPES 2014)**. Target-distribution matching: **Traffic Morphing
(NDSS 2009)**, **Surakav (S&P 2022)**, **Walkie-Talkie (USENIX 2017)**. Adaptive/zero-delay:
**WTF-PAD (ESORICS 2016)**, **FRONT (USENIX 2020)**, **adaptive padding (ESORICS 2006)**. Cover
traffic/link padding: **Loopix (USENIX 2017)**, **dependent link padding (CCS 2008)**, **Stop-and-Go
(IH 1998)**, **Fuzzy Time (S&P 1991)**. Formal privacy-vs-overhead in a tunnel: **Pacer (USENIX
2022)**, **NetShaper (USENIX 2024, differential privacy)**. In-network line-rate template (not
byte-preserving): **ditto (NDSS 2022)**, **NetWarden (USENIX 2020 / HotCloud 2019)**. The corpus's one
invariant — *padding = adding bytes* — is why none transfers in-band to cleartext DNP3.

## 5. Timing mitigation
The formal backbone of `release = max(ready, deadline)`: **predictive mitigation (Askarov CCS 2010;
Zhang CCS 2011)**. Low-overhead instantiation: **Köpf–Dürmuth bucketing (CSF 2009)**. Closest
ACK-timing precedent: **the NRL Pump (CCS 1993; IEEE TSE 1996)**. Capacity under a delay budget:
**Giles–Hajek (T-IT 2002)**. Mix-timing correlation limits: **Levine et al. (FC 2004)**.

## 6. Software systems
Timed-release at scale, cited **to reject** as over-provisioned for DNP3's rate: **Carousel (SIGCOMM
2017)**, **Eiffel (NSDI 2019)**, **timing wheels (Varghese-Lauck 1997)**, **calendar queues (Brown
1988)**. Kernel egress-timing paths (relevant only to a future in-path proxy): **tc-etf / SO_TXTIME**,
**AF_XDP**; and the new SmartNIC-offload systems **hXDP (OSDI 2020, new)** and **PANIC (OSDI 2020,
new)**.

## 7. Programmable switches (P4/Tofino)
RMT/Tofino architecture (**Bosshart, SIGCOMM 2013**; Open-Tofino); programmable scheduling
(**PIFO/Sivaraman SIGCOMM 2016**, **SP-PIFO NSDI 2020**, **Loom NSDI 2019**, **Nimble 2021**);
in-dataplane time & state (**Kannan 2019**, **NetVRM 2022**, **TEA 2020**). Time-aware shaping:
**P4-TAS**, **IEEE 802.1Qbv**, **IEEE 1588**. Closest in-network obfuscation precedents: **ditto**,
**NetWarden**.

## 8. SmartNIC / DPU / FPGA
BlueField Accurate Send Scheduling / DOCA (vendor docs; **DPDK mlx5 doc, new**); measured BlueField-2
ARM ceiling (**Liu et al. 2021, new** — ~half line-rate for kernel-space packet processing, never
binding here); Netronome NFP; FPGA schedulers **Corundum**, **NetFPGA-SUME**.

## 9. Operational safety
**IEEE 1815-2012** (function codes, SBO, application CONFIRM, no min-latency); **IEC 61850-5**
(protection performance classes, for scoping protection out of DNP3); the SCADA-periodicity work
(**Barbosa**) supporting that supervisory latency tolerates a bounded pad.

## Optimization methodology (for the multi-objective Pareto — all new this study)
**NSGA-II (Deb 2002)**, **NSGA-III (Deb 2014)**, **hypervolume (Zitzler-Thiele 1999)**, **pymoo
(Blank-Deb 2020)**, **ε-constraint (Haimes 1971)** — for the constrained many-objective policy
selection and Pareto fronts (see `evaluation_plan.md` §14).

**Verification note:** the 14 new works were verified this session (DOIs/venues checked); the base
102 carry the prior study's verification. No reference was invented; abstract-level only.
