# Citation Audit — Defense 4 (RRC + BOR) DNP3 in-network obfuscation

**Date:** 2026-08-14
**BibTeX export:** `/home/philip/Projects/DNP3-size-probe/paper/rewrite/refs.bib`
**Zotero collection:** `OBfus_defense` (key `DP4TQCSF`) — created successfully.

## Tooling status (fallbacks recorded per task constraint)

- **Semantic Scholar MCP tools: UNAVAILABLE.** The `semantic-scholar` MCP server
  loaded its instructions into the session but exposed no callable tool functions
  (`get_paper_details` / `search_papers` / `batch` were not present in the toolset).
  All metadata was therefore verified against authoritative web sources I opened
  directly: **DBLP** record/author pages, **ACM Digital Library**, **IEEE Xplore**,
  the **NDSS/USENIX** proceedings pages, and **doi.org** DOI resolution.
- **Zotero — collection creation: WORKED** (`OBfus_defense`, key `DP4TQCSF`, created
  via the Zotero Web API write path).
- **Zotero — item ingestion: BLOCKED.** `zotero_add_by_doi` and `zotero_add_by_bibtex`
  both failed with `[Errno 111] Connection refused` — they require the Zotero **local
  API** (`localhost:23119`), which is down because **Zotero desktop is not running**.
  Retried per policy; still refused. `zotero_get_collections` and keyword item search
  likewise hit the local API and failed/returned only stale semantic-index junk.
  **Action required:** with Zotero desktop open, import `refs.bib` and file all 19
  entries into `OBfus_defense`, OR re-run `zotero_add_by_bibtex(file_path=refs.bib,
  collections=["DP4TQCSF"], if_exists="file", attach_mode="none")`. `if_exists="file"`
  makes the import idempotent (reuses any existing DOI match instead of duplicating).
- **Dedup note:** because the local API was down, I could not enumerate existing
  library items to dedup by hand. The manuscript's current citations are LaTeX
  placeholders (`\bibitem ... [complete citation]`), not real Zotero items, so
  duplication risk is low; `if_exists="file"` on import will additionally collapse
  any DOI collisions.

## Verification legend

- **Metadata verified against** lists the authoritative source(s) actually opened.
- **Zotero status** is uniform: *Verified; queued for `OBfus_defense` (DP4TQCSF);
  item-add blocked by offline local API — import from refs.bib.*

---

## Audit table

| # | Paper-claim / category | citekey | Source title | Supporting section / idea | Metadata verified against | Zotero status |
|---|---|---|---|---|---|---|
| F1 | Foundational — DNP3 is the SCADA request/response protocol whose layered framing (app fragment → transport FIR/FIN → 292 B link frames with per-16 B-block CRCs) produces the fingerprint | `dnp3std` | IEEE Standard for Electric Power Systems Communications—Distributed Network Protocol (DNP3), IEEE Std 1815-2012 | Defines DNP3 link/transport/application framing and the per-block CRC-16/DNP that the RRC carve preserves | IEEE Xplore doc 6327578; DOI 10.1109/IEEESTD.2012.6327578 resolves to that document | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| F2 | Foundational — passive recon precedes real grid attacks; motivation | `ukraine2015` | Analysis of the Cyber Attack on the Ukrainian Power Grid (E-ISAC/SANS Defense Use Case) | Documents the Dec 2015 attack (~225k customers) and the reconnaissance-first kill chain against grid SCADA | E-ISAC/SANS DUC v5 (Kaspersky/NSA-Archive mirrors); authors Lee, Assante, Conway; 18 Mar 2016 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| F3 | Foundational — the OpenDNP3 stack underlying the master/outstation harness | `opendnp3` | opendnp3: open-source DNP3 (IEEE-1815) protocol stack | The real DNP3 implementation (via ChargePoint pydnp3 bindings) the master/outstation runners use | github.com/dnp3/opendnp3 (Automatak/Step Function I/O), C++11, latest 3.1.2, archived 2022 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 1a | Cat 1 ICS/CPS device fingerprinting (ANCHOR) — devices identifiable from observable behavior without payload decoding | `formby2016` | Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems | Cross-layer response-timing / operation-timing fingerprinting distinguishes ICS device types and instances | DBLP conf/ndss/…; NDSS 2016 proceedings PDF; authors Formby, Srinivasan, Leonard, Rogers, Beyah | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 1b | Cat 1 — passive/active traffic-timing fingerprinting recovers device type/instance | `gtid2015` | GTID: A Technique for Physical Device and Device Type Fingerprinting | Wire-side timing signatures fingerprint device and device-type, supporting the "shape gives the device away" premise | DBLP journals/tdsc/…; IEEE Xplore 6951398; TDSC 12(5):519–532; DOI 10.1109/TDSC.2014.2369033 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 2a | Cat 2 timing/traffic-analysis ATTACK — sizes+timing recover content even on encrypted sessions | `sirinam2018` | Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning | CNN attack reaches >98% (undefended) / >90% (WTF-PAD) from packet sequences — the size/timing side channel is strong | DBLP rec conf/ccs/SirinamIJW18; CCS 2018 pp. 1928–1943; DOI 10.1145/3243734.3243768 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 2b | Cat 2 DEFENSE — adaptive padding as a low-overhead traffic-analysis defense | `juarez2016` | Toward an Efficient Website Fingerprinting Defense (WTF-PAD) | Adaptive padding of inter-packet gaps as the reference efficient WF defense our timing normalization is set against | DBLP pid/129/8347; ESORICS 2016 pp. 27–46; DOI 10.1007/978-3-319-45744-4_2 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 2c | Cat 2 timing side-channel (foundational) — inter-event timing leaks secret content | `song2001` | Timing Analysis of Keystrokes and Timing Attacks on SSH | Seminal demonstration that inter-packet timing alone leaks information — the general timing-channel basis for CLRT hiding | USENIX Security 2001 proceedings page; DBLP; authors Song, Wagner, Tian | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 3a | Cat 3 morphing — reshape one traffic class's size/timing to look like another | `wright2009` | Traffic Morphing: An Efficient Defense Against Statistical Traffic Analysis | Optimally morphs packet-size distributions of one class into another — the morphing lineage of segment-shape normalization | DBLP rec conf/ndss/WrightCM09; NDSS 2009 proceedings page; authors Wright, Coull, Monrose | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 3b | Cat 3 padding/fragmentation limits — naive size countermeasures fail; motivates exact-boundary approach | `dyer2012` | Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail | Shows per-packet padding/fragmentation defenses (incl. BuFLO) leave exploitable size/count features — why RRC must control segmentation, not just pad | DBLP rec conf/sp/DyerCRS12; IEEE S&P 2012 pp. 332–346; DOI 10.1109/SP.2012.28 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 4a | Cat 4 MTD/anti-recon ICS (ANCHOR) — virtualize physical functions to disrupt grid reconnaissance | `defrec2020` | DefRec: Establishing Physical Function Virtualization to Disrupt Reconnaissance of Power Grids' Cyber-Physical Infrastructures | Content/connectivity-level deception against grid recon — the anti-recon line our wire-shape obfuscation complements | DBLP rec conf/ndss/LinZHZ20; NDSS 2020 page; authors Lin, Zhuang, Hu, Zhou | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 4b | Cat 4 MTD/anti-recon ICS (ANCHOR) — randomize network communication to mislead attackers | `raincoat2019` | RAINCOAT: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers | Randomized data acquisition + decoy measurements steer attackers into ineffective strategies | DBLP rec journals/tsg/LinKI19; IEEE TSG 10(5):4893–4906; DOI 10.1109/TSG.2018.2870362 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 4c | Cat 4 (ANCHOR) — testbed/methodology for evaluating anti-reconnaissance on grid CPS | `lintestbed2020` | Cyber-Physical Testbed: Case Study to Evaluate Anti-Reconnaissance Approaches on Power Grids' Cyber-Physical Infrastructures | Evaluation methodology for anti-recon defenses on power-grid CPS; positions RRC/BOR evaluation | LASER 2020 (NDSS co-located); NSF PAR 10336809; DECPS lab page; authors Lin, Shrestha, Hu | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 4d | Cat 4 / DNP3 monitoring — specification-based IDS on DNP3 (detection line, contrasted with proactive obfuscation) | `linbro2013` | Adapting Bro into SCADA: Building a Specification-Based Intrusion Detection System for the DNP3 Protocol | Bro/Zeek specification-based DNP3 monitoring detects malicious activity — a detect-after line vs. our pre-emptive shaping | DBLP rec conf/csiirw/LinSMKI13; CSIIRW 2013; DOI 10.1145/2459976.2459982 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 4e | Cat 4 / CPS safety — analysis of malicious control-command consequences | `lincps2016` | Safety-Critical Cyber-Physical Attacks: Analysis, Detection, and Mitigation | Analyzes physical consequences of malicious control activity — the harm the recon we blunt ultimately enables | DBLP rec conf/hotsos/LinACKI16; HotSoS 2016 pp. 82–89; DOI 10.1145/2898375.2898391 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 5a | Cat 5 programmable-switch obfuscation (ANCHOR) — line-rate traffic shaping on a P4 switch | `ditto2022` | Ditto: WAN Traffic Obfuscation at Line Rate | Pads/reshapes traffic to a deterministic pattern at line rate on programmable hardware — closest in-network shaping precedent | DBLP rec conf/ndss/MeierLV22; NDSS 2022 page; authors Meier, Lenders, Vanbever | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 5b | Cat 5 — programmable data-plane substrate (P4) enabling in-switch parsing/rewrite | `p4ccr2014` | P4: Programming Protocol-Independent Packet Processors | Defines the P4 programmable-parser/match-action model the Tofino-1 implementation is written against | DBLP; ACM DL 10.1145/2656877.2656890; SIGCOMM CCR 44(3):87–95 | Verified; queued for DP4TQCSF; add blocked (offline local API) |
| 5c | Cat 5 — programmable packet scheduling / queueing at line rate (basis for hold-and-release timing) | `pifo2016` | Programmable Packet Scheduling at Line Rate (PIFO) | Push-in-first-out queues enable programmable scheduling/shaping in hardware — the queueing/replication basis for BOR/RRC release timing | DBLP; ACM DL 10.1145/2934872.2934899; SIGCOMM 2016 pp. 44–57 | Verified; queued for DP4TQCSF; add blocked (offline local API) |

---

## Summary counts

- **Verified:** 19 / 19 (all metadata confirmed against DBLP / ACM DL / IEEE Xplore / NDSS / USENIX / doi.org).
- **Added to `OBfus_defense`:** 0 (blocked — Zotero local API offline; see tooling status). Collection itself created.
- **Reused (existing Zotero item):** 0 (could not enumerate library — local API offline).
- **Corrected during verification:** 2 —
  (1) `lincps2016` author list: an intermediate DBLP author-summary dropped *Daniel Chen*; the authoritative DBLP record (conf/hotsos/LinACKI16) confirms **Lin, Alemzadeh, Chen, Kalbarczyk, Iyer** — corrected in refs.bib.
  (2) `linbro2013` venue: initial guess was HiCoNS 2013; the authoritative DBLP record (conf/csiirw/LinSMKI13) confirms **CSIIRW 2013**, DOI 10.1145/2459976.2459982 — corrected.
- **Rejected:** 0.
- **Could not verify:** 0 items outright unverifiable. Two caveats worth noting:
  (a) NDSS/USENIX papers (`formby2016`, `defrec2020`, `ditto2022`, `wright2009`, `song2001`) legitimately carry **no DOI and no page numbers** (Internet Society / USENIX open proceedings) — this is correct, not missing data.
  (b) `dnp3std` and `opendnp3`/`ukraine2015` are a standard, software, and a technical report respectively; they have no conference pages by nature.

## Mapping to the manuscript's existing placeholder keys

The current `_baseline.tex` placeholders re-key cleanly as follows:
`ref:dnp3`→`dnp3std`, `ref:ukraine`→`ukraine2015`, `ref:raincoat`→`raincoat2019`,
`ref:defrec`→`defrec2020`, `ref:fp`→`sirinam2018` (+ `wright2009`/`dyer2012` for the
padding/shaping side), `ref:bro`→`linbro2013`, `ref:cps`→`lincps2016`,
`ref:opendnp3`→`opendnp3`. Formby is added as the Cat-1 fingerprinting anchor
(`formby2016`); the Cat-2/3/5 and testbed entries are new for the Defense 4 related-work.
