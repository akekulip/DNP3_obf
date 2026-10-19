# Citation audit, 2026-10-19

Scope: the 35 keys cited in `/home/philip/Projects/DNP3/main.tex` (Dr. Lin's draft) against
`paper/rewrite/References.bib`, plus new candidate references for the NOMAD paper. No manuscript
or bib file was edited. All Zotero writes went to the collection **`OBfus_defense`** (key
`DP4TQCSF`). The collection is spelled "defense" in Zotero, not "defence".

Method: Semantic Scholar `get_paper_details` / `get_paper_citations` for venue, year and DOI;
every DOI listed below was resolved through `https://doi.org` and redirected to the publisher
(IEEE Xplore, ACM DL, NDSS, PETS, Elsevier). USENIX papers have no DOI; their metadata was taken
from the BibTeX block on each usenix.org presentation page. No arXiv record was used as a source
of record.

Column "key": the existing References.bib key where one exists; otherwise a proposed key in the
Better BibTeX default pattern (author + first title words + year). The proposed keys are not
verified, because Better BibTeX was not queried. Run `refresh-bib.sh` and read the exported key.

Status values: **existing** (already in References.bib), **added** (newly filed in OBfus_defense
this session), **filed** (already in the library, now also filed in OBfus_defense),
**arXiv-only flagged**, **not found**.

## 1. The three keys missing from References.bib

| key | title | authors | venue / type | year | DOI / URL | source of record checked | claim it supports | status |
|---|---|---|---|---|---|---|---|---|
| CISA2026SecureOT | Barriers to Secure OT Communication: Why Johnny Can't Authenticate | Cybersecurity and Infrastructure Security Agency (CISA) | CISA guidance, TLP:CLEAR | 2026 (published Feb 10) | https://www.cisa.gov/resources-tools/resources/barriers-secure-ot-communication-why-johnny-cant-authenticate (PDF: https://www.cisa.gov/sites/default/files/2026-02/Barriers-to-Secure-Communication-Why-OT-Johnny-Cant-Authenticate_508_2.pdf) | yes, PDF text read | main.tex l.170: owners and operators do not use available security measures. The PDF supports this: "Secure versions of industrial protocols have existed since the early 2000s (e.g., ... DNP3 to DNP3-SAv5 ...)", followed by "Why are organizations not implementing them?" The barriers it lists are cost, complexity, latency and bandwidth, inspection of encrypted traffic, and legacy interoperability. | added (Zotero `K6RPMXB9`) |
| p42022psa | P4_16 Portable Switch Architecture (PSA), Version 1.2 | The P4.org Architecture Working Group | P4.org specification | 2022 (2022-12-22) | https://p4.org/wp-content/uploads/sites/53/p4-spec/docs/PSA-v1.2.html | yes | The PSA model: "six programmable P4 blocks and two fixed-function blocks" (PRE, BQE), with an ingress parser, control and deparser and the same on egress. **It does not support the sentence in main.tex l.145 that PSA has "up to four ingress and four egress pipelines".** That is a Tofino-1 property (four pipes), and the spec defines one logical ingress and one logical egress pipeline. Cite the Tofino documentation for the four-pipe claim, or reword it. | added (Zotero `3SP5EPHD`) |
| seion7550 | PowerLogic ION7550/ION7650 Series | Schneider Electric | product range page | n.d. (accessed 2026-10-19) | https://www.se.com/us/en/product-range/1460-powerlogic-ion7550-ion7650-series/ | yes | Identifies the device. The page lists DNP 3.0, Modbus RTU/TCP, MV-90 and IEC 61850. **The range is marked "Discontinued"**, which may be worth one clause in the manuscript. The user guide (7EN02-0248) is a more stable alternative citation. | added (Zotero `2IPRS37F`) |

## 2. New candidate references (filed in OBfus_defense)

### (a) ICS/IIoT device fingerprinting (forward citations of Formby NDSS 2016)

| key | title | authors | venue | year | DOI / URL | SoR checked | claim it can support | status |
|---|---|---|---|---|---|---|---|---|
| shen2018 | Hybrid-Augmented Device Fingerprinting for Intrusion Detection in Industrial Control System Networks | Shen, Liu, Tan, Wang, Xu, Su | IEEE Wireless Communications 25(6):26–31 | 2018 | 10.1109/MWC.2017.1800132 | yes | inter-layer response processing time used as an ICS fingerprint (same feature family as CLRT) | existing in bib (uncited); added (`EZ8FCXBJ`). **Creates a third library copy**, see section 4 |
| ahmed2021 | Scanning the Cycle: Timing-based Authentication on PLCs | Ahmed, Ochoa, Zhou, Mathur | ACM AsiaCCS | 2021 | 10.1145/3433210.3453102 | yes | the PLC scan cycle, read passively from network timing, identifies the device | existing in bib (uncited); filed (`AGZR7269`) |
| pospisil2023 | Identifying Industry Devices via Time Delay in Dataflow | Pospisil, Fujdiak | ICCNS 2023 (ACM) | 2023 | 10.1145/3638782.3638808 | yes | passive PLC-model identification from OPC UA time delays | existing in bib (uncited); filed (`WT7WRIIG`) |
| babunCPSDeviceClassIdentification2021 | CPS Device-Class Identification via Behavioral Fingerprinting: From Theory to Practice | Babun, Aksu, Uluagac | IEEE TIFS 16:2413–2428 | 2021 | 10.1109/TIFS.2021.3054968 | yes | device-class fingerprinting of CPS devices (behavioural, challenge/response) | added (`9IRN369A`) |
| formbyCaseStudyPower2017 | A Case Study in Power Substation Network Dynamics | Formby, Walid, Beyah | Proc. ACM POMACS 1(1) | 2017 | 10.1145/3084456 | yes | measured timing regularity of real substation traffic, which is what makes timing a stable feature | added (`FR8KJXBQ`) |
| fengCharacterizingIndustrialControl2016 | Characterizing industrial control system devices on the Internet | Feng, Li, Wang, Sun | IEEE ICNP | 2016 | 10.1109/ICNP.2016.7784407 | yes | identification of ICS devices from protocol responses at Internet scale | added (`3EDBTZSR`) |
| kumarDeviceFingerprintingCyberphysical2023 | Device Fingerprinting for Cyber-Physical Systems: A Survey | Kumar, Paul | ACM Computing Surveys 55 | 2023 | 10.1145/3584944 | yes | survey anchor for CPS fingerprinting | added (`C9BZ2IDV`) |
| shengNetworkTrafficFingerprinting2025 | Network Traffic Fingerprinting for IIoT Device Identification: A Survey | Sheng, Zhou, Han, Ma, Zhu, Wen, Xiang | IEEE TII 21:3541–3554 | 2025 | 10.1109/TII.2025.3534441 | yes | recent survey of packet-, flow- and business-level IIoT fingerprinting | added (`URHHDBAV`) |
| barbieriAssessingUseInsecure2021 | Assessing the Use of Insecure ICS Protocols via IXP Network Traffic Analysis | Barbieri, Conti, Tippenhauer, Turrin | IEEE ICCCN | 2021 | 10.1109/ICCCN52240.2021.9522219 | yes | measured prevalence of plaintext ICS traffic: 75.6% of ICS hosts used unencrypted communication without integrity protection. Independent evidence for the claim at l.170 | added (`5C5RBSUP`) |
| jeon2016passive | Passive Fingerprinting of SCADA in Critical Infrastructure Network without Deep Packet Inspection | Jeon, Yun, Choi, Kim | arXiv only (Semantic Scholar venue: arXiv.org) | 2016 | no DOI; no peer-reviewed version found | yes (S2) | passive SCADA fingerprinting without DPI | **existing, arXiv-only flagged**: the bib entry is `@misc` with no eprint or URL |

### (b) ICS anti-reconnaissance and moving-target defense (forward citations of DefRec / RAINCOAT)

| key | title | authors | venue | year | DOI / URL | SoR checked | claim it can support | status |
|---|---|---|---|---|---|---|---|---|
| yangDecIEDScalableKanonymous2020 | DecIED: Scalable k-Anonymous Deception for IEC61850-Compliant Smart Grid Systems | Yang, Mashima, Lin, Zhou | ACM CPSS workshop (AsiaCCS) | 2020 | 10.1145/3384941.3409592 | yes | decoy IEDs that are indistinguishable from real ones, a related anti-reconnaissance approach at the device level | added (`RHXANK3Q`) |
| chenSurveyMovingTarget2025 | Survey of Moving Target Defense in Power Grids: Design Principles, Tradeoffs, and Future Directions | Chen, Konstantinou, Mashima, Srivastava, Lakshminarayana | IEEE Open Access J. Power and Energy | 2025 (S2 lists 2024) | 10.1109/OAJPE.2025.3577012 | yes (resolves to IEEE Xplore 11026104) | positions NOMAD relative to grid MTD | added (`WD6NMNK6`). Check the year on Xplore |
| huIDETECTInnetworkDeep2026 | I-DETECT: In-network Deep Packet Inspection for Timed Event Correlation in Industrial Control Systems | Hu, Lin, Qu, Jin | IEEE/IFIP DSN, pp. 627–640 | 2026 | 10.1109/DSN69566.2026.00065 | yes | P4 switches processing ICS traffic in real time on the same kind of testbed (Lin group) | added (`E8DF4WQK`) |
| lintestbed2020 | Cyber-Physical Testbed: Case Study to Evaluate Anti-Reconnaissance Approaches ... | Lin, Shrestha, Hu | NDSS LASER workshop | 2020 | 10.14722/laser.2020.23001 | yes | testbed for evaluating anti-reconnaissance | existing (in bib and Zotero `TUKZ224Q`). **main.tex cites the wrong key for it**, see section 3 |

### (c) Traffic-analysis defenses: splitting, padding, timing, cover-traffic cost

| key | title | authors | venue | year | DOI / URL | SoR checked | claim it can support | status |
|---|---|---|---|---|---|---|---|---|
| walkietalkie2017 | Walkie-Talkie: An Efficient Defense Against Passive Website Fingerprinting Attacks | Wang, Goldberg | USENIX Security, pp. 1375–1390 | 2017 | https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-tao | yes | half-duplex burst molding; supersequence padding | existing (bib + Zotero `XPGPI7M6`), not cited in main.tex |
| cadenaTrafficSliverFightingWebsite2020 | TrafficSliver: Fighting Website Fingerprinting Attacks with Traffic Splitting | De la Cadena, Mitseva, Hiller, Pennekamp, Reuter, Filter, Engel, Wehrle, Panchenko | ACM CCS | 2020 | 10.1145/3372297.3423351 | yes | splitting as a defense, which matches NOMAD's splitting of control units | added (`V62S4V5U`) |
| gongZerodelayLightweightDefenses2020 | Zero-delay Lightweight Defenses against Website Fingerprinting (FRONT, GLUE) | Gong, Wang | USENIX Security, pp. 717–734 | 2020 | https://www.usenix.org/conference/usenixsecurity20/presentation/gong | yes | zero-delay dummy-packet defenses; the latency/bandwidth trade-off | added (`N76CJGN5`) |
| gongSurakavGeneratingRealistic2022 | Surakav: Generating Realistic Traces for a Strong Website Fingerprinting Defense | Gong, Zhang, Zhang, Wang | IEEE S&P, pp. 1558–1573 | 2022 | 10.1109/SP46214.2022.9833722 | yes | regulated sending patterns; overhead figures compared with Tamaraw and FRONT | added (`VZ968HDJ`) |
| hollandRegulaTorStraightforwardWebsite2022 | RegulaTor: A Straightforward Website Fingerprinting Defense | Holland, Hopper | PoPETs 2022(2) | 2022 | 10.2478/popets-2022-0049 | yes | rate-regulation (timing) defense with a low latency cost | added (`7AVUG4U5`) |
| wangEffectiveAttacksProvable2014 | Effective Attacks and Provable Defenses for Website Fingerprinting | Wang, Cai, Nithyanand, Johnson, Goldberg | USENIX Security, pp. 143–157 | 2014 | https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/wang_tao | yes | k-NN attack; provable supersequence defenses and their cost | added (`IUHFH2DC`) |
| tamaraw2014, juarez2016, dyer2012, wright2009, apthorpe2019, pacer2022, netshaper2024 | — | — | — | — | — | yes | already cited | existing |

### (d) In-network / programmable-switch obfuscation and scheduling

| key | title | authors | venue | year | DOI / URL | SoR checked | claim it can support | status |
|---|---|---|---|---|---|---|---|---|
| ditto2022 | ditto: WAN Traffic Obfuscation at Line Rate | Meier, Lenders, Vanbever | NDSS | 2022 | 10.14722/ndss.2022.24056 | yes | padding and chaff on Tofino at 100 Gbps | existing (bib lacks DOI) |
| minos2025 | Minos : A Lightweight and Dynamic Defense against Traffic Analysis in Programmable Data Planes | Wang, Li, Xie, Zhao, Li, Fan, Ma, Jiang | USENIX ATC, pp. 399–415 | 2025 | https://www.usenix.org/conference/atc25/presentation/wang-zihao | yes | Tofino-1 defense covering website and IoT fingerprinting | existing (bib incomplete, see section 3) |
| securitas2026 | Defending against Traffic Analysis Attacks with Flexible In-Network Obfuscation | Xie, Li, Shi, Antichi, Zhu, Li, Weng, Miano, Jiang, Xu | USENIX NSDI, pp. 2043–2063 | 2026 | https://www.usenix.org/conference/nsdi26/presentation/xie-guorui | yes | learning-guided fragmentation and insertion on Tofino, FPGA, eBPF and BMv2 | existing (bib title and authors wrong, see section 3) |
| nethide2018 | NetHide: Secure and Practical Network Topology Obfuscation | Meier, Tsankov, Lenders, Vanbever, Vechev | USENIX Security, pp. 693–709 | 2018 | usenix.org/.../usenixsecurity18/presentation/meier | yes | in-network obfuscation of observable network structure | existing, uncited |
| datta2019spine | SPINE: Surveillance Protection in the Network Elements | Datta, Feamster, Rexford, Wang | USENIX FOCI workshop | 2019 | https://www.usenix.org/conference/foci19/presentation/datta | yes | an early P4 in-network metadata-obfuscation design | added (`5C7RK2JN`). Workshop paper |
| sharma2020pcq | Programmable Calendar Queues for High-speed Packet Scheduling | Sharma, Zhao, Liu, Kannan, Kim, Krishnamurthy, Sivaraman | USENIX NSDI, pp. 685–699 | 2020 | https://www.usenix.org/conference/nsdi20/presentation/sharma | yes | time-based release and scheduling on Tofino (pausing queues, recirculation) | added (`KMBAPJMB`) |
| sharma2018afq | Approximating Fair Queueing on Reconfigurable Switches | Sharma, Liu, Atreya, Krishnamurthy | USENIX NSDI, pp. 1–16 | 2018 | https://www.usenix.org/conference/nsdi18/presentation/sharma | yes | per-flow queue assignment on RMT switches | added (`QJIBJ6N5`) |
| pifo2016, sppifo2020, p4ccr2014 | — | — | — | — | — | yes | already cited | existing |
| ProgME | — | — | — | — | — | — | ProgME (2007) is a traffic-measurement framework, not obfuscation. It was not added | not relevant |
| Tofino recirculation-delay paper | — | — | — | — | — | — | No peer-reviewed paper dedicated to recirculation-based delay on Tofino was found in the time spent. PCQ is the closest | not found |

### (e) DNP3 standard and DNP3 security / SAv5

| key | title | authors | venue | year | DOI / URL | SoR checked | claim it can support | status |
|---|---|---|---|---|---|---|---|---|
| dnp3std | IEEE Standard for Electric Power Systems Communications—Distributed Network Protocol (DNP3) | IEEE | IEEE Std 1815-2012 | 2012 | 10.1109/IEEESTD.2012.6327578 | yes (resolves to Xplore 6327578) | the protocol, including SAv5 | existing. Zotero holds two copies (section 4) |
| amoahFormalModellingAnalysis2016 | Formal modelling and analysis of DNP3 secure authentication | Amoah, Camtepe, Foo | J. Network and Computer Applications 59:345–360 | 2016 | 10.1016/j.jnca.2015.05.015 | yes | SAv5 complexity and its weaknesses, background for why it goes undeployed | added (`H3NDZIRS`) |
| CISA2026SecureOT | (section 1) | | | | | yes | SAv5 adoption barriers | added |

### (f) Attackers and timing features

| key | title | authors | venue | year | DOI / URL | SoR checked | claim it can support | status |
|---|---|---|---|---|---|---|---|---|
| sirinam2018 | Deep Fingerprinting | Sirinam, Imani, Juarez, Wright | ACM CCS, pp. 1928–1943 | 2018 | 10.1145/3243734.3243768 | yes | DL attacker | existing |
| hayes2016kfp (proposed) | k-fingerprinting: A Robust Scalable Website Fingerprinting Technique | Hayes, Danezis | USENIX Security, pp. 1187–1203 | 2016 | https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/hayes | yes | **Random-forest attacker.** The paper scopes its results to a Random-Forest attacker, so k-FP is the closest published precedent | added (`G2B2VRBX`) |
| rahmanTikTokUtilityPacket2020 | Tik-Tok: The Utility of Packet Timing in Website Fingerprinting Attacks | Rahman, Sirinam, Mathews, Gangadhara, Wright | PoPETs 2020(3):5–24 | 2020 | 10.2478/popets-2020-0043 | yes | timing-only and directional-timing features defeat WTF-PAD | added (`7WMXMQ7T`) |
| feghhi2016, panchenko2016 | — | — | — | — | — | yes | already cited | existing |

### (g) Normalization, timing-channel mitigation and content-based ICS fingerprinting (added later on 2026-10-19)

| key | title | authors | venue | year | DOI / URL | SoR checked | claim it can support | status |
|---|---|---|---|---|---|---|---|---|
| normalization2001 | Network Intrusion Detection: Evasion, Traffic Normalization, and End-to-End Protocol Semantics | Handley, Paxson, Kreibich | 10th USENIX Security Symposium, Washington, D.C. | 2001 | https://www.usenix.org/conference/10th-usenix-security-symposium/network-intrusion-detection-evasion-traffic-normalization | yes, BibTeX block on the usenix.org page (no DOI; no pages listed) | in-network normalization of protocol behaviour: a forwarding element rewrites traffic so a monitor sees one unambiguous form | added (Zotero `D6CJD2D4`), bib key added |
| smart2000 | Defeating TCP/IP Stack Fingerprinting | Smart, Malan, Jahanian | 9th USENIX Security Symposium, Denver, CO | 2000 | https://www.usenix.org/conference/9th-usenix-security-symposium/defeating-tcpip-stack-fingerprinting | yes, BibTeX block on the usenix.org page (no DOI; no pages listed) | defeating stack fingerprinting by rewriting traffic in the network (the fingerprint scrubber) | added (Zotero `KQWWPSNT`), bib key added |
| askarov2010 | Predictive Black-Box Mitigation of Timing Channels | Askarov, Zhang, Myers | ACM CCS '10, Chicago, pp. 297–307 | 2010 | 10.1145/1866307.1866341 | yes, DOI resolves to dl.acm.org; metadata from the ACM Crossref deposit (the ACM page itself returned 403 to the fetcher) | predictive timing-channel mitigation: release at predicted, schedule-determined times, the idea behind deadline release | added (Zotero `8NNAKU5I`), bib key added |
| keliris2016 | Remote Field Device Fingerprinting Using Device-Specific Modbus Information | Keliris, Maniatakos | IEEE 59th MWSCAS, pp. 1–4 | 2016 | 10.1109/MWSCAS.2016.7870006 | yes, DOI resolves to IEEE Xplore 7870006; metadata from the IEEE Crossref deposit (the Xplore page renders client-side and could not be read) | content-based ICS device fingerprinting from vendor-specific Modbus information, which NOMAD's metadata-only scope does not address | added (Zotero `5C7AGF7Q`), bib key added |

## 3. Keys in main.tex whose References.bib entry or usage disagrees with the source of record

| key | problem | fix |
|---|---|---|
| securitas2026 | The bib title "Securitas: Defending against ..." does not match the official title, which has no "Securitas:" prefix. Authors are "Xie, Guorui and others"; the paper has 10 named authors. Pages are missing (2043–2063). | Replace the entry with the usenix.org BibTeX (section 2d) |
| minos2025 | Authors are "Wang, Zihao and others"; the paper has 8 named authors. Pages are missing (399–415). The official title is "Minos : A ..." (with a space before the colon) | Use the usenix.org BibTeX |
| lincps2016 (main.tex l.293) | Cited for "a testbed that evaluates such anti-reconnaissance approaches on grid infrastructure". That entry is the HotSoS 2016 safety-critical-attacks paper. The testbed paper is `lintestbed2020` (LASER 2020) | Change the key to `lintestbed2020` and add DOI 10.14722/laser.2020.23001 |
| p42022psa (l.145) | The entry is correct; the claim is not. PSA does not specify "up to four ingress and four egress pipelines" | Reword, or cite Tofino documentation for the four-pipe figure |
| jeon2016passive | arXiv-only preprint with no peer-reviewed version; the bib `@misc` has no eprint, URL or venue | Add `eprint = {1608.07679}` (unverified ID, confirm) or replace it with a peer-reviewed passive ICS fingerprint such as Shen 2018 or Feng 2016 |
| formby2016, defrec2020, panchenko2016, ditto2022 | NDSS entries with no DOI. The DOIs exist and resolve: 10.14722/ndss.2016.23142, 10.14722/ndss.2020.24365, 10.14722/ndss.2016.23477, 10.14722/ndss.2022.24056 | Add the DOIs (optional under IEEEtran) |
| ditto2022 | NDSS styles the system name in lowercase ("ditto") | Cosmetic |
| pacer2022, netshaper2024 | Pages missing (2819–2838; 3385–3402) | Optional |
| feghhi2016 | Pages missing (1747–1759, per Semantic Scholar) | Optional |
| liufdia2009, kohno2005, gtid2015 (l.293) | Cited for "These methods ... help in the execution of false-data injection and process control attacks". Kohno 2005 and GTID are fingerprinting papers, not attack papers. `cardenas2011` appears twice in the same `\cite` list | Prose and citation clean-up for Dr. Lin |

Every other DOI in the cited set resolved to its publisher: apthorpe2019, cardenas2011, dnp3std,
dyer2012, east2009, feghhi2016, gtid2015, gu2018, juarez2016, kohno2005, lincps2016, liufdia2009,
p4ccr2014, pifo2016, raincoat2019 (volume, issue and pages match Semantic Scholar), rfc9293,
sirinam2018, stuxnet2011, tamaraw2014. The following were not checked against an online source of
record: sel751a (the manual is in the lab), ukraine2015 (E-ISAC/SANS report), and wright2009
(NDSS 2009, no DOI).

## 4. Library hygiene: duplicates (reported, not merged)

`zotero_find_duplicates` found no duplicates inside OBfus_defense. The library-wide DOI scan found
these copies that touch this collection:

- **Shen 2018** (10.1109/MWC.2017.1800132): `EZ8FCXBJ` was created this session and duplicates
  the earlier `R7PZ5CV9` and `M3FN4N89`. The `if_exists="file"` check missed them because the
  DOI case differs. Keep one and merge the others.
- **Ahmed 2021** (10.1145/3433210.3453102): `AGZR7269`, which is filed in OBfus_defense, and
  `HX76ISCW`.
- **IEEE 1815-2012** (10.1109/IEEESTD.2012.6327578): `AQADUZR8`, which is in OBfus_defense, and
  `P33WUD7A`.
- **P4 CCR 2014** (10.1145/2656877.2656890): `QZTDX2VP`, which is in OBfus_defense, and `AGHSBM79`.

The scan also found duplicates outside this collection (FlowPulse, OmniPath Ping, finance and law
papers). They were not touched.

## 5. Retractions

`scite_check_retractions` on OBfus_defense checked the 27 items that have DOIs and found no
retractions or editorial notices. Items without a DOI (USENIX, NDSS without DOI, the CISA
guidance, the PSA spec, the product page) cannot be checked by Scite.

## 6. Counts

- Cited keys in main.tex: 35. Missing from References.bib: 3, all now in Zotero.
- Added this session: 3 (missing keys) + 21 new candidates (15 by DOI, 6 USENIX by publisher
  BibTeX) = 24 new Zotero items. One of them, Shen 2018, is a duplicate copy. Two existing library items (Ahmed 2021, Pospisil 2023) were filed into the
  collection.
- arXiv-only flagged: 1 (jeon2016passive).
- Bib or usage disagreements: 10 rows in section 3, three of them substantive (securitas2026
  title and authors, lincps2016 used for the testbed claim, and the PSA four-pipeline claim).

To pull the new items into a `.bib`, run `~/ResearchVault/_bin/refresh-bib.sh`. Zotero must be
running for it (Local API on localhost:23119). It was not run in this session.
