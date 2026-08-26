# Claim-citation matrix

Every externally verifiable claim in `paper/rewrite/sections/*.tex`, with the key it cites in
`library.bib`, what the source is, the exact support, how it was verified, and any action.
Verification this session (2026-08-26) was against the bibliographic record in `library.bib`
(a Zotero/BetterBibTeX export), the earlier verification of 2026-08-14
(`paper/rewrite/CITATION_AUDIT.md` at tag `archive/defense4-local-unpushed-paper-20260824`,
which checked DBLP / ACM DL / IEEE Xplore / NDSS / USENIX pages for 19 of these entries), and web
lookups this session for the three entries that were incomplete or post-date the earlier audit
(Minos, Securitas, Jeon). Status values: VERIFIED (record complete and the source supports the
sentence), VERIFIED-RECORD (record complete; support is the paper's well-known content, not
re-read this session), PARTIAL, UNVERIFIED.

| # | section | claim | key | source | type | exact support | status | action |
|---|---|---|---|---|---|---|---|---|
| 1 | Intro ¶1 | In the 2015 Ukraine grid attack the adversaries are believed to have stayed in the systems for at least six months for reconnaissance | `leeAnalysisCyberAttack2016` | Lee, Assante, Conway, "Analysis of the Cyber Attack on the Ukrainian Power Grid", E-ISAC/SANS, 2016 | technical report | the report's timeline: initial compromise via phishing months before the December 2015 event, reconnaissance and credential harvesting over more than six months | VERIFIED-RECORD | none |
| 2 | Intro ¶1 | Stuxnet depended on detailed knowledge of the specific controllers it targeted | `langnerStuxnetDissectingCyberwarfare2011` | Langner, "Stuxnet: Dissecting a Cyberwarfare Weapon", IEEE S&P 9(3):49–51, 2011, DOI 10.1109/MSP.2011.67 | magazine article | Langner describes the payload's dependence on a specific Siemens S7 controller configuration and the insider-level knowledge it required | VERIFIED-RECORD | entry added this session (not in the Zotero export); import into Zotero when convenient |
| 3 | Intro ¶2 | Many studies present traffic obfuscation to disrupt fingerprinting | `wrightTrafficMorphingEfficient2009`, `dyerPeekaBooStillSee2012` | Wright, Coull, Monrose, NDSS 2009; Dyer et al., IEEE S&P 2012, pp. 332–346 | conference | both are traffic-analysis countermeasure papers | VERIFIED (2026-08-14 audit) | none |
| 4 | Intro ¶2 | General fingerprinting relies on packet size and inter-packet latency | `kohnoRemotePhysicalDevice2005`, `sirinamDeepFingerprintingUndermining2018` | Kohno, Broido, Claffy, IEEE TDSC 2(2):93–108, 2005; Sirinam et al., CCS 2018 | journal; conference | Kohno: clock skew from timing; Sirinam: packet-direction/size/timing sequences | VERIFIED (2026-08-14 audit for Sirinam; Kohno record complete) | none |
| 5 | Intro ¶2 | Padding and splitting change the packet-size distribution | `wrightTrafficMorphingEfficient2009`, `caiSystematicApproachDeveloping2014` | Wright 2009; Cai et al. (Tamaraw), CCS 2014, pp. 227–238, DOI 10.1145/2660267.2660362 | conference | morphing of size distributions; fixed-size padding | VERIFIED (2026-08-14 audit) | none |
| 6 | Intro ¶2 | Delaying and dummy packets disrupt inter-packet timing | `dyerPeekaBooStillSee2012`, `juarezEfficientWebsiteFingerprinting2016` | Dyer 2012 (BuFLO); Juarez et al. (WTF-PAD), ESORICS 2016 | conference | BuFLO fixed-rate schedule; WTF-PAD adaptive padding of gaps | VERIFIED (2026-08-14 audit) | none |
| 7 | Intro ¶2 | Recent work offloads obfuscation onto programmable switches at line rate | `meierDittoWANTraffic2022`, `wangMinosLightweightDynamic2025`, `xieSecuritasDefendingTraffic2026` | Meier, Lenders, Vanbever, NDSS 2022; Wang et al., USENIX ATC 2025; Xie et al., NSDI 2026, pp. 2043–2063 | conference | Ditto: line-rate padding/chaff on Tofino; Minos: switch-based morphing and scheduling; Securitas: in-network fragmentation/insertion on Tofino, FPGA, eBPF, BMv2 | VERIFIED (Ditto: 2026-08-14 audit; Minos and Securitas: USENIX pages and GitHub record fetched 2026-08-26; author lists completed in `library.bib`) | Securitas title corrected to the USENIX listing (no "Securitas:" prefix) |
| 8 | Intro ¶3, Background | DNP3 is the standard protocol; it validates each application block with a CRC | `ieeeIEEEStandardElectric2012` | IEEE Std 1815-2012, DOI 10.1109/IEEESTD.2012.6327578 | standard | link-layer framing with a 16-bit CRC per data block | VERIFIED (2026-08-14 audit) | none |
| 9 | Intro ¶3, Threat model | DNP3 is deployed without encryption by default; its attack surface | `eastTaxonomyAttacksDNP32009` | East, Butts, Papa, Shenoi, IFIP AICT 311, pp. 67–81, 2009 | book chapter | taxonomy of DNP3 attacks premised on the absence of authentication/encryption in deployed DNP3 | VERIFIED-RECORD | none |
| 10 | Intro ¶3, Background, Threat model, Related work | CLRT and control-operation time fingerprint device types and models; passive on-path observer | `formbyWhosControlYour2016` | Formby, Srinivasan, Leonard, Rogers, Beyah, NDSS 2016 | conference | cross-layer response time and physical operation time fingerprinting of ICS devices | VERIFIED (2026-08-14 audit) | duplicate record `formbyWhosControlYour2016a` exists in the export; only the unsuffixed key is cited |
| 11 | Threat model, Related work | Control-related attacks such as false-data injection need knowledge of the target | `liuFalseDataInjection2009` | Liu, Ning, Reiter, CCS 2009, pp. 21–32, DOI 10.1145/1653662.1653666 | conference | FDIA construction requires the system's measurement matrix | VERIFIED (2026-08-14 audit) | none |
| 12 | Background | P4 defines the programmable parser and match-action model | `bosshartP4ProgrammingProtocolIndependent2014` | Bosshart et al., SIGCOMM CCR 44(3):87–95, 2014, DOI 10.1145/2656877.2656890 | journal | the P4 language paper | VERIFIED (2026-08-14 audit) | none |
| 13 | Background, Related work | Programmable scheduling at line rate; strict-priority approximation | `sivaramanProgrammablePacketScheduling2016`, `alcozSPPIFOApproximatingPushIn2020` | Sivaraman et al., SIGCOMM 2016, pp. 44–57, DOI 10.1145/2934872.2934899; Alcoz, Dietmüller, Vanbever, NSDI 2020, pp. 59–76 | conference | PIFO; SP-PIFO on strict-priority queues | VERIFIED (2026-08-14 audit for PIFO; SP-PIFO record complete) | none |
| 14 | Related work | Remote device fingerprinting from clock skew | `kohnoRemotePhysicalDevice2005` | as row 4 | journal | TCP timestamp clock skew | VERIFIED-RECORD | none |
| 15 | Related work | GTID fingerprints a device and its type from packet timing | `radhakrishnanGTIDTechniquePhysical2015` | Radhakrishnan, Uluagac, Beyah, IEEE TDSC 12(5):519–532, 2015, DOI 10.1109/TDSC.2014.2369033 | journal | inter-arrival-time signatures | VERIFIED (2026-08-14 audit) | duplicate record `radhakrishnanGTIDTechniquePhysical2014` exists; only the 2015 key is cited |
| 16 | Related work | Device physics as a fingerprinting feature | `guFingerprintingCyberPhysicalSystem2018` | Gu, Formby, Ji, Cam, Beyah, IEEE S&P Magazine 16(5):49–59, 2018, DOI 10.1109/MSP.2018.3761722 | magazine article | "Device Physics Matters Too" | VERIFIED-RECORD | none |
| 17 | Related work | Passive SCADA fingerprinting without deep packet inspection | `jeonPassiveFingerprintingSCADA2016` | Jeon, Yun, Choi, Kim, arXiv:1608.07679, 2016 | preprint | title and abstract | VERIFIED (arXiv record fetched 2026-08-26) | `howpublished` added so the reference renders the arXiv identifier |
| 18 | Related work | Process-control attacks enabled by reconnaissance | `cardenasAttacksProcessControl2011` | Cárdenas et al., ASIACCS 2011, pp. 355–366 | conference | attack model against process control | VERIFIED-RECORD | none |
| 19 | Related work | DefRec: physical function virtualization to disrupt reconnaissance | `linDefRecEstablishingPhysical2020` | Lin, Zhuang, Hu, Zhou, NDSS 2020 | conference | deceptive content and connectivity | VERIFIED (2026-08-14 audit) | none |
| 20 | Related work | RAINCOAT: randomized data acquisition and decoy measurements | `linRAINCOATRandomizationNetwork2019` | Lin, Kalbarczyk, Iyer, IEEE TSG 10(5):4893–4906, 2019, DOI 10.1109/TSG.2018.2870362 | journal | randomization and decoys | VERIFIED (2026-08-14 audit) | none |
| 21 | Related work | Testbed for anti-reconnaissance evaluation on grid infrastructure | `linCyberPhysicalTestbedCase2020` | Lin, Shrestha, Hu, LASER 2020 | workshop | title | VERIFIED (2026-08-14 audit) | none |
| 22 | Related work | Padding/fragmentation leave exploitable features | `dyerPeekaBooStillSee2012` | as row 3 | conference | main result | VERIFIED | none |
| 23 | Related work | Tamaraw fixes size and rate at a bandwidth cost | `caiSystematicApproachDeveloping2014` | as row 5 | conference | Tamaraw | VERIFIED | none |
| 24 | Related work | WTF-PAD pads inter-packet gaps adaptively | `juarezEfficientWebsiteFingerprinting2016` | as row 6 | conference | adaptive padding | VERIFIED | none |
| 25 | Related work | Deep fingerprinting defeats several defenses | `sirinamDeepFingerprintingUndermining2018` | as row 4 | conference | >90% against WTF-PAD | VERIFIED | none |
| 26 | Related work | Website-fingerprinting accuracy at Internet scale is contested | `panchenkoWebsiteFingerprintingInternet2016` | Panchenko et al., NDSS 2016 | conference | open-world scale results | VERIFIED-RECORD | none |
| 27 | Related work | Smart-home devices identified under encryption; shaping as countermeasure | `apthorpeKeepingSmartHome2019` | Apthorpe et al., PoPETs 2019 | journal | "Smart(er) IoT Traffic Shaping" | VERIFIED-RECORD | none |
| 28 | Related work | Pacer and NetShaper shape tenant traffic to bound side channels | `mehtaPacerComprehensiveNetwork2022`, `sabziNetShaperDifferentiallyPrivate2024` | Mehta et al., USENIX Security 2022; Sabzi et al., USENIX Security 2024 | conference | cloud network side-channel mitigation by shaping | VERIFIED-RECORD | none |
| 29 | Related work | NetHide obfuscates topology against link-flooding reconnaissance | `meierNetHideSecurePractical2018` | Meier et al., USENIX Security 2018, pp. 693–709 | conference | topology obfuscation | VERIFIED-RECORD | none |
| 30 | Related work | Programmable switches to enhance industrial-protocol security | `huIndustrialNetworkProtocol2023` | Hu, Lin, Waind, Qu, Chen, Jin, IEEE SmartGridComm 2023 | conference | title | VERIFIED-RECORD | none |
| 31 | Related work | Specification/state-based intrusion detection adapted to DNP3 | `linAdaptingBroSCADA2013`, `fovinoModbusDNP3StateBased2010` | Lin et al., CSIIRW 2013; Fovino et al., AINA 2010, pp. 729–736 | workshop; conference | DNP3 IDS | VERIFIED (2026-08-14 audit for Lin 2013; Fovino record complete) | none |

## Bibliography hygiene

* Cited keys: 33; all resolve in `library.bib` (`lin_check` citations check).
* Duplicate records in the export that could be mistaken for separate papers:
  `formbyWhosControlYour2016a`, `radhakrishnanGTIDTechniquePhysical2014`, `dyerPeekaBooStillSee2012a`,
  `meierDittoWANTraffic2022a`, `sirinamDeepFingerprintingUndermining2018a`,
  `juarezEfficientWebsiteFingerprinting2016a/b`, `linAdaptingBroSCADA2013a`. None of the suffixed
  keys is cited; the export is left as is (no bulk edit), and the duplicates should be merged in
  Zotero.
* Entries edited this session, each individually: `wangMinosLightweightDynamic2025` (author list),
  `xieSecuritasDefendingTraffic2026` (author list, pages, title as listed by USENIX),
  `jeonPassiveFingerprintingSCADA2016` (`howpublished`), and `langnerStuxnetDissectingCyberwarfare2011`
  (added).
* `refs.bib` (legacy, 41 hand-written keys) is not referenced by `main.tex`; every claim above cites
  `library.bib`, so it is archived (see `CLEANUP_PLAN.md`).
* No Stuxnet or Ukraine statement is made without a citation, and each incident carries only the
  claim its source supports (`LIN_TEXT_CHANGELOG.md` 1.4).
