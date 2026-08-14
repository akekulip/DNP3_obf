# Literature gap matrix

Organized by the twelve research categories from the repair prompt (§9). Columns: current coverage
(keys already in `refs.bib`) | weak spot | candidate primary source(s) to add | venue + tier |
exact claim it supports | intended citation location | status. Status legend: **V** = already in
`refs.bib`, verified; **D3** = present in the Defense-3 Zotero library (`63ZBT94Q`), metadata
readable, to add after approval; **F** = to find + verify (Semantic Scholar → DOI/proceedings).
Current `refs.bib` = 32 verified entries; target = ~40–50 (only if each directly supports the paper).

## Category coverage snapshot (refs.bib, 32)
fingerprinting: formby2016, gtid2015, kohno2005, gu2018 · timing/TA: song2001, sirinam2018,
panchenko2016, pacer2022 · padding/morphing: wright2009, dyer2012, tamaraw2014, walkietalkie2017,
apthorpe2019, netshaper2024, juarez2016 · anti-recon ICS: defrec2020, raincoat2019, lintestbed2020,
linbro2013, lincps2016, nethide2018, liufdia2009 · switch shaping: p4ccr2014, pifo2016, sppifo2020,
ditto2022, securitas2026, minos2025, hulin2023 · standards/incident: dnp3std, ukraine2015, opendnp3.

## 1. Remote and passive device fingerprinting
| coverage | weak spot | candidate | venue/tier | claim | location | status |
|---|---|---|---|---|---|---|
| kohno2005, gtid2015 | missing the formal/protocol-fingerprinting line | Shu & Lee, *Network Protocol System Fingerprinting — A Formal Approach* | GLOBECOM (IEEE) | protocol state machines yield formal device fingerprints | RW ¶a | D3 (`36V28PBF`) — verify tier |
| | clock-skew anchor present | (kohno2005) | IEEE TDSC | remote clock-skew fingerprinting | RW ¶a | V |

## 2. ICS / CPS device fingerprinting
| formby2016, gu2018 | missing a passive-SCADA-without-DPI result | Jeon et al., *Passive Fingerprinting of SCADA in Critical Infrastructure Networks without DPI* | (verify venue) | SCADA device fingerprint from passive metadata, no DPI | RW ¶b, Intro ¶2 | D3 (`S2JIKZDB`) — **verify venue/tier before use** |

## 3. Cross-layer timing and response-time fingerprints
| formby2016 (CLRT) | thin on timing-only web analysis | Feghhi & Leith, *A Web Traffic Analysis Attack Using Only Timing Information* | IEEE Trans. Information Forensics & Security | timing alone (no size) fingerprints activity | Intro ¶3 / RW ¶c | D3 (`M6USVZ5C`) |

## 4. Website and encrypted-traffic fingerprinting
| sirinam2018, panchenko2016 | anonymity-layer TA resistance context | Chen et al., *TARANET* (EuroS&P 2018); Chen et al., *HORNET* (CCS 2015) | IEEE EuroS&P / ACM CCS | network-layer traffic-analysis-resistant designs | RW ¶d | D3 (`RX2TMWHR`,`6NWN4NS9`) |

## 5. Traffic morphing and packet-size defenses
| wright2009, dyer2012 | congestion-sensitive BuFLO variant | Cai, Nithyanand, Johnson, *CS-BuFLO* | WPES (ACM CCS-affiliated) — **workshop-tier; use only if the BuFLO lineage needs it, else keep tamaraw2014** | congestion-sensitive constant-rate defense | RW ¶e | D3 (`D8UM4CJW`) — tier caution |

## 6. Adaptive padding and constant-rate defenses
| juarez2016, tamaraw2014, walkietalkie2017 | low-latency link padding origin | Wang, Motani, Srinivasan, *Dependent Link Padding Algorithms for Low Latency Anonymity Systems* | ACM CCS 2008 | provably-optimal dependent link padding | RW ¶f | D3 (`GUHS7AID`) |

## 7. Differential-privacy traffic shaping
| netshaper2024 | adequately covered | (netshaper2024) | USENIX Security | differentially-private network side-channel shaping | RW ¶g | V |

## 8. In-network and programmable-switch traffic obfuscation
| ditto2022, securitas2026, minos2025, nethide2018 | one more early in-switch obfuscation | Wang, Kim, Mittal, Rexford, *Programmable In-Network Obfuscation of Traffic* | **preprint — verify a peer-reviewed version (CoNEXT/HotNets?) before use** | early P4 traffic-obfuscation design | RW ¶h | D3 (`F8ZQJ5BH`) — **verify venue** |

## 9. P4 scheduling, shaping, recirculation, replication
| p4ccr2014, pifo2016, sppifo2020 | strong; optional survey pointer | Kfoury et al. P4 survey | preprint/journal — **survey; use only if a background pointer is needed (prompt discourages surveys over primaries)** | breadth of P4 dataplane applications | Impl background (optional) | D3 (`6VCIH7GH`) — likely reject (survey) |

## 10. ICS reconnaissance and moving-target defense
| defrec2020, raincoat2019, lintestbed2020, liufdia2009 | process-control attack/impact anchor | Cárdenas et al., *Attacks Against Process Control Systems: Risk Assessment, Detection, and Response* | ACM ASIACCS 2011 | consequence model for ICS control attacks | Intro ¶1 / RW ¶j | D3 (`VKSTMIIN`) |
| | grid-CPS security overview | Sridhar, Hahn, Govindarasu, *CPS Security for the Electric Power Grid* | Proc. IEEE (journal) | grid CPS threat/impact framing | Intro ¶1 (optional) | D3 (`QBVHFH2I`) |

## 11. DNP3 security, IDS, specification analysis, in-switch processing
| linbro2013, hulin2023 | thin on DNP3-specific attack/IDS taxonomy | East et al., *A Taxonomy of Attacks on the DNP3 Protocol* (IFIP CIP 2009); Fovino et al., *Modbus/DNP3 State-Based IDS* (IEEE CRITIS/ARES) | IFIP / IEEE | DNP3 attack surface + state-based detection (detect-after contrast) | RW ¶k | D3 (`QN2Q2EMP`,`4UXAFWUM`) — verify venue |
| | in-network industrial protocol security | hulin2023 | IEEE SmartGridComm | programmable-switch industrial-protocol security | RW ¶h/k | V |

## 12. Standards and authoritative incident reports
| dnp3std (IEEE 1815), ukraine2015 (E-ISAC/SANS) | ICS-security guidance | NIST SP 800-82 Rev.2/3, *Guide to Operational Technology (ICS) Security* | NIST (authoritative standard) | canonical ICS security guidance | Threat Model / Intro | F — verify current revision |

## Verification of the 17 author-supplied leads (prompt §9.2)
| lead key | resolves to | status |
|---|---|---|
| kohno2005remote | kohno2005 (IEEE TDSC 2005) | **V** |
| radhakrishnan2014gtid | gtid2015 (IEEE TDSC) | **V** (note: printed vol. year — verify 2014 vs 2015) |
| shu2006fingerprint | Shu & Lee (GLOBECOM) | D3 — add, verify tier |
| wright2009morphing | wright2009 (NDSS 2009) | **V** |
| cai2014csbuflo | CS-BuFLO (WPES 2014) | D3 — **workshop; prefer tamaraw2014 unless BuFLO lineage needed** |
| juarez2016wtfpad | juarez2016 (ESORICS 2016) | **V** |
| apthorpe2019stp | apthorpe2019 (PoPETs 2019) | **V** |
| sabzi2024netshaper | netshaper2024 (USENIX Sec 2024) | **V** |
| mehta2022pacer | pacer2022 (USENIX Sec 2022) | **V** |
| dyer2012peekaboo | dyer2012 (IEEE S&P 2012) | **V** |
| sirinam2018df | sirinam2018 (CCS 2018) | **V** |
| jeon2016passive | Jeon et al. | D3 — **verify venue/tier** |
| formby2016control | formby2016 (NDSS 2016) | **V** |
| east2009taxonomy | East et al. (IFIP CIP 2009) | D3 — add, verify |
| fovino2010modbus | Fovino et al. | D3 — verify venue |
| cardenas2011attacks | Cárdenas et al. (ASIACCS 2011) | D3 — add |
| hu2023dnp3p4 | hulin2023 (SmartGridComm 2023) | **V** |

## Net plan
- **Add after approval (verify each):** shu2006, feghhi2016, taranet2018, hornet2015, wang2008dlp,
  cardenas2011, east2009, fovino2010, jeon2016, sridhar2012, nist80082 → ~11 additions → **~43 total**.
- **Hold / tier-caution:** cs-buflo (workshop), Wang-Kim-Mittal-Rexford (preprint — need peer-reviewed
  venue), P4 survey (survey). Add only if a specific claim needs them and the venue clears.
- **Rejection rule:** no source added only to raise the count; every addition maps to one exact claim
  and one location above.
