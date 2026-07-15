# Sources Audit — Per-Claim Provenance

_Every load-bearing claim with source, evidence type, confidence, and caveat. Evidence: **[M]**
measured this session · **[S]** standard · **[V]** vendor/kernel-doc · **[P]** paper (abstract-level) ·
**[I]** inference · **[H]** hypothesis. Compiled from the nine agent reports + measured_evidence.md,
2026-07-13. Detailed records in `agent_reports/`._

## A. Measured facts
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| A1 | Response piggybacked on ACK, 9/9; req→ACK 0.239 ms, req→response 1.014 ms | analyze_ack.py on large_read.pcap, this session | [M] | High | — |
| A2 | Timing: SELECT/OPERATE 0.179/0.214 ms/CROB, R²=0.9985/0.9954 | sweep pcaps, this session | [M] | **Med** | **n=1 per N** — a 10-point line, not a replicated law; one device |
| A3 | **Size: 14.6 B/CROB, R²=0.9999, 37→256 B (N=1→16)** | sweep pcaps payload sizes, this session | [M] | **Med** | n=1 per N; one device; CROB-count ≠ DB-size |
| A4 | Read-plane size ∝ point count (~5.7 B/pt); large READ 12,204 B / 9 frags / 49 frames / 20 segs | baseline_segmentation.md, prior rig | [M] | High | — |
| A5 | Split: 2407 B → 141/71/36/18 chunks (bpc 1/2/4/8), master accepts, 0 retransmits/resets, no CRC recompute; total bytes unchanged | split_aggressiveness_sweep.md, prior rig | [M] | High | — |
| A6 | Invalid-index CROB padding → OUT_OF_RANGE, partial SELECT blocks OPERATE, not insertable | padding_candidate_results.md, prior rig | [M] | High | This OpenDNP3 build/host/config only |

## B. Standard / source-grounded (Agent A, OpenDNP3 fork + IEEE 1815)
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| B1 | Master reassembles ANY byte-offset split (stream-oriented link parser); CRC-block alignment is a defense/auditability choice, not a reassembly requirement | LinkLayerParser.cpp:88-138 | [S][I] | High | Do NOT claim master enforces CRC-block splitting |
| B2 | Master rejects byte MODIFICATION (bad block/header CRC → frame dropped) | LinkFrame.cpp:51-69 | [S] | High | — |
| B3 | No byte-preserving semantically-inert DNP3 padding at any layer (parser consumes to empty; 7-qualifier whitelist; no length field; no NUL/padding object) | APDUParser.cpp:60-112; QualifierCode.cpp:42-63; IEEE 1815 | [S][I] | High | Generalizes A6; one build |
| B4 | No link-layer ACK (unconfirmed link only) | fork, prior study | [V] | High | — |
| B5 | IEEE 1815 has no minimum-latency requirement; DNP3 fields reveal type not criticality | IEEE 1815-2012 (metadata) | [S] | High | Standard not read in full |

## C. Transport (Agent B)
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| C1 | Split survives the wire via PACING, not NODELAY; zero-delay split may re-merge (autocorking/GSO) | tcp_autocorking verified [M] + RFC/kernel | [M][S][I] | High | — |
| C2 | Mid-path SPAN is ground truth (sender under-counts via GSO, receiver over-merges via GRO) = attacker vantage | kernel offload docs | [S][I] | High | — |
| C3 | Binding RTO differs: timing-hold stresses Vision request-RTO; split stresses Hulk tail-RTO | RFC 6298 + inference | [S][I] | **Med** | Tail-RTO hazard inferred, not yet measured — needs one capture |
| C4 | Effective RTO must be measured (both hosts); ~200 ms is Linux floor, not universal | ip-sysctl, RFC 6298 | [S][V] | High | Not yet measured |
| C5 | Budget = three inequalities (initial-hold, per-gap, cumulative), not one sum; 141×10 ms ran clean | Agent H + [M] | [I] | High | — |

## D. Traffic analysis / attacker (Agent C, I)
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| D1 | Split relocates the size leak to packet count (I(chunks;N)≈I(size;N)); can re-leak magnitude | Agent C/I + [M] | [M][I] | High | — |
| D2 | Jitter averageable; class-independent normalization not (repeated-poll observer) | Crosby, Brumley-Boneh [P] + synthesis | [P][I] | High | Attacker-model-dependent |
| D3 | A lone shaped device is a beacon (shaped vs unshaped separable) | Wang CCS 2015 [P] + inference | [P][I] | High | Needs a fleet for anonymity set |
| D4 | SCADA near-closed-world → attacker stronger than in WF | Juarez CCS 2014 [P] | [P][I] | Med | — |

## E. Platform (Agents F, G)
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| E1 | Tofino S1 classify + S2 chunk pacing/gap-norm buildable in-phase (~4-5 stages, 2 queues, 3 SALUs) | Agent F + Open-Tofino | [V][I] | Med | Sketch, not built |
| E2 | Tofino can PACE split chunks but cannot CREATE the split (needs TCP-seq rewrite = out of phase) | Agent F | [I] | High | — |
| E3 | Tofino first-response absolute delay only via unbuilt recirc-hold; TM bounds rate not first-packet latency | Agent F + inference | [I] | Med | Unbuilt/unmeasured; costs are inference |
| E4 | BlueField Accurate Send Scheduling (500 ns–1 ms, ~4.19 s window) and FPGA calendar queue are native absolute-delay homes; DPU hardware fastpath avoids the ARM ceiling | NVIDIA docs [V]; Liu 2021 [P] | [V][P] | High | Not measured on our hardware |

## F. Software (Agent E)
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| F1 | Replay server generates bytes → schedules send() directly; split/pad can't be a per-packet kernel/NIC shaper; timing wheels/DPDK over-provisioned (cited to reject) | Agent E + split_server.py | [I] | High | — |
| F2 | Release queue must be per-flow FIFO deque, not a global min-heap (would reorder within a flow) | Agent E | [I] | High | — |
| F3 | Target host is Python 3.8.10 (no public clock_nanosleep; monotonic_ns ample); dependency-free (random.Random) | Agent E, verified this session | [M] | High | Corrects the prior study's 3.11 assumption |

## G. Padding (Agents A, D)
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| G1 | Only tunnel/envelope padding (cat 5) cleanly closes the size leak; FUTURE, needs endpoints | Agent D + [S] | [P][I] | High | — |
| G2 | Closing N=1→16 by constant-shape padding costs ~+219 B (~+590%) per SELECT/OPERATE | Agent D, [M]-anchored | [M][I] | High | — |
| G3 | Inert decoy points may stay distinguishable from real | Agent D | [H] | — | Unmeasured; future experiment |

## H. Evaluation / optimization (Agent I)
| # | Claim | Source | Type | Conf | Caveat |
|---|---|---|---|---|---|
| H1 | Report conditional I(T;N|size), not marginal | Agent I | [I] | High | Size channel open |
| H2 | Class-independence checkable as I(policy_choice; secret\|class)≈0 | Agent I | [I] | High | — |
| H3 | Multi-objective policy selection (NSGA-III/ε-constraint/pymoo); privacy-latency/-bandwidth/-hardware Pareto | Agent I + [P] (5 new cites) | [P][I] | High | 5 new methodology cites verified |
| H4 | Everything gated on Precondition #0: replicate the n=1/N sweeps before any defended run/optimization | Agent I | [I] | High | — |

## Citation integrity
- **115-entry bibliography** = 101 prior + **14 new verified this session** (wang2015seeing,
  juarez2014critical, nagle896congestion, linuxtcp7, linuxsegoffloads, lin2020panic, brunella2020hxdp,
  liu2021bluefield2perf, dpdk_mlx5, deb2002fast, deb2014evolutionary, zitzler1999multiobjective,
  blank2020pymoo, haimes1971bicriterion). Agent I confirmed the Haimes DOI (10.1109/TSMC.1971.4308298).
- **paper_matrix.csv** here = the 14 new works (21-col schema); the base is in
  `../ack_timing_normalization/paper_matrix.csv` (prior schema). **Bookkeeping reconciliation:** the base
  matrix lists **102 rows** but the base bibliography has **101 entries** — the one-row gap is NetWarden,
  which the base matrix lists as both its 2019 (HotCloud) and 2020 (USENIX) versions while the base
  bibliography keeps only the 2020 canonical entry. Standards (IEEE 1815, IEC 61850-5) are counted in
  both. So: base 102 matrix rows / 101 bib entries + 14 new works = 116 distinct matrix works / 115 bib
  entries.
- All verification abstract/metadata-level; no full texts read; no reference invented; A/D/E/F/H added
  no new works (facts trace to source/measured/existing corpus).

## The load-bearing caveats (read before writing the paper)
1. Both flagship leaks are **n=1 per N** — replicate first.
2. **Size ≠ database-size** (CROB-count vs read-plane point-count; timing↔DB-size unmeasured).
3. **No current-phase padding** — size is a residual; do not claim it solved.
4. **Split hides no total bytes** and can re-leak magnitude / beacon.
5. **Effective RTO unmeasured** (Vision for holds, Hulk for splits).
6. **Tofino recirc-hold unbuilt**; Tofino cannot create the split.
7. Normalization-beats-jitter is **attacker-model-dependent**; report conditional MI.
8. One device ⇒ configuration/complexity claim only; classification needs ≥2 stacks.
