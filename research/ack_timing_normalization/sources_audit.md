# Sources Audit — Per-Claim Provenance

_For every important factual claim in the study: its source, the exact supporting locus where
available, whether it is direct evidence or inference, evidence confidence, and any contradictory
evidence. Evidence types: **[M]** measured this session · **[S]** standard-defined · **[P]**
paper-reported (abstract/metadata-level unless noted) · **[V]** vendor/kernel-documented ·
**[I]** our engineering inference · **[H]** untested hypothesis. Compiled by the synthesizing lead
from the six agent reports, 2026-07-13._

## A. The measured leak (the empirical core)

| # | Claim | Source / locus | Type | Confidence | Contradictory / caveat |
|---|---|---|---|---|---|
| A1 | Response is piggybacked on the TCP ACK, 9/9 requests | `analyze_ack.py` on `large_read.pcap`, re-run this session | [M] | High | — |
| A2 | mean req→ACK 0.239 ms, req→response 1.014 ms (baseline READ) | same run; matches prior `tcp_ack_fingerprinting.md` | [M] | High | — |
| A3 | SELECT-resp = 0.179 ms/CROB, R²=0.9985; OPERATE-resp = 0.214 ms/CROB, R²=0.9954 | `analyze_ack.py` on `captures/sweep/multicrob_n{1..16}.pcapng`, this session; regression in `measured_timing_data.md` | [M] | **Med** | **n = 1 sample per N-level** → R² describes a 10-point line, not a replicated law; no within-N variance / CI, so conditional I(T;N) not yet computable (replication E1 pending). Single device/rig — NOT a cross-device / device-identity claim |
| A4 | OPERATE-resp 1.62→4.90 ms over N=1→16 (3×) | same sweep | [M] | High | — |
| A5 | Processing-time↔complexity leak generalizes to other ICS devices | Formby NDSS 2016 [P]; TIDF NPC 2025 [P] | [P] | Med | Their result, not ours; TIDF metadata-only |
| A6 | Processing time ∝ **database size** specifically | — | [H] | — | NOT measured; separate experiment (evaluation_plan T2). Do not claim from CROB sweep |

## B. Transport / TCP constraints (Agent B)

| # | Claim | Source / locus | Type | Confidence | Contradictory / caveat |
|---|---|---|---|---|---|
| B1 | Binding constraint is master effective TCP RTO, not DNP3 timers | RFC 6298; Linux source; synthesis | [S]/[I] | High | — |
| B2 | Linux `TCP_RTO_MIN` = HZ/5 ≈ 200 ms | `include/net/tcp.h` (kernel source, verified) | [V] | High | 200 ms is a Linux default/floor, NOT universal |
| B3 | Effective RTO must be measured on Vision (`tcp_retries2`, `ip route rto_min`, observed retransmit) | RFC 6298 backoff; `ip-route(8)`; ip-sysctl docs | [S]/[V] | High | Not yet measured — placeholder in all budgets |
| B4 | Holding an ACK-bearing segment → spurious retransmit (loudest tell) | RFC 6298/9293; synthesis | [S]/[I] | High | — |
| B5 | Fast-retransmit dup-ACK threshold = 3 (reordering risk) | RFC 5681 | [S] | High | Only relevant for multi-segment responses |

## C. DNP3 / SCADA / safety (Agent C)

| # | Claim | Source / locus | Type | Confidence | Contradictory / caveat |
|---|---|---|---|---|---|
| C1 | No link-layer ACK on this wire (unconfirmed only) | OpenDNP3 fork `LinkContext.cpp:158`; `LinkFrame::FormatConfirmedUserData` zero callers | [V] | High | Specific to this stack/config |
| C2 | Outstation select timeout 10 s; sol-confirm/app-response 5 s; keepalive 60 s | fork `OutstationParams.h:41,44`; `MasterParams.h:41`; `LinkConfig.h:64` | [V] | High | Implementation defaults of standard timers |
| C3 | IEEE 1815 imposes no minimum-latency requirement | IEEE 1815-2012 [S] (metadata-level; not read in full) | [S] | High | Standard not read in full this session |
| C4 | Shape read plane fully; SELECT/OPERATE responses to fixed N-indep deadline under allowlist; bypass CONFIRM/unsolicited/critical controls | Agent C §5 synthesis from C1–C3 | [I] | High | Design recommendation, not a proven result |
| C5 | DNP3 fields encode operation type, not physical criticality | IEEE 1815 field semantics [S] + inference | [S]/[I] | High | — |
| C6 | Protection tripping (~3 ms, GOOSE/hardwired) is not DNP3-carried | IEC 61850-5 [S] via secondary literature | [P] | Med | IEC 61850-5 NOT read; 3 ms figure from secondary source |
| C7 | A Zeek/Bro `dnp3` correctness IDS is blind to timing-only manipulation | Lin et al. CSIIRW 2013 [P] + inference | [P]/[I] | Med | Abstract-level |
| C8 | Do NOT assert SEL-751A inert-control capability | — (no vendor doc consulted) | guardrail | — | Must not claim without vendor docs |

## D. Software implementation (Agent D)

| # | Claim | Source / locus | Type | Confidence | Contradictory / caveat |
|---|---|---|---|---|---|
| D1 | Replay server generates bytes → schedules `send()` directly; no live packet → tc/eBPF/XDP/DPDK/proxy unnecessary | `split_server.py` (read) + synthesis | [I] | High | True for the replay-endpoint deliverable; an in-path proxy would differ |
| D2 | CPython `time.monotonic_ns` + one `time.sleep` (clock_nanosleep since 3.11) meets sub-ms precision | python.org docs; man7 `clock_nanosleep(2)` | [V] | High | GC/GIL negligible at concurrency <1 |
| D3 | Timing wheels / calendar queues / DPDK are over-engineered for DNP3 rate | Carousel [P], Eiffel [P], Varghese 1997 [P], Brown 1988 [P] + rate math | [P]/[I] | High | Cited to reject |
| D4 | CPU ≪0.1% of a core; memory KB resident | order-of-magnitude inference from rate | [I] | Med | Estimate, not benchmarked |

## E. Programmable hardware (Agent E)

| # | Claim | Source / locus | Type | Confidence | Contradictory / caveat |
|---|---|---|---|---|---|
| E1 | Pacing / inter-packet-gap normalization native on Tofino (TM) | Open-Tofino; ditto [P]; NetWarden [P]; PIFO/SP-PIFO [P] | [V]/[P] | High | Bounds rate, not first-packet latency |
| E2 | TM shaping does NOT bound first-packet latency (lone frame leaves empty shaped queue immediately) | token-bucket behavior; Intel withholds detailed TM model | [I] | Med | Rests on standard token-bucket, not an Intel TM latency spec |
| E3 | First-packet absolute delay native on BlueField (Accurate Send Scheduling / PTP tx time) and FPGA (calendar queue) | NVIDIA Accurate Send Scheduling docs [V]; Corundum/SUME [P] | [V]/[P] | High | — |
| E4 | Tofino absolute delay only via recirculation + timestamp-deadline loop | Open-Tofino + NetVRM/TEA/Kannan2019 [P] + inference | [I] | Med | **Unbuilt/unmeasured on our chip**; hits bf-p4c gateway/range limits; costs are inference |
| E5 | Recirc-hold affordable for DNP3 (single-digit kbps, <1 held frame, <1% pipe) | prior brief §4.3 rate math | [I] | Med | Design argument, not measured |
| E6 | NetWarden is the closest published in-network IPD-normalization precedent | NetWarden USENIX 2020 [P] | [P] | High | Abstract-level |

## F. Evaluation methodology (Agent F)

| # | Claim | Source / locus | Type | Confidence | Contradictory / caveat |
|---|---|---|---|---|---|
| F1 | Additive i.i.d. jitter is averageable; normalization (class-independent) is not | Crosby TISSEC 2009 [P]; Brumley–Boneh 2005 [P]; Giles–Hajek 2002 [P]; synthesis | [P]/[I] | High | Claim is attacker-model-dependent (repeated-poll observer) |
| F2 | Must report **I(T;N \| size)** (conditional), not marginal I(T;N) — size channel open in byte-preserving phase | Agent F analysis | [I] | High | Marginal I(T;N) would inflate the closure claim |
| F3 | Single device supports info-theoretic claim; device-classification needs ≥2 stacks | claim ladder (Agent F) | [I] | High | — |
| F4 | KSG MI estimator + bootstrap CI; McNemar/DeLong; BH-FDR; GroupKFold-by-session | Kraskov 2004; McNemar 1947; DeLong 1988; Benjamini–Hochberg 1995; Efron 1993 [P] | [P] | High | Standard methodology |
| F5 | RAINCOAT = Hui Lin, IEEE TSG 2019, DOI 10.1109/TSG.2018.2870362 (Dr. Lin first author) | DBLP + IEEE Xplore, verified by A and F | [P] | High | — |

## G. Citation-integrity ledger (whole study)

- **Verification level:** all ~101 matrix papers verified at title/authors/year/venue/DOI-or-URL/
  abstract level. **No full texts were read.** Paper-reported results (attack accuracies, overhead
  figures) are from abstracts/landing pages and are labeled [P].
- **Preprints flagged (not peer-reviewed):** Jeon et al. 2016 (arXiv 1608.07679); Ahmed et al.
  "Time Constant" 2024 (arXiv 2409.16536).
- **DOIs unverified for some venues** (USENIX/NDSS papers often lack DOIs): stable URLs recorded
  instead (`paper_matrix.csv` `url` column); `bibliography.bib` notes where a DOI was not found.
- **Standards not read in full:** IEEE 1815-2012, IEC 61850-5:2013 — cited at metadata level;
  frozen facts (function-code hex, SBO semantics) are safe from standard knowledge, but the IEC
  61850-5 ~3 ms protection figure is from secondary literature and marked [P]/Med.
- **NetWarden** appears as a 2019 **HotCloud '19** workshop paper (Xing, Morrison, Chen) and a
  2020 USENIX Security full paper (Xing, Kang, Chen); the matrix keeps the 2020 canonical entry.
  (Corrects an earlier "HotNets" mislabel.)
- **No reference was invented.** Any field the agents could not verify is `NA` in the matrix.

## H. The load-bearing caveats (read before writing the paper)

1. The measured leak is **CROB-count**, not database-size — do not conflate (A6).
2. The **effective RTO on Vision is not yet measured** — every budget is provisional (B3).
3. The **Tofino recirc-hold is unbuilt and unmeasured** — future work, not a result (E4).
4. Report **conditional** I(T;N|size), not marginal — the size channel stays open (F2).
5. **One device** ⇒ information-theoretic claim only; classification needs ≥2 stacks (F3, A3).
6. Normalization-beats-jitter is **attacker-model-dependent** (repeated-poll observer) (F1).
7. The leak sweep is **n = 1 per N-level** — replicate (E1, ≥30/N, bootstrap CI on β) before any
   "near-deterministic / R²>0.99 law" wording (A3, M2).
8. **No defense has been run** — the primitive is *designed*, not "software-validated"; the RTO
   budget is *provisional*, not "measured"; the contribution is *designed to remove* the leak, not
   "destroys" it, until the defended runs (E2/E3) exist.
9. Say **device-configuration / request-complexity** leak, not "device-identity" — identity
   (telling devices apart) is the future ≥2-stack claim.
10. A **single shaped device is separable from unshaped traffic** (a beacon) — the anonymity-set
    argument needs a fleet; add a detectability-of-the-normalizer experiment (S4).
