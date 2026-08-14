# Claim–evidence ledger — Defense 4 paper rewrite

Every quantitative statement and security claim in the rewritten sections must appear here and use
the **allowed wording**, never the **prohibited overclaim**. Source of truth: the frozen evidence at
`defense4/size/native_parity/evidence/E_FINAL/` (commit `5a0fb73`), the P4 program
`defense4_rrc_bor_unified12.p4` (source sha256 `7ce30494…`, silicon binary `33fa3a77`), and
`defense4/CLAIMS.md`. Status codes: **M** = measured on hardware, **V** = verified by
offline model / compiler, **D** = design intent (not directly observed).

Notation (fixed everywhere): request/OPERATE arrives at `T0`; master sees ACK at `T0+A`, response/echo
at `T0+R`; **CLRT = R − A**. Final policy `A = 20 ms`, `R = 24 ms` ⇒ CLRT = 4 ms.

| claim_id | proposed claim | section | evidence source | exact location | status | citation | allowed wording | prohibited overclaim |
|---|---|---|---|---|---|---|---|---|
| CL-1 | Native CLRT: READ median 1.272 ms (mean 1.880, std 1.354, n=999); SELECT median 2.107 ms (mean 3.115, std 2.530, n=488) | Intro/Eval | `verdict_stats.json` | native READ/SELECT blocks | M | Formby [fp] | "the hardware captures show native CLRT of …" | — |
| CL-2 | Defended CLRT: READ 4.001 ms (std 0.0222, n=599); SELECT 4.001 ms (std 0.0212, n=499); both bootstrap-95 median CI [4.000,4.002] | Intro/Eval | `verdict_stats.json` | defended blocks | M | — | "defended CLRT is normalized to a fixed ≈4.001 ms" | not "eliminates timing" |
| CL-3 | Added master-facing latency: READ +2.73 ms, SELECT +1.89 ms | Impl/Eval | `E_FINAL/README.md` | latency line | M | — | "adds a bounded latency of …" | — |
| CL-4 | A/R master-facing medians ≈21/25 ms include ~1 ms path/capture offset over configured 20/24 ms; internal deadline vs switch-T0 not separately instrumented | Threat/Impl | `VERDICT.json` | `bor_operate_timing.note` | M+D | — | "master-facing A/R ≈21/25 ms include a documented ~1 ms path/capture offset" | do not present A/R as the exact internal deadline |
| CL-5 | Native response is one 49-byte segment `[49]`; defended eligible responses are `[28,21]` | Intro/Impl/Eval | `size_verdict.csv` | segment_vector col | M | — | "the fixed segment vector `[49]`→`[28,21]`" | not "size hiding" |
| CL-6 | Defended eligible responses total **1,280** (READ 600 + SELECT 500 + SBO-SELECT 90 + SBO-OPERATE 90), all `[28,21]` | Eval | `size_verdict.csv`,`VERDICT.json` | 1380 rows; 100 native + 1280 defended | M | — | "1,280 defended eligible responses, all `[28,21]`" | do not use superseded arrival-order counts |
| CL-7 | Reconstruction is sequence-contiguous, DNP3-block-CRC-valid, IP/TCP-checksum-valid (1280/1280); **0** unsplit-49-byte escapes | Impl/Eval | `size_reconstruct.py`,`VERDICT.json` | `all_dnp3_block_crc_valid`,`source_copy_escapes_49B:0` | M | — | "sequence-contiguous, block-CRC- and checksum-valid 49-byte reconstruction; zero eligible escapes" | not "byte-identical to a source frame" (no source oracle) |
| CL-8 | Byte-identity to a source frame is NOT established (no paired source-side oracle captured) | Threat/Impl | `VERDICT.json` | byte-identity note | — | — | "the evidence does not establish byte identity to a source frame" | never "byte-identical" |
| CL-9 | Total reassembled payload stays 49 bytes; the defense normalizes the observed segment vector, not total length | Intro/Threat/Impl | derivation from CL-5 | 28+21=49 | M | — | "normalizes the eligible-class segment vector; the reassembled payload remains 49 bytes" | not "hides the response length" |
| CL-10 | Byte 28 is a selected existing DNP3 CRC-block boundary; TCP may segment at any offset, so this is a deterministic-carving choice, not a TCP requirement | Impl | DNP3 frame structure | link hdr(10)+blk0(18)+blk1(18)+final(3)=49 | D | DNP3 [dnp3] | "byte 28 is a chosen block-aligned carve point that simplifies deterministic carving" | not "the only safe cut" |
| CL-11 | BOR: echo−ACK ≈4.00 ms, master-visible, invariant across J∈{2,6,12} ms (per-J med 4.001/4.002/4.003, std 0.0258/0.0256/0.0276; pooled n=90 med 4.002, std 0.0264) | Threat/Impl/Eval | `sbo_j{2,6,12}.csv` | A=T_ack−T0, R=T_echo−T0 | M | — | "the master-visible echo−ACK gap stays ≈4.00 ms across the evaluated J values" | not "J is unrecoverable in general" |
| CL-12 | BOR intended release at `T0+J`, the epoch/hold/release/retire state machine | Impl | `bor_unified_lifecycle.py`,`defense4_rrc_bor_unified12.p4` | 19/19 invariants, 11/11 mutants | V | — | "the offline model verifies the release-at-`T0+J` state machine" | not measured on the relay-facing link |
| CL-13 | Relay-facing `T0+J` timestamp and relay-facing delivery multiplicity were NOT observed (dp68 is internal, not a tap) | Threat/Impl | `VERDICT.json`,`CLAIM_MATRIX.md` | limitations block | — | — | "the relay-facing `T0+J` and delivery multiplicity are not directly observed" | never "exactly once" on hardware |
| CL-14 | The master issued one OPERATE per transaction (observed); copies reaching the relay unknown | Threat/Eval | `h3_operate` results | master-facing pcap | M(partial) | — | "the master issued one OPERATE per transaction" | not "exactly-once relay delivery" |
| CL-15 | Mutual information MI(class;CLRT), common bins linspace(0,12,61): native 0.424 bits (perm-null 95% CI [0.0155,0.0330]) → defended 0.0018 bits (within null [1.1e-6,0.0032]) | Eval | `verdict_stats.json` | MI block | M | — | "MI drops from 0.424 bits to 0.0018 bits, within the permutation-null band" | — |
| CL-16 | Jensen–Shannon **distance** (=√divergence, scipy): native READ-vs-SELECT 0.676 → defended 0.043; native-vs-defended READ 0.997, SELECT 0.914 (distribution replacement) | Eval | `verdict_stats.json`,`e4e5_analysis.py` | JS block | M | — | "the JS distance (√divergence) shows the classes collapse together and the distribution is replaced" | do not call it "divergence" |
| CL-17 | READ-vs-SELECT classifier (LogReg on CLRT), transaction-disjoint 60/40 split (NOT session-disjoint): balanced accuracy 0.592 (CI [0.558,0.626]) → 0.500 (chance) | Eval | `verdict_stats.json` | classifier block | M | — | "a READ-vs-SELECT transaction-class classifier drops to chance (0.500)" | not a device-identity classifier; not "prevents fingerprinting" |
| CL-18 | Single device (one SEL-751) → the native CLRT + segment-shape signature is replaced by policy | Intro/Threat/Eval | `VERDICT.json` | single_device note | M | Formby [fp] | "single-device signature replacement for the evaluated features" | not "multi-device indistinguishability/anonymity" |
| CL-19 | TCP timestamps absent in the final defended captures (verified packet-level; required for the timing argument) | Threat/Impl | `h3_operate_j6_single_result.md` | `tcp_timestamps=0`, TS-option gate | M | — | "TCP timestamps are absent in the evaluated captures, as the timing argument requires" | — |
| CL-20 | Two independent scheduling domains: dp8 (RRC ladder qid7>qid6>qid5>qid4) and dp10 (BOR qid3>qid2); a shared strict-priority ladder starved the BOR queues after OPERATE, shifting release toward A/R | Impl | `RRC_BOR_PRIMITIVE.md`,`RRC_BOR_UNIFIED12_FIXED.md` | §"two domains", Blocker analysis | D+V | — | "a shared ladder starved the BOR queues; dp8/dp10 give RRC and BOR independent schedulers" | not a measured starvation latency unless cited |
| CL-21 | One P4 program, one ingress pipe, ≤12 MAU stages; decision-table flatten → one `meta.outcome` → one terminal `tbl_commit` | Impl | bf-p4c place logs,`RRC_BOR_UNIFIED12_RESULT.md` | `switch_compile_9132/` | V | — | "the program fits one ingress pipe in ≤12 MAU stages via a single compact outcome and one commit table" | — |
| CL-22 | Same physical master, SEL-751, links, Tofino, capture clock, and loaded binary for native and defended; only a runtime mode change (OFF vs D4) | Threat/Impl/Eval | `E0_testbed_preservation.md`,`VERDICT.json` | invariance table | M | — | "native and defended trials share the same testbed and binary, toggled at runtime" | — |
| CL-23 | Safety: guarded driver permitted only isolated CROB points `{1,3}`; breaker-close index 6 refused; all 32 relay outputs remained OPEN throughout | Threat/Impl/Eval | `readbacks/relay_outputs_final.json`,`relay_operate_guarded.py` | `all_open:true`, guard test | M | — | "only points `{1,3}` were permitted, index 6 refused, all 32 outputs stayed OPEN" | do not imply a breaker operation was attempted |
| CL-24 | RRC = Release-Replicate-Carve: strict-priority blocker reservoirs hold ACK+response; release at absolute offsets from `T0`; PRE makes two master-facing copies; egress carves 28-prefix + 21-suffix | Impl | `defense4_rrc_bor_unified12.p4`,`defense4_rrc_bor_unified12_setup.py` | commit actions, PRE `RRC_MGID`=0x2849 | V | — | "PRE replication creates the two master-facing copies; egress carving emits the 28+21 segments" | the physical relay creates the response — a clone/mirror does NOT create the response or echo |
| CL-25 | The reproduction is deterministic; MANIFEST covers 63 files, all SHA-256 verified | Eval | `MANIFEST.sha256`,`reproduce.sh` | manifest | V | — | "the analysis regenerates deterministically; the 63-file manifest verifies" | — |

## Prohibited words globally (unless a ledger row explicitly approves the exact wording)
`proves`, `guarantees`, `eliminates`, `prevents fingerprinting`, `exactly once`, `byte-identical`,
`indistinguishable`, `general`, `novel`, `groundbreaking`, `robust`, `comprehensive`,
`state-of-the-art`, `seamless`.

## Section coverage check (every rewritten section's claims must be in this ledger)
- Introduction: CL-1,2,5,9,13,17,18,21,23 (+ contributions map to CL-21,24,20,22,23).
- Related Work: comparative only (citations, not our numbers).
- Threat Model: CL-4,8,9,13,14,18,19,22,23.
- Implementation: CL-3,7,10,12,20,21,24 (+ failure behavior from CL-13,20).
