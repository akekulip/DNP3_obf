# Native distributions and a common size pattern for READ and SELECT/OPERATE — Phase B analysis

Scope: read-only, offline analysis. No switch contacted, no compiler invoked, no traffic generated.
Companion to `INTEGRATION_CONTRACT.md` (decision record) and `DNP3_Timing_Size_Integration_Prompt.md`
(task source). This document is the Phase B deliverable: recovered extractor, repaired-and-verified
distributions, and a scored, ranked — but not final — recommendation for the common size pattern. A
parallel hardware-feasibility assessment is running independently; final selection is a human
decision that synthesizes both.

**Byte convention, repeated because it is the single most important thing to get right**: this
document uses two units that must never be compared directly. The historical size-pattern-builder
(`single128`, `two_state_round8`, `cover_larger_corpus`, `ack_data_split`) and the base/long/multicrob
fingerprint corpus are in **Ethernet-frame bytes, no FCS, 60-byte minimum applied**. The RRC hardware
evidence (`49`, `28`, `21`) and the current Case 4 software profile (`35`, `55`, `37`, `57`, `29`) are
in **TCP-payload bytes** (includes DNP3 framing and CRC). Every table below states its unit.

## 0. What was recovered and how it was verified

All files in this directory were recovered read-only from history and placed under this new
directory; no tracked file was modified.

| Recovered from | Into | Verification |
|---|---|---|
| `2ce9910a1cae97d8a32e623b55edbbbc53ae1072:research/tofino_dcrn_feasibility/p4/queue_microbench/size_pattern_builder/{SIZE_PATTERN_BUILDER_REPORT.md,extract_inventory.py,generate_candidates.py,evaluate_candidates.py,test_pattern_builder.py,inventory/inventory_summary.json,evaluation*.json,queue_pattern_candidates/**}` | this directory, same relative layout | `test_pattern_builder.py`: **16/16 pass**, unmodified, this session |
| `99f03fa2c9631e5b03c2beadb385d52b4f1f35f7:"Traffic Trace"/{SEL751,AB1400,ION7550}{,L}.pcap` (6 files; deleted from the tree at the later allowlist-reduction commit `48410e1d`) | scratch (`/tmp/.../pcaps_base/`, not committed) | re-ran `extract_inventory.py --scope base/long`: **byte-for-byte identical** role/size histograms and ack-mode tallies to `inventory_summary.json`'s published `n=4804` (base) / provenance numbers |
| `99f03fa2c9631e5b03c2beadb385d52b4f1f35f7:dnp3_multicrob_harness/captures/*.pcap` (5 files) | scratch (`/tmp/.../pcaps_multicrob/`) | re-ran `extract_inventory.py --scope multicrob`: **byte-for-byte identical** to the published `n=98` |
| `9ffa9102d7a60095ed286f5c5dde2561a679b3d9:defense4/size/native_parity/{RRC_DESIGN.md,RRC_HW_RESULTS.md,READSBO_NORMALIZATION_RESULT.md}` | this directory | read in full, cited below |
| `9ffa9102d7a60095ed286f5c5dde2561a679b3d9:defense4/size/native_parity/evidence/{hw_rrc_readsbo_20260812T212234Z,hw_rrc_joint_20260812T223342Z}/captures/{read,sbo}.pcap` (4 files) | scratch (`/tmp/.../pcaps_rrc/`) | parsed directly with scapy this session (§2 below); matches the prose in `READSBO_NORMALIZATION_RESULT.md` exactly |

The recovered PCAPs were **not** left in the tracked tree (task instruction). `build_rrc_pool.py` in
this directory re-derives a small, labelled TCP-payload-byte JSON pool (`inventory_v2/rrc_pool.json`,
244 response-segment records / 124 transactions) directly from the four RRC PCAPs so the scoring in
§4 is reproducible from that JSON without needing the PCAPs again; regenerate with:

```sh
$RESEARCH_PYTHON build_rrc_pool.py <readsbo/read.pcap> <readsbo/sbo.pcap> <joint/read.pcap> <joint/sbo.pcap> inventory_v2/rrc_pool.json
```

The base/long/multicrob PCAPs are **not** re-vendored here (storage; they are fully reproducible from
the commit hashes above). `extract_inventory_v2.py` was run against them and its per-packet
`{base,long,multicrob}_{raw,analysis}.json`/`.csv` outputs were verified (byte-for-byte match against
`inventory_summary.json`) but are **not committed**: `base`+`long` raw+analysis together were ~103MB, and
this repository already paid once this session for an oversized-file cleanup, so a reproducible
intermediate should not repeat it. Regenerate them with the command in "Reproducibility" below if needed.
Only `multicrob_{raw,analysis}.{json,csv}` (136K/28K) and `rrc_pool.json` (136K) are small enough to commit
and are kept here.

## 1. Repaired-extractor corpus-deficiency findings

`SIZE_PATTERN_BUILDER_REPORT.md` and the integration prompt (§2.3) name three unrepaired gaps in
`extract_inventory.py`'s per-packet `parse_dnp3()`: it does not reconstruct TCP-coalesced DNP3 frames,
frames split across TCP segments, or general multi-fragment (FIR/FIN) responses. `extract_inventory_v2.py`
in this directory fixes all three by walking a per-(flow, direction) **byte stream** instead of a
per-packet payload, using the DNP3 length field to find frame boundaries (never a second substring
search, which is itself unsound — see below) and the real DNP3 transport header (offset 10: FIN/FIR/SEQ)
to distinguish an application-fragment-opening segment from a continuation.

**Result on the current, decontaminated base/long/multicrob corpus: none of the three gaps is actually
triggered.** This was verified, not assumed:

1. **TCP-coalesced frames.** A naive "does this payload contain the substring `0x0564` twice" scan over
   `Traffic Trace/*.pcap` found 53 apparent hits, all in `AB1400L.pcap`. Decoding one example
   (`05641ac40a0001008a1cd3c3050c01280100020003016400000018056400000000005b`, 35 bytes) with the DNP3
   **length field** shows it is a single 35-byte frame whose own object data happens to contain the byte
   pair `05 64` — a false positive of the substring approach, not a second frame. A length-aware walk of
   every payload-bearing packet in base, long, and multicrob finds **zero** genuine multi-frame segments.
   The original report's "~0.25% of payload packets" estimate for this gap could not be reproduced on
   this corpus and most likely came from the same substring false-positive; `extract_inventory_v2.py`'s
   walker is immune to it by construction (it never searches past an already-length-validated frame).
2. **Frame split across a TCP segment boundary.** The only non-DNP3 "unknown"-with-payload records in
   base/long (4 total: 2× in `AB1400.pcap`, 2× in `ION7550.pcap`) are **zero-filled, 2–6 byte payloads
   attached to RST/RST-ACK segments at connection teardown** (e.g. `multi_crob`-style flow close), not a
   DNP3 frame whose tail landed in a later segment. Inspected directly: `AB1400.pcap` flow
   `10.0.0.3:53459` ends `...len=6 flags=A 000000000000` then `...len=6 flags=RA 000000000000`;
   `ION7550.pcap` flow `10.0.0.3:57143` ends the same way. `extract_inventory_v2.py`'s stream buffer
   confirms zero records anywhere in base/long/multicrob needed reassembly across more than one TCP
   segment (`reassembled_from_segments > 1` count = 0 in every scope). v1.1's own characterization
   ("labelled unknown (correct, not misparsed)") was right; this was a documented absence of handling,
   not an active corruption.
3. **Multi-fragment (FIR/FIN) responses.** Every parsed link frame across base, long, and multicrob has
   transport-header FIR=1 (continuation-frame count = 0 everywhere). The report's own statement — "all
   base responses are single-fragment (FIR=FIN=1)" — is confirmed directly from the transport header,
   not inferred from response size alone.

**Practical consequence:** `extract_inventory_v2.py` reproduces `extract_inventory.py`'s output
byte-for-byte on this corpus (verified: identical `(direction, role, tcp_payload_bytes)` histograms and
identical `ack_mode_observed` tallies for all three scopes), while now being structurally correct for a
future higher-rate or physical-SEL-751 capture where any of the three cases could occur. The repair is
real engineering (a different code path, instrumented with `reassembled_from_segments` and
`is_continuation_segment` counters so the next capture can prove or disprove the gaps empirically rather
than by inspection), but it changes **zero** records in the evidence used below. Treat the base/long
distributions in §2 as validated against all three named gaps, not merely re-stated from the old report.

## 2. Five role-specific native distributions

### 2.1 Pure ACKs — base corpus (Ethernet-frame bytes, no FCS, 60B min)

| size (B) | count | note |
|---:|---:|---|
| 60 | 1200 | min-frame-padded TCP ACK (0 payload) |
| 66 | 600 | TCP ACK with 12B timestamp option |

n=1800 ACK records, 3 devices, chronologically ordered, base scope.

### 2.2 READ requests and responses

**Base/long corpus (Ethernet-frame bytes)** — SEL751/AB1400/ION7550, 697 READ-opened transactions:

| role | size (B) | count |
|---|---:|---:|
| READ_REQUEST | 76 | 598 |
| READ_REQUEST | 88 | 99 |
| RESPONSE (SEL751) | 103, 120 | 200, 99 |
| RESPONSE (AB1400) | 91, 108 | 200, 199 |
| RESPONSE (ION7550) | 91, 115 | 400, 399 |

Mean aggregate transaction bytes (all packets in a READ-opened transaction, request+ACKs+response):
**261.6 B**, mean packet count **3.14** (base scope).

**RRC hardware evidence (TCP-payload bytes), physical SEL-751, `9ffa9102`** — directly re-measured
from the recovered PCAPs this session, 30 transactions × 2 trials (`hw_rrc_readsbo`, `hw_rrc_joint`) =
60 READ transactions:

| direction | role | size (B) | count |
|---|---|---:|---:|
| master→outstation | READ_REQUEST (23-point G10V2) | 20 | 60 |
| outstation→master | RESPONSE prefix (carved) | 28 | 60 |
| outstation→master | RESPONSE suffix (carved, no DNP3 header) | 21 | 60 |

Reassembled: 60 × exactly 49 B. Ordered segment vector **[28, 21]** (hardware-proven, R1–R4, PASS).
**Recorded arrival order is `[21,28]`; TCP sequence order is `[28,21]`** — these are different claims
(integration prompt §2.5); this document reports sequence order (the carve design's own labelling) and
flags arrival order as a separate, still-open question about where the reversal occurs (capture,
PRE scheduling, or elsewhere).

### 2.3 SELECT requests and their responses

**Multicrob corpus (TCP-payload bytes), real captures, `2ce9910a`** — two distinct encodings observed:

| encoding | request (B) | response (B) | count | capture |
|---|---:|---:|---:|---|
| 1-CROB | 35 | 37 | 2 | `multi_crob_test_a.pcap`, `multi_crob_test_b.pcap` |
| 2-CROB (double header) | 50 | 52 | 3 | `multi_crob_sbo.pcap`, `multi_crob_sbo_test_c.pcap`, `multi_crob_negative_test_d.pcap` |

**RRC hardware evidence (TCP-payload bytes), physical SEL-751, `9ffa9102`**, directly re-measured —
2-CROB SELECT (real point 0 + decoy point 1, master-generated, non-actuating):

| direction | role | size (B) | count |
|---|---|---:|---:|
| master→outstation | SELECT | 45 | 60 |
| outstation→master | RESPONSE prefix (carved) | 28 | 60 |
| outstation→master | RESPONSE suffix (carved) | 21 | 60 |

Reassembled: 60 × exactly 49 B, **identical segment histogram to READ** (R5/R6, PASS, physically
measured, non-actuating — both points read OPEN before and after). This document's first pass inferred
the object-header structure behind the 45B request from byte deltas alone; the parallel
hardware-feasibility analysis (`HARDWARE_FEASIBILITY_ANALYSIS.md` §1.2, decoding `RRC_REQUEST_PROFILES.txt`
directly) establishes the precise construction and **supersedes that inference here**: the 45B request
is `0C 01 17 02` (group 12, var 1, qualifier `0x17` = 1-byte index prefix, count=2) followed by two
`(1-byte index + 11-byte CROB)` pairs — 4B header + 2×12B objects = 28B of object data, versus the
multicrob 50B encoding's two separate single-count object headers (2×(4+11)=30B). The 5B delta (30−28 ≈
the two extra per-object header repeats minus the one shared qualifier byte saved) matches the observed
45-vs-50 and 49-vs-52 gaps; see the cited analysis for the exact byte accounting.

**Current Case 4 software profile (TCP-payload bytes, software/codec evidence, not a wire capture)**,
`framework/size/{case4_padding.py,CASE4_SOFTWARE_EVIDENCE.md}` — single-CROB native command, separate
switch-inserted trailing G12V1 decoy header:

| state | request (B) | response (B) |
|---|---:|---:|
| native (1-CROB) | 35 | 37 |
| padded (+separate decoy header) | 55 | 57 → carved [28, 29] |

The native 35/37 values are now **independently confirmed** against the multicrob 1-CROB real capture
(§ above, exact match) — this is a genuine cross-check this pass performed, not merely a restatement of
the codec doc's own numbers.

### 2.4 OPERATE requests and their responses

**Multicrob corpus (TCP-payload bytes), real captures** — OPERATE is byte-identical to SELECT at every
cardinality actually captured:

| encoding | request (B) | response (B) | count | capture |
|---|---:|---:|---:|---:|
| 1-CROB | 35 | 37 | 2 | `multi_crob_test_a.pcap`, `multi_crob_test_b.pcap` |
| 2-CROB (double header) | 50 | 52 | 2 | `multi_crob_sbo.pcap`, `multi_crob_sbo_test_c.pcap` |

**Physical hardware: not measured.** `RRC_HW_RESULTS.md`: "Physical OPERATE: NOT RUN (gated on explicit
authorization)." No PCAP exists for an OPERATE transaction through the RRC carve at any cardinality.
Given OPERATE and SELECT agree exactly at both cardinalities that **were** captured (35/37 and 50/52),
a 2-CROB single-header OPERATE landing at 49B response like SELECT's is a well-grounded structural
inference, not a measurement — flagged explicitly in §4 and §6.

### 2.5 Complete SBO transactions and background/state-read traffic

**RRC hardware evidence (TCP-payload bytes)** — all-points G10 state read, present in both SBO trials as
background traffic surrounding the SELECT-only exchanges:

| direction | role | size (B) | count |
|---|---|---:|---:|
| master→outstation | READ (all-points state check) | 18 | 4 |
| outstation→master | RESPONSE (unsplit) | 58 | 4 |

This 18B request does not match the 49B-payload eligibility profile, so the 58B response is correctly
**not split** — direct evidence that RRC eligibility keys on the 49B native size, not "split
everything" (`READSBO_NORMALIZATION_RESULT.md`).

**Multicrob corpus (TCP-payload bytes)** — every SELECT/OPERATE transaction in this corpus is preceded
by a WRITE_REQUEST/RESPONSE pair (21B request, 17B response ×2, likely a time-sync or clear-restart
step) and followed by TCP-ACK-only closure; see `generate_candidates.py`'s synthetic-SBO schedule
(seeded from these real sizes: SELECT=116B/OPERATE=116B/RESPONSE=118B **in Ethernet-frame-byte
convention**, i.e. `35+... → align`; do not confuse with the TCP-payload 35/37/50/52 figures two rows
above — same transactions, two different byte conventions, reported for completeness since
`generate_candidates.py`'s synthetic SBO schedule is itself an Ethernet-byte artifact).

## 3. Reproduced historical candidate ranking (baseline)

`generate_candidates.py` and `evaluate_candidates.py` were re-run unmodified against the repaired v2
inventory (`inventory_v2/`). Candidate definitions, fit flags, and the full MI/bootstrap/permutation/
grouped-CV ranking reproduce the historical `evaluation.json`/`evaluation_long.json`/
`evaluation_multicrob.json` exactly (same states, same `fits_existing_p4`, same ranking order at every
leakage weight `w ∈ {0,1,5,20,100}`, same Pareto frontier). Headline, base scope:

| candidate (Ethernet-frame bytes) | states | fits existing P4 | MI(operation) Miller-Madow | mean padding/pkt |
|---|---|---|---:|---:|
| `single128_corpus_baseline` | [128] | yes | 0.000 bits (constant-feature invariant) | 45.89 B |
| `cover_larger_corpus` | [128,256] | yes | 0.000 bits | 45.89 B |
| `two_state_round8` | [80,128] | no (80∉pad set) | leaks operation (record-level p=0.001; flow-grouped CI spans 0 on this 3-flow corpus) | 21.83 B |
| `ack_data_split` | [72,128] | no (72∉pad set) | similar operation leak | 24.81 B |

This baseline answers a **different question** than the one Phase B is tasked with: it ranks Ethernet-
frame padding candidates for the queue-microbench's synthetic UDP classifier, over READ vs
DIRECT_OPERATE (not SELECT/OPERATE — DIRECT_OPERATE is explicitly the unsupported role per the
integration contract). It is reproduced here as the required baseline, not as a candidate for the
actual READ/SELECT/OPERATE RRC pattern, which uses TCP-payload bytes and a completely different
carving mechanism. Full outputs: `inventory_v2/`, re-run evaluation JSON at
`evaluation_base_rerun.json`/`evaluation_long_rerun.json`/`evaluation_multicrob_rerun.json` (committed
in this directory; see the commands in "Reproducibility" below).

## 4. Scored options for the actual mismatch — READ `[28,21]` vs control `[28,29]`

All TCP-payload bytes. Evidence pool for the empirical MI numbers: `inventory_v2/rrc_pool.json` (built
by `build_rrc_pool.py` from the 4 recovered RRC PCAPs — 244 response-segment records / 124
transactions, 4 flow-groups: `hw_rrc_readsbo_{read,sbo}` and `hw_rrc_joint_{read,sbo}`). This pool is
**small and thin on flow-groups** (4 groups, each single-operation) — every leakage number below is
reported with that caveat; see §6.

### 4.1 The status quo, for contrast (not a candidate — the thing Phase B must resolve)

READ carves 49→[28,21]; the current Case 4 **software** control profile carves 57→[28,29]. The
**prefix is identical (28B) in both**; only the suffix differs (21 vs 29, two disjoint values). A
size-only observer watching the full ordered response vector therefore separates READ from control
**deterministically** from the second segment alone — this is not a measured MI (no pcap exists mixing
both profiles on one wire), it is a structural fact of two disjoint size sets, and it is exactly the
mismatch named in `INTEGRATION_CONTRACT.md` §5. Request direction is also unresolved under every
option below: READ request is 20B native, SELECT/OPERATE request is 35–55B native/padded, and no
option in this document closes that forward-channel gap (`READSBO_NORMALIZATION_RESULT.md`'s own
"honest residuals" already names it; see §6).

### 4.2 Option A — converge on the proven RRC shape: 49B pre-carve, cut28 → [28,21]

READ already reaches 49B natively (20B request, no padding needed). SELECT reaches 49B via a 2-CROB
command under **one shared G12V1 header** (count=2): measured 45B request → 49B response, **already
hardware-proven** (R5/R6, PASS) with the **same** [28,21] carve as READ, on the same loaded RRC kernel,
no new PRE group, no new carve profile. Empirical leakage on the 244-segment pool, states=[21,28]:

- MI (plug-in) = 0.0162 bits, Miller-Madow = 0.0132 bits, flow-grouped bootstrap 95% CI = **[0.0, 0.206]**
  (spans zero), permutation-null p = **0.166** (not significant at the conventional 0.05 threshold).
- 4 of 244 segments (the all-points 58B background reads) do not fit [21,28] and are correctly excluded
  from the 49B-eligible pool — direct quantitative confirmation of the eligibility-exclusion property.
- Grouped (leave-one-flow-group-out, k=4) balanced accuracy = 0.25 against a reported chance of 0.75 —
  **not a reliable number at this n**: with only 4 flow-groups (2 pure-READ runs, 2 pure-SBO runs) and
  a majority-vote classifier, one wrong fold dominates the average; read the permutation p-value and
  bootstrap CI above as the trustworthy headline, not this CV estimate (same caveat the original report
  applied to base/long's 3-flow corpus).

**Critical caveat, load-bearing for the recommendation below:** the 45B 2-CROB SELECT in this hardware
trial was **generated by the test master itself**, not inserted by the switch
(`READSBO_NORMALIZATION_RESULT.md`; integration prompt §2.5 states this explicitly: "not proof of
switch-inserted command padding"). Option A as hardware-proven today requires a **master that already
emits the two-object command**. It does **not** prove a switch mechanism that transforms a stock
1-CROB master's command into the 2-object form on the wire.

The parallel hardware-feasibility analysis (`HARDWARE_FEASIBILITY_ANALYSIS.md` §1.3) works this
construction question through precisely and reaches a sharper, corrected conclusion than this
document's own first-pass estimate: reaching exactly 49B from the native 37B response is **not**
achievable by appending any separate G12V1 object (the smallest legal one costs ≥16 application bytes,
landing at 52–55B, not 49B), and is **not** achievable by only bumping the existing object's count
field under its current qualifier `0x28` (that costs 13 application bytes, landing at 52B). The only
construction that reaches exactly 49B rewrites the native object's qualifier from `0x28` to `0x17`
(lossless only while the point index is below 256) in addition to raising its count from 1 to 2 — which
that analysis correctly identifies as a **correctness/policy decision** (it changes the native header's
own byte encoding, conflicting with the current codec's "the original object is never reconstructed"
invariant), **not an ASIC limitation**. Both independent analyses agree: there is no ASIC blocker here,
and the carve side (RID1/RID2 at any fixed cut) is proven or trivially compilable; the open question is
whether rewriting the native qualifier byte is an acceptable correctness trade, which is a switch/
endpoint design decision outside this read-only task's scope, not something either analysis can close
alone. Any such codec is **not implemented**; it is the concrete next engineering step this analysis
identifies (see §7), not something this read-only task built or ran.

OPERATE's response under this exact mechanism (2-CROB single header) is **not measured** (physical
OPERATE never run). The structural inference in §2.4 (OPERATE matches SELECT exactly at every
cardinality that *was* captured) supports expecting 49B, but this is an inference, not evidence at the
same level as the READ/SELECT hardware proof.

### 4.3 Option B — Ditto-style N-state pattern (single state, N=1, seeded at 58B)

A single padded state covering the full observed native range, including the 58B background state-read
— no splitting at all. Evaluated at transaction (reassembled) granularity on the same pool, states=[58]:

- MI = 0.0000 bits (exact; constant-feature invariant — every one of 124 transactions maps to the one
  state, so the single-state sanity gate holds trivially). This is the cleanest possible leakage result
  of any option scored here.
- Cost: every response pads to 58B regardless of native size. For the 60 READ/SELECT transactions
  natively at 49B, that is +9B per response (vs 0B for Option A's exact-fit carve); for background
  state-reads it is 0B (already 58B).
- No splitting means no PRE/RID carve machinery at all — removes essentially all of the RRC egress
  complexity, at the cost of giving up the "exact native size, zero waste" property Option A already
  has proven on hardware.

### 4.4 Option D — single uniform pad target, no splitting, 49B

Same no-split structure as B but at the already-proven 49B target instead of 58B — deliberately
**excludes** the 58B background class to show the cost of choosing a target too small for the full
native range. Evaluated at transaction granularity, states=[49]:

- MI = 0.0315 bits, Miller-Madow = 0.0315 bits, flow-grouped CI = **[0.0, 0.337]** (spans zero),
  permutation p = **0.119**. Still not significant, but higher than Option A's segment-level MI because
  the same 4 unfit 58B transactions are now a larger fraction of a smaller pool (4/124 vs 4/244) and,
  unlike Option B, they are not absorbed into the target — they must pass through natively, which is
  itself an observable, fully distinguishable residual class.
- This quantifies, with real numbers, the prompt's own worked arithmetic example: splitting 49B into
  28+21 costs 181 total frame bytes (before FCS) versus 115 for one unsplit 49B frame — a **66-byte
  per-transaction increase** for the split version. Option D (and B) avoid that increase entirely, at
  the cost of (D) an unhidden exception class or (B) extra padding on every transaction.

### 4.5 Option C — a different cut point within the same two states

Mutual information is invariant to a bijective relabelling of the state values: cutting 49B at a
different boundary (e.g. 24/25 instead of 28/21) produces the same two-states-per-transaction structure
and therefore the **identical** MI/CI/permutation numbers reported for Option A in §4.2 — the
leakage result does not distinguish cut points; only hardware/parser feasibility does (flagged for the
parallel hardware-feasibility assessment, not resolved here). The one technically load-bearing fact
is in `RRC_DESIGN.md` §6: the current kernel hard-codes `RRC_49_CUT28` and explicitly removes a
runtime-configurable cut parameter ("No false configurability... reject any value ≠ 28"). A different
cut point is a recompile, not a configuration change, under the proven design.

### 4.6 Option E — documented, narrow role split (default-rejected)

Not run as a default: Options A/B/D all satisfy the common-pattern objective (shared state set, no
role-specific residual) at measured leakage statistically indistinguishable from zero on the available
data. Option E (give READ one pattern, control another) is by construction maximally informative —
MI = H(operation) for whatever the deployed class balance is, since the two state sets would be
disjoint — this is analytic, not something requiring a bootstrap: if the two profiles never share a
size value, observing any segment resolves the operation with certainty. Scored here only to close the
required table; not recommended, consistent with the prompt's framing ("This is not the default
outcome; argue for it only if forced to").

### 4.7 Required-field scoring table

| field | Option A (49B, cut28→[28,21]) | Option B (58B, no split) | Option D (49B, no split) | Option E (role split) |
|---|---|---|---|---|
| Public ordered size vector (TCP-payload bytes, response direction) | [28, 21] | [58] | [49] | disjoint per role (e.g. READ [28,21] vs control [X,Y], Y∉{21,28}) |
| Input coverage | READ (49B native, proven); SELECT (49B via 2-CROB single-header, proven); OPERATE (49B expected by structural symmetry, **unmeasured**); excludes the 58B background class (stays unsplit, by design, per eligibility) | Covers READ, SELECT, OPERATE (≤58B) and the 58B background class in one state; 0 exclusions observed | Covers READ/SELECT/OPERATE at 49B; **excludes** the 58B background class (4/124 txns in this pool) — that class is a residual tail (see below) |  full coverage per role, by definition, since roles never share a state |
| Padding map | 0B for 49B-native transactions; **request-side** rewrite for OPERATE/SELECT not yet specified if the native-header qualifier-rewrite codec (§4.2, §7) is adopted | +9B on every ≤58B response (worst case +40B for the 18B/58B pair is not applicable here, since 58B is already native max) | 0B at 49B; 58B class has no legal pad target under this option (must be excluded, not padded) | role-specific, same as today |
| Splitting map | 49→[28,21], fixed cut, no runtime parameter (`RRC_DESIGN.md` §6) | none | none | READ 49→[28,21] (proven); control profile TBD per role |
| Residual tail | request-direction size (20B READ vs 35–55B control) remains unresolved by this option alone (§4.1); OPERATE response size unverified | request-direction residual, same as Option A; no response-direction residual | the 58B background class is itself a residual (must bypass, fully identifying that traffic as "not a 49B-eligible transaction") + request-direction residual | role is the residual, by construction — this option fails the stated common-pattern objective |
| Latency | release-to-carve, hardware-measured under the D4 hold: READ median 22.665ms, SBO median 22.639ms (0.026ms apart) — already enforced-identical under the joint D4+size bundle (`READSBO_NORMALIZATION_RESULT.md`) | padding adds ~0 transaction latency (same queue/hold mechanism; no new carve stage) | same as B | same hold mechanism per role; no stated difference |
| Bandwidth (external vs internal, separately) | external: 181B/transaction frame bytes before FCS for a split 49B payload vs 115B unsplit (+66B, prompt's own worked example, confirmed arithmetic); internal: 0 new blocker/recirculation traffic — reuses the existing PRE group unchanged | external: +9B/txn padding only, no split growth; internal: none new | external: 0B growth at 49B but the 58B class must travel as itself (no disguise); internal: none new | external/internal: unchanged from the current two-profile status quo |
| Hardware cost (this analysis's estimate; **flag for p4-dataplane-engineer**) | **Lowest of the four**: reuses the already-compiled, already-loaded `defense4_rrc_kernel` (0 new ingress registers, PRE not MAU, 1 PRE group, 2 RIDs) **if** the native-header qualifier-rewrite request codec (`0x28`→`0x17`, §4.2) is judged an acceptable correctness trade for SELECT/OPERATE's multi-function admission (flagged, not resolved here — same per-function expected-ACK table extension `RRC_DESIGN.md` §1–2 already designs) | Removes the RID/carve machinery entirely (simpler egress than A), but needs a new compile-time pad target (58B) not in the currently loaded pad set; unknown whether this requires new table entries only or a new parser constant | Needs a 49B pad target (already a parser constant, per `RRC_DESIGN.md`) plus an explicit bypass path for the excluded 58B class (a new table branch) | Unchanged resource footprint from status quo (no RRC kernel change needed for the split side; the control side keeps whatever insertion mechanism is already running) |
| Security evidence (this pool, honestly scoped) | MI not significant at this n (p=0.166, flow-grouped CI spans 0); **not flow-generalizable** beyond the 4 runs in this pool — same finite-sample caveat the original report applied to its own 3-flow base corpus | MI=0 exactly, strongest result of the four, but on a pool with the same 4-flow-group thinness | MI not significant (p=0.119); residual 58B class is deterministically identifiable whenever it occurs | not evaluated statistically — analytically maximal leakage by construction |

## 5. Ranked recommendation (not a final decision)

The parallel hardware-feasibility analysis (`HARDWARE_FEASIBILITY_ANALYSIS.md`) identifies a variant
this document's A–E list did not separately name: **Option A′ — converge on the native 37B control size
with no switch-side padding at all**, by choosing a READ poll (point count) that also yields a 37B
response. Because A′ requires zero bytes inserted into any request, it needs no sequence/ACK/window
mapper at all (the mapper is exactly the unresolved cost `M_RECIRCULATION_VERDICT.md` flags as not
currently fitting) — it is cheaper than every other option scored here, A included, on the hardware
axis. This document has no independent pcap evidence at 37B-response READ (no capture in any recovered
corpus happens to carry a point count that lands there), so its leakage cannot be measured the way
Option A's was in §4.2; structurally, though, a shared 37B native size with no split (or an optional
split, since 37 still fits the same RID-carve machinery at a different cut) inherits the same
zero-bytes-added, zero-exclusion properties this document already scored well for Option B, and the
two independent analyses' rankings converge:

1. **Option A′** (37B shared native size, no padding, no mapper) is the strongest candidate once the
   hardware analysis's finding is weighed in: it has the lowest engineering cost of any option (no new
   insertion mechanism, no mapper, at most the already-proven 3-stage carve), at the price of an
   operator/master-side constraint on the READ poll definition — a **P**olicy question, not a hardware
   or statistical one, and outside what either analysis can close alone.
2. **Option A** (converge on the already-hardware-proven 49B pre-carve, cut28 → [28,21]) is the
   strongest candidate for which this document has direct, independently measured leakage evidence
   (§4.2): MI statistically indistinguishable from zero, identical carve already proven on silicon for
   both READ and SELECT. Its cost, per the hardware analysis, is confined to the control side reaching
   49B, which needs a native-header qualifier rewrite (`0x28`→`0x17`) that is a correctness/policy
   decision, not an ASIC blocker.
3. **Option B** (single 58B state, no split) is the strongest fallback if neither A′'s poll constraint
   nor A's qualifier rewrite is acceptable. It has the cleanest measured security result of every option
   scored here (MI=0 exactly) and the simplest egress, at a flat, small per-response bandwidth cost.
4. **Option D** is dominated by A and B for this corpus: it buys nothing A doesn't already have, while
   introducing an unhidden 58B exception class that A handles the same way (exclude it, by design) and B
   absorbs for free. The hardware analysis independently ranks it last on cost (11–12 ingress stages for
   in-stream padding, plus the same mapper problem).
5. **Option C** is not a separate recommendation on either axis — it is Option A with a different,
   unproven cut point. The hardware analysis confirms a cut point alone cannot equalize the 49-vs-57
   byte totals; it is a free parameter once a common total is already chosen, not a solution by itself.
6. **Option E** is rejected by this analysis, consistent with the prompt's framing: nothing here forces
   a role split, and adopting one would reintroduce the exact size-channel leak the project exists to
   close. The hardware analysis agrees it is the cheapest option and the one that does not solve the
   problem.

**The one fact this recommendation depends on and cannot close from this task's available access**:
whether an operator-acceptable READ poll definition can hit exactly 37B (closing Option A′ outright), or
failing that, whether the native-header qualifier-rewrite codec (`0x28`→`0x17` plus count 1→2, §4.2, §7)
is an acceptable correctness trade on the switch, and whether a 2-CROB single-header OPERATE actually
reaches 49B on real hardware the way SELECT did. All three are concrete, falsifiable next steps (§7),
not open-ended research.

## 6. What remains uncertain, and what the hardware-feasibility assessment needs to weigh in on

- **OPERATE at 49B is inferred, not measured.** Every multicrob cardinality that was captured shows
  OPERATE byte-identical to SELECT (35/37 and 50/52), which supports expecting a 2-CROB single-header
  OPERATE to also land at 49B, but physical OPERATE has never been run through the RRC kernel at any
  cardinality (`RRC_HW_RESULTS.md`, gated on separate authorization). This is the single largest gap
  between "Option A is hardware-proven" and "Option A is hardware-proven **for all three protected
  roles**."
- **The native-header qualifier-rewrite codec does not exist yet.** `case4_padding.expand_control()`
  implements the separate-header approach (18 app bytes, 57B result); the `0x28`→`0x17` qualifier-rewrite
  construction this recommendation leans on for exactly 49B is precisely worked out arithmetically
  (`HARDWARE_FEASIBILITY_ANALYSIS.md` §1.3) but not implemented or tested as a codec. Building and testing
  it is outside this read-only analysis task's authorization (no compiler, no hardware).
- **Request-direction leakage is unresolved by every option in this document.** READ request (20B)
  and SELECT/OPERATE request (35–55B depending on profile) remain trivially separable regardless of
  which response-direction option is chosen. `READSBO_NORMALIZATION_RESULT.md` already names this as an
  "honest residual," and nothing in Phase B as scoped (response-direction convergence) closes it. Any
  claim of full operation-indistinguishability must account for this gap explicitly.
- **The arrival-order reversal (`[21,28]` recorded order vs `[28,21]` TCP sequence order) is unexplained**
  and inherited unchanged from the integration prompt (§2.5); this document does not add new evidence on
  it and flags it as open.
- **Flow-group thinness.** Every MI number in §4 rests on 4 flow-groups (2 READ runs, 2 SBO runs); the
  flow-grouped bootstrap CIs span zero but are wide, and the grouped-CV balanced-accuracy numbers are not
  reliable at this n (explicitly flagged, not glossed over, in §4.2/§4.4). A larger, multi-session RRC
  capture (same mechanism, more independent runs) would tighten these intervals; this analysis does not
  have authorization to collect one.
- **Hardware cost estimates in §4.7 are this analysis's best estimate, explicitly not a compiler or
  resource-allocation result.** The parallel hardware-feasibility assessment is the authority on whether
  the native-header qualifier-rewrite codec, the 58B pad target (Option B), or the 49B-with-bypass structure
  (Option D) actually fit the loaded pipeline's stage/PHV/table budget; this document deliberately does
  not attempt to resolve ASIC feasibility itself, per the task's own instruction.

## 7. Concrete next engineering step (not performed in this task)

Two candidates, in the order the ranked recommendation (§5) suggests evaluating them:

1. **Option A′ first** (cheapest, per the hardware analysis): determine whether the operational READ
   poll definition can be set to a point count that yields a 37B response (the native, unpadded
   SELECT/OPERATE response size, confirmed in §2.3 against a real multicrob capture), and whether an
   optional 37B carve (e.g. `[28,9]`) is wanted for defense-in-depth or whether equal native totals alone
   are judged sufficient. This needs no new switch mechanism at all — only a poll-definition decision
   and, if a split is wanted, a straightforward recompile of the already-proven carve at a different
   fixed cut (§4.5, Option C's finding that cut point is a free parameter).
2. **Option A second** (if A′'s poll constraint is unacceptable): implement and bench, off-switch first
   (software codec + unit tests, same pattern as `case4_padding.py`'s existing suite), a native-header
   rewrite variant that converts an existing G12V1 object header's qualifier from `0x28` to `0x17` and
   raises its count from 1 to 2 (in place, recomputing the affected DNP3 CRC block and the link length),
   appending the decoy's `(1-byte index + 11-byte CROB)` pair under the new qualifier — targeting exactly
   49B for both SELECT and OPERATE instead of the current 57B separate-header result. This is explicitly
   a correctness/policy change (it alters the native object's own encoding, not just its surroundings)
   and must be validated against the same OpenDNP3 `endpoint_gate` semantic harness already built for the
   separate-header profile, specifically checking that a `0x17`-qualifier SELECT/OPERATE is accepted and
   correctly echoed by production master and outstation code paths. Only after that software/semantic
   gate passes does either candidate become a candidate for the hardware-feasibility assessment's queue.

## Reproducibility

```sh
# repaired extractor, both the verification run and the production inventories in this directory
$RESEARCH_PYTHON extract_inventory_v2.py --scope all --outdir inventory_v2

# historical candidate baseline, reproduced against the repaired inventory
$RESEARCH_PYTHON generate_candidates.py --scope all --invdir inventory_v2 --outdir /tmp/candidates_v2
$RESEARCH_PYTHON evaluate_candidates.py --scope base --invdir inventory_v2 --candir /tmp/candidates_v2 --out evaluation_base_rerun.json
$RESEARCH_PYTHON evaluate_candidates.py --scope long --invdir inventory_v2 --candir /tmp/candidates_v2 --out evaluation_long_rerun.json
$RESEARCH_PYTHON evaluate_candidates.py --scope multicrob --invdir inventory_v2 --candir /tmp/candidates_v2 --out evaluation_multicrob_rerun.json

# RRC hardware pool + Options A-E scoring (needs the 4 RRC PCAPs recovered from 9ffa9102, see Sec 0)
$RESEARCH_PYTHON build_rrc_pool.py <readsbo/read.pcap> <readsbo/sbo.pcap> <joint/read.pcap> <joint/sbo.pcap> inventory_v2/rrc_pool.json
$RESEARCH_PYTHON evaluate_options_AE.py

# original unmodified regression suite (validates the historical v1.1 tooling is intact)
$RESEARCH_PYTHON test_pattern_builder.py
```
