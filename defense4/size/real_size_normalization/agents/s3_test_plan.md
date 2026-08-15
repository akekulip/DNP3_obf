# Gate S3 Test and Evaluation Matrix

Owner: S3 test-engineering lane

Scope: offline trace-level prototype only. No live hardware, SSH mutation, interface changes,
P4 load, relay traffic, or package installation is part of this gate.

## Verdict

Gate S3 should be treated as a deterministic codec-and-observer gate, not a
hardware feasibility gate. The approved S2 design can advance to S4 only if an
offline prototype proves all of the following from committed inputs and generated
artifacts:

- exact trusted-boundary byte recovery for every non-failing epoch;
- fixed public outer size, count, direction sequence, and slot schedule across
  the declared RN-L policy domain;
- encrypted/hidden inner length, type, data/cover state, and padding boundary;
- safe, fixed-transcript behavior for corruption, loss, duplication, reordering,
  replay, nonce restart, malformed metadata, overflow, reconnect, and control
  traffic;
- reproducible PCAP, CSV, manifest, and observer-analysis outputs;
- whole-transcript attacker features show no length signal: permutation-calibrated
  mutual information near zero and balanced-accuracy confidence intervals that
  include chance.

S3 must not claim the Tofino `ens1`/`bf_kpkt` punt/reinject path works. That
remains S6.

## Evidence inputs

Use committed repository evidence only:

| Input class | Required use |
| --- | --- |
| Physical SEL admitted READ/SELECT/OPERATE traces | Small current-testbed fixtures: 20-byte READ requests, 45-byte SELECT/OPERATE requests, 49-byte responses, historical `[49]` and `[28,21]` negative controls. |
| Physical state-read outliers | Overflow/boundary fixture: 18-byte request and 58-byte response families. |
| ION comparison evidence | Current relay-leg diversity fixture: 17-byte READ response and 32-byte SELECT echo, without claiming multi-device indistinguishability. |
| OpenDNP3 software loopback evidence | Large offline boundary fixture: 243-byte response and 1574-byte reassembled response. |
| Synthetic byte fixtures | Stratified lengths and malformed/fault cases needed to reach reliable coverage beyond the small physical corpus. |

Generated S3 evidence should live under a new directory such as
`defense4/size/real_size_normalization/evidence/s3_offline_codec/`, with a
manifest and command log. Do not write into frozen `E_FINAL`.

## Prototype interfaces under test

The offline prototype should expose narrow deterministic functions that tests can
call directly:

| Interface | Behavior under test |
| --- | --- |
| `encode_epoch(inner_frames, policy, direction, epoch, key_state, fault=None)` | Emits exactly the configured public cells for every declared slot. |
| `decode_epoch(cells, policy, direction, key_state)` | Returns the original ordered inner frames or a fail-closed status with no partial bytes. |
| `emit_pcap(transcript, path)` | Writes observer-link fixed-cell PCAPs and trusted-boundary PCAPs from deterministic records. |
| `emit_csv(transcript, path)` | Writes one row per public cell and one row per epoch summary. |
| `analyze_observer(csv_or_pcap)` | Computes invariant checks, feature table, mutual information, classifier balanced accuracy, and confidence intervals. |

Test inputs must fix all random seeds except AEAD nonces/counters. AEAD plaintext
padding may be random, but observer-visible size/count/direction/slot features
must remain deterministic for a given policy.

## Stratified test corpus

Minimum corpus: at least 50 successful non-overflow RN-L epochs plus explicit
negative/fault epochs. The 50 successful cases must include at least two distinct
inner response lengths and should be stratified as follows:

| Stratum | Count | Lengths / cases | Purpose |
| --- | ---: | --- | --- |
| Physical small | 10 | 17, 20, 32, 45, 49, 58 byte current-testbed families, repeated across directions/classes | Prevents losing contact with committed evidence. |
| Near-zero and tiny | 8 | 0, 1, 2, 7, 15, 16, 31, 63 bytes | Exercises metadata-only and padding-heavy cells. |
| Around cell payload boundaries | 12 | `P-2`, `P-1`, `P`, `P+1`, `2P-1`, `2P`, `2P+1`, repeated for request/response slots | Catches off-by-one count leaks. |
| Around schedule capacity | 8 | `L_max-3`, `L_max-2`, `L_max-1`, `L_max`, with one-frame and multi-frame encodings | Proves no final-cell or frame-count leak. |
| Large software-derived | 6 | 243 bytes, 1574 bytes if within provisional policy, and truncated/subsampled variants if not | Keeps larger DNP3 stack evidence represented. |
| TCP lifecycle/control | 6 | startup, reconnect, FIN, RST, ACK-only, idle/cover-only epoch | Prevents established-payload-only evidence. |

If provisional `L_max` is too small for 1574 bytes, the 1574 case must be a
deterministic overflow test, not silently excluded.

## Functional tests

Each test verifies one behavior. Names below are intended to become test names.

| Test | Fixture | Pass criteria |
| --- | --- | --- |
| `recovers_exact_inner_bytes_for_single_frame_epoch` | One inner Ethernet frame at a physical small length | Decoded frame bytes equal input byte-for-byte; no extra bytes. |
| `recovers_exact_inner_bytes_for_multi_frame_epoch` | Multiple inner frames in one epoch | Decoded ordered frame list equals input list byte-for-byte. |
| `preserves_empty_epoch_as_cover_only_without_inner_output` | No inner data, cover-only slot | Public transcript is valid and fixed; decoder returns no inner frames. |
| `encrypts_true_length_type_and_cover_state` | Data and cover cells at same public slot | Public fields never contain true length, protected type, data/cover marker, final marker, or padding boundary. |
| `uses_distinct_direction_keys_and_nonce_spaces` | Same epoch/counter value in both directions | Nonce/key tuple is distinct by direction; analyzer sees no collision. |
| `rejects_duplicate_nonce_before_ciphertext_release` | Forced repeated direction/key/nonce | Encoder fails closed; no PCAP cell is emitted for the invalid epoch. |
| `does_not_reuse_nonce_after_restart` | Simulated restart with persisted counter and with missing counter | Persisted counter advances; missing counter requires fresh key epoch or startup refusal. |
| `rejects_replayed_valid_cell` | Valid cell from earlier epoch replayed into current epoch | Decoder returns fail-closed status; no inner bytes. |
| `drops_epoch_on_tag_corruption` | One ciphertext/tag bit flipped | Whole epoch fails closed; no partial inner bytes; public transcript row stays fixed. |
| `drops_epoch_on_malformed_public_metadata` | Bad version, wrong policy, wrong EtherType, wrong fixed size | Decoder/gate rejects; no public variable error cell is generated. |
| `reassembles_bounded_reordered_cells` | Same cell set shuffled within the allowed epoch window | Decoded bytes equal input; public transcript order policy remains the generated slot order for transmitted cells. |
| `drops_epoch_with_missing_cell` | Remove one required cell | Decoder emits no inner bytes; transmitter-side CSV still contains fixed cover/data schedule for the epoch under test. |
| `drops_conflicting_duplicate_cell` | Duplicate index with different ciphertext | Decoder fails closed; no partial inner bytes. |
| `ignores_identical_duplicate_cell_without_public_recovery` | Duplicate exact cell | Decoder either ignores duplicate or fails closed per spec; no NACK/retry/error frame appears. |
| `fails_closed_on_overflow_without_spill_cells` | `L_max+1` and 1574 bytes when out of policy | Public transcript has exactly configured cover count; no partial decode; overflow metric is local-only. |
| `fails_closed_on_late_real_content` | Response arrives after fixed release deadline in the offline scheduler | Public response slot is cover; no late variable cell or native frame. |
| `keeps_reconnect_and_control_traffic_in_declared_fixed_epochs` | ARP/NDP/LLDP/TCP setup/FIN/RST/idle fixtures | Clear control traffic is absent from observer PCAP; declared control epochs have fixed `C/K/slot` records. |
| `round_trips_committed_physical_trace_fixtures` | SEL/ION trace-derived inner frames | All in-policy frames recover exactly and map to fixed outer transcript rows. |
| `negative_control_reconstructs_current_49_from_28_21` | Historical `[28,21]` fixture | Observer analyzer labels historical result `SEGMENT SHAPE ONLY`, proving the new gate rejects old evidence. |

## Public transcript invariant tests

For every successful in-policy epoch, derive a canonical observer feature vector:

```text
epoch_id
policy_id
slot_name
direction
cell_index
wire_len
public_header_len
ciphertext_len
tag_len
slot_offset_us
outer_flow_id
fragment_flag
retry_or_error_flag
```

Required deterministic assertions:

| Assertion | Pass criteria |
| --- | --- |
| Fixed wire size | `nunique(wire_len) == 1` within each policy and slot; value equals `C`. |
| Fixed count | Every epoch has exactly `K_req`, `K_ack`, `K_resp`, and configured tail/control cells. |
| Fixed direction sequence | Direction vector hash is identical for all successful epochs in the RN-L domain. |
| Fixed slot schedule | Slot names and nominal offsets are identical for all successful epochs; jitter is zero in offline traces or exactly the deterministic configured value. |
| Fixed total outer bytes | Per-epoch total public bytes are identical for all successful in-policy epochs. |
| No visible fragmentation/retransmission | Fragment/retry/error flags are absent or constant zero in generated observer traces. |
| No clear DNP3 | Observer PCAP contains no native DNP3 start bytes on clear IP/TCP payloads and no non-cell EtherType outside declared fixed control epochs. |
| Cover indistinguishability at transcript level | Data-bearing and cover-only epochs have identical public feature vectors. |

Fail the gate on any invariant violation before running statistical analysis.

## Fault and adversarial matrix

| Fault class | Cases | Expected public behavior | Expected trusted-boundary behavior |
| --- | --- | --- | --- |
| Loss | Drop each cell index once; drop all cover cells; drop all data cells | No public retransmission/NACK/adaptive count; generated schedule remains fixed for transmitter-side epochs | Missing required cell drops inner epoch. |
| Duplication | Exact duplicate; duplicate with corrupted body; duplicate before original | No public recovery traffic | Ignore exact duplicate or fail closed; conflicting duplicate fails closed. |
| Reordering | All cells reversed; random shuffle; late within window; late beyond window | Transmitted transcript stays fixed; receive processing has no public error | In-window reorders recover; late beyond deadline fails closed. |
| Replay | Prior epoch replay; prior direction replay; stale key epoch replay | No native/error egress | Reject by epoch/nonce/replay window. |
| Tag corruption | Flip every tag byte position in a parameterized test | No public variation | Reject entire epoch. |
| Metadata corruption | Wrong version, policy, length, nonce length, cell index, direction, slot | No public variation | Reject before plaintext release. |
| Overflow | `L_max+1`, `KP+1`, too many frames, frame offset table overflow | Exactly fixed cover transcript | No partial inner bytes; local overflow only. |
| Restart | Counter persisted; counter missing; key epoch rollback; clock reset | Either monotonic counter/fresh key or no cells emitted | Startup refusal or fresh key epoch; never nonce reuse. |
| Control/reconnect | SYN, FIN, RST, ACK-only, idle, ARP/NDP/LLDP-like fixtures | Only declared fixed control epochs or silence; no clear side traffic | Endpoint frames reconstructed only when policy admits them. |

## Observer analysis

The attacker model must train on the complete outer transcript, not packet sizes
alone. Produce both cell-level and epoch-level CSVs.

### Required features

For each epoch, compute:

- ordered packet-size vector;
- total outer bytes;
- cell count by direction and slot;
- complete direction sequence;
- slot/timing vector and inter-cell timing;
- public flow/protocol metadata;
- fragmentation/retry/error indicators;
- overflow/fail-closed class as a separate label, excluded from successful RN-L
  leakage tests but counted in safety results.

### Mutual information

Compute mutual information between protected inner length `L` and each feature
family, plus the concatenated whole-transcript feature:

```text
I(L; total_outer_bytes)
I(L; packet_size_vector)
I(L; cell_count_vector)
I(L; direction_sequence)
I(L; slot_timing_vector)
I(L; whole_outer_transcript)
```

Pass criteria:

- deterministic invariant tests already pass exactly;
- empirical MI point estimate is `0.0` for deterministic fixed features, or no
  larger than the median of label-permutation null runs plus one numerical
  tolerance `epsilon <= 1e-9` for floating estimators;
- 95% permutation interval includes the observed MI;
- at least 1,000 fixed-seed permutations are used, or the report explicitly marks
  the result as exploratory and not gate-passing.

### Classifier balanced accuracy

Train a length attacker with transaction-disjoint splits. At minimum:

- majority/chance baseline;
- logistic regression or equivalent simple linear classifier on encoded features;
- tree/random-forest style nonlinear classifier if available without new
  dependencies, otherwise a documented stdlib/permutation nearest-centroid fallback.

Pass criteria:

- balanced accuracy 95% confidence interval includes chance for every successful
  RN-L stratum and for the pooled set;
- no fold contains the same source transaction in train and test;
- report per-stratum and pooled scores;
- if a classifier exceeds chance, the gate fails even if deterministic invariants
  appear to pass.

Use bootstrap confidence intervals with fixed seed and at least 2,000 resamples,
or Wilson/binomial intervals when the prediction task is binary.

## Required output artifacts

S3 should produce:

| Artifact | Required contents |
| --- | --- |
| `README.md` | Exact command sequence, policy parameters, claim boundary, and result label. |
| `policy.json` | `C`, `P`, `L_max`, `K_*`, slots, deadlines, nonce layout, key epoch policy, and corpus hash. |
| `manifest.sha256` | Hashes for every input, generated PCAP, CSV, JSON, script, and report. |
| `trusted_inner_input.pcap` / `.csv` | Original inner frames or deterministic byte fixtures. |
| `observer_outer_cells.pcap` / `.csv` | Fixed public cell transcript. |
| `trusted_inner_decoded.pcap` / `.csv` | Decoded frames and byte-equality status. |
| `fault_cases.csv` | One row per fault with expected/actual fail-closed result. |
| `observer_features.csv` | Feature table used for MI/classifier analysis. |
| `observer_stats.json` | MI, permutation intervals, balanced accuracy, confidence intervals, seeds, and versions. |
| `OFFLINE_CLAIM_MATRIX.md` | PASS/PARTIAL/FAIL rows for functional correctness, transcript invariance, size security, fault behavior, timing policy, and limitations. |

No artifact may contain keys, plaintext secrets, or per-transaction true lengths
outside the trusted input/decoded CSVs required for offline evaluation. Public
observer CSVs may include only test labels in a separate analysis join file, not
as observer-visible fields.

## Gate pass/fail matrix

| Gate item | PASS | FAIL |
| --- | --- | --- |
| Corpus size | At least 50 successful stratified in-policy epochs plus negative/fault cases. | Fewer than 50, one protected length only, or missing boundary cases. |
| Byte recovery | Every successful in-policy epoch decodes exactly to original bytes. | Any byte mismatch, reordering, extra byte, missing byte, or partial decode on failure. |
| Fixed transcript | Size/count/direction/slot/total bytes invariant tests all pass exactly. | Any variable public size, count, direction, slot, retry, error, or control escape. |
| Length metadata | Length/type/final/cover/padding state absent from public fields. | Any public field encodes inner length, class, occupancy, or padding boundary. |
| Fault behavior | Faults fail closed or recover exactly where specified without public variation. | Adaptive recovery, NACK/retry/error, spill cells, native clear fallback, or partial release. |
| Nonce/replay | Directional nonce uniqueness and replay rejection are proven by tests. | Any repeated `(key, nonce)` emission or accepted stale cell. |
| Observer MI | Whole-transcript MI indistinguishable from permutation null under deterministic-invariant pass. | MI signal above null/tolerance or missing reproducible permutation result. |
| Classifier | Balanced-accuracy CI includes chance on transaction-disjoint splits. | CI excludes chance, split leakage, or no classifier report. |
| Reproducibility | PCAP/CSV/JSON/manifest regenerate byte-identically under documented command. | Missing manifest, nondeterministic outputs without explanation, or non-reproducible stats. |
| Claim discipline | Labels result as S3 offline proof only; no hardware or multi-device claim. | Claims deployment, CPU punt/reinject proof, RN-T, or multi-device suppression. |

## Recommended execution order

1. Implement deterministic fixture loader and corpus manifest.
2. Write RED tests for exact byte recovery and fixed transcript invariants before
   implementing the codec.
3. Implement the minimal offline encoder/decoder to pass byte and invariant tests.
4. Add fault tests for corruption, loss, duplication, reordering, replay, restart,
   overflow, reconnect, and control traffic.
5. Generate PCAP/CSV outputs from the same test fixtures.
6. Run observer feature extraction, invariant checks, MI, and classifier analysis.
7. Write `OFFLINE_CLAIM_MATRIX.md` only after tests and stats are fresh.

## Stop condition

S3 is complete only when the deterministic tests pass, generated evidence is
reproducible from committed commands, observer analysis shows no whole-transcript
length signal, and the report explicitly limits the claim to offline fixed-cell
prototype behavior. Otherwise the gate remains open and S4 must not begin.
