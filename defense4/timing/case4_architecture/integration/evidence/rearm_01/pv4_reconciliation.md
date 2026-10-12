# Frozen pv4 reconciliation

The retained pv4 engineering characterization contains **14/14 originally passing blocks under the corroborated max-stale-5 policy**, **9/14 strict-zero blocks**, and **2/7 completely strict-zero matched pairs**. All five nonzero blocks recorded exactly five stale tokens; all were at 3,723 PPS. This does not change the approved paper campaign_v2.

The strict-zero block criterion is the original retained trial pass, an independent raw endpoint/integrity/counter audit, and `after.OUT_TOKEN_STALE - before.OUT_TOKEN_STALE == 0`. A strict-zero pair requires both of its rate blocks to meet that criterion. This is a subset classification of frozen characterization, not a retroactive declaration that pv4 meets every current production gate.

| Trial | Pair | PPS | Delay ms | Gap input ms | Seed | Stale delta | Strict zero | p99 absolute CLRT error us | Median READ spacing ms |
|---|---:|---:|---:|---:|---:|---:|:---:|---:|---:|
| t0 | 0 | 14892 | 5 | 20 | 201 | 0 | yes | 45 | 53.985 |
| t1 | 0 | 3723 | 5 | 20 | 201 | 5 | no | 44 | 53.991 |
| t2 | 1 | 3723 | 3 | 20 | 202 | 5 | no | 80 | 51.834 |
| t3 | 1 | 14892 | 3 | 20 | 202 | 0 | yes | 54 | 51.843 |
| t4 | 2 | 14892 | 8 | 20 | 203 | 0 | yes | 51 | 56.109 |
| t5 | 2 | 3723 | 8 | 20 | 203 | 0 | yes | 54 | 56.131 |
| t6 | 3 | 3723 | 10 | 20 | 204 | 5 | no | 99 | 58.308 |
| t7 | 3 | 14892 | 10 | 20 | 204 | 0 | yes | 97 | 58.297 |
| t8 | 4 | 14892 | 5 | 5 | 205 | 0 | yes | 42 | 38.978 |
| t9 | 4 | 3723 | 5 | 5 | 205 | 0 | yes | 25 | 38.987 |
| t10 | 5 | 3723 | 5 | 50 | 206 | 5 | no | 41 | 83.994 |
| t11 | 5 | 14892 | 5 | 50 | 206 | 0 | yes | 36 | 83.989 |
| t12 | 6 | 14892 | 5 | 0 | 207 | 0 | yes | 41 | 33.820 |
| t13 | 6 | 3723 | 5 | 0 | 207 | 5 | no | 32 | 33.814 |

At 14,892 PPS, 7/7 blocks are strict zero; at 3,723 PPS, 2/7 are strict zero. The complete strict-zero pairs are pair2 (t4/t5, delay8ms, gap20ms, seed203) and pair4 (t8/t9, delay5ms, gap5ms, seed205). Each condition was run once per rate, with alternating order; neither rate has repeated observations under each fixed condition.

All 700/700 requested READs completed with 23 seed-matching points each. Raw endpoint evidence contains exactly14 real SELECTs and14 real OPERATEs, zero Decoy calls. Each block has50 ACK commits,50 response releases,1 OP release; READ generation is50 triggers/200 tokens, OP generation1 trigger/4 tokens, with zero loop octet gaps. The nine strict-zero blocks contain450 READs and9 real SBOs; the two complete strict-zero pairs contain200 READs and4 real SBOs. These packet/task counts are not additional independent block replications.

A separate retrospective precision audit finds700/700 eligible READs (50/block), with no incomplete, piggyback, or repeated-attempt READ exclusions. Every block has p99 absolute error from the800us target at most100us; the worst block is99us. Percentiles use the sorted index `round(p*(n-1))`, as `clrt_check.stats` does; for50 samples p99 is the maximum. The original run did not record this acceptance gate.

The actual scratch configuration is included in the JSON with its SHA256. Its paired schedule, timing, selected build pins, endpoint pins, and per-trial rates agree with the frozen artifacts. Its selected `mirror_fix_01.max_token_stale` is5. The old campaign record contains no effective stale bound or config hash, so this attribution is corroborated rather than cryptographically bound. The global recorded `shaping_requested` is the unshaped default; all six per-trial queue readbacks instead confirm the intended14,892/3,723 PPS, blocker burst64, hold burst1.

Relevant frozen pins are:

- `bfrt.json`: `4e24bc8a84313b16bfb268aa640bc005548a93bfd63f392abaa8a96909070caa`
- `p0/tofino.bin`: `aff15250cc9af232f99c4d759fd801dd3d4a7b750b712fe760dc637550af2edb`
- `p1/tofino.bin`: `296444ce43e28e3228edd8e1d61c52f2a6f233dc4be357e3e96610e896e02309`
- `p1/response_only.bfa`: `eea04489a6ad5da5a3d2ca91201223af26458d1516c2a7a4b6d3b5843893ff96`
- Original endpoint binary: `f66ad08cce45407483c505edf4547c3d222d9ac3b959f3ba9540281f3c793097`
- Original library sorted-listing aggregate: `6c7a6892d5b9fddb0c09a5ae1d63067f17034b4edf93f8f295f4c4bb32a6d23d`
- Scratch configuration: `b768e886a8695b0c60da9a3d6b2d945f8f65766b7b1f128f3401ad5f29bca438`

Configured timing is Da2ms, readiness30ms, cap40ms, gap800us, OP J2.4ms, k2. Cap is accepted but unused as a deadline in this implementation. The old endpoint identity is `/home/decps/pad58b_20261011`; it is not the later controls build. The apparent zero-gap blocks have measured median READ request intervals33.820ms and33.814ms, so they do not demonstrate zero-pause or rapid request operation. Timing is measured at the same parent-NIC host capture, with integer-microsecond timestamps, rather than as isolated ASIC forwarding latency.

No diagnostic source counters19..24 are retained in pv4. Its aggregate stale counter cannot locate the source or classify the five-token observations as benign. Coverage is limited to combined T1/padding1, separate ACK, no loss, cold-per-trial operation at these two queue rates and these seven heterogeneous conditions. It does not establish reconnect/rearm robustness, other arms, piggyback behavior, zero-pause behavior, long-delay25ms coverage, or a non-aligned950us timing target.

[Machine-readable reconciliation and complete raw-artifact SHA256 inventory](pv4_reconciliation.json). The frozen campaign and all retained files were read and hashed, and verified unchanged after writing these separate reconciliation artifacts.
