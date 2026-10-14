# candidate61 PLAN step 4 — timing and size evaluation on silicon (2026-10-14)

Data: `step4_summary.json` (built by `analysis/step4_report.py`). Six interleaved blocks at 59,570 PPS / 950 us, arm order rotated, 4 arms x 500 READs each, every block restored and production observed. Error metric: READ CLRT minus the 950 us gap for timed arms; raw CLRT for off/size_only (no gap applies). Percentiles are nearest-rank (the ceil(q*n)-th value) and SD is the sample SD; until 2026-10-14 this table used linear interpolation and the population SD, which `step4_summary.json` keeps as `p99_interp` and `sd_population`. The 95% intervals resample pooled packets and are not a block-aware comparison of the two builds. Provisional p99 |error| <= 100 us is a percentile bound, not a maximum-error guarantee.

| build | arm | n | median | p90 | p99 | min / max | abs p99 [95% CI] | >100 us | SD | READ req->resp p50 | OPERATE req->resp p50 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| candidate61 | off | 1500 | 5337.0 | 8361.0 | 8386.0 | 3186.0 / 9429.0 | raw CLRT, no gap: n/a | n/a | 2095.15 | 5498.0 | 5452.0 |
| candidate61 | timing_only | 1500 | 3.0 | 40.0 | 48.0 | -927.0 / 96.0 | 54.0 [49.0, 84.0] | 4 | 51.39 | 6391.0 | 7946.0 |
| candidate61 | size_only | 1500 | 5362.0 | 8338.0 | 8376.0 | 3250.0 / 8400.0 | raw CLRT, no gap: n/a | n/a | 2045.00 | 5505.0 | 5423.0 |
| candidate61 | combined | 1500 | 7.0 | 44.0 | 51.0 | -920.0 / 1150.0 | 51.0 [51.0, 52.0] | 3 | 50.66 | 6397.0 | 7889.0 |
| strict | off | 1500 | 5285.0 | 8358.0 | 8378.0 | 2259.0 / 8453.0 | raw CLRT, no gap: n/a | n/a | 2064.93 | 5441.0 | 5448.0 |
| strict | timing_only | 1500 | 5.0 | 56.0 | 64.0 | -925.0 / 90.0 | 65.0 [64.0, 67.0] | 5 | 59.35 | 6471.0 | 7916.0 |
| strict | size_only | 1500 | 5345.0 | 8296.0 | 8371.0 | 2173.0 / 9406.0 | raw CLRT, no gap: n/a | n/a | 2038.48 | 5509.0 | 5402.0 |
| strict | combined | 1500 | 7.0 | 37.0 | 47.0 | -924.0 / 1157.0 | 51.0 [47.0, 62.0] | 7 | 72.13 | 6455.0 | 7886.0 |

## Size

Every trial carried exactly the bound lengths: candidate61 off/timing_only READ 49, SELECT/OPERATE 37; size_only/combined READ, SELECT, OPERATE 61. Strict READ 58 when padded, SBO 37 in all arms. Measured external growth equals the bound expectation in every trial: candidate61 6,048 B per padded trial (12 x 500 + 24 x 2), strict 4,500 B (9 x 500), native 0. No exclusions (incomplete, retransmitted, piggybacked or missing CLRT) in any eval block.

## Tails

Over-bound READs: candidate61 7 of 3,000 timed, strict 12 of 3,000. All are ~1.1 ms events, and they recur near READ indices 127 and 255 (126 and 254 in candidate61 block 3), about every 128 exchanges, across arms, blocks and both builds.

**Where they arise (corrected twice; the second correction follows the f0baa724a audit).** Both captures are on Vision's switch-facing port, so their timestamps are comparable. Additional elapsed time is observed between the host transmit and receive capture points; it also occurs with timing disabled and in the strict build. Its component and possible interactions remain unresolved: kernel and NIC queues, qdiscs, capture timestamping, the link and the switch are all between those two points, and occurrences in untimed arms do not prove the hold path or the encoding adds nothing under other loads. (Off arm, candidate block 1: pure-ACK tap-to-tap transit median 27 us, two events up to 1,139 us; responses at most 198 us.) The 128-exchange period is a diagnostic lead, not a demonstrated cause. An ACK delayed in transit shortens the measured CLRT (about -920 us); a response delayed in transit lengthens it (about +1.1 ms).

Precision also varies by block for both builds: block 3 shows a median bias of about +34 to +51 us (0 to 7 us in blocks 1-2), and strict timing_only block 2 has abs p95 48 us; the other block 1-2 values are 11-15 us. Neither changes a conclusion.

## OPERATE hold and SBO

OPERATE request-to-response p50 rises from about 5.4 ms (untimed) to about 7.9 ms (timed), the configured op_j 2.4 ms hold. Full SBO completion p50: about 11.2 ms untimed, about 13.6 ms timed, the same for both builds. SBO timing is n = 3 per arm (one cycle per connection); repeated SBO cycles were not run, so control-timing distributions are not quantified. SELECT and OPERATE CLRT (ACK to response) medians in the combined arm are about 5.3 ms and 5.2 ms, not the 950 us READ target: only READ's ACK-to-response gap is normalized on this candidate, and the OPERATE shift is its command hold, not CLRT normalization.

## Piggyback (`candidate61_piggyback_combined_59570_950_01`)

19 of 20 READs piggybacked as designed; lengths 61/61/61; growth 288 = expected. READ request-to-response p50 30.1 ms (combined), the same fallback latency the earlier builds show for timed arms (untimed arms about 0.33 ms). CLRT is not reported for piggybacked READs; no separate request ACK exists.

## Rate trade-off (combined, 3 x 50 READs, same candidate and target)

| rate | abs p99 [95% CI] | median error | >100 us | internal loop packets / trial | loop bytes / trial |
|---|---:|---:|---:|---:|---:|
| 14,892 PPS | 147.0 [146.0, 147.0] | 94.0 | 47 of 150 | 32031 | 2353170 |
| 59,570 PPS | 91.0 [88.0, 92.0] | 38.0 | 0 of 150 | 105671 | 7749171 |

59,570 PPS costs about 3.3x the internal packets and keeps p99 inside the provisional bound; 14,892 PPS does not (recorded as soft timing failures; their `standards.json` did not carry the precision status until the 2026-10-14 serialization fix, while `trial.json` always recorded the failure). External growth is 648 B per trial at both rates. `candidate61_compare_14892_950_01` stopped after one trial because a precision-only failure was re-flagged as a hard standards failure (fixed in `598473ebe`); it is retained.

## Not covered

Repeated SBO cycles per connection; real-relay compatibility; default promotion. Equal 61-byte payload length does not hide plaintext object contents or the one-versus-three DNP3 link-frame structure.
