# Defense-4 timing-policy characterization

Selected and tested under declared constraints; **not** claimed optimal. Software/analysis only over committed raw evidence. Every candidate is labelled DEMONSTRATED (hardware-measured) vs ANALYSIS-ONLY, and every unavailable constraint is left UNKNOWN.

- Protection domain: SEL-751 Case-A (separate-ACK) outstation, READ, corrected binary 97175e7d
- Latency model (AUDIT): `L_master = a + max(C, H) + eps_R  (NOT bounded by H when C>H)`
- `a` = t_A - t_Q (request->ACK): **AVAILABLE** (read_to_ack_ms per row (t_ack-t_read); present in every native row)
- Percentile convention: `nearest`; entropy bin width: 0.5 ms
- Target-band tol: 0.0620 ms (p95 of |CLRT_out - D_R| over covered defended transactions (measured policies), symmetric target-band tolerance; n_covered=1130)
- Bootstrap B=2000, seed=20260807, sha256 verify=True; native rows excluded 54 (clean block-end FIN / reset / inconclusive), validated on EVERY row

## Constraints: evidenced vs UNKNOWN
- `response_timeout_ms`: 2000.0
- `poll_period_ms`: 400.0
- `tcp_rto_ms`: UNKNOWN
- `fail_open_horizon_ms`: UNKNOWN (not t_A-anchored in committed raw)
- `reservoir_horizon_ms`: UNKNOWN (R11 OPEN)
- ACK-delay risk is governed by **D_A** (not H); response-timeout and poll-period margins compare against **a + max(C, H)** (not H).
- Fail-open horizon: a 30.8 ms figure was asserted at budget 18000, but it is **NOT anchored to t_A in the committed raw** (no fail-open release at that horizon appears in the failopen blocks, which show normal ~10 ms normalization at budget 18000). It is therefore UNKNOWN and gates nothing.

## Native design distribution (C = t_R - t_A), paper pool [DEMONSTRATED]
- members: nat_off_frA, nat_off_frB (n=240)
- C: median 2.925, p95 7.500, p99 13.672, max 15.650 ms; p5-p95 spread 5.693 ms; entropy 3.16 bits (8.9 states)
- a (request->ACK): median 0.470, p95 2.221, max 5.243 ms
- validation pool (fixA+fixB, n=240): C median 2.900, p95 8.502, max 24.405 ms (heavier tail; see threats)

## Release error (eps_R - eps_A)
- `measured` values are from the exact hardware-measured (D_A,D_R) pair; any other policy uses the pooled-median ESTIMATE, labelled `estimate:*`.
- D_A=0,D_R=10: eps=0.0103 ms  [measured:def_D2_frA,def_D2_frB,def_D2_fixA,def_D2_fixB]
- D_A=4,D_R=10: eps=0.0007 ms  [measured:def_D4_frA,def_D4_frB,def_D4_fixA,def_D4_fixB,probe_da4_dr10]
- D_A=2,D_R=10: eps=0.0009 ms  [measured:probe_da2_dr10]
- D_A=2,D_R=4: eps=-0.0001 ms  [measured:probe_da2_dr4]
- D_A=4,D_R=12: eps=0.0010 ms  [measured:probe_da4_dr12]
- D_A=6,D_R=8: eps=0.0009 ms  [measured:probe_da6_dr8]
- pooled-median estimate (unmeasured policies) = 0.0009 ms

## Pareto table (DEMONSTRATED = hardware-measured; ANALYSIS = hardware-unmeasured)
| policy | status | H_ms | native_tail_coverage | coverage_wilson95 | visible_clrt_target_ms | target_band_coverage | ack_delay_ms | L_master_max_ms | added_resp_latency_max_ms | margin_response_timeout_ms | margin_poll_period_ms | margin_fail_open_ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D_A=0,D_R=10 | hardware-measured | 10 | 0.975 | [0.9465,0.9885] | 10 | 0.975 | 0 | 16.117 | 8.219 | 1983.9 | 383.9 | UNKNOWN |
| D_A=2,D_R=4 | hardware-measured | 6 | 0.8792 | [0.8319,0.9145] | 4 | 0.8833 | 2 | 16.107 | 4.219 | 1983.9 | 383.9 | UNKNOWN |
| D_A=2,D_R=10 | hardware-measured | 12 | 0.9792 | [0.9522,0.9911] | 10 | 0.9792 | 2 | 17.244 | 10.219 | 1982.8 | 382.8 | UNKNOWN |
| D_A=2,D_R=12 | analysis-selected, hardware-unmeasured | 14 | 0.9917 | [0.9701,0.9977] | 12 | 0.9917 | 2 | 19.244 | 12.219 | 1980.8 | 380.8 | UNKNOWN |
| D_A=3,D_R=11 | analysis-selected, hardware-unmeasured | 14 | 0.9917 | [0.9701,0.9977] | 11 | 0.9917 | 3 | 19.244 | 12.219 | 1980.8 | 380.8 | UNKNOWN |
| D_A=4,D_R=8 | analysis-selected, hardware-unmeasured | 12 | 0.9792 | [0.9522,0.9911] | 8 | 0.9792 | 4 | 17.244 | 10.219 | 1982.8 | 382.8 | UNKNOWN |
| D_A=4,D_R=10 | hardware-measured | 14 | 0.9917 | [0.9701,0.9977] | 10 | 0.9917 | 4 | 19.244 | 12.219 | 1980.8 | 380.8 | UNKNOWN |
| D_A=4,D_R=12 | hardware-measured | 16 | 1.0 | [0.9842,1.0000] | 12 | 1.0 | 4 | 21.244 | 14.219 | 1978.8 | 378.8 | UNKNOWN |
| D_A=4,D_R=14 | analysis-selected, hardware-unmeasured | 18 | 1.0 | [0.9842,1.0000] | 14 | 1.0 | 4 | 23.244 | 16.219 | 1976.8 | 376.8 | UNKNOWN |
| D_A=5,D_R=10 | analysis-selected, hardware-unmeasured | 15 | 0.9917 | [0.9701,0.9977] | 10 | 0.9917 | 5 | 20.244 | 13.219 | 1979.8 | 379.8 | UNKNOWN |
| D_A=5,D_R=11 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 11 | 1.0 | 5 | 21.244 | 14.219 | 1978.8 | 378.8 | UNKNOWN |
| D_A=6,D_R=8 | hardware-measured | 14 | 0.9917 | [0.9701,0.9977] | 8 | 0.9917 | 6 | 19.244 | 12.219 | 1980.8 | 380.8 | UNKNOWN |
| D_A=6,D_R=10 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 10 | 1.0 | 6 | 21.244 | 14.219 | 1978.8 | 378.8 | UNKNOWN |
| D_A=8,D_R=8 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 8 | 1.0 | 8 | 21.244 | 14.219 | 1978.8 | 378.8 | UNKNOWN |
| D_A=4,D_R=16 | analysis-selected, hardware-unmeasured | 20 | 1.0 | [0.9842,1.0000] | 16 | 1.0 | 4 | 25.244 | 18.219 | 1974.8 | 374.8 | UNKNOWN |
| D_A=2,D_R=14 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 14 | 1.0 | 2 | 21.244 | 14.219 | 1978.8 | 378.8 | UNKNOWN |

## Provisional selection (declared constraints)
- objective: min total horizon H, tie-break min D_A then min D_R
- constraints: coverage >= 0.99 (point estimate), D_R > 0, each KNOWN margin >= its bound; fail-open gate ACTIVE = False (horizon UNKNOWN)
- admissible policies: 12
- **selected**: D_A=2 ms, D_R=12 ms (H=14 ms) — **ANALYSIS-SELECTED, HARDWARE-UNMEASURED**
  - native coverage 0.9917 (Wilson95 [0.9701,0.9977]; validation pool 0.9875)
  - L_master = a + max(C,H) + eps: median 14.472 ms, p95 16.222 ms, max 19.244 ms (validation-pool max 24.857 ms) — NOT bounded by H
  - visible target 12 ms, ACK delay 2 ms, release-error eps 0.0009 ms [estimate:pooled_median_of_measured_band_eps]
  - response-timeout margin 1980.8 ms, poll-period margin 380.8 ms, ACK-vs-RTO margin UNKNOWN, fail-open margin UNKNOWN
- co-optimal at H=14 ms (equal coverage and horizon): (2,12) [ANALYSIS], (3,11) [ANALYSIS], (4,10) [DEMONSTRATED], (6,8) [DEMONSTRATED].
  - **The auto-selected 2,12 is HARDWARE-UNMEASURED.** Hardware-measured co-optimal alternative(s) at the same H exist: (4,10), (6,8). These are DEMONSTRATED and should be preferred if a hardware-attested policy is required; the min-D_A tie-break alone picks the unmeasured point.
- (4,10) D4 [DEMONSTRATED, evaluated, not auto-selected]: H=14 ms, coverage 0.9917, L_master max 19.244 ms, eps 0.0007 ms [measured:def_D4_frA,def_D4_frB,def_D4_fixA,def_D4_fixB,probe_da4_dr10], residual tail 0.0083

## UNKNOWN (not invented)
- `a` (request->ACK): AVAILABLE — this is NOT unknown; loaded per row.
- TCP RTO: UNKNOWN (not in committed raw; 0 retransmits observed). ACK-vs-RTO margin is therefore UNKNOWN and would compare against D_A, not H.
- Fail-open horizon: UNKNOWN (not t_A-anchored in committed raw).
- Reservoir horizon (R11): UNKNOWN (carried OPEN in the evidence freeze).
- UNPINNED registry fields: 30 (all `firmware`: relay firmware/config revision not in raw evidence).
