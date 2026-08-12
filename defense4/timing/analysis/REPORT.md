# Defense-4 timing-policy characterization

Reports one common-domain policy **analysis candidate** under a declared **point-estimate** coverage rule. It is **NOT** confidence-qualified merely by clearing the point estimate, **NOT** claimed optimal, and **NOT** hardware-selected. Software/analysis only over committed raw evidence. Every candidate is labelled DEMONSTRATED (hardware-measured) vs ANALYSIS-ONLY, and every unavailable constraint is left UNKNOWN.

- Protection domain: SEL-751 Case-A (separate-ACK) outstation, READ, corrected binary 97175e7d
- Latency model (FIX 1): `L_master(measured) = directly observed read_to_resp_ms (t_resp-t_read); L_master(analysis-only) = a + max(C,H) MODELLED FLOOR, absolute release error eps_R UNKNOWN. CLRT_out = max(C-D_A,D_R) + (eps_R-eps_A) differential.`
- `a` = t_A - t_Q (request->ACK): **AVAILABLE** (read_to_ack_ms per row (t_ack-t_read); present in every native row)
- Percentile convention: `nearest`; entropy bin width: 0.5 ms
- Target-band tol: 0.0620 ms (**CONDITIONAL jitter, NOT total coverage**; CONDITIONAL jitter: p95 of |CLRT_out - D_R| over the normalized band of covered defended transactions (measured policies). NOT total coverage; the untruncated pooled quantile and the dropped-tail fraction are reported alongside, and native P(C<=H) pairs each policy.)
- Bootstrap B=2000, seed=20260807, sha256 verify=True; native rows excluded 54 (clean block-end FIN / reset / inconclusive), validated on EVERY row

## Master-visible latency L_master (FIX 1)
- Measured policies use the **directly observed** per-row request->response latency `read_to_resp_ms = t_resp - t_read` (provenance-checked against the raw timestamps on every row).
- Analysis-only policies use the **modelled floor** `a + max(C, H)`; the absolute response release error eps_R is **UNKNOWN**. The differential eps = (eps_R - eps_A) is kept ONLY in the observer-visible CLRT_out and is **never** added to L_master.
- Directly observed L_master (measured policies):
  - D_A=0,D_R=10: n=240, median 10.501, p95 13.032, max 17.057 ms
  - D_A=2,D_R=4: n=40, median 6.556, p95 9.834, max 16.317 ms
  - D_A=2,D_R=10: n=40, median 12.495, p95 13.439, max 14.849 ms
  - D_A=4,D_R=10: n=240, median 14.493, p95 15.695, max 23.270 ms
  - D_A=4,D_R=12: n=40, median 19.682, p95 20.502, max 20.636 ms
  - D_A=6,D_R=8: n=40, median 14.479, p95 15.457, max 18.116 ms

## Constraints: evidenced vs UNKNOWN (FIX 4 provenance)
- `dnp3_response_timeout_ms`: UNKNOWN (no OpenDNP3 master in evidence path; raw-socket driver, no DNP3 app timeout)
- `master_socket_recv_timeout_ms`: 4000.0
- `poll_period_ms`: 400.0
- `tcp_rto_ms`: UNKNOWN
- `fail_open_horizon_ms`: UNKNOWN (not t_A-anchored in committed raw)
- `reservoir_horizon_ms`: UNKNOWN (R11 OPEN)
- The timing evidence was produced by the **raw-socket** driver `defense4/timing/control/deploy/campaign_driver.py` (hand-crafted DNP3 READ over `socket.SOCK_STREAM`). Its **socket recv timeout of 4000 ms** (line 80) is the evidenced response-wait ceiling; the **DNP3 application response timeout is UNKNOWN** (no OpenDNP3 master in this path; 2000 ms is neither a DNP3 protocol constant nor the OpenDNP3 3.1.2 default).
- ACK-delay risk is governed by **D_A** (not H); response-wait and poll-period margins compare against **a + max(C, H)** / the directly observed L_master (not H).
- Fail-open horizon: a 30.8 ms figure was asserted at budget 18000, but it is **NOT anchored to t_A in the committed raw** (the failopen blocks show normal ~10 ms normalization at budget 18000). It is UNKNOWN and gates nothing.

## Native design distribution (C = t_R - t_A), paper pool [DEMONSTRATED]
- members: nat_off_frA, nat_off_frB (n=240)
- C: median 2.925, p95 7.500, p99 13.672, max 15.650 ms; p5-p95 spread 5.693 ms; entropy 3.16 bits (8.9 states)
- a (request->ACK): median 0.470, p95 2.221, max 5.243 ms
- validation pool (fixA+fixB, n=240): C median 2.900, p95 8.502, max 24.405 ms (heavier tail; see threats)

## Release error (eps_R - eps_A) [DIFFERENTIAL, observer-visible only]
- `measured` values are from the exact hardware-measured (D_A,D_R) pair; any other policy uses the pooled-median ESTIMATE, labelled `estimate:*`. Used ONLY in the observer-visible CLRT_out; **never** added to the absolute L_master (FIX 1).
- D_A=0,D_R=10: eps=0.0103 ms  [measured:def_D2_frA,def_D2_frB,def_D2_fixA,def_D2_fixB]
- D_A=4,D_R=10: eps=0.0007 ms  [measured:def_D4_frA,def_D4_frB,def_D4_fixA,def_D4_fixB,probe_da4_dr10]
- D_A=2,D_R=10: eps=0.0009 ms  [measured:probe_da2_dr10]
- D_A=2,D_R=4: eps=-0.0001 ms  [measured:probe_da2_dr4]
- D_A=4,D_R=12: eps=0.0010 ms  [measured:probe_da4_dr12]
- D_A=6,D_R=8: eps=0.0009 ms  [measured:probe_da6_dr8]
- pooled-median estimate (unmeasured policies) = 0.0009 ms

## Target-band jitter (FIX 2): conditional vs untruncated, paired with native P(C<=H)
- pooled CONDITIONAL |CLRT_out - D_R| p95: 0.0620 ms over 1130 in-band transactions (this is the band half-width; NOT coverage).
- pooled UNTRUNCATED |CLRT_out - D_R| p95: 0.0758 ms over 1160 transactions (dropped-tail fraction 0.0259).
  - def_D2_frA (D_A=0,D_R=10): cond p95=0.0720 ms, untrunc p95=0.0889 ms, out-of-band 0.0417, paired native P(C<=H)=0.9750
  - def_D2_frB (D_A=0,D_R=10): cond p95=0.0732 ms, untrunc p95=0.0780 ms, out-of-band 0.0417, paired native P(C<=H)=0.9750
  - def_D2_fixA (D_A=0,D_R=10): cond p95=0.0632 ms, untrunc p95=0.0760 ms, out-of-band 0.0417, paired native P(C<=H)=0.9750
  - def_D2_fixB (D_A=0,D_R=10): cond p95=0.0820 ms, untrunc p95=0.0920 ms, out-of-band 0.0333, paired native P(C<=H)=0.9750
  - def_D4_frA (D_A=4,D_R=10): cond p95=0.0281 ms, untrunc p95=0.0300 ms, out-of-band 0.0167, paired native P(C<=H)=0.9917
  - def_D4_frB (D_A=4,D_R=10): cond p95=0.0298 ms, untrunc p95=0.0301 ms, out-of-band 0.0083, paired native P(C<=H)=0.9917
  - def_D4_fixA (D_A=4,D_R=10): cond p95=0.0291 ms, untrunc p95=0.0310 ms, out-of-band 0.0167, paired native P(C<=H)=0.9917
  - def_D4_fixB (D_A=4,D_R=10): cond p95=0.0470 ms, untrunc p95=0.0470 ms, out-of-band 0.0000, paired native P(C<=H)=0.9917
  - probe_da2_dr10 (D_A=2,D_R=10): cond p95=0.0431 ms, untrunc p95=0.0482 ms, out-of-band 0.0250, paired native P(C<=H)=0.9792
  - probe_da2_dr4 (D_A=2,D_R=4): cond p95=0.1430 ms, untrunc p95=2.7341 ms, out-of-band 0.1250, paired native P(C<=H)=0.8792
  - probe_da4_dr10 (D_A=4,D_R=10): cond p95=0.0310 ms, untrunc p95=0.0310 ms, out-of-band 0.0000, paired native P(C<=H)=0.9917
  - probe_da4_dr12 (D_A=4,D_R=12): cond p95=0.0250 ms, untrunc p95=0.0250 ms, out-of-band 0.0000, paired native P(C<=H)=1.0000
  - probe_da6_dr8 (D_A=6,D_R=8): cond p95=0.0280 ms, untrunc p95=0.0280 ms, out-of-band 0.0000, paired native P(C<=H)=0.9917

## Pareto table (DEMONSTRATED = hardware-measured; ANALYSIS = hardware-unmeasured)
| policy | status | H_ms | native_tail_coverage | coverage_wilson95 | visible_clrt_target_ms | target_band_coverage | ack_delay_ms | L_master_max_ms | L_master_kind | margin_master_recv_timeout_ms | margin_poll_period_ms | margin_fail_open_ms |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D_A=0,D_R=10 | hardware-measured | 10 | 0.975 | [0.9465,0.9885] | 10 | 0.975 | 0 | 17.057 | measured | 3982.9 | 382.9 | UNKNOWN |
| D_A=2,D_R=4 | hardware-measured | 6 | 0.8792 | [0.8319,0.9145] | 4 | 0.8833 | 2 | 16.317 | measured | 3983.7 | 383.7 | UNKNOWN |
| D_A=2,D_R=10 | hardware-measured | 12 | 0.9792 | [0.9522,0.9911] | 10 | 0.9792 | 2 | 14.849 | measured | 3985.2 | 385.2 | UNKNOWN |
| D_A=2,D_R=12 | analysis-selected, hardware-unmeasured | 14 | 0.9917 | [0.9701,0.9977] | 12 | 0.9917 | 2 | 19.243 | floor | 3980.8 | 380.8 | UNKNOWN |
| D_A=3,D_R=11 | analysis-selected, hardware-unmeasured | 14 | 0.9917 | [0.9701,0.9977] | 11 | 0.9917 | 3 | 19.243 | floor | 3980.8 | 380.8 | UNKNOWN |
| D_A=4,D_R=8 | analysis-selected, hardware-unmeasured | 12 | 0.9792 | [0.9522,0.9911] | 8 | 0.9792 | 4 | 17.243 | floor | 3982.8 | 382.8 | UNKNOWN |
| D_A=4,D_R=10 | hardware-measured | 14 | 0.9917 | [0.9701,0.9977] | 10 | 0.9917 | 4 | 23.270 | measured | 3976.7 | 376.7 | UNKNOWN |
| D_A=4,D_R=12 | hardware-measured | 16 | 1.0 | [0.9842,1.0000] | 12 | 1.0 | 4 | 20.636 | measured | 3979.4 | 379.4 | UNKNOWN |
| D_A=4,D_R=14 | analysis-selected, hardware-unmeasured | 18 | 1.0 | [0.9842,1.0000] | 14 | 1.0 | 4 | 23.243 | floor | 3976.8 | 376.8 | UNKNOWN |
| D_A=5,D_R=10 | analysis-selected, hardware-unmeasured | 15 | 0.9917 | [0.9701,0.9977] | 10 | 0.9917 | 5 | 20.243 | floor | 3979.8 | 379.8 | UNKNOWN |
| D_A=5,D_R=11 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 11 | 1.0 | 5 | 21.243 | floor | 3978.8 | 378.8 | UNKNOWN |
| D_A=6,D_R=8 | hardware-measured | 14 | 0.9917 | [0.9701,0.9977] | 8 | 0.9917 | 6 | 18.116 | measured | 3981.9 | 381.9 | UNKNOWN |
| D_A=6,D_R=10 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 10 | 1.0 | 6 | 21.243 | floor | 3978.8 | 378.8 | UNKNOWN |
| D_A=8,D_R=8 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 8 | 1.0 | 8 | 21.243 | floor | 3978.8 | 378.8 | UNKNOWN |
| D_A=4,D_R=16 | analysis-selected, hardware-unmeasured | 20 | 1.0 | [0.9842,1.0000] | 16 | 1.0 | 4 | 25.243 | floor | 3974.8 | 374.8 | UNKNOWN |
| D_A=2,D_R=14 | analysis-selected, hardware-unmeasured | 16 | 1.0 | [0.9842,1.0000] | 14 | 1.0 | 2 | 21.243 | floor | 3978.8 | 378.8 | UNKNOWN |

## Coverage verdict and analysis candidate (FIX 3: confidence-aware)
- objective: min total horizon H, tie-break min D_A then min D_R; POINT-ESTIMATE admissibility (coverage point >= min)
- point-estimate admissible: 12; confidence-qualified (Wilson lower >= 0.99 at 95%): 0; max Wilson lower over admissible = 0.9842
- **coverage verdict**: NO candidate establishes coverage >= 0.99 at 95% confidence (max Wilson lower bound 0.9842 over point-admissible candidates). The min-H point-estimate winner is an ANALYSIS CANDIDATE only; more samples or a larger H are required to qualify at confidence.
- confidence-qualified selection: **NONE** — no candidate establishes the threshold at confidence; more samples or a larger H are required.
- **analysis candidate under the point-estimate coverage >= 0.99 rule**: D_A=2 ms, D_R=12 ms (H=14 ms) — **ANALYSIS-SELECTED, HARDWARE-UNMEASURED**, confidence-qualified=False
  - native coverage 0.9917 (Wilson95 [0.9701,0.9977]; validation pool 0.9875) — the Wilson lower bound is the promotion gate, not the point estimate
  - L_master (modelled floor): median 14.471 ms, p95 16.221 ms, max 19.243 ms (validation-pool max 24.856 ms); release error: UNKNOWN (absolute eps_R not isolable from committed raw)
  - visible target 12 ms, ACK delay 2 ms, differential eps 0.0009 ms [estimate:pooled_median_of_measured_band_eps] (CLRT_out only)
  - master-recv-timeout margin 3980.8 ms (DNP3 app-timeout margin UNKNOWN), poll-period margin 380.8 ms, ACK-vs-RTO margin UNKNOWN, fail-open margin UNKNOWN
- co-optimal at H=14 ms (equal coverage and horizon): (2,12) [ANALYSIS], (3,11) [ANALYSIS], (4,10) [DEMONSTRATED], (6,8) [DEMONSTRATED].
  - **The point-estimate candidate 2,12 is HARDWARE-UNMEASURED.** Hardware-measured co-optimal alternative(s) at the same H exist: (4,10), (6,8). These are DEMONSTRATED and should be preferred if a hardware-attested policy is required; the min-D_A tie-break alone picks the unmeasured point.
- (4,10) D4 [DEMONSTRATED, evaluated, not auto-selected]: H=14 ms, coverage 0.9917, L_master max 23.270 ms (measured-direct), differential eps 0.0007 ms [measured:def_D4_frA,def_D4_frB,def_D4_fixA,def_D4_fixB,probe_da4_dr10], residual tail 0.0083

## UNKNOWN (not invented)
- `a` (request->ACK): AVAILABLE — this is NOT unknown; loaded per row.
- DNP3 application response timeout: UNKNOWN (raw-socket driver produced the evidence; the evidenced ceiling is the 4000 ms socket recv timeout instead).
- Absolute response release error eps_R (for analysis-only L_master): UNKNOWN (only the differential eps_R-eps_A is measurable, and it is not an absolute term).
- TCP RTO: UNKNOWN (not in committed raw; 0 retransmits observed). ACK-vs-RTO margin is therefore UNKNOWN and would compare against D_A, not H.
- Fail-open horizon: UNKNOWN (not t_A-anchored in committed raw).
- Reservoir horizon (R11): UNKNOWN (carried OPEN in the evidence freeze).
- UNPINNED registry fields: 30 (all `firmware`: relay firmware/config revision not in raw evidence).
