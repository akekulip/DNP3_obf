# Defense-4 timing-policy characterization

Selected and tested under declared constraints; **not** claimed optimal. Software/analysis only over committed raw evidence.

- Protection domain: SEL-751 Case-A (separate-ACK) outstation, READ, corrected binary 97175e7d
- Percentile convention: `nearest`; entropy bin width: 0.5 ms; target-band tol: 0.0482 ms (auto:D4_paper_p5_p95_spread)
- Bootstrap B=2000, seed=20260807, sha256 verify=True; native rows excluded 54 (clean block-end FIN / reset / inconclusive)

## Evidenced constraints
- `poll_period_ms`: 400.0
- `fail_open_horizon_ms_at_budget_18000`: 30.802139037433157
- `dnp3_response_timeout_ms`: 2000.0
- `tcp_rto_ms`: UNKNOWN (value not evidenced in committed raw; 0 retransmits observed up to ~18.8 ms applied hold)
- `reservoir_horizon_ms`: UNKNOWN (R11 carried OPEN in EXPERIMENTAL_EVIDENCE_FREEZE.md)
- `budget_to_failopen_horizon`: measured only at budget 18000 (30.8 ms); the budget sweep (failopen_*) shows shrinking budget shortens the horizon and collapses normalization when horizon < D_R

## Native design distribution (C = t_R - t_A), paper pool
- members: nat_off_frA, nat_off_frB (n=240)
- median 2.925, p95 7.500, p99 13.672, max 15.650 ms; p5-p95 spread 5.693 ms; entropy 3.16 bits (8.9 states)
- validation pool (fixA+fixB, n=240): median 2.900, p95 8.502, max 24.405 ms (heavier tail; see threats)

## Release error (eps_R - eps_A) from defended evidence
- D_A=0,D_R=10: eps=0.0103 ms  [measured:def_D2_frA,def_D2_frB,def_D2_fixA,def_D2_fixB]
- D_A=4,D_R=10: eps=0.0007 ms  [measured:def_D4_frA,def_D4_frB,def_D4_fixA,def_D4_fixB,probe_da4_dr10]
- D_A=2,D_R=10: eps=0.0009 ms  [measured:probe_da2_dr10]
- D_A=2,D_R=4: eps=-0.0001 ms  [measured:probe_da2_dr4]
- D_A=4,D_R=12: eps=0.0010 ms  [measured:probe_da4_dr12]
- D_A=6,D_R=8: eps=0.0009 ms  [measured:probe_da6_dr8]
- pooled median eps = 0.0009 ms (used for unmeasured policies)

## Pareto table
| policy | H_ms | native_tail_coverage | visible_clrt_target_ms | target_band_coverage | ack_delay_ms | added_resp_latency_max_ms | margin_fail_open_ms | margin_response_timeout_ms | reservoir_requirement |
|---|---|---|---|---|---|---|---|---|---|
| D_A=0,D_R=10 | 10 | 0.975 | 10 | 0.975 | 0 | 8.219 | 20.802 | 1990.0 | H_ms < fail_open_horizon; 10 < 30.8021 OK |
| D_A=2,D_R=4 | 6 | 0.8792 | 4 | 0.8833 | 2 | 4.219 | 24.802 | 1994.0 | H_ms < fail_open_horizon; 6 < 30.8021 OK |
| D_A=2,D_R=10 | 12 | 0.9792 | 10 | 0.9792 | 2 | 10.219 | 18.802 | 1988.0 | H_ms < fail_open_horizon; 12 < 30.8021 OK |
| D_A=2,D_R=12 | 14 | 0.9917 | 12 | 0.9917 | 2 | 12.219 | 16.802 | 1986.0 | H_ms < fail_open_horizon; 14 < 30.8021 OK |
| D_A=3,D_R=11 | 14 | 0.9917 | 11 | 0.9917 | 3 | 12.219 | 16.802 | 1986.0 | H_ms < fail_open_horizon; 14 < 30.8021 OK |
| D_A=4,D_R=8 | 12 | 0.9792 | 8 | 0.9792 | 4 | 10.219 | 18.802 | 1988.0 | H_ms < fail_open_horizon; 12 < 30.8021 OK |
| D_A=4,D_R=10 | 14 | 0.9917 | 10 | 0.9917 | 4 | 12.219 | 16.802 | 1986.0 | H_ms < fail_open_horizon; 14 < 30.8021 OK |
| D_A=4,D_R=12 | 16 | 1.0 | 12 | 1.0 | 4 | 14.219 | 14.802 | 1984.0 | H_ms < fail_open_horizon; 16 < 30.8021 OK |
| D_A=4,D_R=14 | 18 | 1.0 | 14 | 1.0 | 4 | 16.219 | 12.802 | 1982.0 | H_ms < fail_open_horizon; 18 < 30.8021 OK |
| D_A=5,D_R=10 | 15 | 0.9917 | 10 | 0.9917 | 5 | 13.219 | 15.802 | 1985.0 | H_ms < fail_open_horizon; 15 < 30.8021 OK |
| D_A=5,D_R=11 | 16 | 1.0 | 11 | 1.0 | 5 | 14.219 | 14.802 | 1984.0 | H_ms < fail_open_horizon; 16 < 30.8021 OK |
| D_A=6,D_R=8 | 14 | 0.9917 | 8 | 0.9917 | 6 | 12.219 | 16.802 | 1986.0 | H_ms < fail_open_horizon; 14 < 30.8021 OK |
| D_A=6,D_R=10 | 16 | 1.0 | 10 | 1.0 | 6 | 14.219 | 14.802 | 1984.0 | H_ms < fail_open_horizon; 16 < 30.8021 OK |
| D_A=8,D_R=8 | 16 | 1.0 | 8 | 1.0 | 8 | 14.219 | 14.802 | 1984.0 | H_ms < fail_open_horizon; 16 < 30.8021 OK |
| D_A=4,D_R=16 | 20 | 1.0 | 16 | 1.0 | 4 | 18.219 | 10.802 | 1980.0 | H_ms < fail_open_horizon; 20 < 30.8021 OK |
| D_A=2,D_R=14 | 16 | 1.0 | 14 | 1.0 | 2 | 14.219 | 14.802 | 1984.0 | H_ms < fail_open_horizon; 16 < 30.8021 OK |

## Provisional selection (declared constraints)
- objective: min total latency H, tie-break min D_A then min D_R
- constraints: coverage >= 0.99, fail-open margin >= 5.0 ms, D_R > 0
- admissible policies: 12
- **selected**: D_A=2 ms, D_R=12 ms (H=14 ms), native coverage 0.9917 (validation pool 0.9875), visible target 12 ms, ACK delay 2 ms, max added response latency 12.22 ms
- co-optimal at H=14 ms (equal coverage and total latency): (2,12), (3,11), (4,10), (6,8). These differ only in how H is split between ACK delay and visible target; the data-only cost cannot see the ordering-robustness margin that motivates a larger D_A, so the tested (4,10) is co-optimal here, not dominated.
- tested (4,10) [evaluated, not auto-selected]: H=14 ms, coverage 0.9917 (validation 0.9875), visible target 10 ms, eps 0.0007 ms, residual tail fraction 0.0083, fail-open margin 16.80 ms

## Unknowns (not invented)
- TCP RTO: UNKNOWN (not evidenced in committed raw); 0 retransmits observed.
- Reservoir horizon (R11): UNKNOWN (carried OPEN in the evidence freeze).
- UNPINNED registry fields: 30 (all `firmware`: relay firmware/config revision not in raw evidence).
