# D5 parameter calibration

## ►► CORRECTION (2026-08-07)
Section 3 below framed D2's non-shaping as "structural for Case A ... a claim boundary, not a defect."
That framing is WITHDRAWN. D2's non-shaping is an OPEN `tag_retire_if_unmarked` lifecycle defect (the
ACK release retires the transaction before the response is pending), the same defect that causes the
D4 bypass fraction; the frozen Defense 2 held responses 200/200, so it is fixable, not inherent. The
Section 4 D4 entry ("CLRT normalized to about 8.00 ms") is also corrected: across n=240, D4 is a
mixture, 160/240 held at ~8 ms and 80/240 (33%) bypassing at native (p25 3.06, p50 8.00, p99 11.09).
The selected D4 D_A of 4 ms does not cover the native response tail; the next run must raise the ACK
deadline to cover it and fix the retire logic. The tables below are retained as the measured data.


All values below come from live campaigns on the deployed `defense4_caseA` binary (sha256
`0ec4e452...`) against the physical SEL-751, using the corrected harness (sustained connections,
one-time initialize, per-block set-policy, real millisecond parameters via the quantization
authority). Raw evidence: `campaign_d5_pilot_20260807T031231Z/` (native) and
`campaign_d5_grid_20260807T031538Z/` (grid). Delays are reported as configured and realized;
no delay is called optimal.

## 1. Native OFF distribution (n = 120, sustained connections, 2 blocks)

| quantity | median | p5 | p95 | p99 | max | IQR | mean | sd |
|---|---|---|---|---|---|---|---|---|
| CLRT (ACK to RESPONSE), ms | 2.871 | 1.805 | 6.993 | 12.212 | 14.279 | [2.770, 4.127] | 3.466 | 1.906 |
| READ to ACK, ms | 0.462 | 0.402 | 1.515 | 2.422 | 3.542 | [0.442, 0.522] | 0.726 | 0.539 |
| READ to RESPONSE, ms | 3.366 | 2.313 | 7.524 | 13.704 | 15.721 | [3.266, 4.647] | 4.191 | 2.001 |

Session to session variation is small (block medians 2.861 and 2.892 ms). Reliability: 120/120
responded, 0 retransmissions, 0 duplicates, 0 resets, 0 missing ACK. This native CLRT median of
2.871 ms agrees with the frozen Defense 3 campaign value of 2.828 ms (`defense3/REPORT.md`).

Bounds that constrain the grid: the poll interval is 400 ms, the parameter policy maximum delay
is about 24.8 ms (poll overlap), and the fail-open horizon at budget 18000, K=64 is about 30.8 ms.
So delays in the single-digit-millisecond range sit far inside every safety bound.

## 2. Grid results (N = 30 per block; what each deadline actually does)

| block | mode | D_A ms | D_R ms | CLRT median (ms) | CLRT p95 | READ to RESP median | deadline releases | RESP held | RESP bypass |
|---|---|---|---|---|---|---|---|---|---|
| d2_dr4 | D2 | 0 | 4 | 3.00 | 11.36 | 3.90 | 0 | 0 | 30 |
| d2_dr6 | D2 | 0 | 6 | 2.79 | 7.35 | 3.31 | 0 | 0 | 30 |
| d2_dr8 | D2 | 0 | 8 | 3.02 | 11.96 | 3.55 | 0 | 0 | 30 |
| d2_dr10 | D2 | 0 | 10 | 2.92 | 7.13 | 3.38 | 0 | 0 | 30 |
| d3_da4 | D3 | 4 | 0 | 0.03 | 2.96 | 4.55 | 25 | n/a | n/a |
| d3_da8 | D3 | 8 | 0 | 0.03 | 0.04 | 8.52 | 29 | n/a | n/a |
| d4_2_6 | D4 | 2 | 6 | 2.07 | 6.01 | 4.79 | 11 | 11 | 19 |
| d4_4_8 | D4 | 4 | 8 | **8.00** | **8.01** | 12.48 | 22 | 22 | 8 |
| d1_3_3 | D1 | 3 | 3 | 3.22 | 4.21 | 6.52 | 30 | n/a | n/a |

"RESP held" and "RESP bypass" are the per-block deltas of the `RESP_HOLD_EARLY` and `RESP_BYPASS`
counters read from the switch.

## 3. Load-bearing finding: D2 alone does not shape a Case-A RESPONSE

Across all four D2 blocks (120 transactions, D_R from 4 to 10 ms) the switch counters show
`RESP_BYPASS += 30` and `RESP_HOLD_EARLY += 0` in every block, `deadline_release = 0`, and qid4
never occupied. The CLRT stays at the native value regardless of D_R. This is structural, not a
magnitude problem: with D_A = 0 the held ACK is released immediately at its native arrival (about
0.46 ms after the READ), which retires the transaction (`ACK_REL_RETIRE`) before the RESPONSE
arrives about 2.9 ms later. The now-inactive transaction then classifies the RESPONSE as
`RESP_BYPASS` and forwards it unshaped. For a Case-A separate-ACK device, where the ACK always
precedes the RESPONSE, response-deadline shaping therefore requires the ACK to be held long enough
for the RESPONSE to arrive and be marked, which is exactly what D4 does. D2 as specified (immediate
ACK, held RESPONSE) is not effective for Case A and is recorded as a claim boundary, not a defect
to force away. This is preserved, not hidden.

By contrast d4_4_8 holds 22 of 30 responses (`RESP_HOLD_EARLY += 22`, `RESP_BYPASS += 8`), because
its 4 ms ACK hold keeps the transaction active until the RESPONSE arrives; the 8 bypasses are the
native tail whose RESPONSE arrives after T_RESP = 12 ms (native READ to RESP p95 is 7.5 ms, p99
13.7 ms).

## 4. Selected campaign values (calibrated and tested, not optimal)

| mode | configured | realized | what it produces |
|---|---|---|---|
| D3 (ACK deadline) | D_A = 8 ms, D_R = 0 | D_A word 7,999,744 ns | ACK held to about 8 ms; CLRT collapses to about 0.03 ms; READ to RESP normalized to about 8.5 ms |
| D4 (dual deadline) | D_A = 4 ms, D_R = 8 ms | words 3,999,744 / 11,999,744 ns | flagship: CLRT normalized to about 8.00 ms with p95 8.01 ms (native median 2.87, p95 6.99); 22/30 responses held to the deadline |
| D1 (event) | D_A = 3 ms, D_R = 3 ms | word 2,999,808 ns | ACK held to the RESPONSE event; CLRT about 3.2 ms |
| D2 (response deadline) | D_A = 0, D_R = 8 ms | word 0 / 7,999,744 ns | recorded but does not shape a Case-A RESPONSE (all bypass); kept in the statistical campaign to document the boundary |
| OFF | none | none | native passthrough baseline |

All selected delays satisfy low byte zero, da_dr below 2^31, da_dr below the 400 ms poll interval,
and da_dr below the fail-open horizon and the 24.8 ms policy maximum. These values feed the D6
statistical campaigns and the D4 per-mode validation.
