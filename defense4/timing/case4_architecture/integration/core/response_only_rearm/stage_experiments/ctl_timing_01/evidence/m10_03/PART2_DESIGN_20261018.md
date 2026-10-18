# Part 2: the timing-parameter experiment on m10_03, reconciled and prepared (2026-10-18)

**Status: prepared, not launched.**
- The grid's 50 configs exist and pass every check.
- The four-arm attacker is tested offline.
- `freeze_v3.json` binds only the six Step 4 configs, so `run_block_frozen.sh` refuses every Part 2 config ("not
  bound"; verified). Running them needs a freeze that names them, and Philip's authorization.
- The restart path stays model-proven, not exercised on silicon. m9 timing measurements stay inherited evidence.

## 1. What each knob does on m10_03 (verified against the frozen P4, source `d9b84fcc…`)

P = `m10_03/response_only.p4`. The clock is `md.now = global_tstamp[39:8] & 0xfffffffe` (P:1655): 256 ns units on a
512 ns grid. Durations are written as `ceil((ns + 512) / 256)` (`response_only/hw/t_config.py`:27-44).

| key | P use | controls | anchor | 950 µs configs |
|---|---|---|---|---|
| `da` | `da_delta` (P:2133, 2137) | minimum request→ACK | lane t0 (`t0_reg`) | 2 ms |
| `gap` = **D** | `gap_delta = (now − gap) − ack_commit_at_reg` (P:1819-1821, 2139) | ACK→response, the replacement CLRT | **a_commit**, the ACK's own release pass | 0.95 ms |
| `readiness` | `readiness_delta` (P:2138) | fallback for the ACK and the response | t0 | 30 ms |
| `pb` | `pb_delta` (P:2134-2136) | piggybacked-response bound | t0 | 4 ms |
| `op_j` = **J** | `op_delta` (P:2148-2150) | OPERATE command hold | `op_t0_reg` | 2.4 ms |
| `cap` | accepted, never stored (P:1520-1521) | nothing in the dataplane; a validator bound on readiness | — | 40 ms |
| `budget` | `ladder.budget`, decremented per lap (P:2054, 2085-2099) | blocker lap budget, in laps, not time | — | 240,000 (default) |

**Release rules.** A delta has "passed" when its sign bit is 0.
1. **ACK commits** when `da_delta` has passed **and** a response child of this generation has been seen. That pass
   writes a_commit (P:2198-2200, 2427-2429, 1822-1823).
2. **ACK fallback** when `readiness_delta` has passed. No a_commit is written (P:2201, 2430).
3. **Response** when the commit generation matches and `gap_delta` has passed, i.e. now ≥ a_commit + gap
   (P:2264, 2435). `gap` runs from the ACK's actual release pass, not from a precomputed deadline; the old
   `resp_deadline` register is gone (P:1848-1851).
4. **Response fallback** when `readiness_delta` has passed (P:2263, 2436).
5. **Piggyback:** no standalone ACK and `pb_delta` passed, then one lap (P:2265-2266, 2434). The lap is inferred from
   the table logic.
6. **OPERATE:** the command is held until op_t0 + J (P:2323, 2457). Its ACK and response lane is anchored at the
   OPERATE's arrival at T, the same `md.now` (P:1787, 2174), not at its release. That is why `op_j < pb` is
   required. The outstation sees the command only after J, and the ACK commits only once a response child has been
   seen (rule 1), so for OPERATE **request→ACK = max(da, J + L)**. On m9's combined arm, OPERATE's ACK median was
   7.9 ms against 5.5 ms for READ and SELECT (code review H1).

**Timeline, separate-ACK READ or SELECT** (L = outstation response latency):
- request at T at t0;
- the ACK is released at max(t0 + da, arrival of the response) plus at most one lap = a_commit;
- the response is released at a_commit + gap plus at most one lap;
- request→ACK = max(da, L) for READ and SELECT, and max(da, J + L) for OPERATE;
- ACK→response = gap: D, by construction from the ACK's actual release.

## 2. What the historical 5/10/15/20 ms were

Sources are `defense4/timing/latency_search/`: the 2026-09-26 fixed screen
(`evidence/screen_20260926T141505Z/`) and the 2026-09-27 matched grid
(`evidence/delay_grid/random_screen_20260927T021133Z/`).

| historical | meaning | on m10_03 | comparable? |
|---|---|---|---|
| DA ∈ {5, 10, 15, 20} ms (`d_ticks`) | request-anchored **ACK deadline** (`anchor_req=1`) | `da` | **yes**, same knob and anchor; the release rule differs (below) |
| gap = `da_dr − d_ticks` ≈ 1 ms (±0.5 random on 09-27; {1, 2, 4, 6, 8} ms on 09-26) | T_RESP − T_A, **both from the request** | `gap` = D, **from the ACK's actual release** | nominally equal only when the ACK leaves exactly at T_A and the response is early |
| J codebook {0.25, 0.5, 1} ms | OPERATE hold, randomized | `op_j` = 2.4 ms fixed | same knob; smaller there because J up to 12 ms was incompatible with DA = 5/10 (`README.md`:174) |
| budget 18,000 (H ≈ 30.8 ms) | fail-open horizon | `readiness` | analogous role; not the same mechanism (inference) |

**Build.** The 09-27 grid ran `randomized/defense4_timing_randomized.p4`, sha256 `8e6d0ad9…` (it matches its
`program_identity.json`). The 09-26 screen ran a different binary; its source hash could not be confirmed in the cited
evidence and is not stated here. Neither is m10_03.

**Behaviour that differs.**
- **Then:** the ACK left at its deadline whether or not the response had arrived (`OUT_AB_DL`). A late response was
  released about one blocker pass after it arrived (`OUT_RB_DL`), so its CLRT grew with its lateness. At DA 5 ms,
  8.5–12 % of responses were more than 1 ms late, and CLRT p99 reached 10.2 ms.
- **Now:** the ACK waits for max(da, response), and D starts at the ACK's release.

**Results then.** No policy passed (`grid_report.json`: `passing_policies: []`). From `grid_attacks.json`:
- the primary ACK/CLRT attack set, three-class maximum balanced accuracy: da5 0.553, da10 0.654, da15 0.423,
  da20 0.429, against a threshold of 0.383;
- the all-timing diagnostic attack set (`ack_clrt_gap`, adaptive): da5 0.988, da10 0.993, da15 0.999, da20 0.999.

CLRT medians were 0.86–1.17 ms.

**Who set them.** The preregistered 2026-09-26 objective was to minimize the worst added median latency at
balanced accuracy ≤ chance + 0.05 (commit `ada190a44`). Philip chose da5/gap1 for the focused study. The four values
then carried into the response-ready and Case 4 plans.

**Reconciliation.**
- The historical numbers are request→ACK deadlines, so the comparable current axis is `da`, with D held at 1 ms (the
  historical CLRT centre).
- A separate axis shows that D itself is configurable.
- The comparison is with the same knob under a different release rule. It is never a replication of the historical
  runs.

## 3. Supported range and the constraints

- **Validators** (`protocol/hw_vepa/campaign.py`:103-114, `t_config.py`:194-210):
  - op_j < pb < readiness;
  - da < readiness ≤ cap;
  - each of da, readiness, cap, gap and op_j in (0, 1 s);
  - every value < 2^31 T units.
- **Required by the implementation, and checked by no validator.** readiness ≥ max(da, L + J) + gap + slack, the
  J term covering OPERATE. Below it, the readiness fallback releases the response before a_commit + gap, and the
  condition no longer measures D. `seg61_02/hw/part2_grid.py` checks this with L read from each config's fixture and
  slack = 5 ms. The slack is a stated margin for lap and shaping granularity, not a measured bound. This is a new check,
  not a loosened one.
- **One fixture delay.** Every Part 2 config uses L = 5 ms (`check_config` fails any other). The rotation templates
  carry 5, 3 and 8 ms by block. Under leave-one-block-out, that hides even the undefended baseline's leak (section 7).
- **Arithmetic is not a limit:**
  - the clock wraps every ≈ 1,099.5 s;
  - sign-bit comparisons are valid below ≈ 549.8 s.
- **Load:** ACK-blocker lifetime grows with da, and response-blocker lifetime with gap. Recirculation work grows with
  both. The lap budget (240,000) is counted in laps, not time.
- **Not yet measured, so the feasibility gate checks it:** endpoint timeouts at da + gap up to 21 ms; whether a
  control-timed SELECT also waits gap before its OPERATE.

## 4. The grid (`part2_grid.CONDITIONS`)

| condition | da | D = gap | readiness | pb = da + gap | purpose |
|---|---|---|---|---|---|
| ref_r30 | 2 ms | 0.95 ms | 30 ms | 2.95 ms | the qualified setting, unchanged |
| ref_r40 | 2 ms | 0.95 ms | 40 ms | 2.95 ms | the same at the grid's readiness |
| da05_g100 … da20_g100 | 5 / 10 / 15 / 20 ms | 1 ms | 40 ms | da + 1 ms | axis 1: the historical request→ACK values |
| da10_g095 … da10_g800 | 10 ms | 0.95 / 2 / 4 / 8 ms | 40 ms | 10 ms + gap | axis 2: D is configurable |

Fixed across the grid: J = 2.4 ms, cap = 40 ms, the shaping preset `shape_59570`, the fixture (separate ACK, L = 5 ms in
every block) and the workload.

**Whether request→ACK is nominally normalized** (`part2_grid.normalizes`, strict inequality; lap and shaping
overhead not modelled):

| condition | READ / SELECT (da > L) | OPERATE (da > L + J = 7.4 ms) |
|---|---|---|
| ref_r30, ref_r40 (da 2 ms) | no | no |
| da05_g100 | **no**: equality is not enough; on m9 at L = 5 ms the median was about 5.45 ms, above da | no |
| da10, da15, da20 | yes (nominal) | yes (nominal) |

In the conditions marked "no", request→ACK still carries outstation latency, and for OPERATE also J. The attacker's
request→ACK feature can use it, and the result is reported per kind.

**Confounds, stated rather than hidden:**
- **Readiness.** Readiness is 40 ms, not the qualified 30 ms, so that it is not a hidden variable (30 ms would leave
  4 ms at da 20). The reference therefore runs at both 30 and 40 ms.
- **pb.** pb differs across conditions (= da + gap). This keeps piggyback request→response comparable to separate-ACK
  request→response.
- **da 5 ms.** This sits at the fixture's own L = 5 ms. Request→ACK is not normalized there for any kind: READ and
  SELECT ran at about 5.45 ms on m9, above da. It is kept and reported as the boundary condition.
- **J.** J is fixed at the qualified 2.4 ms and not randomized as the historical codebook was.
- **Rotation.** Three blocks over four arms is not a full Latin square. Some arm positions never occur; for example,
  `off` is never last. This is inherited from `repeat_orders` and stated here.

## 5. Feasibility gate (one READ and one SBO block per condition, combined arm)

Configs `part2_m10_feas_{read,sbo}_<condition>.json`:
- a persistent READ, 20 reads;
- a repeated SBO, 16 cycles, 17 reads.

Each must show:
- the 61-octet responses (the standards checker);
- delivery exactly once;
- measured ACK→response against gap, and request→ACK against max(da, L);
- OPERATE hold J;
- `ACK_COMMIT`/`RESP_RELEASE` counted apart from `ACK_FALLBACK`/`RESP_FALLBACK` (any fallback means the
  condition did not measure D);
- retransmissions, `max_token_stale` 0, and the internal work counters.

Verdict per condition: feasible, infeasible (with its cause), or indeterminate. An infeasible condition is
reported, never rescued by changing a bound.

## 6. The paper experiment (specified; prepared; not launched)

- **Arms:** baseline (Timing OFF, no padding), size_only, timing_only, combined.
  - Configs: `part2_m10_<condition>_b{1,2,3}.json`.
  - Three blocks per condition, in the existing Latin rotation (`repeat_orders`).
  - Repeated-SBO workload: 65 reads, 64 cycles, on one pinned build.
- **Attacker:** `seg61_02/analysis/leakage_four_arm.py`.
  - campaign_v2's estimators, imported unchanged.
  - **Competence gate.** For each feature set, the fixed attacker must exceed chance + 0.05 on the undefended baseline.
    Otherwise that comparison is reported as UNINFORMATIVE, because a defended arm at chance would say nothing. The
    margin is borrowed from the 2026-09-26 preregistration, where it bounded the defense; here it is the attacker's
    competence floor.
  - **Adaptive anomaly flag.** An adaptive attacker mean below chance − 0.05 is listed under `adaptive_anomalies`,
    a sign of a cross-block shift, never reported as a plain score.
  - Fixed attacker: trained on baseline and applied to every arm. Adaptive attacker: retrained per defended arm.
  - MI against a within-run permutation null.
  - Leave-one-block-out folds. No confidence interval.
- **Table:** `seg61_02/analysis/four_arm_transactions.py` builds the attacker's table from each block's per-arm
  `timing.json`. The intervals are host-capture-point times. Every excluded exchange is counted per block and arm
  in `*.counts.json`. Retransmitted exchanges are kept and flagged (`retransmitted`), never silently dropped.
- **Commands per condition:**
  ```bash
  python3 four_arm_transactions.py <cond>.csv hw_campaigns/part2_m10_<cond>_b{1,2,3}_01
  python3 leakage_four_arm.py <cond>.csv <cond>_leakage.json
  ```
- **Reporting:**
  - every tail and failure is kept;
  - timing precision, application correctness and classifier effectiveness are reported separately;
  - host-observed timing is reported beside the inherited switch-side figures, labelled as such;
  - classifier results are scoped to the evaluated Random-Forest attackers;
  - results are transaction-class timing, not device identification.
- **Power, a decision for Philip.** Three blocks give three leave-one-block-out folds per condition. That is few, and
  the held-out-run spread will be wide. No figure is given here: the only four-arm silicon data available (section 7)
  varied L by block, so its spread does not measure the effect of the fold count. More blocks per condition would add
  folds, at proportionally more silicon time.

## 7. Offline tests of the attacker (done)

1. **The two-arm restriction equals campaign_v2.** Restricted to baseline and timing_only, `leakage_four_arm.py`
   reproduces `leakage_campaign.py` number for number on campaign_v2's canonical table: MI, every classifier spread,
   and the confusion matrices. Details:
   - table: 63,360 exchanges, sha256 `80da305c…`;
   - test `test_two_arm_restriction_equals_campaign_v2`, opt-in with `LEAKAGE_REPRO=1`;
   - 30 permutations on both sides;
   - passed (94.7 s), and again after the review fixes (103.2 s; spreads compared except their interpretation text).
2. **Synthetic four-arm data.** Tested properties:
   - the fixed attacker separates the leaky arms from the defended ones;
   - MI exceeds the null on a leaky arm and stays inside it on a defended arm;
   - a missing arm-block is skipped and counted;
   - campaign_v2's arm labels map to the four-arm names;
   - a table without baseline is refused.
3. **Pipeline on real four-arm silicon data.** m9's three ACK-diagnostic control blocks (`ctl_m9_ackdiag_ctrl_b{1,2,3}_01`,
   m9_01 build, 2,316 exchanges, none excluded) went through the adapter and the analysis. The workload is Part 2's,
   but the build differs, and the fixture delay was 5, 3 and 8 ms by block. Two things it showed:
   - **The code path runs end to end.**
   - **The design flaw C1, and the gate that catches it.** The CLRT-only comparison is flagged UNINFORMATIVE: the
     fixed attacker scores 0.333 on the undefended baseline although baseline MI is 0.233 bits, because each held-out
     block's CLRT is shifted by its own L. The request→ACK + CLRT comparison passes the gate (0.531).

   None of these numbers is a Part 2 result.
4. **The competence gate on synthetic data.** A per-block offset makes the comparison uninformative; without one, it
   is informative.

## 8. Order, when authorized

1. A freeze naming the Part 2 configs (freeze v3 binds only the Step 4 six).
2. The feasibility gate, all ten conditions.
3. The campaign, feasible conditions only, three blocks each, in rotation.
4. The analysis above, one table per condition.

Each step is detached through `run_block_frozen.sh`, with restore_verify and the stop rule on an unverified restore.
No default promotion.
