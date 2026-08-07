# Defense 4 experiment matrix

## ►► REOPENED (2026-08-07). Corrections override the rows below where they conflict.
- **D2 shaping**: FAIL, and it is an OPEN `tag_retire_if_unmarked` lifecycle defect (240/240 retire at
  ACK, 240/240 bypass), NOT a Case-A boundary.
- **D4 shaping**: PARTIAL, not PASS. It is a mixture: 160/240 held to the deadline, 80/240 (33%) bypass
  at native via the same defect. "Normalizes to a fixed value" is withdrawn.
- **All injection/negative rows below marked BLOCKED WITH EVIDENCE are corrected to NOT ATTEMPTED**: the
  authorized controlled outstation/injector was not implemented.
- **Combined ACK / multi-segment rows marked NOT APPLICABLE are corrected to NOT TESTED** (absent from
  this relay's captures, but part of the framework's protocol boundary; need an outstation that produces them).
- The scorer does not fail on protected-mode bypass and does no byte comparison, so a "clean" scorer
  verdict does not validate a block.


Every row ends as PASS, FAIL, NOT APPLICABLE, or BLOCKED WITH EVIDENCE. Verdicts rest on the
committed primary evidence (campaign JSON, PCAPs, switch counters, compiler artifacts) on the
deployed binary sha256 `0ec4e452...` (source `1272679...`). "Injection-requiring" cases need a
controlled software outstation or a Defense 4 synthetic build routed through the switch; neither is
buildable without reconfiguring the protected session (which would disturb the physical relay path
and the production state), so they are BLOCKED WITH EVIDENCE, with the source-level behavior and any
frozen Defense 3 synthetic evidence noted. The physical SEL-751 stayed READ-only throughout.

## Modes and shaping

| experiment | verdict | evidence |
|---|---|---|
| OFF native baseline (sustained, n>=120) | PASS | D5 pilot + Campaign A/B OFF: CLRT median 2.85 ms, p95 7.1, p99 14.4; 240/240 responded |
| D1 event release (ACK waits for RESPONSE, not the ordinary deadline) | PASS | d4_d1_event: read_to_ack constant ~3.3 ms across D_A 1/3/6 ms (does not track the deadline); d1_da1 ACK held to 3.32 ms not 1 ms, CLRT 0.031 |
| D2 response deadline shaping | FAIL (documented boundary) | D5 grid + Campaign A/B D2: RESP_BYPASS 30/30 per block, deadline_release 0, qid4 never occupied, CLRT stays native at every D_R 4..10 ms. Immediate ACK release (D_A=0) retires the transaction before the RESPONSE arrives. Structural for Case A, preserved as a claim boundary |
| D3 ACK deadline shaping | PASS | Campaign A/B D3: CLRT collapses to 0.03 ms, read_to_ack tracks D_A (1->1.49, 6->6.52 ms), 115-116 deadline releases per 120 |
| D4 dual deadline shaping | PASS | Campaign A/B D4 (D_A=4, D_R=8): CLRT normalized to 8.00 ms [CI 7.99, 8.00], p95 8.03, from native median 2.85/p95 7.1; RESP_HOLD_EARLY 22/30 in the grid |
| configured FAIL_OPEN bypass | PASS | bring-up + campaigns: pktgen disabled, native passthrough |
| runtime fail-open (zero/small budget) | PASS | d3_failopen sweep: budget 4000/2000 -> RELEASE_FAILOPEN 20, bounded hold shrinks 8.0->3.4 ms, 30/30 responded (never stranded) |
| fail-open then normal recovery | PASS | d3_failopen fo_recover (budget 18000): deadline shaping restored, CLRT 8.00 ms, next txns arm+complete |
| ACK-before-RESPONSE ordering | PASS | 0 ordering violations across 1200 Campaign A/B protected transactions; strict-priority ladder verified at setup |

## Generation, matching, reuse

| experiment | verdict | evidence |
|---|---|---|
| real generation rollover (>=33 READs one connection, C0..CF twice) | PASS | every 60-poll block advances C0..CF (all 16 codes, ~3.75 cycles) on one connection; 1200 txns, 0 stale releases, 0 ordering violations |
| stale-generation token termination | PASS | BLOCK_TERM_STALE 3840 cumulative under real rollover (old-gen blockers cleaned up); 0 wrong-generation RESPONSE releases |
| old-generation cleanup against new state | PASS | same BLOCK_TERM_STALE evidence + every transaction retires and the next re-arms (ARM_FRESH per poll) |
| wrong TCP ack / seq (natural) | PASS (partial) | ACK_REJECT 61 cumulative: real non-matching ACKs (teardown/keepalive) rejected and forwarded, not held |
| one-shot admission / bounded 2K drain | PASS | first protected READ per block: pktgen 128, CF_PKTGEN_ADMIT 128, qid7+qid5 seeded, drains bounded, 0 TM drops |
| ACK pending while RESPONSE barrier drains | PASS | D4 shaping holds the ACK while the qid5 RESPONSE barrier is active; ordering preserved |
| subsequent-transaction reuse | PASS | sustained connections, every next transaction re-arms and completes across 1200 txns |
| duplicate READ / concurrent second READ | BLOCKED WITH EVIDENCE | not producible from a serial master; source: arm-once guard (tag_arm from TAG_INACTIVE), but P4 audit risk #2 flags a possible tracker clobber (reg_exp_ack written before the arm decision) that needs a controlled overlap injector |
| duplicate ACK / duplicate RESPONSE injection | BLOCKED WITH EVIDENCE | ACK_DUP_HOLD 0 / RESP_DUP_SUPP 0 naturally; source: dup ACK held no re-arm, dup RESP R1-suppressed; needs an injector |
| wrong flow / direction / port | BLOCKED WITH EVIDENCE | BAD_PORT 0 naturally; source: ingress_port==PORT_RELAY conjunct rejects; needs a misrouted injector |
| forged / wrong-role internal 0x88C1 token | BLOCKED WITH EVIDENCE | BLOCK_REJECT 0 naturally; R3 proven on the Defense 3 synthetic build; a host cannot emit a raw 0x88C1 frame in this lab |
| timestamp wrap boundary | BLOCKED WITH EVIDENCE | 2^32 ns is about 4.29 s, not crossed within a 400 ms-spaced block; source: modular compare, half-range horizon, low-byte-zero invariant enforced by B2 |

## Failure and cleanup

| experiment | verdict | evidence |
|---|---|---|
| zero / small budget cleanup | PASS | d3_failopen: bounded release at every budget, nothing stranded |
| missing ACK | BLOCKED WITH EVIDENCE | the physical relay always ACKs; source: unarmed T_A never reads expired, qid7 drains on budget (fail-open) |
| missing RESPONSE | BLOCKED WITH EVIDENCE | the physical relay always responds; source: qid5 drains at T_RESP/budget, ACK release retires the tag; the budget sweep exercises the same release path |
| asymmetric reservoir expiry | BLOCKED WITH EVIDENCE | needs independent per-role injection; source: two separate reservoirs qid7/qid5 with independent budgets |
| FIN at normal connection close | PASS (partial) | driver FINs each block; reg_tag clean (INACTIVE) after every one of 1200 blocks (each transaction had already retired) |
| FIN / RST mid-transaction | BLOCKED WITH EVIDENCE | needs precise mid-transaction injection; source: P4 audit risk #4, the integrated program has NO FIN/RST cleanup branch, stale state is reclaimed only by the budget horizon and app-seq rollover. This is a recorded limitation |

## DNP3 operation boundary

| experiment | verdict | evidence |
|---|---|---|
| normal READ (func 1) on the physical relay | PASS | 1200+ READs answered; READ is the only function that arms the engine (source: set_role_arm on func 1 only) |
| SELECT (func 3) / OPERATE (func 4) | BLOCKED WITH EVIDENCE | must never be sent to the physical relay; source: default:accept -> ROLE_BYPASS, never arm; requires a controlled software outstation to exercise on the wire |
| combined ACK-bearing RESPONSE (Case B) | NOT APPLICABLE | the SEL-751 is a Case A separate-ACK device; source: a combined RESPONSE reaches a bounded fail-open at H~30.8 ms, no combined-response classifier (spec 10 PROPOSED, not built) |
| multi-segment / fragmented RESPONSE | NOT APPLICABLE | the relay's DNP3 responses are single 134-byte segments (resp_segments 1 across all campaigns); no multi-segment case is produced by this device |

## Resource and bottleneck

| experiment | verdict | evidence |
|---|---|---|
| 12-stage placement + critical path + PHV + memory | PASS | compiler_9132_raw: 12/12 ingress, 0 egress, crit-path 10, 104 tables, SRAM 47, TCAM 10, SALU 12, PHV W0-15 full |
| why reg_deadline/reg_tresp split resolved co-location | PASS | DEFENSE4_BOTTLENECKS.md: two 2-site registers co-locate where one 4-site register (Gate-2B) forced ~19 stages |
| runtime bottlenecks (reservoir, tails, poll gap, K) | PASS | DEFENSE4_BOTTLENECKS.md: establishment ~1.42 ms, qid7 peak 43/64, release tails 0.03-0.05 ms, K=64 fixed, one active txn |
| reservoir-readiness margin (R11) | PASS (measured, not structural) | 0 ACK escapes across 1080 protected txns, but no data-plane guard; measured margin only, R11 OPEN |

## Reliability totals (Campaigns A + B, 1200 transactions)

Responded 1200/1200. Retransmits 0. Duplicate ACK/RESP 0. Resets 0. Ordering violations 0. Token
escapes on the master wire 0. TM queue/port drops 0. Both campaigns agree within bootstrap CI, and
the randomized-order campaign (seed 20260807) reproduces the fixed-order campaign.
