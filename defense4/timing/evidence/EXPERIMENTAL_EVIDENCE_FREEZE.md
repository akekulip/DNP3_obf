# Defense 4 experimental evidence freeze (corrected binary)

This is the authoritative freeze. It supersedes the earlier freeze that was reopened after the D2/D4
lifecycle defect was found; that defect is now fixed and the results below are recomputed from
committed primary evidence on the corrected binary. The pre-fix defective D2/D4 campaigns are kept as
pre-fix evidence in their own directories and are not part of this freeze.

## Exact implementation tested

- P4 source: `defense4/timing/p4/defense4_caseA.p4`, sha256 `1242ca4d68e78430587b01c15f69befa9d7bd33c57a11445579773389ba33127` (fix commit e47bcaa).
- Deployed binary: `tofino.bin` sha256 `97175e7dc1a77c3cdbe235baa13b906e18d3227bf09cb84cfacfee6f0a928a19`, 1418611 bytes, BF-SDE 9.13.2 (`p4c 9.13.2 SHA 1baf055`), 0 errors, places 12/12 ingress (SRAM 47, TCAM 10, 107 logical tables). Artifacts: `compiler_9132_fix/`.
- Testbed: Tofino-1 switch `decps@10.10.54.81`, master `decps@10.10.54.19`, physical SEL-751 `192.168.10.7:20000`, READ-only.

## The fix

The defect was a mode-blind `tag_retire_if_unmarked`: on ACK release it retired the transaction even
in D2/D4, so a RESPONSE arriving after the ACK release found a dead transaction and bypassed. Seven
changes (verified by an independent P4/Tofino design pass, then against source): D2/D4 preserve the
tag on ACK release (D1/D3 still retire); the qid5 RESPONSE blocker drains on the deadline only when a
RESPONSE is pending, otherwise it loops to the bounded budget; a read-only `reg_ack_rel` companion
makes RESP_HOLD_EARLY vs RESP_HOLD_LATE real again; the ACK-release counter counts a retire only when
one happened. No new register, SALU, PHV field, or counter; `reg_tag` stays at 4 actions. `D_A` was
not raised to mask the defect.

## Proven timing transformations (fixed binary, corrected campaigns A + B, n = 120 / condition)

| mode | CLRT p5 | p50 | p95 | p99 | reading |
|---|---|---|---|---|---|
| OFF | 1.8 | 2.90 | 7.5-8.5 | 13-19 | native passthrough; the high-variance fingerprint |
| D1 (event) | 0.03 | 3.20 | 4.21 | 4.23 | ACK held to the RESPONSE event; native tail (p99 ~18) collapsed to ~4.2 ms |
| D2 (RESP deadline) | 9.97 | **10.00** | 10.08 | 16.4 | **now normalizes CLRT to 10 ms** (was native, no shaping, pre-fix) |
| D3 (ACK deadline) | 0.00 | 0.03 | 0.05 | 5-6 | ACK held to T_A; CLRT collapsed |
| D4 (dual deadline) | 9.98 | **10.00** | 10.03 | 10.1-12.7 | **true normalization to 10 ms** (was a bimodal mixture, p25 3.06, pre-fix) |

D2 and D4 at the calibrated D_A=4, D_R=10 (T_RESP = t_A + 14 ms, covering the native p99 ~13.7 ms
tail). Both campaigns agree within the bootstrap CI; Campaign B randomized the block order (seed
20260807). Across all 1200 corrected transactions: **0 ordering violations, 0 token escapes on the
master wire, 0 TM queue or port drops, 0 retransmissions, 0 resets, 1200/1200 responded.**

## RESPONSE disposition and counter reconciliation

Per protected block (60 READs): ARM_FRESH = 60, and RESP_HOLD_EARLY + RESP_HOLD_LATE + RESP_BYPASS =
60 (every response accounted for). Per-mode RESP_BYPASS over 120 transactions: **D2 = 0** (was 240),
**D4 = 0** (was 80), D1 = 0, D3 = 5-6 (the late-tail RESPONSE that arrives after the ACK deadline and
forwards after the ACK, correct for D3 since D_R = 0), OFF = 120 (bypass mode). For D3 the retire
count equals the bypass count exactly (5 -> 5, 1 -> 1). The three D4 response-arrival buckets were all
exercised in the recalibration: before T_A (D_A=6: 37 early), between T_A and T_RESP (D_A=2,D_R=10: 26
late), after T_RESP (D_A=2,D_R=4: p99 13.1 > T_RESP 6 ms, released via the late path, still held).

## Fail-open, bounded cleanup, and re-arm

A budget sweep on the fixed binary (budgets 3000 / 1500 / 800) forces RELEASE_FAILOPEN = 30, yet 30/30
respond at every budget (bounded release, never stranded), ARM_FRESH = 30 (every next transaction
re-arms), and reg_tag is clean after each block; budget 18000 recovers to deadline release. This
exercises the same fail-open code path a genuine missing RESPONSE takes and proves the no-stranding
invariant. The qid5 fix keeps a no-RESPONSE blocker generation-bound to the budget horizon (it no
longer vanishes at T_RESP).

## Byte preservation

Guaranteed by construction: the P4 writes no byte of any host frame; originals are held queue-resident
and released unmodified. Empirically: every released response keeps its exact length (134 bytes) and
DNP3 framing (0x0564, 0 bad frames) across all modes, and is accepted by the master with a valid DNP3
CRC (a single altered byte would fail the CRC and appear as a retransmission or missing response; none
occurred). A cross-poll byte-for-byte content diff is not usable here because the SEL-751 returns
live-changing data every poll (even OFF's own same-app-seq responses are all distinct).

## Reliability, ordering, isolation

1200/1200 responded; 0 ordering violations (ACK before RESPONSE held by the strict-priority ladder);
0 token escapes on the master wire; 0 queue or port TM drops; 0 retransmissions or resets. Generation
rollover exercised throughout (every 60-poll block advances C0..CF ~3.75x on one connection) with 0
stale releases. D1 and D3 regression: both still shape as before the fix (D1 event tail-collapse, D3
ACK collapse), confirming the D1/D3 paths are unchanged.

## Resource / bottleneck

12/12 ingress, 0 stage headroom, SRAM 47, TCAM 10, 107 logical tables (up 3 from 104 for the fix,
absorbed with no stage increase). The LTID-saturated stage 8-11 tail absorbed the fix's gateway/count
refinements. Raw artifacts in `compiler_9132_fix/`.

## What is NOT covered (scope boundary, not an open defect)

The genuine missing-ACK and missing-RESPONSE cases with a silent relay, and SELECT/OPERATE on the
wire, require a controlled software outstation routed through the switch; they were not implemented.
Their handling is proven at the source level and, for the fail-open release, empirically via the
budget path. The evaluation is one physical relay and the CLRT observable only. No cross-device
indistinguishability or full-fingerprint claim is made.

## R11 status

OPEN. Reservoirs use the READ-triggered pktgen burst (proven harness method); readiness rests on a
measured margin, not a data-plane guard. 0 ACK escapes across all corrected protected transactions,
but this is a measured property.

## Final switch state

Recorded by the closing step: the switch runs the corrected binary `97175e7d` in the calibrated D4
policy (tbl_params d_ticks=4,000,000 = D_A 4 ms, da_dr=13,999,872 = D_A+D_R 14 ms so D_R 10 ms),
reg_tag idle, forwarding verified (0.62 ms); raw snapshot committed (final_state_fix_*). Defense 3 is used only if the corrected D4 fails a check.

## Verdict

**TIMING EXPERIMENTS PASS.** The lifecycle defect is fixed and proven on silicon: D2 and D4 normalize
the CLRT to a fixed value with zero RESPONSE bypass, D1 and D3 are unchanged, fail-open is bounded and
never strands the next transaction, byte preservation holds, and reliability is clean across 1200
randomized and fixed-order transactions with full distributions. The remaining controlled-outstation
negatives are a scope boundary resolved into explicit paper wording, not an open defect. Paper writing
may proceed with claims bounded to these results.
