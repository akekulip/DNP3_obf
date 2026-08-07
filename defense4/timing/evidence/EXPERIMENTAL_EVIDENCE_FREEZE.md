# Defense 4 experimental evidence freeze

## ►► REOPENED / INVALID (2026-08-07) — do not rely on this freeze; paper writing is quarantined

A repository audit at commit `b0e1752` contradicted two central conclusions of this freeze, and
recomputation from the committed evidence confirmed the audit. This freeze is **INVALID and
reopened**. The corrected findings are inlined below next to the original text. The load-bearing
errors were:

1. **D2 is a lifecycle defect, not a Case-A limitation.** D2 (n=240) shows `deadline_release=0`,
   `RESP_BYPASS=240`, `ACK_REL_RETIRE=240`: every transaction retires at ACK release and every
   response bypasses. `tag_retire_if_unmarked` retires the transaction when the ACK releases before
   a response is pending, so the later response finds no live transaction. This is a fixable P4
   defect (the frozen Defense 2 held responses 200/200), NOT an inherent Case-A boundary.
2. **D4 does not normalize CLRT to a fixed value; it produces a mixture distribution.** D4 (n=240):
   only **160/240 reach the deadline (RESP_HOLD_EARLY=160); 80/240 (33%) bypass** at native timing
   via the same retire defect. The CLRT is bimodal: p25=3.06 ms (bypass mass), p50=8.00, p99=11.09.
   The tight median CI [7.99, 8.00] is a **misleading statistic** because the median sits in the
   held population while a third of the mass is native.
3. **The negative tests were not attempted, not "blocked with evidence."** The authorized controlled
   outstation/injector experiments (missing ACK/RESP, duplicate, wrong-flow, forged token, wrap,
   SELECT/OPERATE, combined, multi-segment) were not implemented; those rows are NOT ATTEMPTED, and
   the combined/multi-segment rows are not-tested rather than inherently not-applicable.
4. **The scorer is insufficient** (it does not fail on a protected-mode response bypass and does no
   incoming/outgoing byte comparison) and **the SHA256SUMS manifest is incomplete** (5 compiler logs
   and the control/deploy scripts are absent).
5. **The final D4 switch state is not repository-verifiable**; the last committed raw snapshot is
   D3 ~6 ms.

**Corrected verdict: TIMING EXPERIMENTS PARTIAL, INTEGRATED-LIFECYCLE DEFECT OPEN.** The engineering
is a substantial partial success (load, forward, D1 event release, D3 ACK-deadline shaping, budget
fail-open with recovery, generation rollover, 12/12 resource fit), but D2 and one-third of D4 are
governed by an open `tag_retire_if_unmarked` defect. Do not merge. Do not integrate the Introduction.
The original text below is retained for the record; where it conflicts with this banner, the banner wins.

---

This freezes the overnight experimental campaign. Paper writing may proceed only for the verdict
stated at the end. All results are recomputed from committed primary evidence on the deployed
binary; no result is taken from a prior prose report.

## Exact implementation tested

- P4 source: `defense4/timing/p4/defense4_caseA.p4`, sha256 `1272679c84e4e86ad867764f086b5c79d5990e61b328db3d56276329c46f678b`.
- Deployed binary: `tofino.bin` sha256 `0ec4e452f63a63c2257282934bdfd7c353b5db39f99c7e0b6eb0835ee90e1242`, 1416979 bytes, BF-SDE 9.13.2 (`p4c 9.13.2 SHA 1baf055`). Source and binary hashes match the recorded compile.
- Testbed: Tofino-1 switch `decps@10.10.54.81`, master `decps@10.10.54.19`, physical SEL-751 at `192.168.10.7:20000`, READ-only.

## Actual supported modes (measured)

- OFF: true bypass, native passthrough.
- D1 (event): the ACK is held until the RESPONSE event, not an ordinary deadline (read_to_ack independent of D_A). Proven.
- D2 (response deadline): does not shape, because of an OPEN LIFECYCLE DEFECT (corrected). `tag_retire_if_unmarked` retires the transaction at ACK release before the response is pending, so the response bypasses (n=240: deadline_release 0, RESP_BYPASS 240, ACK_REL_RETIRE 240). This is a fixable P4 defect, not a Case-A limitation (frozen Defense 2 held responses 200/200).
- D3 (ACK deadline): the ACK is held to T_A = t_A + D_A (read_to_ack tracks D_A); CLRT collapses to about 0.03 ms. Proven.
- D4 (dual deadline): a MIXTURE, not a fixed normalization (corrected). Of n=240 at D_A=4, D_R=8: 160/240 are held to the deadline (CLRT ~8 ms) but 80/240 (33%) bypass at native timing because their response lands after the T_A ACK deadline and hits the same retire defect. CLRT is bimodal (p25 3.06, p50 8.00, p99 11.09). The held subset shapes; the design does not yet normalize the population.
- FAIL_OPEN (configured): bypass. Runtime fail-open (budget exhaustion) releases held packets with a bounded hold and never strands them; recovery to deadline shaping is clean. Proven.

## Actual supported DNP3 operations

READ (function 1) is the only operation that arms the engine and the only one exercised on the
physical relay. SELECT and OPERATE bypass transparently in source and were not sent to the relay
(they require a controlled software outstation to exercise on the wire). Combined ACK-bearing
RESPONSE (Case B) is not applicable to the Case-A SEL-751. Responses are single-segment.

## Actual generation mechanism

The per-transaction generation is the DNP3 application-control octet, domain 0xC0..0xCF, a 16-value
reuse space supplied by the master. There is no data-plane generation counter. This differs from
the specification text that calls for an internal generation; the divergence is recorded. Rollover
through all 16 codes was exercised on sustained connections with zero stale-generation releases.

## Actual fail-open behavior

Held packets are released, never dropped. A small pass budget forces the runtime fail-open path
(RELEASE_FAILOPEN), shrinking the hold; every transaction still received its RESPONSE at budgets
down to 500. Recovery to full deadline shaping is immediate when the budget is restored.

## Proven timing transformations

- D4 transforms the variable native CLRT (median 2.85 ms, p95 7.1, p99 14.4) into a tight fixed
  value of 8.00 ms (95% median CI [7.99, 8.00], p95 8.03) across 240 transactions in two campaigns.
- D1 collapses the native CLRT tail (native p99 14.4 ms) to about 4.2 ms.
- D3 collapses the CLRT to about 0.03 ms by holding the ACK to the RESPONSE.
- All transformations preserve ACK-before-RESPONSE ordering (0 violations in 1200 transactions).

## Reliability results

Campaigns A (fixed order) and B (randomized, seed 20260807): 1200 transactions, 1200 responded,
0 retransmissions, 0 duplicates, 0 resets, 0 ordering violations, 0 token escapes on the master
wire, 0 TM queue or port drops. The randomized campaign reproduces the fixed campaign within CI.

## Protocol limitations

D2 does not shape Case A. The implementation protects READ only. There is no combined-ACK
classifier and no FIN/RST cleanup branch (stale state is reclaimed by the budget horizon and
app-seq rollover). Concurrency, duplicate injection, wrong-flow injection, forged-token injection,
and timestamp-wrap were not exercised on hardware and require a controlled outstation or injector.

## Tofino bottlenecks

12 of 12 ingress stages with 0 headroom, critical path 10, SALU 12, SRAM 47, TCAM 10, 104 tables.
The binding constraint is placement and co-location plus the fully occupied 32-bit PHV group W0-15,
not depth or capacity. Splitting reg_deadline and reg_tresp into two 2-site registers is what fits
the program at 12 of 12. The only remaining headroom is the empty egress pipeline (deferred).

## R11 status

OPEN. The reservoirs are established by a READ-triggered pktgen burst (the proven harness method).
There is no data-plane reservoir-readiness guard; readiness rests on a measured timing margin. No
ACK escape was observed in 1080 protected transactions, but this is a measured property, not a
structural guarantee.

## What the evidence does and does not show about fingerprint mitigation

It shows that the mechanism transforms the CLRT observable: D4 normalizes CLRT to a fixed value,
D1 collapses its tail, D3 collapses it toward zero, byte-identically and without drops. It does not
show full device anonymity or defeat of a fingerprint classifier: only the CLRT observable is
altered, the TCP and ACK-mode characteristics and the response size are unchanged, and only one
physical relay was evaluated, so no cross-device indistinguishability is claimed. The demonstrated
result is CLRT-timing transformation feasibility on silicon, not fingerprint-classification defeat.

## Final switch state (verified 2026-08-07)

The switch runs `defense4_caseA` (binary sha256 `0ec4e452...`) in the calibrated D4 policy:
tbl_params mode=4, d_ticks=4,000,000 ns (D_A=4 ms), da_dr=12,000,000 ns (D_A+D_R=12 ms, so
D_R=8 ms), budget=18000. These parameters passed the corrected campaign (normalized CLRT 8.00 ms).
A final probe returned CLRT median 7.990 ms with 8/8 responded, and the relay is reachable through
the switch (ping 0.35 ms). The old uncalibrated 0x8000 (32.768 us) policy has been replaced. Defense
4 is intentionally left running with this known, verified, campaign-passed policy. The safe restore
path remains `bash /home/decps/d4_build/rollback_defense3.sh`.

## Verdict

**SUPERSEDED by the REOPENED banner at the top. The original verdict below is retained for the record
and is WITHDRAWN.**

~~TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY.~~ Withdrawn: the claim boundary was not
closed (D2 and one-third of D4 are governed by an open `tag_retire_if_unmarked` defect, not a
boundary), D4 "normalization" was a mixture distribution reported via a misleading median CI, and
the negative tests were not attempted rather than blocked with evidence.

**Corrected verdict: TIMING EXPERIMENTS PARTIAL, INTEGRATED-LIFECYCLE DEFECT OPEN. Freeze invalid
and reopened; paper writing quarantined; do not merge.** The next authorized run must fix
`tag_retire_if_unmarked`, regression-test D2 and D4, calibrate D4 so the ACK deadline covers the
measured native response tail, implement the authorized controlled negative testing, repair the
scorer (add byte comparison; fail on protected-mode bypass) and the manifest, re-run every mode
affected by the P4 change, and commit a final live-state snapshot. Only then may the Introduction
be revised.
