# Defense 4 experimental evidence freeze

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
- D2 (response deadline): does not shape a Case-A RESPONSE. With D_A=0 the immediate ACK release retires the transaction before the RESPONSE arrives, so every RESPONSE bypasses (RESP_BYPASS 30/30). Documented boundary, not a usable mode for Case A.
- D3 (ACK deadline): the ACK is held to T_A = t_A + D_A (read_to_ack tracks D_A); CLRT collapses to about 0.03 ms. Proven.
- D4 (dual deadline): the ACK is held to T_A and the RESPONSE to T_RESP = T_A + D_R; CLRT is normalized to a fixed value equal to D_R (8.00 ms at D_A=4, D_R=8, p95 8.03). Proven.
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

TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY.

The core timing transformations (D1 event, D3 ACK-deadline, D4 dual-deadline normalization, runtime
fail-open with bounded release and recovery, generation rollover) are demonstrated on silicon
against the physical relay with clean reliability. Every limitation is resolved into an explicit
claim boundary: D2 is ineffective for Case A, protection covers READ only, there is no combined-ACK
or FIN/RST-cleanup path, the injection and wrap negatives are blocked with evidence and source
analysis, R11 is open, and only CLRT is transformed on a single device. No mandatory experiment is
left unknown. Paper writing may proceed with wording bounded to these results.
