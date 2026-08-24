# Defense 4 experimental evidence freeze

## Verdict: TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY

The timing-normalization result on the corrected binary is accepted, and its claim boundary is
explicit and closed: no integrated D2/D4 lifecycle defect and no unbounded safety defect remains open.
It is not a full PASS because the controlled software-outstation negatives and cross-device
classification are physically blocked and were not executed. This verdict was set after an independent
re-derivation from the raw evidence (below), not from a summary.

## Exact implementation

- P4 source `defense4/timing/p4/defense4_caseA.p4`, sha256 `1242ca4d…` (fix commit `e47bcaa`).
- Deployed binary `97175e7d…`, BF-SDE 9.13.2, 12/12 ingress. Verified: the running pipeline's loaded
  conf points at this binary (checked from the conf, not a disk file). A fresh reproducible compile of
  the same source yields a same-size binary (`compiler_9132_repro/`).

## What is ACCEPTED (independently re-derived from raw, 2026-08-07)

Recomputed directly from the raw block JSONs and counter dumps of Campaigns A and B, not from the
scorer summaries:

- **240 valid transactions per mode** (OFF/D1/D2/D3/D4), 1200 total, across two campaigns (A fixed
  order, B randomized seed 20260807).
- **D2 RESP_BYPASS = 0 and D4 RESP_BYPASS = 0** across 240 transactions each. The pre-fix binary
  bypassed D2 240/240 and D4 80/240, so the lifecycle defect is closed on silicon. D3 forwards 39
  post-deadline responses (its D_R=0 design, not a bypass); OFF passes all through.
- **CLRT normalized** (master-facing, ms): OFF median 2.92, p5-p95 spread 5.69; D2 median 10.02,
  spread 0.12; D4 median 10.00, spread 0.05; D3 median 0.03; D1 median 11.14. D2 and D4 reduce the
  p5-p95 spread 45.6x and 118x and the CLRT entropy from 3.63 to ~1.1 bits (≈12 → ≈2 effective timing
  states). Full distributions with the honest late tail (D2 max 16.6, D4 max 18.8) are in
  `NORMALIZATION_ANALYSIS.md`; the two campaigns agree.
- **Targeted lifecycle cases PASS** (`TARGETED_CASES.md`): response-survives-ACK-release (D2 held all
  240 after-release responses, 0 bypass; D4 held 60), C0..CF rollover on one connection (>33 READs),
  fail-open bounded release (30/30 responded, 30 fail-open releases, every txn re-armed, no stale tag).
- **Fail-closed pipeline**, proven by 78 adversarial fixtures. Both campaign manifests verify with
  `sha256sum -c`.

## Experiment scope (Philip, 2026-08-07): master + the physical SEL-751 outstation

The experiment is the DNP3 master polling the physical SEL-751 outstation through the switch, and the
CLRT timing above is its complete result. The controlled software-outstation negatives are OUT OF
SCOPE for this experiment, not a blocked deliverable (an earlier note framed them as needing a Hulk
software outstation on dp11; that framing is withdrawn). The DNP3 net has the master (.1), the SEL-751
(.7, Case A), and the ION7550 (.8, Case B combined-ACK); there is no separate Linux outstation host on
a shaped switch port, and none is needed for the defined experiment.

## What is bounded (the closed claim boundary)

- **Controlled software-outstation negatives** (missing ACK, missing RESPONSE, FIN/RST, combined,
  multi-segment, SELECT/OPERATE) are out of the experiment's scope. The lifecycle handling is proven
  by the counters (RESP_HOLD_LATE, fail-open) on the physical path; the deterministic software
  outstation that would exercise the remaining edge cases is built and offline-validated (58/58) and
  is available if a software outstation is ever put on the shaped path.
- **Byte preservation**: by construction the switch edits no packet; empirically every response is
  delivered and accepted with a valid DNP3 CRC. The paired comparator is validated on crafted captures.
  A live paired dual capture is not available on the master-facing single-capture physical setup.
- **Cross-device classification**: needs a second comparable Case-A (separate-acknowledgment) device.
  We have one (SEL-751); the ION7550 is Case B (no separate-ACK CLRT). So the result is timing
  normalization for the one device, quantified; no cross-device fingerprint-defeat claim is made. This
  is future work needing hardware, not part of the defined experiment.
- **R11** (reservoir readiness) remains a measured margin, carried OPEN into this partial verdict.

## Accepted claim (bounded)

On the corrected binary, on the physical SEL-751, READ-only, the response-deadline (D2) and
dual-deadline (D4) modes normalize the master-facing CLRT to a fixed 10 ms and hold every response
(0 bypass), reproduced across two campaigns and quantified as a ~50-118x spread reduction and a
collapse of the CLRT observable from ≈12 to ≈2 effective timing states, with an honest late tail.
The lifecycle fix, fail-open bounding, and generation rollover are proven by the counters. No claim is
made about the physically-blocked negatives, live byte identity, or cross-device classification.

## Final switch state

The switch runs the corrected binary `97175e7d` in the D4 policy (D_A 4 ms, D_R 10 ms, budget 18000),
idle, forwarding verified, no watchdog armed (completion marker present). This is the intended
leave-running state for a closed PARTIAL.
