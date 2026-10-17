# Committed-path precondition, attempts 05, 04 and 01 (derived; the attempt directories are not touched)

`committed_precondition.json` and `committed_precondition_attempt04.json` are `committed_precondition_check.py` run on
`../../model_contention_m10_03_05` and `../../model_contention_m10_03_04`.

## Attempt 05, `sweep_OPERATE_090ms`: `in_switch_delay`, unresolved

All times below are T's clock, measured from t0 (`hold_operate`); readiness is 2000 ms.
- The response entered the switch (pipe-0 ingress, port 9) between 1777.5 and 1807.5 ms. That is before readiness.
- It reached T at 2070.0 ms, after readiness. The ACK had already fallen back; the response then fell back too.
- Points bracketed this tightly show 100–123 ms from switch ingress to T. Here it was at least 262.5 ms: about
  150 ms extra. The code review found that during this interval there was a 148 ms wall-clock gap
  (15:38:57.620963 to .768989) in which neither pipe processed any packet.

- The dataplane did the same work as on the undelayed points (`n_passes_operate_05.txt`): 3 N passes carried the
  response, as on 6 of the other 8 OPERATE points. The difference is one idle gap of 0.148 s wall, in which no packet
  was processed in either pipe; on every other point the largest gap is 0.015–0.016 s.

**Correction to the attempt's FAILURE note.** The note calls this a harness defect because the response reached T
after readiness. That reading is not supported. The stimulus entered the switch in time; the delay was inside the
switch or the simulator.
- The delay is not extra dataplane work (same passes). It is a simulator idle gap while T's clock kept running:
  the same kind of stall as attempt 01's resolved `sweep_OPERATE_030ms` and `sweep_SELECT_060ms`. Why the
  simulator stalled is not known.
- Attempt 01's `sweep_OPERATE_030ms` classifies the same way here (`committed_precondition_attempt01.json`:
  switch ingress 1425.0–1453.8 ms, T 2393.8 ms). It was resolved through the driver's readiness rule, which covers
  the ACK_COMMIT lane. Attempt 05's point took the ACK_FALLBACK lane, which that rule does not cover.

The stimulus margin is still thin and contributes:
- In the 5 OPERATE points with tight brackets, the response entered the switch 1681–1841 ms after t0.
- The driver's OPERATE request capture waits a 0.9 s quiet after the relayed OPERATE, plus 0.2 s, before it sends
  the ACK.
- That quiet is the only window in which a duplicate OPERATE release would be observed, because `judge` does not
  inspect relay-port frames.

## Attempt 04

- 28 committed cases measured.
- 10 `unattributed`: the failed cases after the packet-path stall. Their lanes cannot be located, so none is
  excused.

## Other committed cases

- Attempt 05: 33 `measured`; 4 `measured_unverified` (the restart and reconnect `_new_READ` cases have no window of
  their own; they passed).
- Attempt 01: 32 `measured`; 3 `measured_unverified` (among them `sweep_SELECT_060ms`, whose response entered the
  switch while the request sat in N, before T admitted the lane).
