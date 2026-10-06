# Master retransmission timer on the candidate build, and the admission verdict — 2026-10-06

Authorised by Philip ("run the master timer measurement according to the plan"). Method: `audit_current/master_rto_20260916/master_rto.py`, extended in
`framework/analysis/master_rto_probe.py` with kernel `TCP_INFO` sampling on the same socket. Candidate `defense4_timing` (source `df5991016285…`) loaded with the release
block **disabled** (the mechanism off); one DNP3 connection (`192.168.10.1:43238 → 192.168.10.7:20000`); inbound from the outstation dropped for that single 4-tuple
by an `iptables` rule tagged `master-rto-probe`; one non-actuating READ; 30 s hold. The rule was removed and its absence verified by the script and again independently; no connection
or rule remained. The lab was then restored (fourth time this session, configuration identical, SEL 5/5).

## Result

| quantity | value | source |
|---|---|---|
| kernel RTO on the idle DNP3 socket | **201 ms** (SRTT 0.661 ms, RTTVAR 0.330 ms) | `TCP_INFO` |
| first repeat of the request on the wire | **204.4 ms** (3.4 ms after the kernel figure) | master-side capture, nanosecond timestamps |
| later repeats | 412.4, 820.4, 1,676, 3,340, 6,604, 13,452, 26,764 ms (9 transmissions) | capture |
| kernel RTO over the hold | 201, 402, 804, 1,608, 3,216, 6,432, 12,864, 25,728 ms; backoff and retransmits reach 7 | `TCP_INFO` every 20 ms |
| 2026-09-16 recorded first repeat (frozen build) | 200.8 ms | `RESULT.md`, reproduced from its capture by the analysis tests |

Reading, with its limits: the master's request feedback timer on this connection is about 201 ms by the kernel's own account, and the first repeat appears about 204 ms after the
send. The near-equal first two gaps (204 and 208 ms) before the doubling begins are consistent with a tail-loss probe preceding the first true timeout (RFC 8985), so the firm
statements are the kernel RTO and the observed first repeat, not which mechanism fired it. SSH socket figures are irrelevant to this connection. The value is a property of Vision's
TCP stack and this path; it is **not** a bound for any other host, device or day.

## Admission for the holding arms: `provisional`, not admitted

`framework/analysis/admission_record.py` assembles the ten inputs from evidence files only and runs `active_control/delay_admission.evaluate` for the worst-case hold (the 30.8 ms watchdog
horizon, which the ACK can reach whatever D_A is) with a 1 ms gap.

- **Now established on this connection and build:** master RTO 201 ms; native request-to-ACK, request-to-response and smallest CLRT from the OFF smoke; the driver's 500 ms application deadline (operator); the 40 ms cap check **passes** (31.8 ms requested).
- **Still unavailable, and exactly these three:** `detect_ms` and `release_tail_ms` (data-plane terms that need an instrumented measurement of the mechanism on this build; the 2026-09-15 values, 1.2 µs and 1.705 µs, are from the frozen build), and `outstation_feedback_path_ms` (needs a relay-facing observation point, which does not exist).
- The three checks (master TCP, outstation TCP, master application deadline) therefore read "cannot be computed", and the verdict is `provisional`. The activation gate admits only `admitted_conditional`, so **no holding arm runs**.
- For scale only, not as an admission: worst-case hold 30.8 ms against a 201 ms master timer is about 6.5×, against the 500 ms application deadline about 16×, and the unmeasured data-plane terms are microseconds against a 3 ms declared margin.
  That is a reason to think the policy is safe, not evidence that satisfies the rule.

## Ways forward (decisions, not done)

1. Run the holding arms under an **explicit, recorded operator acceptance** of the `provisional` verdict for a bounded smoke (30 READs, D_A ≤ 20 ms), stated as such in the evidence; this loosens a gate and needs an auditable field, not a silent change.
2. Measure `detect_ms` and `release_tail_ms` on this build, which needs an instrumented variant that fits the stage budget, run under the same kind of acceptance for the measurement itself.
3. Obtain a relay-facing observation point for `outstation_feedback_path_ms` and the outstation's timer on this build.
