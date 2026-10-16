# Trace: m6_07 model contention, sweep_SELECT_000ms (240/241), 2026-10-16

Source: the retained model log `model_20261016_061439.log`, sha256 `5bff053d…3714`, matching its entry in
`UNTRACKED_LARGE_LOGS.sha256`. It was parsed with `../../trace_model_log.py LOG OUT 4e207531 0001e849`, which selects
outstation-to-master frames on this point's tuple with server SEQ 125001 (ISNs client 120000 and server 125000, from
the driver's SYN, SYN-ACK and final-ACK records). Times are model `global_tstamp` values in ns. They are relative to
the SELECT request's admission to T.

| model ms | record | where | action |
|---:|---|---|---|
| 0.0 | request | T ingress, port 180 | `admit_request` (readiness 2 s, `da` 1 ms, as installed by the driver) |
| — | idle | model | no packet processed for 3.16 s wall between the request's clone drop and the outstation ACK |
| 3982.5 | ACK, native | N | stage-1 to stage-3 passes; the response arriving one lap later finds the cell busy and retries (`busy_retry`, then `busy_retry_next` twice) |
| 4126.2 | ACK event | T | `mark_ack_seen`, then `hold_ack` |
| 4137.5 | held ACK | T | **`release_ack_fallback`**: readiness had expired 2.1 s earlier, so the ACK goes to E and the master |
| 4216.2 | response event (0x0b00) | T | `read_resp_done`, then `admit_response`: the response is held |
| … | 152 laps | T held_return, port 182 | `rewait_response` |
| 6296.2 | held response | T | **`release_response_fallback`**: 2.08 s after admission; E sends the 61-octet image to the master |
| about 6296 | driver resend | N to T | `first_response_dup` (0x0119) and `seq_retx`; T `passthrough_tev_forward` (the original is done) |

## Findings (corrected 2026-10-16 after adversarial review; the first reading was wrong)

**The original response was not lost.** E sent it to the master (record 0x279, `out_commit`, port 9, 06:15:31.7066
wall) 2.08 s after T admitted it, after the driver's 1.5 s quiet cutoff.

**Mechanism: 32-bit aliasing of T's readiness test (a T defect, inherited since m4).** T's anchor `t0_reg` and
`md.now` are 32-bit nanosecond values, and `held_verdict` releases on the sign bit of `now − readiness − t0`
(`readiness_delta`).
- **ACK verdict, 4.1375 s after the request anchor:** `readiness_delta` = +2.1375 s, just under 2³¹ ns (2.1475 s).
  The sign bit is 0, so the ACK was released by fallback.
- **Response admitted at 4.216 s:** `readiness_delta` = 2.216 s, above 2³¹. The sign bit is 1, so T read it as "not
  ready" and re-waited it (152 laps).
- **Release:** it came when `now − t0` wrapped modulo 2³² back past readiness. 2³² ns + 2.0 s − 4.216 s = 2.079 s,
  which is the observed 2.08 s. This was not a bounded fallback.

For anchor ages between readiness + 2³¹ ns and 2³² ns (about 4.15–4.29 s here) T holds packets as "not ready". From
2³² ns (4.29 s) onward an old exchange aliases to a fresh one: a commit becomes possible and the fallback is delayed.
Silicon uses the same arithmetic.

**Run `_02` was misread at first.** Its request and its ACK verdict lie in different upper timestamp words (`0x000c`,
`0x000d`). About 4.50 s really elapsed, and T saw 0.206 s because of the aliasing. That point's commit was an
**aliased false commit**, not evidence that it was in profile. Model time tracks wall time (about 1.25×). In `_01`, the
3.16 s wall-time idle before the ACK accounts for the 4.14 s on T's clock.

**Unavailable in the retained record:** counter snapshots at the moment of the judgement, and N register state
between points.

## Consequences

The harness changes made during the first reading are not accepted:
- The "wall time is not a proxy" comment and the withdrawn wall-time rule rest on the misread `_02`.
- `tests/test_late_stimulus.py` never reaches the aliasing region.

The original 240/241 stays recorded. The fix belongs in T (directive: "if it is in N/T/E, fix the authoritative
generator"). It needs a design decision on T's time arithmetic; see the 2026-10-16 status report.
