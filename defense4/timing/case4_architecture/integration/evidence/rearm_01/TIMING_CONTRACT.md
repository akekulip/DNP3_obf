# candidate61 timing contract: code, configuration and what an observer measures

Source: `seg61_02/evidence/full_04/response_only.p4` (SHA256 `1b2d62d1…65aa`). Configuration: `timing_params_ns` in the candidate61 configs (`da` 2 ms, `readiness` 30 ms, `cap` 40 ms, `gap` 950 µs, `op_j` 2.4 ms). Measurements come from the repeated-SBO silicon blocks `candidate61_repeat_sbo_950_b1_02`, `_b2` and `_b3` (64 cycles per connection, separate-ACK fixture with a 5 ms outstation response delay), summarized by `seg61_02/analysis/repeat_sbo_report.py`.

## Which events reach T

N classifies each packet (`packet_kind`) and, at the end of a Work, `read_terminal_t` decides what T sees. Kinds are N's internal codes.

| Transaction | Request | Outstation standalone ACK | Response | Path in N (`read_terminal_t`) |
|---|---|---|---|---|
| READ | kind 9, `commit_before_t(9)`: T `REQUEST` | kind 10, `emit_tev(0x0a00)`: T `ACK` (held) | kind 11, `emit_tev(0x0b00)`: T `RESPONSE` (held) | timed |
| SELECT | kind 5: `terminal_strip`, forwarded natively | not routed to T | kind 6: `terminal_strip`, natively, then padded by E | **untimed** |
| OPERATE | kind 7, `commit_before_t(12)`: T `OPERATE` (command hold) | not routed to T | kind 6: natively, then padded by E | **command hold only** |

## Deadlines and anchors in T

| Event | Released when | Anchor | Counter |
|---|---|---|---|
| READ ACK (held) | `ack_go_check`: `da` passed since the request AND a response child of this generation has been seen; otherwise `readiness` passed | request admission `t0` | `OUT_ACK_COMMIT` records `a_commit`; `OUT_ACK_FALLBACK` |
| READ response (held) | `resp_go_check`: `a_commit + gap` passed (a genuine commit of this generation); otherwise `readiness` passed | `a_commit` | `OUT_RESP_RELEASE`; `OUT_RESP_FALLBACK` |
| OPERATE request (held) | `op_go_check`: `op_t0 + op_j` passed | OPERATE admission `op_t0` | `OUT_OP_RELEASE` |

## What an observer at the master measures

| Quantity | READ | SELECT | OPERATE |
|---|---|---|---|
| ACK→response (CLRT) | normalized to `gap`: pooled median +7 µs error, p99 51 µs (step 4) | native: median 5.33 to 5.35 ms in every arm, p99 about 8.4 ms (the fixture's response delay); n = 192 per arm | native: median 5.30 to 5.32 ms in every arm; n = 192 per arm |
| request→ACK | the response arrival time (about 5.4 ms), because the ACK is held until the response is seen | native, median 0.16 ms | timed arms median 2.65 ms (the `op_j` 2.4 ms command hold before the outstation sees the OPERATE); untimed median 0.09 ms |
| request→response | about 6.4 ms (response arrival + `gap`) | median 5.48 to 5.51 ms | timed median 7.95 ms (`op_j` + native); untimed 5.40 ms |
| SELECT request→OPERATE response | | median 11.1 ms untimed, 13.6 ms timed | |
| Piggyback (no standalone ACK) | CLRT undefined; response opens only by `readiness` (median 30.1 ms) | not measured | not measured |

## Contract decisions (Philip, 2026-10-14)

- All three CLRTs (READ, SELECT, OPERATE) are to be normalized to `gap`. The current candidate meets this for READ only. SELECT and OPERATE CLRT are native; the OPERATE request→response shift is the command hold, not CLRT normalization.
- The OPERATE command hold `J` is a separate objective and stays. Both are verified independently: OPERATE request→ACK ≥ `J`, and OPERATE ACK→response ≈ `gap`.
- Piggyback gets a bounded response latency, detected per response, without shortening the global `readiness` that slow separate-ACK responses rely on.

## Supported and unsupported shapes (singleton authority)

- Supported: READ; SELECT immediately followed by its OPERATE; repeated on one connection (64 cycles verified on silicon and in the model, across application and transport sequence wraps).
- An OPERATE with no preceding SELECT on the connection is dropped by N and releases nothing (model `model_repeat_04` probes).
- **Unsupported, explicit expectation:** a SELECT followed by anything other than its OPERATE (an abandoned SELECT). N drops the next request indefinitely (measured over 7.5 s in the model, with T on and off); a qualified RST is forwarded and a new connection is then admitted (`model_abandon_03`). The connection stalls until the master resets it.

## Control-timing candidate (ctl_timing_01 m3)

- SELECT and OPERATE responses are released at `a_commit + gap`, like READ. OPERATE keeps its command hold J (`op_go_check`). A piggybacked response, with no standalone ACK in its lane generation, is released at `t0 + pb`.
- **Request→ACK is not normalized**, for any kind. The ACK is held until the response is seen, so request→ACK carries the outstation's response latency: about 5.3 ms in the separate-ACK fixture, and for OPERATE `J` plus that latency.
- The independent J check is measured from the captures: master transmit to outstation receive of each OPERATE (`repeat_sbo_report.py`, `operate_request_transit_us`).

### Measured on silicon (2026-10-14, ctl_timing m3, 59,570 PPS / 950 us, pb 4 ms)

Three blocks per fixture, 4 arms x 65 READs x 64 SBO cycles; 1,536/1,536 cycles verified per cycle; every block restored and pinged. Summaries: `seg61_02/evidence/ctl_timing_separate_ack_summary.json`, `ctl_timing_piggyback_summary.json`, `ctl_timing_cost_summary.json`.

| Measure (timed arms) | Separate ACK | Piggyback |
|---|---|---|
| SELECT CLRT - gap | median +4 to +4.5 us, abs p99 55-56 us (n = 192 per arm) | undefined (ACK on the response) |
| OPERATE CLRT - gap | median +5 to +10 us, abs p99 87-92 us | undefined |
| READ CLRT - gap | median +4 to +5 us | undefined |
| OPERATE command hold J (master TX to outstation RX) | min 2468 us, median 2527 us | min 2438 us |
| request->response | READ 6.46 ms, OPERATE 8.9 ms (median) | READ median 4.12 ms, p99 4.16 ms; SELECT and OPERATE about 4.12 ms (candidate61: 30.1 ms) |
| internal RX frames / exchange | about 1,060 (candidate61 on the same workload: about 530) | about 630 |

Untimed arms are unchanged (native CLRT, about 3-5 internal receives per exchange).
