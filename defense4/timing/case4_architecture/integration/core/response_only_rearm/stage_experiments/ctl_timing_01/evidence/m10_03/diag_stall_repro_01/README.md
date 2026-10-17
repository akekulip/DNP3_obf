# Instrumented reproduction of the contention attempt-04 stall (2026-10-17): NOT reproduced. Diagnostic only.

This is not a qualification run and does not replace attempt 04.

- **What ran:** `model_contention.py`, unchanged, sections `sweep,dup` only: the shortest sequence that reached the
  attempt-04 stall at `dup_SELECT_final_ACK`. It ran on m10_03's local compile under `../../health_wrapper.py`, which
  sampled once a second, inside the launcher's namespace, which veths existed and their state and whether
  tofino-model and bf_switchd were alive (`health.jsonl`).
- **Result:** 212/212 passed (session.log), from 15:21:59 to 15:24:32. The stall did not recur.
- **Health:** 142 samples covering the whole run with no gap over 3 s. tofino-model and bf_switchd were alive
  throughout, and all 14 veths stayed up.

## What this establishes, and what it does not

- The stall is not deterministic in this sequence. A passing reproduction means it was not reproduced under this
  instrumentation; it does not explain or resolve attempt 04.
- The health checks cover only process and interface survival. They do not establish packet delivery and do not
  explain the capture-loop behaviour.

## Attempt 04, as far as the evidence goes

- **Last confirmed working event:** `dup_SELECT_SYNACK` passed (one exact frame). The model then logged ingress of
  the master's `dup_SELECT_final_ACK` (14:57:32.469, port 9), its normalize lap (port 48), and its N pass on port 68
  (packet 0xb61, 14:57:32.498).
- **First confirmed failure:** `dup_SELECT_final_ACK`, 0 frames. After 0xb61 the model logged no further packet; its
  log ends on "Waiting for packets to process".
- **Unknown:**
  - whether the driver's later sends left the host;
  - whether capture stayed bound to live interfaces;
  - process and interface state during attempt 04 (not instrumented then);
  - how long the remaining 179 cases took. Buffered output and file times do not establish it, and no per-case
    timestamps exist.
- An apparent `connection`-table miss on 0xb61's pass is the ordinary routing of a master-side lap pass (a `ports`
  hit follows). It is not evidence of the cause.
