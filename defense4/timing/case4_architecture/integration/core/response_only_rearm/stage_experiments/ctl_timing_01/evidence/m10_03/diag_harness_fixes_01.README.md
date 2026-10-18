# Bounded diagnostic of the four harness fixes (2026-10-17; not an attempt)

Philip authorized bounded targeted checks before attempt 07. This was one model run on m10_03 with the uncommitted
driver: sections `sweep,abort,restart_targeted`, timeline on (`diag_harness_fixes_01.timeline.jsonl`), closure in
`diag_harness_fixes_01.closure.json`. Results: `diag_harness_fixes_01/contention_results.json`, **302/302**.

1. **OPERATE watch (fix 1).** 9 sweep OPERATE points; every `request_not_relayed_again` passed, with no confirmed
   duplicate and nothing unclassified.
2. **Abort order (fix 2).**
   - Every held READ/SELECT abort (including +48 and +50) saw T's admission of the response in the model log within
     0.041–0.060 s, then the pre-send read showed it still held. No order was inconclusive.
   - OPERATE held: released before the send, as the supported profile states (J > D).
   - The log-decided order (`order_decided`) was not needed in this run. It is tested on attempt 06's case:
     release 36.972, reset applied 37.016 (`tests/test_model_log_view.py`).
3. **Targeted restart (fix 3).** On the first try for each kind:
   - the RST's stage-0 pass was seen 0.013 s after the send;
   - the response then claimed the cell, and `count_busy[5]` advanced by 1;
   - the RST was relayed once.

   The revised reset contract passed for both tries:
   - READ: no release.
   - SELECT: one copy, released at 52.326, before T applied the reset at 52.348.
4. **Interruption stop (fix 4).** Not triggered: no handshake step got 0 frames.

Committed-path precondition: all 28 points measured. OPERATE responses reached T 931–1049 ms after t0 (readiness
2000 ms).

## Diagnostics 02–04: the trigger, corrected twice (after the code review's fixes H1/H2/M2/L1/L2)

- **02** (`abort,restart_targeted`): **146/146**, but the trigger was not controlled. Three tries fired 0.8 ms after
  the RST send and did not restart. Coverage came only from READ try 3 and SELECT try 2. The cause: the previous
  connection's cleanup RST logged its `first_close` after the next try took its log offset. Corrected:
  - `model_log_view.wait_idle`: wait for the model log to stop growing before taking the offset;
  - require this RST's ingress on the wire port, then `first_close` after it.
- **03** (`abort,restart_targeted`): **159/159**. Four tries still matched within 1 ms, and only try 3 of each kind
  restarted. These were now this RST's own lines. `Model.send` opens a socket per call (about 25 ms), so the model had
  already run the RST's stage-0 pass before the wait began, and the response arrived late for the window. Corrected:
  the RST is sent from a socket opened beforehand, and each try records `rst_send_s` and `rsp_after_rst_s`.
- **04** (`restart_targeted`): **28/28**. The RST send took 0.0001 s or less. The RST's own stage-0 pass appeared after
  0.026 s (READ) and 0.033 s (SELECT). The first try of each kind restarted (`count_busy[5]` +1), and both passed the
  revised reset contract.

Every try in 02–04 was judged in full, including the recovery READ after each try, and passed. The tries that did not
restart recorded `stage0_seen` and their wait times. Held aborts in 02–03 saw T's admission within 0.025–0.060 s and
stayed held. None was inconclusive, unmeasured or not established.
