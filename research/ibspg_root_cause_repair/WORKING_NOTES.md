
## Checkpoint 2026-07-24 — empty-gap program Parts 4-8 DONE (positive)
- Part 4 loop timing: RTT=408ns, ring synchronizes (bursts+RTT gaps). IBSPG_BLOCKER_LOOP_TIMING_REPORT.md
- Part 5 empty-gap model: counting bound N_safe~18; but see EMPIRICAL OVERRIDE. IBSPG_EMPTY_GAP_MODEL.md
- **Parts 6/8 HOLD WORKS ON SILICON**: corrected max_priority + K=1 recirculating blocker holds 32 HELD
  with 0 leak; releases all 32 intact on stop; held-then-released order; 15/15 reps; K=0 control=H=32.
  Three measurement artifacts removed (H=0 ambiguous; overflow skips-recording-keeps-looping;
  trace-full masks drain). IBSPG_HOLD_ON_SILICON_RESULT.md. Commit 7dc2152.
- Empty-gap counting model OVERTURNED as a leak mechanism: RTT dt-gaps are NOT Q_HOLD service windows.
- Switch restored to queue_microbench_abs.conf (1 bf_switchd, ASIC, Vision/Hulk/switch reachable).
- NEXT (gated/large): Part 9 controlled drain-event release (not budget-expiry); Part 10 timeout/
  fail-open; Part 11 paired ACK-before-response; Part 12 HOLD_RESPONSE; Part 13 DNP3 integration (replay).
