# run 135 — INVALID for target-accuracy analysis

**Do not present run 135 (`run_id=135`, B=16384, T=40 ms) as a valid 40 ms hold measurement.**

- Achieved: **median 359.94 ms, σ 239.70 ms, target-error 319.94 ms** for a 40 ms target
  (`results.jsonl`, run_id 135). That is ~9× the requested hold.
- Cause: the point sits just past the 16384-pass burst-credit breakpoint, where the pass-budget→hold
  mapping is extremely sensitive — `hold_passes` 18826→20474 (runs 134→135) jumps the achieved hold
  from ~24 ms to ~360 ms.
- The digest telemetry for this run is still internally consistent (110/110 records,
  `ctr_grad==ctr_digest_emit==records`, loss=0), so it is VALID as **breakpoint-instability evidence**
  — but NOT as a 40 ms target-accuracy data point.

The raw row is preserved unchanged in `results.jsonl`; this marker records its invalidity for
target-accuracy analysis without altering the preserved artifact. See
`../../DEEP_CODE_AND_RESULTS_AUDIT.md` Q12 §9 and §D.
