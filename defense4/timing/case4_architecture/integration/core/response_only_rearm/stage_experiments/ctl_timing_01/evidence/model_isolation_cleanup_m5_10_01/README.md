# model_isolation_cleanup on m5_10 (2026-10-16): characterization, not a reproduction test

`driver_source.py` is byte-identical to `../../model_isolation_cleanup.py`, the driver that ran. Result:
`isolation_cleanup_results.json`, 27/27 traffic cases ok and 0 outcome-6 (`TOKEN_STALE`) events.

What this run shows, and what it does not (code review, 2026-10-16):
- **Not gated.** The 27 cases are traffic sanity checks. Outcome 6 appears only in `meta.windows`, so "27/27 ok" says
  nothing about stale retirement.
- **No preconditions.** Every step ends with a capture that needs 1.5 s of quiet, so every SELECT blocker can reach
  `done` and stop silently (`stop_blocking`, uncounted) before the OPERATE advances the lane generation. Outcome 6
  needs a blocker that is still alive at that advance (m5_10 `held_verdict`/`hb_verdict`). This driver never creates
  that state.
- **Missing pieces:**
  - no lane-generation reads;
  - no positive control;
  - no c2 pause; the docstring's "quiet-isolation workload" scope string is inaccurate: this is the control shape
    without the pause.
- **Weak checks:**
  - `read()` and `operate()` count two master-bound frames without checking their content;
  - `rst()` checks only the relay side;
  - the first outcome snapshot is not persisted, and `OLD_EPOCH_DROP: 2` predates c1 with no record of why.

Read it as "0 outcome-6 events under a workload paced at 1.5 s or more between steps". It does **not** show that the
model cannot produce stale retirement. The silicon attribution (`seg61_02/evidence/hw_campaigns/ctl_m5_stale_iso20_950_01/C3_ATTRIBUTION_20261016.md`)
does not depend on it.
