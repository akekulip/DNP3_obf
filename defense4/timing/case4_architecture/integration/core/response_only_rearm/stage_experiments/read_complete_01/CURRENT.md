# Current status — c26 headroom and timing + padding on hardware (run started 2026-10-23)

One status file, updated in place. Dated history: STATUS.md; full record: COMPLETION_RECORD.md (sections 0, 0a).
Directive: `Claude_C26_Headroom_Hardware_Directive.md` (repository root, untracked).

## Scope
Pipe-0 headroom (N and E both at highest occupied stage index <= 10 in one integrated build) on m12p_c26, then the
four-arm comparison and recovery blocks on the selected image on the physical Tofino, through the existing gates.
IEEE 1815 audit DEFERRED. No relay OPERATE, Vision reboot, kernel/firmware change, D/J/attacker campaign, keep-alive
traffic, relaxed thresholds or manual ownership edits.

## Starting state (verified 2026-10-23)
- HEAD = origin/main = 403f60c3e; testbed ownership active False, unsafe_restoration False; no running units.
- m12p_c26 (21b98f51...): generator reproduced (7 modes byte-identical); retained model evidence recomputed
  (model_gate_passed); N/E/T/p1-egress 12/12/11/4. No hardware run on c26. c25 hardware: padding byte-exact, timing
  FAILED, recovery not run (c25 evidence does not qualify c26 or any successor).

## Completion criteria
| # | deliverable | criterion | state |
|---|---|---|---|
| 1 | headroom | both SDKs: N and E highest occupied index <= 10, T <= 11, p1 egress <= 4; per-stage evidence | open |
| 2 | model | new model run: full v3 gate on the selected source; c26 control_timing_01 failure traced | open |
| 3 | hardware four-arm | new hardware run: off/timing/size/combined on the selected image, readout, restore verified | c26 _03: sizing byte-exact all arms, readout OK, restore verified; _01 lost forwarding (base-pipeline intermittent, open) |
| 4 | hardware recovery | new hardware run: loss (mixed, full), persistence graceful/rst, reconnect, held OPERATE | BLOCKED: _04 preflight failure (endpoint not deployed to series run dir) set unsafe_restoration; reconcile refused; needs Philip |
| 5 | timing | unchanged 100 us precision criterion measured; failures stay failures | MEASURED, FAILED on c26 (p99 ~2.0-9.7 ms) |
| 6 | close | records, fresh-checkout reproduction, restoration verified | open |

## Work in progress
P4 placement experiments (Philip's three: calculations into the padding branch; CRC metadata isolated from lifecycle
fields; unreachable READ declarations, checking compiler elimination first) in .scratch_p4; c26 control_timing_01 trace.

## Next action
Hardware stopped (unsafe_restoration flag, reconcile refused): Philip to decide how to clear it. Offline: P4 headroom
experiments, then the selected candidate's gates.
