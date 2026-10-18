# m10_03: decisions recorded after the baseline delivery (Philip, 2026-10-17)

## 1. Attempt 06's interruption: retrospective approval

Philip approved, after the freeze and the silicon blocks: attempt 06's `sweep_SELECT_008ms` interruption (a
simulator stall of unknown cause) is disclosed and unresolved, and attempt 07 supplies complete replacement
coverage.
- **Retrospective.** The disposition was applied by analogy to his attempt-04 decision before he approved it. The
  gate (`d60d5dd00`), the freeze (`ff179e740`) and the silicon blocks (`b286cf090`) were produced under it.
- **Attempt 06 is not a pass.** Its recorded result stays 370/388, and its evidence and the freeze history are
  unchanged.
- **The exception does not waive semantic failures.** It covers only the interruption. Attempt 06's other failure
  classes stand on their own evidence and resolutions, in its FAILURE note.

## 2. Whole-run stop on a handshake with nothing back: accepted

Harness fix 4 stops the whole run when a handshake step receives nothing (`PointInterrupted`), not only the affected
sequence. Philip accepted this deviation. No restructuring and no additional run are needed for it.
- **Reporting rule.** Every case after the stop is not executed. It is absent from the results, never counted as
  passed. The driver's `exception` case fails the attempt, and meta `interrupted` keeps the step's evidence.
- No attempt has triggered it so far (attempt 07: no interruption).

## 3. Labels kept

- **The restart path is model-proven only.** It was not exercised on silicon (`CLAIMS_20261017.md` row 2b).
- **m9 timing measurements are inherited evidence.** These are the switch-side 7 µs, the host-observed p99 FAIL and
  the isolation results. They were not re-measured on m10_03.

## 4. Stage-count correction

The claim table first said that m10 adds one N stage over m9_01. The compiler placement of both builds shows N 12,
E 12, T 11 for each, on both SDKs (`context.json`). The N 11 figure was candidate61's, the resource review's baseline.
Row 9 is corrected in place, with a note saying so.
