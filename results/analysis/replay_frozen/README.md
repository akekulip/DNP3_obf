# Frozen-tree replay of the c72 qualification matrix (audit 2026-10-28, section 4.6)

`scripts/analysis/replay_frozen.py` rebuilds the checker tree that the campaign freeze bound and replays the retained
evidence with it. Every freeze-listed `scripts/` file is taken from commit `b2634701d` and written only if its SHA-256
matches `freeze.json`. 112 of 114 match. The two that do not, `scripts/hardware/matrix.py` and
`scripts/model/retained_logs.py`, changed after the run and are not imported by the replay. Every repository module the replay
loads is a hash-verified frozen file (17 in original mode, 18 with the adapter); standard-library and site-packages
modules are listed separately as the environment. The evidence is hardlinked into the same tree, so the frozen code runs unpatched.

| File | Mode | Result |
|---|---|---|
| `qualification_original.json` | frozen replay, unadapted (exit 1) | did not complete: 1,934 of 2,440 exchanges reached; it stops at block 06's missing `result.json`, so blocks 07-10 are not reached |
| `qualification_scenario_adapter.json` | same tree plus `scripts/analysis/replay_scenario_adapter.py` (SHA-256 recorded) | 2,440 exchanges accounted for in replay; recorded verdicts reproduced; block 10 (`loss_full`) keeps its recorded FAIL (t3) |

"Accounted for in replay" means the recorded verdicts were reproduced, failures included; it does not mean 2,440
exchanges passed. The corrected-v3 checker analysis is a third, separate result in `results/analysis/corrected_v3/`.
Tests: `tests/analysis/test_replay_frozen.py` (RED `tdd_red.log`, GREEN `tdd_green.log`).
