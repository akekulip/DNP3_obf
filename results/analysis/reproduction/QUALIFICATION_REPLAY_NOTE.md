# Qualification-matrix replay with the frozen tool (2026-10-28)

`scripts/checks/replay.py results/hardware/rc01_hw_c72_20261027_02_index.json` does not complete. With the frozen
tool, blocks 01-05, 09 and 10 replay exactly (2,242 of 2,440 exchanges, including block 10's recorded FAIL):
`qualification_replay_per_block_20261028.json`.

Blocks 06-08 (persistence graceful, persistence RST, reconnect; 198 exchanges) are three-connection trials. Their
endpoint result is in `scenario.json`, and they have no top-level `result.json`. `replay_trial` always reads
`result.json` and stops with `FileNotFoundError` (`replay_scenario_endpoint_red_20261028.log`). The live campaign used
the Vision step's output, which is byte-for-byte the content of `scenario.json`.

`qualification_replay_scenario_diag_20261028.json` is a diagnostic only. It wraps the read in the script itself, takes
the endpoint from `scenario.json`, and leaves the repository unchanged. With that read, all three blocks reproduce
their recorded verdicts exactly (66 of 66 each).

The one-line fix in `replay.py` was tried and reverted. Every recorded standards verdict binds the SHA-256 closure of
all `scripts/checks/*.py`, which includes `replay.py` itself. After the edit, replay of block 01 failed with
`checker.version mismatch`. Repairing the tool therefore needs a decision:
- Fix `replay.py` and record that the retained verdicts no longer bind its new version.
- Or move the replay entry point out of the hashed checker set for future runs.
