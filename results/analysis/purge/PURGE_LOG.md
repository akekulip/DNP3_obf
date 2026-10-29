# Purge of proven-dead Python code (2026-10-29, Part 2 step 9)

The rule was the Karpathy guideline: remove only code proven dead or duplicated, keep behaviour, never weaken a
test. One entry per change, with the evidence of no use and the last commit that touched it, is in `PURGE_LOG.json`.

**Size.** Python under `scripts/` went from 32,692 to 31,087 lines (−1,605); `tests/` is unchanged at 8,956. The
diff is 68 lines added and 1,687 deleted across 21 paths.

| Group | Entries | Lines removed | Examples |
|---|---:|---:|---|
| Dead files | 3 | 226 | `scripts/analysis/paper_palettes.py` (never imported), `scripts/hardware/run_block.sh` (refused by `guarded_block.py` without `--freeze`), `scripts/reproduce.sh` (never invoked) |
| Dead code | 12 | 1,369 | the 11 unused `utils_mpl.py` helpers; the old software-outstation path and the unreachable `setup`/`casea`/`restore` blocks of `vision_run.main()`; the uncalled calibration, CPU-latency and RX-coalescing helpers of `capture_observation.py`; the capture-side `loss.py` chain; unused `campaign_base` methods and constants |
| Duplicate | 1 | 10 | the second tcpdump-statistics parser |
| Narrative | 6 | 20 | review-history tags and a re-pin story in `evaluation_campaign.py` and `freeze_gate.py` |
| Stale references | 9 | 2 | comments naming files that no longer exist |

**`vision_run` restore path checked.** `setup` and `restore` are dispatched at the top of `main()` through
`relay_offload_lifecycle`, which also repairs the mirror interface, and then return. The removed later blocks were
the old software-outstation lifecycle, unreachable before the purge.

**Excluded on purpose.** The 58 files of the c72 model-gate closure, `p4/`, `results/`, Archive, and the files whose
SHA-256 is recorded in the diagnostic and E4 evidence. The c72 live model gate stays `model_gate_passed`.

**Left in place.**
- **`generation_headroom.assess_headroom`:** the E4b golden test pins this file's SHA-256 through the trial record.
- **The nic-repair and vision-unreachable reconcile branches:** retained repair records exist, and the command is
  still live.
- **Unused `vision_run` options:** removing them would turn an accepted flag into an error, and a golden test pins
  the keyword set.
- **`campaign_base.host_diagnostic_evidence`:** it still soft-fails a block whose config asks for the diagnostic,
  which config validation refuses anyway.

**Checks.** Repository suite 471 passed (as before); analysis suite 138 passed, 2 skipped; pyflakes clean on every
modified file.

**Identity.** `loss.py` and `dnp3_codec.py` are in the relay-checker closure, and `vision_run.py`, `campaign.py`,
`campaign_base.py` and `capture_observation.py` are in the runner and Vision hashes. These edits change the identity
recorded by future runs only. Retained verdicts replay through `scripts/analysis/replay_frozen.py`.
