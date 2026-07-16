# Phase 02 — Closeout

Phase 02 received a CONDITIONAL PASS with a required correction. This closeout fixes the
bounded-PRNG defect (and a second log-directory defect found during the rerun), reruns the
whole matrix from a clean committed state, regenerates every report and figure, separates the
tail metrics, and adds real pydnp3 task-correctness. The two wire-capture items remain BLOCKED
in this environment. No Phase 03 work has begun.

- **Experiment code commit:** `3306bbaa885d2be37fb57ff916c7ac97f20be4e5` (run manifest
  `dirty_tree = false`).
- **Analysis commit:** `c5bb597edfa33662d75c7272e08696f1eaa222d3` (native N/A + ECDF four-curve + bounded numerical validation;
  post-processing over the same run).
- **Closeout / results commit:** `c87aa88167372fc1dc96a43927574ca75e26e3eb`.
- **Fresh run ID:** `20260716T123500Z_phase_02_combined_timing_normalization` (`--reps 50
  --run-seed 20260716`).

## 1. Defect identified (original bounded experiment)

Every bounded repetition launched a fresh `split_server` with a hard-coded `--timing-seed
12345`. Each server reinitialized the PRNG to the same seed, so the bounded target became a
deterministic function of **transaction position**: the 2407 B READ (position 4) received
**22.9864 ms in all 30 repetitions**, and each bounded config held only five unique target
values across 150 transactions. The target was therefore coupled to response type, the CI was
artificially narrow, and the decorrelation result was not a valid randomized experiment.

**Second defect (found during the rerun):** the per-repetition log directory was named by the
config's mode prefix only, so `bounded/full` and `bounded/crc-split` shared a directory.
`split_server` opens `timing_decisions.jsonl` in append mode, so the crc-split configs read the
full configs' stale server-side timing.

## 2. Root cause

(1) PRNG lifecycle: seed initialized once per repetition (per server subprocess) instead of
once per run. (2) Log dir: non-unique name across configs sharing a mode prefix, combined with
the server's append-mode JSON-L log.

## 3. Code correction

- `phase02_normalize_experiment.py`: a top-level `--run-seed` plus `rep_seed(run_seed,
  config_idx, rep_idx)` — a deterministic seed unique per (run, config, repetition), depending
  only on run seed + config + rep (never on size/type). Injected per bounded rep. Log dirs now
  config-indexed (unique per config).
- `phase02_projected_leakage.py`: four separated tail metrics (below); native mode → N/A.
- `tests/test_phase02_experiment.py` (9 tests total): rep-seed determinism; position-not-fixed; same seed
  reproduces the sequence; different seed changes it; target-size independence; uniform
  distribution (mean≈25, std≈2.89); separated tail metrics (flag == direct); native N/A.

## 4. Old vs corrected results

| item | original (defective) | corrected |
|---|---|---|
| bounded 2407 B READ target | 22.9864 ms every rep (1 value) | 50 distinct targets across 50 reps |
| bounded distinct targets (n=250) | 5 | 250 |
| bounded target mean / std | ~n/a (pinned) | 24.86 / 2.735 ms (uniform) |
| bounded READ visible median (full) | 23.30 ms (artificial) | 25.12 ms |
| bounded READ visible CI | [23.30, 23.31] (artificially narrow) | [24.06, 26.27] (true spread) |
| bounded corr(visible, native) | coupled | 0.009 (decorrelated) |
| crc-split server-side timing | contaminated by full configs | correct (unique log dirs) |
| dirty_tree | true (uncommitted code) | **false** (commit `3306bbaa`) |

## 5. Clean commit and run

Corrected source committed before measurement; the authoritative run's manifest records commit
`3306bbaa`, `dirty_tree = false`, `run_seed = 20260716`, all six-field environment, input hash,
and exact command. Populated-directory refusal re-verified (exit 2).

## 6. Target-distribution validation

Bounded targets span [20.01, 29.99] ms, mean 24.86 ms, std 2.735 ms (expected Uniform(20,30)
std 2.887), 250/250 distinct; corr(target, position)=0.052 and corr(target, size)=0.017 (both
~0) — **no deterministic position-to-target mapping remains**, and the target samples span the
tested sizes. Full numerical validation in `phase02_bounded_validation.md` and the post-review
corrections below (uniformity is not claimed from the histogram alone).

## 7. Byte-preservation

100% (250/250 per config) across native/fixed/bounded × full/crc-split; `b"".join(chunks) ==
response`, no CRC recompute, no field edit.

## 8. pydnp3 correctness

`phase02_pydnp3_integration.py`: a real pydnp3 master completes a genuine DNP3 integrity poll
(OnTaskComplete + database decode) through the timing-enabled `split_server` for **all 6**
native/fixed/bounded × full/crc-split configs, every response held to target, byte-preservation
PASS, zero deadline-miss/bypass. Correctness is now DNP3 task-level, not just replay byte-identity.
(Loopback, not a wire PCAP.)

## 9. PCAP wire timing — BLOCKED

Loopback capture is permission-denied (`dumpcap` `root:wireshark`, this user not in the group)
and the two-host Vision/Hulk rig is unavailable this session. Wire timestamps cannot be produced
here. Run on the rig: `dumpcap -i <if> -w wire.pcap` at one/both endpoints per config.

## 10. ACK mode after normalization — BLOCKED

Whether `fixed25`/`bounded20-30` turns a native combined ACK-bearing response into
request → pure TCP ACK → DNP3 response cannot be answered without a sniffer. Never inferred;
`fig07` is an explicit BLOCKED panel; `ack_mode_pcap` is uniformly `not_captured`.

## 11. Retransmissions and resets

Not observable without a PCAP on this host (recorded `na_no_pcap`); the rig experiment must
classify TCP retransmission/duplicate-ACK/reset from capture.

## 12. Corrected tail metrics

Four distinct metrics (`phase02_projected_leakage.json`): `actual_deadline_miss_rate` (scheduler
flag, native>selected) = 0.0032 bounded / 0.0022 fixed; `native_above_selected_target_rate`
(direct) = identical (confirms semantics); `native_above_lower_bound_rate` (native>20) = 0.0095;
`native_above_upper_bound_rate` (native>30) = 0.0006. The old 0.95% was native>lower-bound,
mislabeled "native>target".

## 13. Figures

Eight distribution-based figures with full metadata (`producing_script = phase02_figures.py`,
source table SHA-256, run id, git commit, seed, n) — no "phase02 inline figure", fig titles not
clipped, fig08 renamed "Projected normalization suppresses bulk timing variation while native
tails retain residual correlation".

## 14. Tests

55 pass (see the report). No skips except rig/PCAP (environmentally unavailable).

## 15. Limitations

Loopback timing is not wire timing; the ACK-mode-after-normalization question and exact wire
timestamps require the rig. All statements are scoped accordingly.

## Post-review corrections (second review pass)

1. **ECDF (`fig02`) fixed.** It filtered by `timing_mode`, so `fixed25/full` and the
   `fixed300-rto105` UNSAFE_TARGET **bypass** (both `timing_mode==fixed`) were merged into one
   "fixed (n=100)" curve. Regenerated with **four separately-labeled config curves**
   (native/full, fixed25/full, bounded20-30/full, fixed300-rto105/full — bypass); a fail-open
   bypass is never merged with a successful normalization mode.
2. **Bounded numerical validation added** (`phase02_bounded_validation.py` →
   `tables/phase02_bounded_validation.json`, `reports/phase02_bounded_validation.md`): n=250,
   250 unique, min 20.01 / max 29.99, mean 24.858, median ~24.9, std 2.735 (expected
   Uniform(20,30) std **2.887**), p5/p25/p75/p95; **corr(target, response size)=0.017**,
   **corr(target, transaction position)=0.052** (crc-split 0.025 / 0.000); per-position and
   per-size summaries. The `fig01` histogram legend now reads "Expected count per bin under
   Uniform(20,30)"; uniformity is not claimed from the histogram alone.
3. **Figure language refined:** `fig05` → "bounded target samples across tested response sizes"
   (not "flat"); `fig06` → "no deterministic position-to-target mapping remains" (not "all
   position distributions identical").
4. **Authoritative clean-run artifacts committed** under `reports/phases/phase_02/`: manifest
   (`dirty_tree=false`), `tables/phase02_transaction_log.csv`, `phase02_config_summary.json`,
   `phase02_projected_leakage.json`, `phase02_bounded_validation.json`, the phase report,
   `phase_status.json`, `validation/test_report.txt`. Every figure metadata sidecar's
   `source_table_sha256` = `d70aa8255d3596903573a9aff64b64726fb26cc1fad354e5d32d0bc99435b4c4`,
   matching the committed transaction log. Run ID `20260716T123500Z_...`.
5. **Four native-tail metrics** reported separately; the difference between the first two:
   `actual_deadline_miss_rate` is the scheduler's `deadline_missed` flag, and
   `native_above_selected_target_rate` recomputes native>selected directly — they are **equal
   (0.0032)**, confirming the flag captures exactly native>selected (no semantic gap);
   `native_above_lower_bound_rate`=0.0095, `native_above_upper_bound_rate`=0.0006.

Tests: **55 pass** (added the bounded-validation position-coupling test).

## Final gate verdict

Phase 02 PASS requires, among other things, that wire timing is captured and ACK mode after
normalization is measured. Both require a packet sniffer that is unavailable in this environment.
Every other condition is met: bounded sampling correct, run from a clean committed state, bytes
preserved, DNP3 task correctness demonstrated, tail metrics correctly defined, no Phase 03 work.

**Status: CONDITIONAL PASS.** `next_phase_allowed = false`.

```
PHASE 02 CLOSEOUT COMPLETE
Status: CONDITIONAL PASS
Code commit: 3306bbaa885d2be37fb57ff916c7ac97f20be4e5
Run ID: 20260716T123500Z_phase_02_combined_timing_normalization
Report: reports/phases/phase_02/phase_02_closeout.md
Wire PCAP: BLOCKED (no capture permission / no rig)
ACK-mode result: BLOCKED (needs sniffer PCAP)
Open blockers: wire PCAP timing; ACK-mode-after-normalization; human authorization for Phase 03
STOP: Awaiting human authorization before Phase 03.
```
