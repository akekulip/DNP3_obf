# Migration plan (Phase 00)

Old → new → compatibility action for reorganizing the obfuscation research line into
the target tree (`proposed_repository_tree.md`). **This is a plan only.** No move
happens in Phase 00. Nothing is deleted until its replacement is tested, all imports
are updated, reproduction commands are updated, and a compatibility decision is
recorded (§D of the phase plan).

## Migration principles (hard)

1. Create the old→new map (this file) before moving anything.
2. Preserve every current command-line entry point via a thin wrapper if its file
   moves (`cli/<name>.py` re-exports/execs the relocated module).
3. Do not move raw PCAPs without updating a SHA-256 manifest in the same change.
4. Do not commit large raw PCAPs unless Git LFS is intentionally configured.
5. Never delete a legacy file until (a) its replacement is tested, (b) imports are
   updated, (c) reproduction commands are updated, (d) the decision is documented.
6. Repository reorganization and experimental-logic changes go in **separate** commits.

## Sequenced migration (each step is independently reviewable, tests green between steps)

| # | Old | New | Compatibility action | Risk |
|---|---|---|---|---|
| M1 | `numpy/pandas/scikit-learn/matplotlib` undeclared; tshark undocumented | `pyproject.toml` (or expanded `requirements.txt`) + a `docs/` prerequisite note for the tshark binary | Add deps; guard `ack_fingerprint_eval.py` sklearn import like `attacker_eval.py` already does. No file moves. | LOW — pure additive; unblocks clean-env repro |
| M2 | `timing_policy.py` (flat) | `src/dnp3_obf/timing/{profiles,scheduler,ack_planner,safety}.py` | Split by existing internal seams; keep `timing_policy.py` as a shim re-exporting the public names so `split_server.py`, `trace_before_after.py`, tests keep importing unchanged. Run the 22 unit tests before/after. | LOW-MED |
| M3 | `attacker_eval.apply_defense`, `ack_fingerprint_eval.apply_defense` (re-implemented math) | import the canonical scheduler from `dnp3_obf.timing` | Replace the two `np.maximum(native,target)` copies with calls into `timing_policy`. **Add a regression test** asserting the eval path and `ReleaseScheduler` agree on a fixture before removing the copies. | MED — behavior-equivalence must be proven first |
| M4 | `analyze_ack.py` (scapy) vs `characterize_ack_traces.py` (tshark) | one `src/dnp3_obf/pcap/ack_classification.py` | Decide the canonical extractor (tshark path feeds downstream today). Keep `analyze_ack.py` as legacy wrapper until a fixture proves the scapy/tshark observables match; then retire. | MED |
| M5 | `rto_probe.py` + `ack_separation_probe.py` (~10 duplicated helpers) | shared `src/dnp3_obf/tcp/capture_validation.py` | Factor the tshark capture/probe scaffold into one module; both CLIs import it. Wrappers preserve `python3 rto_probe.py …` invocation. | MED |
| M6 | `split_server.py` (flat) | `src/dnp3_obf/replay/{server,splitting,byte_validation}.py` + `cli/` wrapper | Preserve the exact `python3 split_server.py …` command via a wrapper; byte-preservation assertion and CONFIRM-wait logic move verbatim. | MED-HIGH (largest active module) |
| M7 | root `Traffic Trace/*.pcap` | `data/raw/` + `data/README.md` + SHA-256 manifest | Move raw pcaps under the package with a manifest; update the ~4 analysis scripts' input paths in the same commit. Confirm hashes unchanged (see `DATA_PROVENANCE.md`). | MED (path fan-out) |
| M8 | `archive_experiments/`, `archive_original/`, `future_work/` | `legacy/` with one README | Consolidate the already-inert archives (no active import — verified). Pure move + README; never delete. | LOW |
| M9 | fixed `reports/*.{csv,json,png}` outputs; `run_master` CSV append | `runs/<id>/` outputs + manifest; truncate-or-version writers | Retrofit each writer to a run directory; fix the `run_master` append (M-critical for the 800-measurement bar). This is the run-isolation contract, staged per CLI. | MED — touches every writer |
| M10 | root `dnp3_experiment_harness*.zip` (stale pre-split snapshots) | remove from tree (history retains them) or move to `legacy/` | Decide with the human; they are duplicate snapshots, not active. | LOW |

## Explicitly deferred (not before the human approves the target)

- The full flat→`src/dnp3_obf/` package conversion (M2, M4, M5, M6) rewrites every
  bare `import timing_policy` / `import lab_config` / `import dnp3_crc` to package
  paths. It is the largest, most import-fragile change and must be done module by
  module with the test suite green at each step and `cli/` wrappers holding the old
  entry-point names stable.
- Any change that touches ACK/timing behavior (M3, M9's `run_master` fix) is a
  logic change, not a move — it gets its own commit and its own regression test, and
  it is out of scope until Phase 00 is approved.
