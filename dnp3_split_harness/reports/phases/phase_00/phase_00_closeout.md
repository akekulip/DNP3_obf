# Phase 00 — Closeout

Phase 00 (repository audit) was human-reviewed and **conditionally approved**. This
closeout executes the reviewer's required corrections (tasks A–G) without beginning
Phase 01. Authorized now: migration item **M1**, the **Phase-01 slice of M9**, the
claim-label and codename corrections. **M2–M8 and M10 remain deferred.** All work is on
branch `research/ack-timing-phased`.

Baseline audited commit: `dea8f8b`. Phase 00 audit deliverables: `6011a3f`.
Closeout deliverable commit: `22baf968791ffb431cf1555b6bd046a65cf82b79`.

---

## A. Scientific claim-label corrections

Six documents that present **separate-ACK manipulation** results (ACK-delay-only,
response-delay-only, independent ACK/response delay, gap normalization, Phase-2 ACK
manipulation) now carry a visible **PROJECTED / NOT WIRE-VALIDATED** label. Each label
states explicitly that: no current packet-control mechanism enforces the planned
pure-ACK release time; no current PCAP demonstrates independent delay of an existing
pure TCP ACK; the result is a distributional projection, not a live defended capture.

| File | Label placement | Scope |
|---|---|---|
| `reports/trace_before_after.md` | banner under the title | whole doc is a trace projection |
| `reports/ack_delay_master_report.md` | banner + corrected the "measured/validated" sentence | scoped to the ACK manipulation |
| `reports/ack_timing_implementation_report.md` | banner under the title | scoped to Phase-2 modes |
| `reports/ack_delay_tutorial.html` | banner after `<body>` | scoped to ACK manipulation |
| `reports/dnp3_timing_obfuscation_briefing.html` | banner above the hero | scoped to the ACK→response gap |
| `docs/ack_timing_explainer.html` | banner after `<body>` | scoped to the Defend/normalize demo |

Constraints honored: **no result was deleted, no numerical value was altered, nothing
projected is described as measured.** The labels are deliberately **scoped to the
separate-ACK manipulation** — the rig-validated Phase-1 response-time normalization and
the measured trace characterization are explicitly left unaffected (relabeling them
would itself be inaccurate). The ledger is `RESEARCH_CLAIMS.md` (C8) / Phase 00 risk R1.

## B. `phase_status.json` correction

The ambiguous `supported_claims` list was replaced with four buckets:
`claims_supported_by_this_phase` (audit findings + the 22 live unit-test result only),
`prior_claims_with_sufficient_provenance` (C1, C2, C5, C7),
`prior_claims_requiring_reproduction` (C3, C4, the 16 gap-reports), and
`projected_or_unsupported_claims` (C8 + the labeled Phase-2 before/after + the pad-rig
projection). Added `audited_baseline_commit` (`dea8f8b`) and
`phase_00_deliverable_commit` (`6011a3f`). `status = PASS`, `next_phase_allowed = false`.

## C. Dependency declaration (migration M1)

- `requirements.txt` now declares the actual dependency set with **Python 3.8 upper
  pins** (numpy `>=1.24,<1.25`, pandas `>=2.0,<2.1`, scikit-learn `>=1.3,<1.4`,
  matplotlib `>=3.7,<3.8` — the last releases supporting 3.8), keeps `pydnp3` +
  `scapy>=2.4.3`, and documents **tshark** as a required external binary (not
  pip-installable).
- **`check_env.py`** added — reports the interpreter, required/optional packages, and
  the tshark binary; exits non-zero if a required dependency is missing (`--json` for a
  machine-readable form).
- **sklearn guard:** `ack_fingerprint_eval.py`'s scikit-learn import is now wrapped in
  `try/except` (matching `attacker_eval.py`); an unavailable optional dependency now
  yields a **precise message and exit 2** instead of an import crash.
- No files were moved; no experimental calculation was altered.

## D. Phase 01 run isolation (Phase-01 slice of migration M9)

- **`run_manifest.py`** (new, standard-library only, 3.8-compatible) provides the
  minimum reusable run-directory + manifest support: a unique run id, immutable SHA-256
  input hashes, **refusal to write into an already-populated directory**, and a manifest
  recording git commit/branch/dirty-tree, Python + tshark versions, input hashes, the
  exact command, start/end timestamps, and exit status. Output paths are fresh and
  run-scoped (`tables/`, `profiles/`, …); nothing appends or overwrites a fixed
  `reports/*` path.
- **`characterize_ack_traces.py`** gained opt-in `--run-dir` / `--isolated` /
  `--run-name` flags that route all outputs into the run directory with a manifest. The
  **legacy command is unchanged** (no flag → the old `reports/` + `profiles/` behavior),
  so backward compatibility is preserved. A populated `--run-dir` is refused gracefully
  (exit 2, clear message).
- Not retrofitted: the other CLIs' run isolation (deferred; that is the rest of M9).

## E. Internal codename removal

The internal codename was replaced with a neutral placeholder in the one in-scope
document that contained it (`docs/implementation_guide.md`). Technical meaning is
unchanged. Verified: `dnp3_split_harness/` is now codename-clean (the agent worklog that
had echoed it was also redacted during the audit).

## F. Validation (evidence)

| Check | Result |
|---|---|
| `python3 -m pytest tests/ -q` | **30 passed** (22 timing_policy + 8 new run_manifest) on Python 3.8.10 |
| `python3 check_env.py` | exit **0** — all required deps present (scapy 2.4.3, numpy 1.24.4, pandas 2.0.3, sklearn 1.3.2, matplotlib 3.7.5, tshark 4.4.9) |
| sklearn-guard path (sklearn hidden) | `ack_fingerprint_eval.py` prints a precise message, **exit 2** (no import crash) |
| run-isolated characterization smoke | manifest written (input SHA-256 match `DATA_PROVENANCE.md`, git+versions recorded, exit_status=0); reconstruction ground-truth **ALL PASS**; tracked `reports/` **not** overwritten |
| Skipped (reported as skipped, not passed) | rig/pydnp3 integration tests (`native_master_loopback.sh`, `loopback_smoke.py`, two-host rig) — environment unavailable |

## G. Files changed

- **Added:** `run_manifest.py`, `check_env.py`, `tests/test_run_manifest.py`,
  `reports/phases/phase_00/phase_00_closeout.md`.
- **Modified (source):** `characterize_ack_traces.py` (opt-in run isolation),
  `ack_fingerprint_eval.py` (sklearn guard), `requirements.txt` (M1).
- **Modified (docs, labels only):** `reports/trace_before_after.md`,
  `reports/ack_delay_master_report.md`, `reports/ack_timing_implementation_report.md`,
  `reports/ack_delay_tutorial.html`, `reports/dnp3_timing_obfuscation_briefing.html`,
  `docs/ack_timing_explainer.html`, `docs/implementation_guide.md` (codename).
- **Updated:** `reports/phases/phase_00/phase_status.json`.
- **Not moved / not deleted:** no file relocation (M2–M8, M10 deferred).

## Exact commands

```bash
cd dnp3_split_harness
python3 -m pytest tests/ -q                        # 30 passed
python3 check_env.py                               # env check, exit 0
python3 characterize_ack_traces.py --isolated --run-name ack_characterization
#   -> runs/<UTC>_phase_01_ack_characterization/{manifest.json,config.json,tables/,profiles/}
python3 characterize_ack_traces.py                 # legacy path unchanged (reports/ + profiles/)
```

## Remaining blockers

- Human authorization is required to begin Phase 01.
- R13 (codename) and R4 (deps) are resolved; R1 is resolved by labeling (the projection
  is retained and honestly labeled, not removed).
- Deferred migration items **M2–M8, M10** remain, each gated on its own phase approval.

## Readiness for Phase 01

Ready pending authorization. Phase 01 will re-derive **all** trace-characterization
numbers from the six raw PCAPs (not from any prior report) using the run-isolated path
(`--isolated`), producing a manifested run directory per the DATA_PROVENANCE contract.
The env check and dependency pins make a clean 3.8 environment reproducible.

`next_phase_allowed = false` until explicit human authorization.
