# Proposed repository tree (Phase 00 target)

This is the **target** layout for the obfuscation research line, adapted from the
phase plan (`acj_delay2.md` §D) to what actually exists. It is a destination, **not**
permission for an immediate mass migration. The old→new mapping and compatibility
actions live in `migration_plan.md`; nothing moves until Phase 00 is human-reviewed.

## Decision: `dnp3_split_harness/` is the active project root

Confirmed in Phase 00: `dnp3_split_harness/` is the active obfuscation research root
(it holds `timing_policy.py`, `split_server.py`, the ACK/trace/attacker tooling, the
tests, and all obfuscation reports). The sibling `dnp3_multicrob_harness/` is a
separate, non-obfuscation line and is left untouched. Top-level archives
(`dnp3_experiment_harness*.zip`, `PyDNP3/`) are reference-only.

## Target structure

```
dnp3_split_harness/
├── pyproject.toml            # NEW: declare deps (pydnp3, scapy, numpy, pandas, scikit-learn)
├── README.md                 # exists
├── PROJECT_CONVENTIONS.md    # created in Phase 00
├── RESEARCH_CLAIMS.md        # created in Phase 00
├── DATA_PROVENANCE.md        # created in Phase 00
├── CHANGELOG_RESEARCH.md     # NEW: one entry per completed phase
│
├── src/dnp3_obf/
│   ├── __init__.py
│   ├── common/               # clocks, logging_utils, manifests, types
│   ├── pcap/                 # transaction_reconstruction, ack_classification, fields
│   ├── timing/               # profiles, scheduler, ack_planner, safety  (from timing_policy.py)
│   ├── replay/               # server, splitting, byte_validation        (from split_server.py)
│   ├── tcp/                  # ack_separation, socket_options, capture_validation
│   ├── evaluation/           # features, classifiers, statistics, overhead, figures
│   └── reporting/            # phase_report, latex_export
│
├── cli/                      # thin wrappers preserving current entry-point names
│   ├── characterize_ack_traces.py
│   ├── run_timing_experiment.py
│   ├── run_ack_separation.py
│   ├── run_attacker_evaluation.py
│   └── generate_phase_report.py
│
├── experiments/
│   ├── configs/phase_01 … phase_06/
│   ├── runners/
│   └── manifests/
│
├── tests/{unit,integration,privileged,fixtures}/
│
├── data/
│   ├── raw/                  # the six device pcaps move here (with manifest)
│   ├── derived/              # per-phase derived CSV/JSON
│   └── README.md
│
├── runs/<run_id>/            # manifest.json, config.json, stdout.log, events.jsonl, pcaps/, tables/, figures/
│
├── reports/
│   ├── phases/phase_00 … phase_07/
│   └── final/
│
├── docs/{architecture,experiment_protocols,limitations}/
│
└── legacy/                   # archive_experiments/, archive_original/, future_work/ consolidate here (README explains each)
```

## Adaptation notes (target vs plan)

1. **`src/dnp3_obf/` package** — the current design is flat: ~16 top-level modules
   that import each other by bare module name (`import timing_policy`, `import
   lab_config`, `import dnp3_crc`). Moving to a package requires updating those bare
   imports to `dnp3_obf.timing…` and keeping `cli/` wrappers that re-export the old
   entry-point names so documented commands keep working. This is the largest and
   riskiest migration item — deferred until tests can prove equivalence.
2. **`timing/` split** — `timing_policy.py` cleanly separates into `profiles.py`
   (`TimingProfile`), `scheduler.py` (`ReleaseScheduler`, `TimingDecision`,
   `FlowTimingState`), `ack_planner.py` (`plan_ack_response_release`), and `safety.py`
   (`BypassReason`, bound checks). It is already layered internally, so this is low
   risk once imports are wrapped.
3. **`data/raw`** — the six pcaps currently live at repo-root `Traffic Trace/`, one
   level ABOVE `dnp3_split_harness/`. Moving them under `data/raw/` changes every
   analysis script's input path; a manifest with SHA-256 must be updated in lockstep
   (see DATA_PROVENANCE.md). Large pcaps are not committed without an explicit Git LFS
   decision.
4. **`legacy/`** — `archive_experiments/`, `archive_original/`, `future_work/` already
   serve this role; consolidate them under `legacy/` with a single README rather than
   inventing a new archive. Never delete; confirm nothing active imports from them.
5. **`experiments/configs/`** — no config files exist yet; experiments are currently
   driven purely by CLI flags. Phase 01+ introduces per-phase config files so runs are
   reproducible from a committed config rather than a remembered command line.
```
