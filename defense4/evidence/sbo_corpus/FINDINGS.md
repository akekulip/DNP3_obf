# SBO corpus — pass-gate repair + N≥17 cause + corpus split

**2026-08-04. Resolves directive §6. All facts wire- or source-verified this session (emulator only:
10.10.54.x hosts; NO physical SEL-751 contacted). Independently corroborated by the offline transaction
oracle (`defense4/analysis/txn_oracle.py`).**

## 1. Pass-gate failure = harness plumbing, NOT a DNP3/SBO fault (VERIFIED)

The earlier `pass=False` (`task_completion=None`, `out_match=False`) was an artifact-transfer bug in the
sweep, not a control failure:

- `pull()` (`dnp3_multicrob_harness/run_multicrob_sweep.py:56`) used `rsync -az` with no `--mkpath` and
  swallowed the return code. Local rsync is 3.1.3; `--mkpath` needs 3.2.3.
- `captures/sweep/` and `reports/sweep/` exist locally, so the pcap + analyzer JSON transfer →
  `analyze_pass=True`. But `logs/master/` and `logs/outstation/` are gitignored and did not exist
  locally; rsync refuses a nested destination whose parent is missing (`rsync: mkdir ".../logs/master"
  failed: No such file or directory (2)`, exit 11). The master JSON was therefore never read:
  `_load_json → None`, so `(None or {}).get('task_completion') → None` and
  `bool((None or {}).get('final_state_matches_expected')) → False`. The blank `sbo_round_trip_sec` in the
  manifest (also a master-JSON field) corroborates.
- `master_exit=0` is authoritative that the master computed `success` and wrote `task_completion:SUCCESS`
  before exiting (`run_master.py:1232`).

**Fix (minimal, non-semantic):** `pull()` now runs `os.makedirs(local_dir, exist_ok=True)` before rsync
(line 61). After the fix, re-running `--points 2,16,17` gives N=2/N=16 → `pass=True task=SUCCESS
out_match=True ana=True`; N=17 → correctly `pass=False`. One-line source edit; nothing else changed.

## 2. N = 1..16 all PASS (VERIFIED from the wire)

Independent raw-byte + CRC analyzer on every pcap N=1..16: SELECT (func 3) and OPERATE (func 4) both
`count=N`, all SELECT- and OPERATE-response statuses `0x00 SUCCESS`, identical SELECT/OPERATE CROB lists,
all CRCs valid (`reanalyze_n1..16.json`). Rig application-side confirmation for N=2 and N=16:
`select_success=N, operate_success=N, rejected_indexes=[], final_state_matches_expected=true`.

## 3. N ≥ 17 cause = `maxControlsPerRequest = 16` (VERIFIED)

Not an out-of-range index (each outstation started with `--control-point-count N`, so 0..N−1 are valid).
The cap is the OpenDNP3 outstation default `OutstationStackConfig.outstation.params.maxControlsPerRequest
= 16`. Boundary wire analysis of N=17,18,19,32,64,128: SELECT response = first 16 statuses `0x00`,
remaining (N−16) `0x08 TOO_MANY_OPS`; OPERATE never sent (`operate_sent=false`). Rig N=17 corroborates:
`select_seen=16, operate_seen=0, pending_selection_count=16, final_state_matches_expected=false` — the
master's task is protocol-SUCCESS but OPERATE never fired. The oracle sees the same shape:
`SELECT → RESPONSE → ACK → ACK`, no OPERATE.

## 4. Corpus split (`corpus_split.json`)

- **Successful** (SELECT + OPERATE both fully accepted): N = 1..16. **Nmax = 16.**
- **Rejected** (SELECT capped at 16 with TOO_MANY_OPS, OPERATE suppressed): N = 17, 18, 19, 32, 64, 128
  (and any N ≥ 17). Kept as a SEPARATE corpus — never mixed into the public size envelope.

## 5. Consequence for the size envelope

The successful public envelope is N = 1..16: request 35→254 B, response 37→256 B TCP payload, 14.6 B/CROB
(both directions). The request *ceiling* for the provisional slot template is the N=16 success boundary
(inner frame 320 B), not N=17's 335 B — see `PROVISIONAL_SLOT_CANDIDATES.md` §2.

## Artifacts (this directory)
`corpus_split.json`, `reanalyze_n1..16.json`, `reanalyze_boundary_n{17,18,19,32,64,128}.json`,
`master_n{2,16,17}.json`, `outstation_n{2,16,17}.json`, `sweep_manifest_after_fix.csv`,
`sweep_manifest.csv` (original failing), `rerun_sweep_2_16_17.log`.
