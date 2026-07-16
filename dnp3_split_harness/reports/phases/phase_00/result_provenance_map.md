# Result provenance map (Phase 00)

Maps each committed report/result to (a) its producing script and (b) the
machine-readable raw data behind it, and flags results not regenerable from a
command. Full table in worklog `worklogs/agents/phase_00/result_provenance.md`.

**Verdict: 24 report documents audited — 8 with solid provenance, 16 with gaps.**

## Solid provenance (regenerable, raw-backed)

All ANALYTIC (PCAP-derived) or LOOPBACK; each has a confirmed producing script (the
`.py` was grepped for the output filename) and reads committed data:

| Report | Producer | Raw backing |
|---|---|---|
| `ack_trace_summary.md` | `characterize_ack_traces.py` | `ack_trace_characterization.{csv,json}` |
| `attacker_eval.md` | `attacker_eval.py` | `attacker_eval_results.json` |
| `ack_fingerprint_eval.md` | `ack_fingerprint_eval.py` | `ack_fingerprint_eval.json` |
| `trace_before_after.md` | `trace_before_after.py` | `trace_before_after.{csv,json}` (see caveat below) |
| `ack_separation_notes.md` | `ack_separation_probe.py` | `ack_separation_matrix.{csv,json}` |
| `rto_probe_notes.md` | `rto_probe.py` | `rto_probe_results.{csv,json}` |
| `field_map_results.md` | `map_response.py` | (field-map output) |
| `timing_experiment_results.{csv,json}` | `run_timing_experiment.py` | self (raw) |

## Provenance gaps (ranked, worst first)

1. **Hand-authored aggregate deliverables with no producing script** —
   `ack_delay_master_report.md`, `ack_timing_implementation_report.md`, and
   `dnp3_timing_obfuscation_briefing.html`. Highest-visibility, every number
   transcribed by hand; the briefing HTML has no machine-readable sibling at all.
2. **`ack_separation_rig_results.md`** — the headline ~40 ms separate-ACK threshold
   comes from manual `tshark` reading of pcaps; the committed
   `ack_separation_client_matrix.csv` records `pure_ack_emitted = undetermined`, so it
   does **not** back the claim. No script produces the table. (→ Phase 03 reproduces.)
3. **June rig-replay reports** (`ordered_replay_results.md`,
   `request_aware_replay_results.md`, `split_aggressiveness_sweep.md`, plus
   `from_live_split_results.md`, `replay_results.md`, `split_results.md`,
   `baseline_segmentation.md`) — reference pre-2026-07-06 script paths that no longer
   exist (`replay_tools/…`, `pydnp3_harness/experiment_master.py`,
   `tcp_split_replay_server.py`), so their reproduce commands are broken; and the
   800-measurement claim points to `logs/master/soe.csv` and `logs/replay/`, both now
   **missing** on disk.
4. **`rig_timing_matrix_results.md`** — the two-host orchestration has no in-repo
   producer (an out-of-repo SSH driver, uncommitted). Only the per-config
   `rig_timing/*_timing_decisions.jsonl` (from `split_server.py`) and the pcaps are
   repo-native; the aggregate `rig_matrix_results.json` is not regenerable in-repo.
5. **`pad_rig_results.md`** — the mechanism is real (`run_outstation.py --pad-*`) and 3
   pcaps back the byte sizes, but the headline device-ID drop **0.90→0.797** is an
   explicit **projection** with no raw file. Keep labeled projected.

Minor: `tcp_ack_fingerprinting.md` cites a stale tool path
(`analysis_tools/analyze_tcp_ack_behavior.py`); its CSVs are regenerable via the
current `analyze_ack.py`.

## The ~22,988-transaction claim

Traces cleanly: `characterize_ack_traces.py` reconstructs 22,988 request→response
transactions from the six real-device PCAPs in `../Traffic Trace/` (all six present,
hashes in `DATA_PROVENANCE.md`) → writes `reports/ack_trace_characterization.csv`
(22,988 rows) + `.json` + `ack_trace_summary.md`. Regenerable via
`python3 characterize_ack_traces.py`. The attacker/fingerprint evaluations use the
device-specific **11,494**-row subset (excluding the shared reference outstation
`10.0.0.2`). **Solid provenance.**

## Consequence for the reorg

The gap analysis is the empirical case for the run-directory + manifest contract
(`DATA_PROVENANCE.md`): the reports with solid provenance are exactly the ones a
single script writes from committed raw data; every gap is a report whose numbers
live only in prose or depend on an uncommitted/renamed producer.
