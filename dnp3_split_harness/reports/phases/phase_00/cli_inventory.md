# CLI / entry-point inventory (Phase 00)

Every runnable entry point in `dnp3_split_harness/`, inspected read-only (no CLI was
executed — several need pydnp3, root, or the two-host rig). Full detail in the
worklog `worklogs/agents/phase_00/cli_inventory.md`; this is the consolidated map.

Supported interpreter: **Python 3.8**. "rig" = the Vision↔Hulk two-host lab.

| Script | pydnp3 | root | rig | Primary output (fixed path?) | Re-run overwrites/appends? |
|---|:--:|:--:|:--:|---|---|
| `split_server.py` | no | no¹ | no | `logs/replay/timing_decisions.jsonl` + per-run `*.log` | jsonl **APPENDS**; log unique |
| `run_master.py` | **yes** | no | rig/loopback | `logs/master/<phase>_soe.csv` (fixed) | **CSV APPENDS — accumulates** |
| `run_outstation.py` | **yes** | no | rig/loopback | `logs/outstation/*_<epoch>.log` | no (unique log) |
| `run_timing_experiment.py` | no | no | no | `reports/timing_experiment_results.{json,csv}` (fixed) | overwrites (wipes logdirs fresh) |
| `characterize_ack_traces.py` | no (**tshark**) | no | no | `reports/ack_trace_characterization.*` + `profiles/*.json` | overwrites all |
| `trace_before_after.py` | no | no | no | `reports/trace_before_after.{csv,json,md,png}` (fixed) | overwrites all |
| `analyze_ack.py` | no (**scapy**) | no | no | `reports/tcp_ack_{details,summary}.csv` | overwrites |
| `map_response.py` | no | no | no | `reports/field_map_results.md` | overwrites |
| `extract_payloads.py` | no (**scapy**) | no | no | `payloads/baseline/{orig,resp}_*.bin`, `metadata.json` | partial; **stale .bin not cleaned** |
| `ack_separation_probe.py` | no | **rec.²** | client/server = rig | `reports/ack_separation_matrix.*` (client side) | overwrites; `--server` writes nothing |
| `ack_fingerprint_eval.py` | no | no | no | `reports/ack_fingerprint_eval.{json,md,png}` (fixed) | overwrites all |
| `attacker_eval.py` | no | no | no | `reports/attacker_eval_results.json`, `attacker_eval.md` (fixed) | overwrites all |
| `rto_probe.py` | no | **rec.²** | client/server = rig | `reports/rto_probe_results.*` (client side) | overwrites; `--server` writes nothing |
| `tests/loopback_smoke.py` | no | no | no | stdout; server → `logs/loopback_smoke/` | jsonl **APPENDS** |
| `tests/native_master_loopback.sh` | **yes** | `fuser -k` | no | `logs/native_master_loopback/` | overwrites (dir `rm -rf` fresh) |
| `tests/test_timing_policy.py` | no | no | no | stdout only | N/A |

¹ `split_server.py` binds unprivileged TCP/20000; root is only for the documented
`sudo fuser -k 20000/tcp` to evict a real outstation before replay.
² "rec." = root recommended so tshark can capture on the interface.

## Fresh-run isolation problems (ranked)

1. **`run_master.py` SOE CSV is append, not overwrite** (`run_master.py:344-352,385`;
   independently confirmed by the lead). Re-running the same `--phase` stacks rows on
   the prior run and silently inflates the "800 measurements" bar. No run-id, no
   truncation. Highest risk — it corrupts the headline success metric.
2. **Timing `.jsonl` sinks accumulate on shared log dirs.** `split_server.py:630` and
   `tests/loopback_smoke.py` append to a `timing_decisions.jsonl` and never clear the
   dir; only `run_timing_experiment.py` and `native_master_loopback.sh` wipe fresh. A
   manual rig run reusing `logs/replay/` blends this session's stats with prior ones.
3. **All analysis/report outputs use fixed, un-scoped filenames.** Every evaluator/probe
   writes constant `reports/*.{csv,json,md,png}` — no run-id/timestamp — so a re-run or
   a different config silently clobbers prior artifacts. `ack_trace_characterization.csv`
   fans out unversioned to three downstream evaluators; `extract_payloads.py` never
   clears `payloads/baseline/`, orphaning higher-numbered `.bin`s after a shorter re-run.

These are the concrete reasons Phase 01+ must adopt the run-directory contract in
`DATA_PROVENANCE.md` (each run → `runs/<id>/` with a manifest; never append, never
reuse a path).
