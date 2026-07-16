# Phase 00 — CLI / Entry-point Inventory (`dnp3_split_harness/`)

Role: CLI/Entry-point Inspector. READ-ONLY audit; no CLI executed, no source edited.
Scope: the 16 runnable scripts named in the task. All paths absolute.
Target Python: 3.8. Config single-source-of-truth: `dnp3_split_harness/lab_config.py`.

Conventions found across the harness:
- Nearly every script anchors relative paths to its own directory
  (`HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))`) so it runs from any cwd.
- `reports/` output filenames are almost universally **fixed** (no run-id, no timestamp),
  so a re-run silently overwrites the prior run's artifacts.
- The per-run **log** files under `logs/**` are timestamped (`*_<epoch>.log`) and therefore
  unique; the timing/SOE data sinks are the ones with accumulation risk (see summary).

---

## Summary table

| script | purpose | needs pydnp3 | needs root | needs rig | writes-to (fixed?) | overwrites-prior? |
|---|---|---|---|---|---|---|
| `split_server.py` | canonical DNP3 replay/split server (full or CRC-boundary) | no | no* (sudo only to free port 20000) | no (loopback ok; used as outstation on rig) | `logs/replay/` (CLI `--log-dir`): `split_replay_server_<epoch>.log`, `timing_decisions.jsonl`, `request_*.bin` | log=unique; **jsonl APPENDED**; `request_NN.bin` overwritten by name |
| `run_master.py` | pydnp3 DNP3 master; drives scans, writes SOE CSV | **YES** | no | rig (or loopback) | `logs/master/<phase>_soe.csv` (fixed per-phase), `<phase>_summary.txt`, `experiment_master_<epoch>.log` | **CSV APPENDED (accumulates)**; summary=overwrite; log=unique |
| `run_outstation.py` | pydnp3 baseline outstation (READ-only, controls rejected) | **YES** | no | rig (or loopback) | `logs/outstation/experiment_outstation_<epoch>.log` only | log=unique; no data output |
| `run_timing_experiment.py` | loopback timing-normalization matrix driver | no | no | no (pure loopback) | `reports/timing_experiment_results.{json,csv}` (fixed); `logs/timing_exp/<label>/` | **overwrites** reports; per-config logdir `rmtree`'d fresh |
| `characterize_ack_traces.py` | parse 6 device PCAPs → ACK/response characterization | no (needs **tshark**) | no | no (reads PCAPs) | `reports/ack_trace_characterization.{csv,json}`, `reports/ack_trace_summary.md`, `profiles/{sel751,ab1400,ion7550}_*.json` (all fixed) | **overwrites all** |
| `trace_before_after.py` | before/after projection of timing policy on real traces | no | no | no | `reports/trace_before_after.{csv,json,md,png}` (fixed) | **overwrites all** |
| `analyze_ack.py` | TCP ACK/timing + fingerprint fields from a pcap | no (needs **scapy**) | no | no | `reports/tcp_ack_details.csv`, `reports/tcp_ack_summary.csv` (CLI-overridable) | **overwrites** |
| `map_response.py` | decode DNP3 header fields of one payload `.bin` | no | no | no | `reports/field_map_results.md` (CLI `--output`) | **overwrites** |
| `extract_payloads.py` | extract raw DNP3 payloads from a pcap | no (needs **scapy**) | no | no | `payloads/baseline/orig_*.bin`,`resp_*.bin`,`metadata.json` (CLI `--output-dir`) | overwrites by name; **stale higher-numbered .bin NOT cleaned** |
| `ack_separation_probe.py` | Phase-2A socket ACK-separation probe | no | **recommended** (tshark capture needs CAP_NET_RAW/root) | `--client`/`--server`=rig; `--loopback`=local | `reports/ack_separation_matrix.{csv,json}`, `reports/ack_separation_notes.md`, `reports/ack_separation_capture.pcap` (client/loopback only) | **overwrites**; `--server` writes nothing |
| `ack_fingerprint_eval.py` | ACK-channel fingerprint eval (sklearn) | no | no | no | `reports/ack_fingerprint_eval.{json,md}`, `reports/ack_fingerprint_clusters.png` (fixed) | **overwrites all** |
| `attacker_eval.py` | attacker device-ID eval (numpy/pandas; sklearn optional) | no | no | no | `reports/attacker_eval_results.json`, `reports/attacker_eval.md` (fixed) | **overwrites all** |
| `rto_probe.py` | TCP RTO/retransmission boundary probe | no | **recommended** (tshark); works w/o via ss/netstat | `--client`/`--server`=rig; `--loopback`=local | `reports/rto_probe_results.{csv,json}`, `reports/rto_probe_notes.md`, `reports/rto_probe_capture.pcap` (client/loopback only) | **overwrites**; `--server` writes nothing |
| `tests/loopback_smoke.py` | loopback integration + timing check for split_server | no | no | no | stdout; launches split_server into `logs/loopback_smoke/` | server `timing_decisions.jsonl` **APPENDED** into shared logdir |
| `tests/native_master_loopback.sh` | Phase-1 integration w/ real pydnp3 master (loopback) | **YES** | uses `fuser -k 20000/tcp` (may need root) | no (loopback) | `logs/native_master_loopback/` (server.log, master.log, timing_decisions.jsonl) | **logdir `rm -rf`'d fresh each run** |
| `tests/test_timing_policy.py` | unit tests for `timing_policy.py` (pure) | no | no | no | nothing (stdout only) | N/A |

\* `split_server.py` binds TCP/20000 (unprivileged port, no root); the only root need is the
documented `sudo fuser -k 20000/tcp` to evict a real outstation before replay.

---

## Per-CLI detail

### `split_server.py`
1. **Purpose.** THE canonical request-aware TCP replay/split server; stands in for the outstation, matches each request's function code + app sequence, replies only with the matching captured response, splits data responses on CRC boundaries (byte-preserving), waits for the master CONFIRM. No pydnp3.
2. **Invocation.** `python3 split_server.py` (crc-boundary default) · `python3 split_server.py --delivery full` · loopback: `--host 127.0.0.1 --port 20077 ...`
3. **Flags** (argparse `split_server.py:679-703`; defaults from `lab_config.py`):
   - `--host` = `BIND_IP` (`0.0.0.0`); `--port` = `DNP3_PORT` (20000)
   - `--delivery` {`full`,`crc-boundary`} = `crc-boundary`
   - `--blocks-per-chunk` = `DEFAULT_BLOCKS_PER_CHUNK` (1); `--chunk-delay-ms` = `DEFAULT_CHUNK_DELAY_MS` (10)
   - `--request-timeout-sec` = 10.0; `--hold-after-response-sec` = `DEFAULT_HOLD_AFTER_RESPONSE_SEC` (20)
   - `--replay-dir` = `DEFAULT_REPLAY_DIR` (`payloads/replay`)
   - `--log-dir` = `logs/replay`
   - plus the whole `timing_policy` argument group (`--timing-mode native|fixed|bounded`, `--target-delay-ms`, `--target-min-ms/--target-max-ms`, `--timing-seed`, `--rto-safe-ms`, …) added at `split_server.py:702` via `tpol.add_timing_arguments(parser)`.
4. **Inputs.** `<replay-dir>/metadata.json` + `orig_*.bin`/`resp_*.bin` (hard-requires `metadata.json`, `split_server.py:712`); `lab_config.py`.
5. **Outputs.** Under `--log-dir` (default `logs/replay`, anchored to harness dir):
   - `split_replay_server_<epoch>.log` — timestamped, unique (`:720`)
   - `timing_decisions.jsonl` — **opened in append mode** (`:630`, `open(..., "a")`)
   - `request_<NN>.bin`, `trailing.bin` byte dumps (`:527`,`:661`,`:667`) — overwritten by fixed name.
6. **Runtime reqs.** pydnp3 NO. root NO (see note *). rig: works on loopback and as the outstation-side replacement on Hulk. Reads `lab_config.py` YES.
7. **Overwrite.** Log file unique per run; `request_NN.bin` clobbered by name; **`timing_decisions.jsonl` accumulates** across runs that reuse the same `--log-dir`.

### `run_master.py`
1. **Purpose.** pydnp3 DNP3 master; performs a safe READ/RESPONSE action, decodes the outstation DB, writes a per-phase SOE CSV + a human-readable receipt.
2. **Invocation.** `python3 run_master.py --phase baseline` → `logs/master/baseline_soe.csv`; `python3 run_master.py --phase crc-split`.
3. **Flags** (`run_master.py:606-656`; defaults from `lab_config.py`):
   - `--host` = `OUTSTATION_IP`; `--local` = `BIND_IP`; `--port` = 20000
   - `--master-addr` = 1; `--outstation-addr` = 10; `--response-timeout-sec` = 2
   - `--action` ∈ `SAFE_ACTIONS`, default `scan-all-classes`
   - `--group` 30 / `--variation` 1 / `--start` 0 / `--stop` 9 / `--repeat` 1 / `--delay-between` 1.0 / `--wait-after-action` 5
   - `--log-dir` = `logs/master`
   - `--phase` {baseline,exact-replay,crc-split,custom} = **baseline**
   - `--csv` (override per-phase path) / `--no-csv` / `--summary` / `--no-summary` / `--receipt-rows` 8 / `--baseline` (compare CSV) / `--enable-periodic-scans`
4. **Inputs.** `lab_config.py`; optional `--baseline` SOE CSV for the PASS/FAIL comparison.
5. **Outputs.**
   - `logs/master/<phase>_soe.csv` (default; `run_master.py:724`) — **row data**
   - `<phase>_summary.txt` receipt (derived from the CSV name, `:504-505`; `open('w')` overwrite)
   - `experiment_master_<epoch>.log` (timestamped, `:664`)
6. **Runtime reqs.** **pydnp3 YES** (`from pydnp3 import ...`, `:14`). root NO. rig: normally Vision→outstation/split server; loopback also works. `lab_config.py` YES.
7. **Overwrite.** **The SOE CSV is APPEND-mode** — `CSVSOEHandler` opens `'a'` and only writes the header if the file is new/empty (`:344-352`,`:385`). Re-running the same `--phase` **adds** rows to the existing file (no truncation), silently inflating the measurement count. Summary `.txt` is overwritten; log unique.

### `run_outstation.py`
1. **Purpose.** pydnp3 baseline outstation — READ-only, controls rejected (`NOT_SUPPORTED`), unsolicited OFF. Builds a large DB for the full read response.
2. **Invocation.** `python3 run_outstation.py`
3. **Flags** (`run_outstation.py:401-441`):
   - `--host` = `BIND_IP`; `--port` = 20000; `--local-addr` = 10; `--remote-addr` = 1
   - `--db-size` 300 / `--num-analog` 200 / `--num-binary` 50 / `--num-counter` 50
   - `--pad-analog` 0 / `--pad-binary` 0 / `--pad-counter` 0
   - `--allow-unsolicited` (flag) / `--allow-controls` (flag)
   - `--apply-initial-values` / `--no-apply-initial-values` (dest `apply_initial_values`)
   - `--hold` (default True) / `--no-hold`
   - `--log-dir` = `logs/outstation`
4. **Inputs.** `lab_config.py` only.
5. **Outputs.** Only `logs/outstation/experiment_outstation_<epoch>.log` (timestamped, `:469`). No CSV/bin/data output.
6. **Runtime reqs.** **pydnp3 YES** (`:28`). root NO. rig: runs on Hulk (or loopback). `lab_config.py` YES.
7. **Overwrite.** No — the only artifact is a unique timestamped log.

### `run_timing_experiment.py`
1. **Purpose.** Reproducible Phase-1 response-time-normalization matrix; drives `split_server.py` over the loopback replay exchange across a native/fixed/bounded matrix, N reps each.
2. **Invocation.** `python3 run_timing_experiment.py` (20 reps) · `--reps 50`.
3. **Flags** (`run_timing_experiment.py:117-120`): `--reps` = 20; `--port0` = 20100. (The timing matrix itself is hard-coded in `DEFAULT_MATRIX`, `:35-49`.)
4. **Inputs.** `payloads/replay/` (via `tests/loopback_smoke.run_one`, imported at `:30`); launches `split_server.py`.
5. **Outputs.** `reports/timing_experiment_results.json` and `.csv` (fixed, `:139`,`:145`); per-config logs in `logs/timing_exp/<label>/` (each `shutil.rmtree`'d then recreated, `:73-75`).
6. **Runtime reqs.** pydnp3 NO. root NO. rig NO (pure loopback smoke). `lab_config.py` indirect (via split_server).
7. **Overwrite.** YES — fixed report paths overwritten; per-config log dirs wiped fresh each run (good isolation for its own logs).

### `characterize_ack_traces.py`
1. **Purpose.** Parse the six real-device PCAPs and reconstruct DNP3 request/response transactions, classifying each as combined-ACK / separate-ACK / other.
2. **Invocation.** `python3 characterize_ack_traces.py`
3. **Flags** (`characterize_ack_traces.py:660-667`):
   - `--traffic-dir` = `/home/philip/Projects/DNP3/Traffic Trace` (**hard-coded absolute default**)
   - `--out-dir` = the harness dir (`reports/` and `profiles/` created under it)
4. **Inputs.** `<traffic-dir>/*.pcap` (six device captures). Parsed via **`tshark`** subprocess (`:141-162`, `subprocess.run(..., check=True)`).
5. **Outputs** (all fixed, all overwritten):
   - `reports/ack_trace_characterization.csv` / `.json`, `reports/ack_trace_summary.md`
   - `profiles/sel751_separate_ack.json`, `profiles/ab1400_combined_ack.json`, `profiles/ion7550_combined_ack.json`
6. **Runtime reqs.** pydnp3 NO. **tshark required.** root NO. rig NO. `lab_config.py` NO.
7. **Overwrite.** YES — every output rewritten (`open('w')`). This CSV is the shared input to `attacker_eval.py`, `ack_fingerprint_eval.py`, `trace_before_after.py`; regenerating it changes all three downstream, unversioned.

### `trace_before_after.py`
1. **Purpose.** Before/after of the ACK/response timing manipulation, projecting the shipped `timing_policy` module over the native per-transaction timings measured in the characterization CSV. No packet forging.
2. **Invocation.** `python3 trace_before_after.py` · `--no-figure`.
3. **Flags** (`trace_before_after.py:430-441`): `--csv` = `reports/ack_trace_characterization.csv`; `--seed` 12345; `--rto-safe-ms` 105.0; `--fixed-ms` 25.0; `--bounded-lo` 20.0; `--bounded-hi` 30.0; `--response-delay-ms` 8.0; `--ack-delay-ms` 8.0; `--gap-ms` 20.0; `--no-figure`.
4. **Inputs.** `reports/ack_trace_characterization.csv` (produced by `characterize_ack_traces.py`); `timing_policy.py`.
5. **Outputs** (fixed, `:449-452`): `reports/trace_before_after.{json,md,csv,png}` (png only if matplotlib present).
6. **Runtime reqs.** pydnp3 NO. root NO. rig NO. Needs `timing_policy` (repo) + matplotlib (optional, for png). `lab_config.py` NO.
7. **Overwrite.** YES — all four fixed outputs overwritten.

### `analyze_ack.py`
1. **Purpose.** Analyze TCP ACK / response-timing behavior + TCP/IP fingerprint fields (options, window, TTL, IP ID, PSH) from a pcap.
2. **Invocation.** `python3 analyze_ack.py` (uses `lab_config` defaults).
3. **Flags** (`analyze_ack.py:52-67`): `--pcap` = `DEFAULT_CAPTURE` (`captures/baseline/read_exchange.pcap`); `--master-ip` = `MASTER_IP`; `--outstation-ip` = `OUTSTATION_IP`; `--port` = 20000; `--output-csv` = `reports/tcp_ack_details.csv`; `--summary` = `reports/tcp_ack_summary.csv`; `--device` = None (defaults to outstation IP).
4. **Inputs.** the `--pcap`; `lab_config.py`. Requires **scapy** (deferred import so `--help` works without it).
5. **Outputs.** `reports/tcp_ack_details.csv`, `reports/tcp_ack_summary.csv` (CLI-overridable).
6. **Runtime reqs.** pydnp3 NO. **scapy required.** root NO. rig NO. `lab_config.py` YES.
7. **Overwrite.** YES — both CSVs written with `open('w')`.

### `map_response.py`
1. **Purpose.** Decode DNP3 link/transport/application header fields (+ header-block CRC via `dnp3_crc`) from a single raw payload `.bin`.
2. **Invocation.** `python3 map_response.py`
3. **Flags** (`map_response.py:208-216`): `--payload` = None → resolves to `payloads/baseline/data_frame.bin`, else `cfg.DEFAULT_RESPONSE_PAYLOAD`; `--output` = `reports/field_map_results.md`.
4. **Inputs.** the resolved payload `.bin`; `lab_config.py`, `dnp3_crc.py`.
5. **Outputs.** `reports/field_map_results.md` (CLI-overridable).
6. **Runtime reqs.** pydnp3 NO. scapy NO. root NO. rig NO. `lab_config.py` YES.
7. **Overwrite.** YES — single fixed markdown, overwritten.

### `extract_payloads.py`
1. **Purpose.** Extract raw DNP3 TCP payload bytes (no L2/L3/L4) from a pcap into per-frame `.bin`s + `metadata.json` — the captured request→response set the replay servers reconstruct.
2. **Invocation.** `python3 extract_payloads.py`
3. **Flags** (`extract_payloads.py:40-51`): `--pcap` = `DEFAULT_CAPTURE`; `--master-ip` = `MASTER_IP`; `--outstation-ip` = `OUTSTATION_IP`; `--port` = 20000; `--output-dir` = `payloads/baseline`.
4. **Inputs.** the `--pcap`; `lab_config.py`. Requires **scapy** (deferred).
5. **Outputs.** in `--output-dir`: `orig_<NNNN>.bin` (requests), `resp_<NNNN>.bin` (responses), `metadata.json`.
6. **Runtime reqs.** pydnp3 NO. **scapy required.** root NO. rig NO. `lab_config.py` YES.
7. **Overwrite.** Partial — `metadata.json` and same-numbered `.bin`s are rewritten, but the output dir is **never cleared** (only `os.makedirs(..., exist_ok=True)`, `:88`). If a prior run produced MORE frames, the stale higher-numbered `orig_/resp_*.bin` survive as orphans (metadata.json won't list them, but they linger in `payloads/baseline/`).

### `ack_separation_probe.py`
1. **Purpose.** Phase-2A socket-level probe: does delaying the application write induce a pure TCP ACK before the DNP3 response? Capability-aware (probes whether tshark can actually capture).
2. **Invocation.** `python3 ack_separation_probe.py --loopback` · rig: `sudo python3 ack_separation_probe.py --client --connect-host 10.10.54.158 --iface eth0 --delays 0,1,2,5,10,20,50 --reps 20` (+ `--server` on the other host).
3. **Flags** (`ack_separation_probe.py:843-874`): mutually-exclusive required `--loopback|--server|--client`; `--connect-host` = `OUTSTATION_IP`; `--bind-ip` = `BIND_IP`; `--port` = 20051 (`DEFAULT_PROBE_PORT`, not the DNP3 port); `--iface` = `lo`; `--delays` = `0,1,2,5,10,20,50`; `--reps` = 20; `--resp-size` = 2407; `--method` {auto,tshark,none} = auto.
4. **Inputs.** `lab_config.py`; optional live tshark capture of its own probe traffic.
5. **Outputs** (client & loopback modes; `:772-789`, all fixed under `reports/`): `ack_separation_matrix.csv`, `ack_separation_matrix.json`, `ack_separation_notes.md`, `ack_separation_capture.pcap`. **`--server` mode writes nothing** (it only serves).
6. **Runtime reqs.** pydnp3 NO. **root recommended** — pure-ACK EMISSION detection needs a privileged capture (CAP_NET_RAW/root); without it the tool still records timing but honestly marks emission "undetermined". rig: `--client`/`--server` are the two-host modes; `--loopback` is local. `lab_config.py` YES.
7. **Overwrite.** YES — the three report files + capture pcap overwritten each client/loopback run.

### `ack_fingerprint_eval.py`
1. **Purpose.** Can an attacker fingerprint the device from the TCP-ACK channel, and what does the ACK-delay defense do to that? Supervised (capture-level split) + unsupervised clustering, before/after the defense.
2. **Invocation.** `python3 ack_fingerprint_eval.py` · `--no-figure`.
3. **Flags** (`ack_fingerprint_eval.py:305-308`): only `--no-figure` (bool). Everything else is hard-coded (input CSV, `TARGET_MS`=25, `GAP_TARGET_MS`=20, device IP map).
4. **Inputs.** `reports/ack_trace_characterization.csv` (hard-coded, `:59`).
5. **Outputs** (fixed, `:328-333`): `reports/ack_fingerprint_eval.json`, `reports/ack_fingerprint_eval.md`, `reports/ack_fingerprint_clusters.png`.
6. **Runtime reqs.** pydnp3 NO. root NO. rig NO. Needs **numpy, pandas, scikit-learn, matplotlib** (all imported at top, not optional). `lab_config.py` NO.
7. **Overwrite.** YES — all outputs overwritten.

### `attacker_eval.py`
1. **Purpose.** Attacker-side classification eval: native device-ID fingerprint baseline, a simulated Phase-1 defense applied to trace features, and a detect-the-defense classifier.
2. **Invocation.** `python3 attacker_eval.py` · `--seed 7`.
3. **Flags** (`attacker_eval.py:776-778`): `--seed` = 42 (`DEFAULT_SEED`); `--csv` = `reports/ack_trace_characterization.csv` (`CSV_PATH`).
4. **Inputs.** `reports/ack_trace_characterization.csv`.
5. **Outputs** (fixed module constants, `:72-73`): `reports/attacker_eval_results.json`, `reports/attacker_eval.md`.
6. **Runtime reqs.** pydnp3 NO. root NO. rig NO. Needs **numpy, pandas**; scikit-learn is **optional** (tree ensembles reported UNAVAILABLE if absent, `:48-56`). `lab_config.py` NO.
7. **Overwrite.** YES — both fixed outputs overwritten.

### `tests/loopback_smoke.py`
1. **Purpose.** Loopback integration + Phase-1 timing validation for `split_server.py`; a minimal no-pydnp3 "replay master" checks byte identity and visible request→response time across timing configs. Also exports `run_one()` reused by `run_timing_experiment.py`.
2. **Invocation.** `python3 tests/loopback_smoke.py`
3. **Flags.** None (no argparse; configs hard-coded at `:127-136`, base port 20077).
4. **Inputs.** `payloads/replay/metadata.json` + `*.bin` (`:29`); launches `split_server.py` as a subprocess.
5. **Outputs.** Prints a table to stdout. Passes `--log-dir logs/loopback_smoke` to the server, so the SERVER writes `split_replay_server_<epoch>.log` + `timing_decisions.jsonl` there. The test file itself writes no report.
6. **Runtime reqs.** pydnp3 NO. root NO. rig NO. `lab_config.py` indirect (via split_server).
7. **Overwrite.** The shared `logs/loopback_smoke/timing_decisions.jsonl` is **append-mode** (server side) and the dir is not wiped, so timing lines accumulate across runs.

### `tests/native_master_loopback.sh`
1. **Purpose.** Phase-1 integration with a REAL DNP3 stack — drives `split_server.py` (timing-enabled) with the real pydnp3 master over loopback and asserts full poll, byte-preservation, zero deadline-miss/bypass/RST.
2. **Invocation.** `bash tests/native_master_loopback.sh` (or `./...`; it's executable).
3. **Flags.** None — hard-coded `PORT=20000`, `LOGDIR=logs/native_master_loopback`, `TARGET_MS=25` (`:16-18`).
4. **Inputs.** `payloads/replay/` (via split_server); the pydnp3 master. Uses `fuser`, `python3`, `timeout`, `grep`.
5. **Outputs.** `logs/native_master_loopback/{server.log,master.log,timing_decisions.jsonl}`.
6. **Runtime reqs.** **pydnp3 YES** (runs `run_master.py --action scan-all-classes`, `:31`). root: uses `fuser -k 20000/tcp` (may need root to kill a foreign owner of the port). rig NO (loopback). `lab_config.py` YES (via runners).
7. **Overwrite.** YES, cleanly — `rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"` at start (`:21`) wipes the dir fresh each run. Good isolation.

### `tests/test_timing_policy.py`
1. **Purpose.** Unit tests for `timing_policy.py` — pure deterministic decision-function checks (no clock, no sockets), incl. structural proof the scheduler holds no packet bytes.
2. **Invocation.** `python3 -m pytest tests/test_timing_policy.py` OR standalone `python3 tests/test_timing_policy.py`.
3. **Flags.** None (pytest/standalone dual runner, `:232-242`).
4. **Inputs.** imports `timing_policy` (repo module). No files, no network.
5. **Outputs.** stdout PASS/FAIL only; no files written.
6. **Runtime reqs.** pydnp3 NO. root NO. rig NO. pytest optional. `lab_config.py` NO.
7. **Overwrite.** N/A — writes nothing.

---

## Fresh-run isolation — the three biggest problems

1. **`run_master.py` per-phase SOE CSV is APPEND, not overwrite (correctness-affecting).**
   `CSVSOEHandler` opens `logs/master/<phase>_soe.csv` with `open(..., 'a')` and writes the
   header only when the file is new/empty (`run_master.py:344-352`, `:385`). Re-running the
   same `--phase` **adds** rows on top of the prior run instead of replacing them — silently
   inflating the headline "800 measurements" success metric. There is no truncation, no run-id,
   no timestamp on this filename. A stale `baseline_soe.csv` from a previous session will
   corrupt the next baseline count unless manually deleted.

2. **Timing-decision `.jsonl` sinks accumulate across runs that share a log dir.**
   `split_server.py` appends every decision to `<log-dir>/timing_decisions.jsonl`
   (`:630`, `open(..., "a")`), and neither `split_server` nor `tests/loopback_smoke.py`
   (shared `logs/loopback_smoke/`) clears the directory first. `run_timing_experiment.py`
   and `native_master_loopback.sh` DO wipe their dirs (`rmtree` / `rm -rf`), so a matrix run is
   clean — but a manual rig run reusing the default `logs/replay/` will blend this session's
   timing stats with prior sessions'.

3. **All analysis/report outputs use fixed, un-scoped filenames; one input CSV fans out unversioned.**
   `attacker_eval.py`, `ack_fingerprint_eval.py`, `trace_before_after.py`,
   `characterize_ack_traces.py`, `analyze_ack.py`, `map_response.py`, and the two probes all
   write to constant `reports/*.{csv,json,md,png}` paths — no run-id/timestamp — so a re-run or
   a different CLI configuration silently clobbers the prior artifacts (you cannot keep two
   configs side-by-side). Compounding it, `reports/ack_trace_characterization.csv` is the shared
   input to three downstream evaluators; regenerating it changes all of them with no version link.
   Separately, `extract_payloads.py` never clears `payloads/baseline/` before writing numbered
   `.bin`s (`:88`), so a shorter re-extraction leaves orphaned higher-numbered files behind.
