# Phase 00 — Repository Architect Audit

**Scope:** `dnp3_split_harness/` (active research root) + root-level note. Read-only classification.
**Method:** tree walk + targeted grep. No files edited/moved/deleted. Every code finding cites `path:line`.
**Caveat:** files were classified from headers, docstrings, imports and call sites — NOT executed. "Active" means "imported/invoked by the current path", not "verified to run".

---

## (A) File classification table

Classes: active-source, active-CLI, test, experiment-config, raw-data, derived-data, generated-result, report, duplicate, legacy, unknown.

### Top-level Python (the 16 in the brief)

| File | Class | One-line reason |
|---|---|---|
| `lab_config.py` | active-source | Single source of truth for lab settings; every script `import lab_config` (`lab_config.py:15-80`). |
| `split_server.py` | active-CLI | The one canonical replay/split server; imports `timing_policy` (`split_server.py:54`), no pydnp3 needed. |
| `run_master.py` | active-CLI | pydnp3 master runner; writes per-phase SOE CSV. |
| `run_outstation.py` | active-CLI | pydnp3 baseline outstation, READ-only, controls rejected. |
| `timing_policy.py` | active-source | Reusable release scheduler; imported by `split_server.py:54`, `trace_before_after.py:45`, `tests/test_timing_policy.py:17`. |
| `dnp3_crc.py` | active-source | CRC-16/DNP helpers; imported by `map_response.py` (and by archived `future_work/dnp3_frame_codec.py:20`). |
| `extract_payloads.py` | active-CLI | PCAP -> `payloads/*.bin` + metadata (scapy, deferred import). |
| `map_response.py` | active-CLI | DNP3 field-map tool over a payload bin. |
| `analyze_ack.py` | active-CLI | scapy ACK/timing analyzer -> `tcp_ack_details.csv` (OVERLAPS `characterize_ack_traces.py`). |
| `characterize_ack_traces.py` | active-CLI | tshark per-transaction ACK characterizer -> `ack_trace_characterization.csv` + `profiles/*.json`. |
| `attacker_eval.py` | active-CLI | ML attacker/fingerprint eval; RE-IMPLEMENTS the defense (`apply_defense` `attacker_eval.py:127`). |
| `ack_fingerprint_eval.py` | active-CLI | ML ACK-fingerprint eval + PNG; RE-IMPLEMENTS the defense (`apply_defense` `ack_fingerprint_eval.py:92`). |
| `trace_before_after.py` | active-CLI | Drives `timing_policy` over trace CSV, before/after + PNG. |
| `rto_probe.py` | active-CLI | Socket probe measuring RTO vs response delay (tshark/ss/netstat). |
| `ack_separation_probe.py` | active-CLI | Socket probe inducing pure-ACK-before-response (near-dup of `rto_probe.py` skeleton). |
| `run_timing_experiment.py` | active-CLI | Loopback timing matrix driver; imports `tests/loopback_smoke.py:30`. |

### Tests

| File | Class | Reason |
|---|---|---|
| `tests/test_timing_policy.py` | test | pytest unit tests for `timing_policy` (22 cases). |
| `tests/loopback_smoke.py` | test | Loopback smoke driver; ALSO imported as a helper by `run_timing_experiment.py:30` (dual test/active-source role). |
| `tests/native_master_loopback.sh` | test | Shell smoke harness. |

### Archived code (per repo CLAUDE.md — superseded)

| File | Class | Reason |
|---|---|---|
| `archive_experiments/dnp3_crc_splitter.py` | legacy | Superseded CRC-split CLI; imported only within `archive_experiments/`. |
| `archive_experiments/dnp3_ordered_replay_server.py` | legacy | Competing replay server (ordered). |
| `archive_experiments/dnp3_replay_server.py` | legacy | Competing replay server (blind). |
| `archive_experiments/legacy_single_response_server.py` | legacy | Competing single-response server. |
| `archive_experiments/split_reader.pcap` | raw-data | Archived capture. |
| `archive_original/*.py` (8 files) | legacy | Unmodified original pydnp3 example scripts (master/outstation/visitors/cmd/simple/prewrapper). |
| `future_work/dnp3_aware_splitter.py` | legacy | Recompute-based splitter (archived, NOT used). |
| `future_work/dnp3_frame_codec.py` | legacy | Recompute/CRC-rebuild codec (archived). |
| `future_work/README.md` | report | Explains the archived recompute line. |

### Data / results / docs

| Path | Class | Reason |
|---|---|---|
| `captures/**/*.pcap*` | raw-data | Source PCAPs (baseline/manual/replay). |
| `payloads/**/*.bin`, `metadata.json` | derived-data | Extracted from captures via `extract_payloads.py`; replay input. |
| `profiles/*.json` | generated-result | Measured device profiles written by `characterize_ack_traces.py`. |
| `logs/**` | generated-result | Runtime logs/SOE/jsonl (gitignored; present on disk). |
| `runs/**` | generated-result | Per-run artifacts (gitignored; present on disk). |
| `reports/*.md`, `*.html` | report | Human write-ups + interactive briefings. |
| `reports/*.csv`, `*.json`, `*.png`, `*.pcap` | generated-result | Analysis outputs (tracked in git). |
| `reports/phases/phase_00/*` | generated-result | Prior Phase-00 artifacts (tree_before, dependency_inventory). |
| `docs/implementation_guide.md` | report | Governing spec (also naming-rule note, see F). |
| `docs/ack_timing_*.{md,html}` | report | Research notes / explainer. |
| `README.md`, `WORKING_NOTES.md` | report | Repo docs. |
| `requirements.txt` | experiment-config | Dependency manifest (INCOMPLETE, see E). |
| `__pycache__/`, `.pytest_cache/` | generated-result | Bytecode/cache; py38 AND py312 pyc present though supported Python is 3.8. |

### Root-level (noted, not deeply audited)

`dnp3_multicrob_harness/` = SEPARATE non-obfuscation line (out of scope). `PyDNP3/`, `Traffic Trace/`, `paper/`, `research/`, `slides_week8/`, `*.pptx`, `*.md` notes = report/reference. `dnp3_experiment_harness.zip` + `dnp3_experiment_harness_code.zip` = **legacy/duplicate** pre-split snapshots (stale archives at repo root).

**Counts:** active-source 3 · active-CLI 13 · test 3 · experiment-config 1 · legacy 15 (4 archive_experiments .py + 8 archive_original .py + 2 future_work .py + 1 archived pcap; plus 2 root zips) · report ~9 · raw-data / derived-data / generated-result = data trees.

---

## (B) Duplicate / competing implementations

**B1 — Defense math implemented in THREE places (top risk).**
The shipped normalization rule `actual_release = max(response_ready, desired_release)` lives in the canonical scheduler `timing_policy.py` (docstring `timing_policy.py:12-14`, `ReleaseScheduler`/`plan_ack_response_release`). It is RE-IMPLEMENTED, not imported, in the two attacker evaluations:
- `attacker_eval.py:127` `apply_defense()` -> `new_resp = np.maximum(native_resp, target)` (`attacker_eval.py:155`).
- `ack_fingerprint_eval.py:92` `apply_defense()` (separate copy).
Only `split_server.py:54`, `trace_before_after.py:45`, `tests/test_timing_policy.py:17` import `timing_policy`. The two ML evals that claim to measure "the implemented defense" carry their own copy of its math, so a change to the real policy will NOT propagate to them.

**B2 — Two parallel ACK/timing feature extractors.**
- `analyze_ack.py` (scapy, `analyze_ack.py:100`) -> `reports/tcp_ack_details.csv` / `tcp_ack_summary.csv`.
- `characterize_ack_traces.py` (tshark, `characterize_ack_traces.py:141`) -> `reports/ack_trace_characterization.csv` + `profiles/*.json`.
Both parse the same DNP3-port-20000 pcaps and compute pure-vs-piggyback ACK, request->ACK and request->response — via different libraries. Downstream (`attacker_eval`, `ack_fingerprint_eval`, `trace_before_after`) consume `characterize`'s CSV, so `analyze_ack.py` is the redundant/older extractor.

**B3 — Near-duplicate socket-probe harness.**
`rto_probe.py` and `ack_separation_probe.py` share ~10 identically-named helpers each (`_tshark_can_capture`, `_start_tshark_capture`, `_stop_tshark_capture`, `_tshark_*`, background-server + client skeleton) — e.g. `rto_probe.py:201/221/232` vs `ack_separation_probe.py:268/310/321`. Copy-paste of the capture/probe scaffold.

**B4 — Competing replay servers (all archived, confirmed inert).**
`split_server.py` is canonical. Superseded siblings: `archive_experiments/dnp3_replay_server.py`, `dnp3_ordered_replay_server.py`, `legacy_single_response_server.py`, `dnp3_crc_splitter.py`; recompute-based `future_work/dnp3_aware_splitter.py` + `dnp3_frame_codec.py`. **No active file imports from `archive_experiments/`, `archive_original/`, or `future_work/`** — verified by grep; the only cross-dir import is `future_work/dnp3_frame_codec.py:20` reaching UP to the active `dnp3_crc.py` (future->active, harmless). No import cycles found.

---

## (C) Hard-coded values

### IP addresses
- **Rig IPs (centralized, tracked):** `lab_config.py:15` `MASTER_IP="10.10.54.19"`, `lab_config.py:16` `OUTSTATION_IP="10.10.54.158"`, `lab_config.py:23` `BIND_IP="0.0.0.0"`.
- **Class-default loopback IPs:** `run_master.py:156` `host='127.0.0.1'`, `run_master.py:157` `local='0.0.0.0'`.
- **Device capture IPs DUPLICATED across 4 analysis files** (not centralized):
  - `characterize_ack_traces.py:54-58` (`REFERENCE_IP="10.0.0.2"`, SEL751 `10.0.0.1`, AB1400 `10.0.0.12`, ION7550 `10.0.0.11`).
  - `ack_fingerprint_eval.py:62` `DEVICE_IPS = {"SEL751":"10.0.0.1","AB1400":"10.0.0.12","ION7550":"10.0.0.11"}`.
  - `attacker_eval.py:75` `REFERENCE_OUTSTATION="10.0.0.2"`.
  - `trace_before_after.py:53-57` (same device map again).
- **Legacy (low priority):** `archive_original/run_master_vision_prewrapper.py:12` `10.10.54.158`; `archive_original/master.py:9` `127.0.0.1`; `archive_original/outstation.py:7` `0.0.0.0`.

### Paths
- **Centralized (good pattern):** `lab_config.py:47` `REPORT_DIR`, `:64` `DEFAULT_REPLAY_DIR`, `:70` `DEFAULT_RESPONSE_PAYLOAD`, `:74` `DEFAULT_CAPTURE`.
- **Hard-coded per-script report/output dirs:** `ack_fingerprint_eval.py:59` (`CSV=.../reports/ack_trace_characterization.csv`) + `:60` (`OUT`), `trace_before_after.py:49` (`OUT_DIR`), `run_timing_experiment.py:32` (`REPORTS`), `map_response.py:39` (`DEFAULT_FIELD_MAP_PAYLOAD="payloads/baseline/data_frame.bin"`), `tests/loopback_smoke.py:90` (`"payloads/replay"` literal).
- **Fixed capture paths (overwritten each run):** `rto_probe.py:666` `reports/rto_probe_capture.pcap`, `ack_separation_probe.py:789` `reports/ack_separation_capture.pcap`.

### Delay / magic constants
- **Centralized (good):** `lab_config.py:32-41` (`DEFAULT_RESPONSE_TIMEOUT_SEC=2`, `DEFAULT_WAIT_AFTER_ACTION_SEC=5`, `DEFAULT_BLOCKS_PER_CHUNK=1`, `DEFAULT_CHUNK_DELAY_MS=10`, `DEFAULT_HOLD_AFTER_RESPONSE_SEC=20`), `:77-80` DB sizes.
- **Hard-coded in code:** `run_master.py:235` `time.sleep(2)`; argparse defaults `run_master.py:629` `--delay-between=1.0`.
- **Inline defense-magnitude config (not in lab_config):** `attacker_eval.py:95-155` (`lo`/`hi`/`floor`, `constant_25`) — the normalization magnitudes are hard-coded inside the attacker sim rather than shared with `timing_policy`/`lab_config`.

---

## (D) CSV-append / pcap-overwrite / mixed-plot offenders

### open(..., "a") on CSV / log (append without truncate)
- `run_master.py:347` and `run_master.py:385` — `open(self.csv_path, 'a', newline='')`. Header is written only if the file is absent or empty (`run_master.py:345`). **Consequence:** re-running the same `--phase` APPENDS rows to the existing `logs/master/<phase>_soe.csv` instead of overwriting — stale runs accumulate and can silently inflate the 800-measurement bar.
- `split_server.py:630` — `open(self._timing_log_path, "a")` appends timing decisions (jsonl-style). Lower risk (per-run path), but same append pattern.

### pcap overwrite (delete-then-rewrite a fixed path each run)
- `rto_probe.py:223-224` — `if os.path.exists(pcap_path): os.remove(pcap_path)` then `tshark -w pcap_path` (`rto_probe.py:226`). Overwrites `reports/rto_probe_capture.pcap`.
- `ack_separation_probe.py:312-313` — same delete-then-`tshark -w` pattern, overwrites `reports/ack_separation_capture.pcap`.

### mixed data-collection + plotting in one file
- `ack_fingerprint_eval.py` — computes ML fingerprint eval AND renders a scatter: `import matplotlib` at `ack_fingerprint_eval.py:191-193`, writes `reports/ack_fingerprint_clusters.png`.
- `trace_before_after.py` — computes the timing projection AND plots: `import matplotlib` at `trace_before_after.py:353-355`, writes `reports/trace_before_after.png`.

---

## (E) Dependency gaps

`requirements.txt` declares only `pydnp3` and `scapy>=2.4.3`. Undeclared third-party imports:

| Library | Imported at | Guarded? |
|---|---|---|
| numpy | `attacker_eval.py:45`, `ack_fingerprint_eval.py:49`, `characterize_ack_traces.py:46` | No (top-level; hard-fail if absent). |
| pandas | `attacker_eval.py:46`, `ack_fingerprint_eval.py:50` | No. |
| scikit-learn | `attacker_eval.py:49-50` (try/except), `ack_fingerprint_eval.py:51-55` (top-level) | `attacker_eval` degrades gracefully; `ack_fingerprint_eval` does NOT — unguarded top-level import will crash without sklearn. |
| matplotlib | `ack_fingerprint_eval.py:191-193`, `trace_before_after.py:353-355` | Yes (deferred/optional). |

Also undeclared **external binary**: `tshark`/`tcpdump` (Wireshark) is a hard runtime requirement for `characterize_ack_traces.py:144`, `rto_probe.py:226`, `ack_separation_probe.py:315` — not expressible in `requirements.txt` but not documented as a prerequisite either. On a clean supported-Python-3.8 environment, `attacker_eval.py`, `ack_fingerprint_eval.py`, `characterize_ack_traces.py` will fail at import for missing numpy/pandas/sklearn.

---

## (F) Naming-rule check

Hard rule: the internal project codename must NEVER appear anywhere. Scan result: **the codename `«REDACTED-CODENAME»` appears in exactly two tracked files, both inside the rule statement itself**:
- `docs/implementation_guide.md:17` — "Do **not** use project-specific names such as «REDACTED-CODENAME» ...".
- `README.md:13` — the naming-rule paragraph.

No codename occurs in any `.py` source, comment, class name, log string, or report body — the code is clean. But per the letter of the rule ("...or README text"), the codename is technically present in tracked docs because the rule uses it as its own example. **Recommendation (flag only, no edit):** replace the literal example in `implementation_guide.md:17` with a generic placeholder so the codename string is absent from the tree entirely.

---

## (G) Top 8 organization problems ranked by risk

1. **Defense math triplicated (HIGH).** `timing_policy.py` vs `attacker_eval.py:127` vs `ack_fingerprint_eval.py:92` — the two attacker evals reimplement `max(native, target)` instead of importing the shipped scheduler, so their "measured defense" can silently diverge from what `split_server.py` actually runs. Consolidate onto `timing_policy`.

2. **Two parallel ACK feature extractors (HIGH).** `analyze_ack.py` (scapy) and `characterize_ack_traces.py` (tshark) compute the same ACK/timing observables from the same pcaps via different tools; only the tshark CSV feeds downstream. Risk of inconsistent "native" baselines; retire or reconcile `analyze_ack.py`.

3. **Undeclared heavy deps + unguarded imports (HIGH, repro-blocking).** numpy/pandas/sklearn/matplotlib and the tshark binary are absent from `requirements.txt`; `ack_fingerprint_eval.py:51-55` imports sklearn unguarded. Clean-env runs of three scripts crash at import.

4. **`run_master` CSV append without truncate (MEDIUM-HIGH).** `run_master.py:347/385` append to the per-phase SOE CSV; re-running a phase accumulates rows, corrupting the 800-measurement success bar. Should truncate (or version) per run.

5. **Device capture IPs hard-coded and duplicated across 4 files (MEDIUM).** `characterize_ack_traces.py:54-58`, `ack_fingerprint_eval.py:62`, `attacker_eval.py:75`, `trace_before_after.py:53-57` each carry their own `10.0.0.x` device map — drift risk; belongs in one shared table (the repo already has the `lab_config` pattern for this).

6. **Data-collection mixed with plotting (MEDIUM).** `ack_fingerprint_eval.py` and `trace_before_after.py` both compute numeric results AND emit PNGs in one file, coupling result generation to matplotlib. Split plotting from analysis.

7. **Near-duplicate socket-probe scaffold (MEDIUM).** `rto_probe.py` and `ack_separation_probe.py` copy ~10 tshark/probe helpers each; maintenance drift. Factor the shared capture harness into one module.

8. **Committed/cluttered artifacts + codename leak (LOW-MEDIUM).** `reports/` generated CSV/JSON/PNG/PCAP are git-tracked; on-disk `logs/`, `runs/`, `__pycache__` (both py38 and py312 bytecode) and two root-level `dnp3_experiment_harness*.zip` pre-split snapshots are stale clutter; `«REDACTED-CODENAME»` string still present in `docs/implementation_guide.md:17` and `README.md:13`.
