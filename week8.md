You are working inside the DNP3 multi-CROB Select-Before-Operate validation harness.

Goal for this task:
Implement and run the boundary-index CROB experiment requested by Dr. Lin. This is not a new Nmax sweep. Nmax has already been determined as 16 for the current default OpenDNP3 configuration. The new goal is to distinguish “too many operations” from “requested output index does not exist.”

Scientific question:
If the outstation is configured with K valid simulated binary output points, what happens when the master sends K+1 CROBs in one G12V1 Select-Before-Operate command set?

Specific experiment:
Case 1: valid baseline

* Outstation configured valid control points: K = 5
* Master sends CROBs: N = 5
* Requested indexes: 0, 1, 2, 3, 4
* Expected: SELECT accepts all 5, OPERATE is sent, all 5 simulated states match the expected final state.

Case 2: invalid-index boundary

* Outstation configured valid control points: K = 5
* Master sends CROBs: N = 6
* Requested indexes: 0, 1, 2, 3, 4, 5
* Expected observation to verify, not assume:

  * SELECT carries G12V1 qualifier 0x28 Count = 6.
  * Indexes 0 through 4 should be valid.
  * Index 5 should be rejected because it does not exist in the simulated outstation.
  * Determine the exact returned DNP3 command status from the PCAP and outstation JSON/log.
  * Determine whether the master sends OPERATE after the partial SELECT failure.
  * Determine whether any valid outputs changed.
* Do not guess the status code. Parse and report it.

Important distinction:

* N=17 previous result: likely OpenDNP3 per-request operation limit, status TOO_MANY_OPS.
* New K=5, N=6 test: should characterize nonexistent-index behavior, likely OUT_OF_RANGE or similar, depending on the stack and handler behavior.

Scope rules:

* Stay with Group 12 Variation 1 CROBs only.
* Do not add multiple groups or variations.
* Do not add analog-output commands.
* Do not modify replay server, CRC-splitting code, Class 0 READ code, P4 code, or any obfuscation code.
* Do not implement padding.
* Do not manipulate or rewrite response statuses.
* Do not raise or change maxControlsPerRequest.
* Do not introduce physical-output behavior. This remains software-only.
* Do not use the internal project codename anywhere.
* Do not treat task-level master SUCCESS as proof that outputs changed. Per-index evidence must come from PCAP plus outstation JSON/log.
* Do not use TCP packet count as a correctness metric. DNP3 logical SELECT/OPERATE content is the correctness metric.

Existing harness structure to preserve:

* run_outstation.py:

  * `--control-test` enables the software-only ControlTestCommandHandler.
  * `--control-point-count N` creates valid simulated indexes `0..N-1`.
  * initial state alternates: even index = False, odd index = True.
  * SELECT records supported CROBs.
  * OPERATE requires matching, unexpired SELECT.
  * partially failed SELECT batch should not leave valid controls armed.
  * JSON evidence should include requested_n, select_seen, select_success, operate_seen, operate_success, rejected_indexes, pending_selection_count, final_state_matches_expected, final_state.
* run_master.py:

  * `--action multi-crob-sbo`
  * `--crob-count N`
  * generates one CommandSet with indexes `0..N-1`.
  * even indexes use LATCH_ON.
  * odd indexes use LATCH_OFF.
* analyze_multicrob_pcap.py:

  * reassembles TCP streams.
  * parses DNP3 link frames.
  * validates DNP3 header CRC and data-block CRCs.
  * reassembles DNP3 transport fragments.
  * parses G12V1 object header, qualifier, count, indexes, control codes, statuses.
* run_multicrob_sweep.py:

  * already shows how to deploy over SSH, start fresh outstation, run dumpcap, run master, pull PCAP/JSON artifacts, run analyzer, and write a manifest.

What to implement:

1. Add a boundary-index analysis mode to `analyze_multicrob_pcap.py`.

Keep the current all-success behavior as the default. Add a mode like:

```bash
python3 analyze_multicrob_pcap.py \
  --pcap captures/boundary/crob_boundary_invalid_k5_n6.pcapng \
  --expected-n 6 \
  --mode boundary-index \
  --configured-points 5 \
  --json reports/boundary/analyze_invalid_k5_n6.json
```

Required CLI additions:

* `--mode`, choices:

  * `all-success`, default, current behavior
  * `boundary-index`
* `--configured-points K`, required when mode is boundary-index
* Optional: `--expect-operate absent|present|either`, default `either` for boundary-index

For `all-success` mode:

* Preserve existing behavior.
* SELECT must exist.
* OPERATE must exist.
* SELECT and OPERATE must carry same G12V1 object list.
* Responses must carry N success statuses.
* all CRCs must validate.

For `boundary-index` mode:

* SELECT must exist.
* SELECT must be G12V1.
* qualifier must be 0x28.
* Count must equal expected_n.
* SELECT indexes should be distinct and should match 0..expected_n-1 for this generated test.
* SELECT response must exist.
* SELECT response must contain expected_n statuses.
* For indexes < configured_points:

  * expected status is SUCCESS 0x00, unless OpenDNP3 rejects the whole request before per-index handler. If that happens, report clearly.
* For indexes >= configured_points:

  * expected status is non-zero. Do not force a specific status unless observed.
* Record:

  * failure_stage
  * first_rejected_index
  * first_rejected_status
  * first_rejected_status_name
  * select_statuses by index
  * operate_sent true/false
  * operate_response_seen true/false
  * all_crc_valid
  * classification string

Recommended classification values:

* `all_success`
* `invalid_index_rejected_during_select_no_operate`
* `invalid_index_rejected_during_select_operate_still_sent`
* `too_many_ops_during_select`
* `parser_or_crc_failure`
* `unexpected_behavior`

Add a small command-status name mapping for the statuses we care about:

* 0: SUCCESS
* 2: NO_SELECT
* 4: NOT_SUPPORTED
* 8: TOO_MANY_OPS
* 12: OUT_OF_RANGE

Do not invent unknown mappings. If an unknown non-zero status appears, report `UNKNOWN_0xNN`.

Output JSON structure for boundary-index mode should include:

```json
{
  "pcap": "crob_boundary_invalid_k5_n6.pcapng",
  "mode": "boundary-index",
  "configured_points": 5,
  "expected_n": 6,
  "pass": true,
  "classification": "invalid_index_rejected_during_select_no_operate",
  "select": {
    "func": 3,
    "qualifier": "0x28",
    "count": 6,
    "indexes": [0, 1, 2, 3, 4, 5],
    "codes": ["LATCH_ON", "LATCH_OFF", "LATCH_ON", "LATCH_OFF", "LATCH_ON", "LATCH_OFF"],
    "data_link_frames": 1,
    "crc_valid": true
  },
  "select_response": {
    "statuses": [0, 0, 0, 0, 0, 12],
    "status_names": ["SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "OUT_OF_RANGE"],
    "first_rejected_index": 5,
    "first_rejected_status": 12,
    "first_rejected_status_name": "OUT_OF_RANGE"
  },
  "operate_sent": false,
  "operate_response_seen": false,
  "all_crc_valid": true,
  "failures": []
}
```

For boundary-index mode, `pass: true` should mean:

* the PCAP was parsed correctly,
* the SELECT request and SELECT response were found,
* the response clearly classifies the boundary-index behavior,
* CRCs are valid.

Do not require OPERATE in boundary-index mode unless `--expect-operate present` is explicitly set.

2. Add a new orchestration script.

Create:

```text
run_crob_boundary_index_test.py
```

Do not overload the highest-N sweep unless the change is tiny. A separate script is cleaner because this is a different experiment.

Purpose:
Run two fixed cases on the rig:

* valid K=5, N=5
* invalid K=5, N=6

Command:

```bash
python3 run_crob_boundary_index_test.py --user decps
```

CLI options:

* `--user`, default from `RIG_USER` or `decps`
* `--valid-points`, default 5
* `--invalid-extra`, default 1
* `--iface`, default `eno1`
* `--remote-dir`, default same as `run_multicrob_sweep.py`
* `--no-deploy`
* `--only valid|invalid|both`, default both

Use the same lab_config roles:

* MASTER_IP = Vision
* OUTSTATION_IP = Hulk
* port 20000

For each run:

* fresh outstation process
* fresh PCAPNG capture
* clear stale local and remote artifacts first
* deploy harness unless `--no-deploy`
* start dumpcap on Hulk
* start outstation on Hulk using:

  * valid case: `--control-test --control-point-count 5 --run-id boundary_valid_k5_n5`
  * invalid case: `--control-test --control-point-count 5 --run-id boundary_invalid_k5_n6`
* run master on Vision:

  * valid case: `--action multi-crob-sbo --crob-count 5 --run-id boundary_valid_k5_n5`
  * invalid case: `--action multi-crob-sbo --crob-count 6 --run-id boundary_invalid_k5_n6`
* stop dumpcap
* pull:

  * PCAPNG
  * master JSON
  * outstation JSON
  * optional logs
* run analyzer:

  * valid case uses `--mode all-success --expected-n 5`
  * invalid case uses `--mode boundary-index --expected-n 6 --configured-points 5 --expect-operate either`
* write:

  * `captures/boundary/crob_boundary_valid_k5_n5.pcapng`
  * `captures/boundary/crob_boundary_invalid_k5_n6.pcapng`
  * `reports/boundary/analyze_valid_k5_n5.json`
  * `reports/boundary/analyze_invalid_k5_n6.json`
  * `reports/boundary/boundary_index_manifest.csv`
  * `reports/boundary/boundary_index_results.md`

Manifest columns:

* case_name
* configured_points
* sent_crobs
* master_exit
* master_task_completion
* outstation_select_seen
* outstation_select_success
* outstation_operate_seen
* outstation_operate_success
* outstation_rejected_indexes
* outstation_final_state_matches_expected
* analyzer_pass
* analyzer_classification
* first_rejected_index
* first_rejected_status_name
* operate_sent
* pcap_path
* analyzer_json
* outstation_json
* master_json
* note

3. Add a short results markdown file.

Create or update:

```text
reports/boundary/boundary_index_results.md
```

The file should explain:

Title:
Boundary-Index CROB Experiment

Purpose:
This experiment distinguishes an OpenDNP3 operation-count limit from a nonexistent-output-index rejection.

Method:

* Keep object type fixed: Group 12 Variation 1 CROB.
* Use one SBO command set.
* Use one object header with qualifier 0x28 and Count=N.
* Configure only K valid software-only output points.
* Send N CROBs, where N can equal K or exceed K.

Expected comparison:

* Valid K=5, N=5: all accepted, OPERATE sent.
* Invalid K=5, N=6: index 5 does not exist, SELECT response should show a rejection for index 5. Observe whether OPERATE is sent.
* Previous N=17 result: TOO_MANY_OPS due per-request operation limit, not nonexistent index.

Do not write that invalid-index padding is implemented. Only say this characterizes protocol behavior needed before any padding strategy.

4. Add or update README section.

Add a short section titled:

Boundary-index CROB test

Include:

* command to run the new script
* artifact outputs
* what the test proves
* what it does not prove

Do not remove the existing Nmax section.

5. Keep code structure clean.

Coding style:

* Follow existing simple Python style.
* Do not introduce large dependencies.
* Use only stdlib plus existing pydnp3 and scapy.
* Reuse helper patterns from `run_multicrob_sweep.py` for SSH, rsync, dumpcap, stop_outstation, JSON loading.
* Keep paths relative to `HARNESS_DIR`.
* Use clear run IDs.
* Avoid hidden state.
* Delete stale artifacts before each run so old files cannot produce false success.
* Use `.pcapng` extension for new captures.
* Use JSON for machine evidence and markdown for human explanation.

6. Testing requirements.

Before final answer, run or at least verify locally:

Static checks:

```bash
python3 -m py_compile analyze_multicrob_pcap.py
python3 -m py_compile run_crob_boundary_index_test.py
python3 -m py_compile run_master.py
python3 -m py_compile run_outstation.py
```

Analyzer regression checks on existing captures, if present:

```bash
python3 analyze_multicrob_pcap.py \
  --pcap multicrob_n16.pcapng \
  --expected-n 16 \
  --mode all-success

python3 analyze_multicrob_pcap.py \
  --pcap multicrob_n17.pcapng \
  --expected-n 17 \
  --mode boundary-index \
  --configured-points 17 \
  --expect-operate absent
```

The N=17 check should classify TOO_MANY_OPS, not invalid index. If the file path differs, find the capture under `captures/` or current directory.

Rig run:

```bash
python3 run_crob_boundary_index_test.py --user decps
```

Expected final deliverables:

* new or updated analyzer supporting boundary-index mode
* new runner script
* two PCAPNG files
* two analyzer JSON files
* manifest CSV
* results markdown
* README update
* no changes to replay, split, Class 0 READ, or P4 code

7. Final response format.

When done, report:

* files changed
* commands run
* whether valid K=5, N=5 passed
* invalid K=5, N=6 classification
* first rejected index and status
* whether OPERATE was sent
* whether any valid output changed
* paths to PCAPNG and JSON artifacts
* any uncertainty or failure

Most important interpretation:
Do not claim padding works. The correct claim is:

“The experiment characterizes how OpenDNP3 responds when one multi-CROB SBO command set includes a nonexistent output index. This tells us whether invalid-index CROBs can be considered later as a padding candidate and what response-side evidence they produce.”
