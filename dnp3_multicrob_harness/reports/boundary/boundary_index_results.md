# Boundary-Index CROB Experiment

## Purpose

This experiment distinguishes an OpenDNP3 operation-count limit (`TOO_MANY_OPS`, the earlier N=17 result) from a nonexistent-output-index rejection (`OUT_OF_RANGE`). Both stop controls from applying, but for different reasons; the SELECT-response per-index `CommandStatus` on the wire tells them apart.

## Method

- Object type fixed: Group 12 Variation 1 CROB.
- One SBO command set, one object header, qualifier `0x28`, Count = N.
- Outstation configured with only K valid software-only output points (indexes 0..K-1).
- Master sends N CROBs (indexes 0..N-1); N can equal K or exceed K.
- Correctness is the logical SELECT/OPERATE content and per-index status (PCAP + outstation JSON), never TCP packet count. Task-level master SUCCESS is NOT proof that any output changed.

## Observation plan (observe and report -- statuses are not assumed)

- **Valid K=5, N=5:** all indexes exist -> expect all SELECT statuses SUCCESS, OPERATE sent (the valid baseline).
- **Invalid K=5, N=6:** index 5 does not exist -> observe and report the returned per-index SELECT-response CommandStatus for index 5 and whether OPERATE is sent. The status is whatever the outstation application returns; this harness does not assume it will be OUT_OF_RANGE.
- **Earlier N=17 result (for contrast):** `TOO_MANY_OPS` came from the per-request operation-count limit (`maxControlsPerRequest`), not a nonexistent index.
- The returned CommandStatus originates in the outstation application control-point backend; OpenDNP3 does not validate a control index natively (see `run_outstation.py`).

## Observed results

### valid_k5_n5

- configured points K = 5 ; CROBs sent N = 5

- master exit = 0 ; task_completion = SUCCESS (task-level only)

- outstation: select_seen=5 select_success=5 operate_seen=5 operate_success=5

- outstation rejected_indexes = [] ; final_state_matches_expected = True

- analyzer: pass=True classification=`all_success` operate_sent=True

- first rejected: index=None status=None

- artifacts: `captures/boundary/crob_boundary_valid_k5_n5.pcapng`, `reports/boundary/analyze_valid_k5_n5.json`, outstation `logs/outstation/multicrob_boundary_valid_k5_n5.json`, master `logs/master/multicrob_master_boundary_valid_k5_n5.json`

### invalid_k5_n6

- configured points K = 5 ; CROBs sent N = 6

- master exit = 0 ; task_completion = SUCCESS (task-level only)

- outstation: select_seen=6 select_success=5 operate_seen=0 operate_success=0

- outstation rejected_indexes = [5] ; final_state_matches_expected = False

- analyzer: pass=True classification=`invalid_index_rejected_during_select_no_operate` operate_sent=False

- first rejected: index=5 status=OUT_OF_RANGE

- artifacts: `captures/boundary/crob_boundary_invalid_k5_n6.pcapng`, `reports/boundary/analyze_invalid_k5_n6.json`, outstation `logs/outstation/multicrob_boundary_invalid_k5_n6.json`, master `logs/master/multicrob_master_boundary_invalid_k5_n6.json`

## Scope / interpretation

Software-only; no index maps to any physical output. Invalid-index padding is NOT implemented. This experiment only characterises how OpenDNP3 responds when a multi-CROB SBO command set includes a nonexistent output index -- i.e. whether invalid-index CROBs can be considered later as a padding candidate and what response-side evidence they produce. Results are for this exact OpenDNP3 build/host/config; they are not a universal DNP3 result.

