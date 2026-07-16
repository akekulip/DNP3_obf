---
name: multicrob-boundary-index-result
description: "DNP3 multi-CROB boundary-index experiment (week8) — OUT_OF_RANGE vs TOO_MANY_OPS, rig-validated"
metadata: 
  node_type: memory
  type: project
  originSessionId: 97c5e9d6-36fb-4efd-b5d2-7eb3904ecb62
---

Week8 task (Dr. Lin) in `dnp3_multicrob_harness/`: distinguish the OpenDNP3
per-request operation-count limit (`TOO_MANY_OPS`, status 8, the N≥17 result) from a
**nonexistent-output-index** rejection. Rig-validated Vision↔Hulk 2026-07-08.

**Result:** configure K=5 valid points, send N=6 CROBs (indexes 0..5). Index 5 (which
does not exist) is rejected in the SELECT response with **`OUT_OF_RANGE` (status 12)** —
per-index, at the outstation command handler (`select_seen=6`, so OpenDNP3 passes each
CROB to the handler; it does NOT reject the whole request first). SELECT statuses =
`[0,0,0,0,0,12]`. The master does **not** send OPERATE after the partial SELECT failure
(`operate_seen=0`), the batch is discarded (`pending_selection_count=0`), and **no valid
output changes** (`final_state_matches_expected=False`). Valid K=5/N=5 → all SUCCESS,
OPERATE sent, 5/5 operated.

**Two independent safety layers both hold:** (1) master suppresses OPERATE on partial
SELECT failure; (2) outstation discards the partially-failed SELECT batch. So the boundary
is `OUT_OF_RANGE` (nonexistent index), cleanly distinct from `TOO_MANY_OPS` (count limit).

**Trap:** in BOTH the invalid-index case AND the N=17 count-limit case the master reports
task-level `SUCCESS` / exit 0. Task-level SUCCESS is NOT proof any output changed —
per-index evidence must come from the outstation JSON + PCAP. [[dnp3-harness-verified]]

**Attribution correction (2026-07-14):** the `OUT_OF_RANGE` (12) here was the outstation
APPLICATION handler's mapping choice, NOT a protocol-native value. OpenDNP3 does not
validate a CROB index natively (proven: SuccessCommandHandler + DB sized K returns
SUCCESS on the wire for index K). Per IEEE 1815-2012 the standard-aligned status for a
*nonexistent* point is `NOT_SUPPORTED` (4) + IIN2.2; `OUT_OF_RANGE` (12) is value-scoped
(assumes the point exists). See [[multicrob-invalid-index-status-refactor]] — the status
decision now lives in a `ControlPointBackend` (single-source constant
`NONEXISTENT_INDEX_COMMAND_STATUS`), retaining OUT_OF_RANGE for byte-continuity.

**How built (no runner changes needed at the time):** `run_outstation.py`/`run_master.py`
already supported this (ControlTestState returned OUT_OF_RANGE for index ≥ K — since
refactored to delegate to the backend; `--crob-count N` generates 0..N-1). Only added: `analyze_multicrob_pcap.py --mode boundary-index
--configured-points K --expect-operate {absent,present,either}` (classification keyed on
first non-zero SELECT-response status; all-success stays the default so the highest-N
sweep is unchanged) + new orchestrator `run_crob_boundary_index_test.py` (valid+invalid
cases) + `reports/boundary/`. Analyzer regression captures: `captures/sweep/multicrob_n16`
(all-success) and `n17` (boundary-index → too_many_ops). Not padding — response-side
characterization only, prerequisite to considering invalid-index CROBs as a padding
candidate later.
