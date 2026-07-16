---
name: multicrob-invalid-index-padding
description: "DNP3 multi-CROB invalid-index \"padding candidate\" suite (week8_next) — placement, decoy, count-limit interaction; rig-validated"
metadata: 
  node_type: memory
  type: project
  originSessionId: 97c5e9d6-36fb-4efd-b5d2-7eb3904ecb62
---

Week8_next task (Dr. Lin) in `dnp3_multicrob_harness/`: can nonexistent G12V1 CROB
indexes act as harmless padding candidates, and what response evidence do they produce?
Extends [[multicrob-boundary-index-result]]. Rig-validated Vision↔Hulk 2026-07-08, all 8
cases analyzer_pass=True.

**Result:** a nonexistent index (>= K) is rejected per-index in the SELECT response with
`OUT_OF_RANGE` (status 12), **regardless of position** (end / begin / middle — all identical).
The master then sends NO OPERATE (partial SELECT failure), no valid output changes. Multiple
invalid indexes each get a rejection (`multiple_invalid_indexes_rejected`); an all-invalid set
is fully rejected (`decoy_only_invalid_rejected`). **K=5, N=17 shows BOTH mechanisms in one
SELECT response:** `status_counts {SUCCESS:5, OUT_OF_RANGE:11, TOO_MANY_OPS:1}` — ops 0-4 ok,
indexes 5-15 OUT_OF_RANGE, the 17th op (index 16) `TOO_MANY_OPS` (8, the maxControlsPerRequest
limit). **K=16, N=17 → `too_many_ops`** (count limit dominates; the invalid index 16 is masked
because op 17 hits the stack count check first). Every case reports task-level master
SUCCESS/exit 0 — task SUCCESS is NOT execution.

**Padding conclusion (supported by the data):** invalid-index CROBs do not execute configured
outputs but ARE visible via non-success SELECT statuses; because a partial SELECT failure
prevents OPERATE, invalid-index padding cannot be inserted into a real control transaction
without additional response-side handling or a different cover-traffic design. NOT padding,
NOT safe for relays, NOT universal DNP3 — this one OpenDNP3 build/host/config only.

**What was built:**
- `run_master.py` `--crob-plan "idx:CODE,idx:CODE,..."` (LATCH_ON/LATCH_OFF; ordered; rejects
  duplicate/malformed/bad-code; ONE CommandSet; master JSON records plan in transmitted order).
  `--crob-count` path unchanged.
- `analyze_multicrob_pcap.py` boundary-index: dropped the 0..N-1 assumption (arbitrary plans),
  added classifications `multiple_invalid_indexes_rejected` + `decoy_only_invalid_rejected`,
  now emits `status_counts`, `invalid_indexes_in_select`, per-index status map, SELECT req/resp
  byte lengths + link-frame counts. all-success stays default (n16/n17 regressions still pass).
- `run_crob_padding_candidate_tests.py` (8 cases) -> `captures/padding_candidates/` +
  `reports/padding_candidates/`.

**GOTCHA fixed in run_outstation.py:** the outstation `End()` wrote JSON evidence only on a
failed SELECT batch or after OPERATE. A stack-level `TOO_MANY_OPS` where every op the HANDLER
saw succeeded (K=16, N=17) triggers neither (any_fail=False, no OPERATE), so it wrote NO
outstation JSON. Fix: write evidence at the end of every SELECT or OPERATE batch (all-success
and failed-SELECT final JSON unchanged). Also observed: a stack-level TOO_MANY_OPS does NOT
trigger the handler's batch-discard, so the 16 valid selects stay armed (pending_selection_count
=16) until the select timeout — harmless (master won't operate; they expire).
