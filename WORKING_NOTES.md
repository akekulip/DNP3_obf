# Working Notes — DNP3 project (repo root)

Detailed per-task notes live in each harness dir. Current focus: multi-CROB week8 series.

## Task (week8_next.md — Dr. Lin): Invalid-index CROB padding-candidate suite — COMPLETE ✅
Location: `dnp3_multicrob_harness/`. Rig-validated Vision↔Hulk 2026-07-08, all 8 cases pass.
- Added `run_master.py --crob-plan "idx:CODE,..."` (ordered; rejects dup/malformed; JSON records order).
- Analyzer boundary-index: dropped 0..N-1 assumption; new classifications multiple_invalid /
  decoy_only; added status_counts, byte lengths, frame counts. all-success default preserved.
- New `run_crob_padding_candidate_tests.py` (8 cases) -> captures/padding_candidates/ + reports/padding_candidates/.
- FIX run_outstation.py End(): write evidence at end of every SELECT/OPERATE batch (was missing
  the stack-level TOO_MANY_OPS-with-all-valid case, K16N17). all-success/failed-SELECT JSON unchanged.
- Result: invalid index -> OUT_OF_RANGE(12) per-index any position, no OPERATE, no output change;
  K5N17 shows OUT_OF_RANGE + TOO_MANY_OPS together; K16N17 -> too_many_ops. Padding NOT insertable.
- Memory: [[multicrob-invalid-index-padding]]. README + RESUME_STATE updated.
- Verified: py_compile x4; n16/n17 regressions pass; no codename; 8 pcapng + 8 JSON + manifest + md.

---

## Task (week8.md — Dr. Lin): Boundary-index CROB experiment — COMPLETE ✅
Location: `dnp3_multicrob_harness/`. Detailed notes: `dnp3_multicrob_harness/WORKING_NOTES.md`.

Goal: distinguish the OpenDNP3 per-request operation-count limit (`TOO_MANY_OPS`, status 8,
the N≥17 result) from a nonexistent-output-index rejection. Software-only, G12V1 only.

### Status: DONE and rig-validated (Vision↔Hulk, 2026-07-08)
- Valid K=5,N=5 → all SUCCESS, OPERATE sent, final state matches (5/5 operate).
- Invalid K=5,N=6 → index 5 rejected `OUT_OF_RANGE` (status 12) in SELECT response
  `[0,0,0,0,0,12]`; master sent NO OPERATE (operate_seen=0); batch discarded; no valid
  output changed. classification=`invalid_index_rejected_during_select_no_operate`.
- Both cases report task-level master SUCCESS/exit 0 → task SUCCESS ≠ outputs changed.
- Boundary is OUT_OF_RANGE (nonexistent index), cleanly distinct from TOO_MANY_OPS (count limit).

### Files changed
- `dnp3_multicrob_harness/analyze_multicrob_pcap.py` — added `--mode {all-success,boundary-index}`,
  `--configured-points`, `--expect-operate`; status-name map; classification. all-success default
  preserved (sweep unchanged).
- `dnp3_multicrob_harness/run_crob_boundary_index_test.py` — NEW rig orchestrator.
- `dnp3_multicrob_harness/README.md` — new "Boundary-index CROB test" section.
- `RESUME_STATE.md`, project memory (`multicrob-boundary-index-result.md`) — updated.
- run_outstation.py / run_master.py / replay / split / Class-0 / P4 — UNCHANGED (scope preserved).

### Verification done
- py_compile x4 OK; analyzer regressions n16 (all-success PASS) + n17 (boundary-index →
  too_many_ops); rig run produced fresh artifacts; no codename leak.

### Artifacts
- captures/boundary/crob_boundary_{valid_k5_n5,invalid_k5_n6}.pcapng
- reports/boundary/analyze_{valid_k5_n5,invalid_k5_n6}.json
- reports/boundary/boundary_index_{manifest.csv,results.md}

### Next action (optional, only if requested)
- Reproducibility re-run (`--only invalid`) or other K/N (`--valid-points 8 --invalid-extra 2`).
- Feeds the later padding-candidate question (response-side evidence: OUT_OF_RANGE vs TOO_MANY_OPS).
