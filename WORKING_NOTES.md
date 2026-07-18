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

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-07-17T23:52:41Z -->
### Compaction handoff — 2026-07-17T23:52:41Z
- Git: branch `research/ack-timing-phased`, 2 uncommitted file(s): dnp3_split_harness/phase04b_dcrn_attacker_eval.py dnp3_split_harness/scripts/phase04b_local_campaign.sh 
- Last verification run recorded: 2026-07-17T23:49:36Z	cd /home/philip/Projects/DNP3/dnp3_split_harness sed -i 's# \[ -n "\$obj" \] && attach "\$obj"# if [ -n "$obj" ]; then a
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- Phase 04B Gate C — 2026-07-17 -->
## Phase 04B (DCRN) — Gate C local paired campaign DONE; two-host rig BLOCKED on rig sudo pw

### Status
- **Gate C local paired campaign PASS** (veth vdcrn0 observer <-> vdcrn1/dcrn-srv server, DCRN on server tc, fq).
  NATIVE req->resp median 16.66ms; DCRN_FIXED 32.61ms (std 0.17); DCRN_COMMON_BOUNDED 37.54ms [32.44,42.61].
  Separate ACK->resp gap 18.14 (native) -> 0.18/0.20ms (DCRN guard delta). Transport clean: 0 retrans/reset/dupack.
- **Attacker eval (measured):** timing_all balanced-acc 0.720 -> 0.639 -> 0.436 (chance 0.333); mode_only + size
  unchanged 0.667; all=1.0. DCRN = timing normalizer, preserves mode/size by design (confirmed scope).
- **Two-host rig BLOCKED:** decps sudo on Vision/Hulk needs a password that is NOT the gambit password and is
  NOT stored (lab-hosts-dnp3: ask the user). Verified passwordless SSH works; gambit pw fails decps sudo on both.
  DCRN load on Hulk eno1 + tcpdump on Vision eno1 both need rig root. Driver + runbook READY.

### Files (this increment)
- reports/phases/phase_04b_dual_case_timing/gate_c_local_campaign.md (writeup)
- reports/phases/phase_04b_dual_case_timing/campaign_local/*.pcap + *.json + spec.json (+ manifests/campaign_local_sha256.txt)
- reports/phases/phase_04b_dual_case_timing/two_host_rig_runbook.md
- scripts/phase04b_local_campaign.sh (fixed set-u `local` split; ran clean)
- scripts/phase04b_rig_campaign.sh (dry-run default; RIG_PW transient; NOT wire-verified on rig)
- phase04b_dcrn_attacker_eval.py (sess[k % len] cycling for multi-run campaigns)
- phase_status.json (gate_c_local_campaign + two_host_rig blocks; loopback PASS, rig BLOCKED)

### Next action
- Get the rig decps sudo password from the user -> run scripts/phase04b_rig_campaign.sh (DRYRUN=0 RIG_PW=...).
- Keep next_phase_allowed=false; rig PASS only from measured rig PCAPs. Do not claim rig success from local.
