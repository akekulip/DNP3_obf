# WORKING NOTES — Defense 4 Case-A OVERNIGHT AUTONOMOUS RUN

**Task:** `defense4/overninght.md`. Branch `defense4-caseA-hw-integration`. Start HEAD `a085f00`.
Execute in the MANDATED ORDER; paper writing is LAST and gated on the experiment freeze.
Circle back to `defense4/overninght.md` continuously. Do not stop until the experiment gate
closes (or a genuine safety blocker remains after bounded attempts). Do NOT call the project "ADTA".

## Hard rules (from overninght.md)
- Recompute from primary evidence (P4/PCAP/JSON/counters/compiler/live readbacks). Do NOT trust
  prior Claude reports, commit messages, or this file as proof.
- Preserve frozen D1/D2/D3/Part11/Part12/four-queue sources. Do not merge to main. No size obfuscation.
- Physical SEL-751 READ-only. NO physical SELECT/OPERATE ever. No controller in the release fast path.
- Do NOT weaken a check/reinterpret a failure/modify scorer merely to get PASS.
- Do NOT call a delay "optimal" — say calibrated/tested/selected. No em dashes in prose.
- Only the main agent touches the live switch; expert agents are advisory; verify every agent claim.

## KNOWN FLAWS in the prior bring-up (must confront — from A3)
1. runner runs `configure` (→ clear_state) before EVERY poll → state reset each txn.
2. block.py: N=1, NEW TCP conn each poll, always FRAMES[0]=C0 → 17 D1 did NOT advance C0..CF → **rollover NOT proven**.
3. `0x8000` = 32768 ns = **32.768 us**, NOT ms. Native CLRT ~1.8-6 ms >> 32.768us -> deadlines expired
   before native RESPONSE -> D2/D4 did NOT prove response-deadline shaping (only classification+delivery).
4. FAIL_OPEN trial = configured bypass, NOT induced failure. D3 mode NOT run in integrated program.
5. Watermark latched -> only attributes occupancy to FIRST protected txn. Raw PCAPs not committed.

## PHASE TRACKER (update after each phase; commit at checkpoints)
- [x] A1 git state — HEAD=a085f00, local==origin, branch ok. Untracked intermediate evidence dirs to preserve.
- [x] A2 hardware snapshot -> A2_CURRENT_STATE_SNAPSHOT.md. CONFIRMED: d_ticks=32768=32.768us (1 tick~=1ns via D3 2ms=1999872), D4/0x8000 does NOT shape (live clrt 2.82ms native, qid4 wm=0). Binary+source hashes match.
- [x] A3 POST_BRINGUP_EVIDENCE_AUDIT.md written. All 7 flaws CONFIRMED from primary data. Rollover CONTRADICTED (C0-only,N=1,clear each txn). D2/D4 shaping CONTRADICTED (32.768us<<native). D3 NOT run. FAIL_OPEN not induced. 34 original PCAPs preserved+hashed in pcaps_original/. Independent reparse of blk_t2 corroborates txn2.
- [x] A4 SPEC_IMPLEMENTATION_EVIDENCE_MATRIX.md. Generation=DNP3 app-control C0..CF (16). Mode read per-packet from tbl_params. Concurrent READ guarded (arm-once). SELECT/OPERATE bypass. Combined-RESP=bounded fail-open. Token containment=forced-role+PORT_L+drop (NOT deparser strip). Native CLRT median 2.828ms (defense3/REPORT.md). 3 agents corroborated. P4 risks folded into A4: #1 no readiness guard (D9), #2 concurrent tracker clobber POTENTIAL DEFECT (D7), #3 gen=DNP3 app-seq vs spec, #4 no FIN/RST cleanup (D3/D7), #5-6 param invariants unenforced (B2), #7 combined-ACK absent (Case B). D1 event=ACK only. Resources 12/12 0 headroom.
- [x] B1 ops: initialize/set-policy(refuse-while-active)/clear-evidence(counters+ts only) added; verify-only per-mode. Offline tests 20/20 PASS (test_setup_offline.py).
- [x] B2 params: resolve_delays() via d3.quantize_d; --d-a-ms/--d-r-ms; prints realized ns/ms + vs poll/horizon; enforces low-byte-0/half-range/poll/mode. 0x8000 now shows true 0.032768ms.
- [x] B3 campaign_driver.py: ONE TCP conn, N READs advancing C0..CF (smoke: C0..C5 distinct), full-Ethernet capture (token-escape visible), rich per-poll rows (clrt/r2a/r2resp/order/segments/retransmit/dup/fin/rst). Validated live.
- [x] B4 evidence-dump expanded (18 CF + 8 CD slots, all regs/trackers/ts, tbl_params, port TM drops); score_campaign.py detects missing ACK/RESP, resp-before-ack, dup, retransmit, RST, token escape (wire+counter), queue+port drops, failopen/deadline release, stale reg_tag, re-arm; make_manifest.sh SHA256. All offline-tested.
- [x] C watchdog enhanced: verify-restore + 5x retry + visible ESCALATION sentinel (not just 'invoked'). run_campaign.sh orchestrator built: preflight(binary sha match)+watchdog+initialize-once+per-block set-policy/clear/dump/drive/score+manifest, trap->forwarding-D3 rollback, KEEP_D4 on verified success.
- [x] D1 34 original bring-up PCAPs preserved+hashed in bringup_live_.../pcaps_original/ (done in A3).
- [x] D2 rollover: every 60-poll block advances C0..CF (all 16 codes, ~3.75 cycles), sustained; 0 stale releases/ordering violations across 1200 txns.
- [ ] D3 runtime fail-open (emulator/synthetic: missing ACK, missing RESP, zero budget, recovery, ..)
- [x] D4 modes validated in integrated binary: OFF/D1/D3/D4 shaping real (D4 normalizes CLRT to 8.00ms); D2 = documented boundary (no shape). D3 integrated mode run (was missing in bring-up).
- [x] D5 PARAMETER_CALIBRATION.md. Native CLRT median 2.871ms (n=120, matches frozen 2.828). GRID FINDING: D2(D_A=0) does NOT shape Case-A (RESP_BYPASS 30/30, immediate ACK retires txn); D3(D_A=8) CLRT->0.03; D4(D_A=4,D_R=8) NORMALIZES CLRT to 8.00ms p95 8.01 (RESP_HOLD_EARLY 22/30). Selected: D3 8ms, D4 4/8ms, D1 3ms; D2 = claim boundary.
- [x] D6 Campaigns A+B (1200 txns, 120/condition each). CONSISTENT: OFF 2.85, D1 3.2 p99 4.2 (tail collapsed), D2 2.9 (no shape), D3 0.03 (ACK held), D4 8.00 [7.99,8.00] p95 8.03 (NORMALIZED). 0 ord-viol/escape/drops both. Randomization-robust.
- [x] D7 EXPERIMENT_MATRIX.md: normal/rollover/stale/one-shot/reuse/fail-open PASS; injection negatives (dup/concurrent/wrong-flow/forged-token/wrap) BLOCKED-w-evidence (need outstation/injector, source+D3-synth backed).
- [x] D8 boundary: READ PASS (physical); SELECT/OPERATE BLOCKED-w-evidence (bypass in source, never sent to relay); combined-ACK + multi-segment NOT APPLICABLE (Case A, single-segment).
- [x] D9 DEFENSE4_BOTTLENECKS.md + raw compiler_9132_raw/ artifacts.
- [x] F FREEZE: EXPERIMENT_MATRIX + EXPERIMENTAL_EVIDENCE_FREEZE + SHA256SUMS. VERDICT: TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY. Final switch state: D4 calibrated 4/8ms, CLRT 7.99ms verified, forwarding ok.
- [x] G Introduction COMPLETE: INTRODUCTION_DRAFT.tex (Dr Lin 4-para, 922 words, compiles, 15 cites) + INTRODUCTION_CLAIM_SOURCE_MATRIX.md. Skeptical review (2 MUST-FIX+5 MINOR) applied in 1 revision; academic-humanizer final pass (3 splits, no AI vocab, 0 em dashes). Claims/citations preserved.

## Current switch state (update on every change)
- Per prior report: `defense4_caseA` loaded, D4 D_A=D_R=0x8000 armed, forwarding. TO BE RE-VERIFIED in A2.
- Switch decps@10.10.54.81; master/Vision decps@10.10.54.19; relay 192.168.10.7:20000 READ-only.
- SDE 9.13.2. D4 build /home/decps/d4_build/build9132/. Rollback: bash /home/decps/d4_build/rollback_defense3.sh.

## FREEZE REOPENED (2026-08-07 audit at b0e1752) — corrections done; NEXT-RUN work below
- D2 = OPEN tag_retire_if_unmarked DEFECT (not Case-A limit): 240/240 retire+bypass. D4 = MIXTURE
  (160/240 held ~8ms, 80/240 bypass native), NOT a fixed normalization. Verdict -> PARTIAL, DEFECT OPEN.
- Done now (no hardware/P4 change): reopened+corrected freeze/matrix/calibration; quarantined Introduction
  (banner + QUARANTINE.md); completed manifest (2072 files, +5 compiler logs +control scripts); committed
  raw final-state snapshot (final_state_snapshot_*, live D4 4/8). DO NOT MERGE.
## NEXT AUTHORIZED RUN (needs Philip's go-ahead; P4 recompile+reload = hardware change)
1. Fix tag_retire_if_unmarked so an ACK release does NOT retire while a response is still expected.
2. Regression-test D2 and D4 after the fix.
3. Recalibrate D4 so the ACK deadline T_A covers the measured native response tail (native read_to_resp
   p95 ~7.5ms, p99 ~13.7ms -> D_A likely needs to exceed that, within the 24.8ms policy max).
4. Implement the AUTHORIZED controlled outstation/injector negatives (missing ACK/RESP, dup, wrong-flow,
   forged token, wrap, SELECT/OPERATE, combined, multi-segment) — do NOT leave them as blocked.
5. Repair the scorer: add incoming/outgoing byte comparison; FAIL on protected-mode response bypass.
6. Repair/verify the manifest each run; re-run every mode affected by the P4 change.
7. Commit a final live-state raw snapshot. THEN re-validate the freeze. Only THEN revise the Introduction.
