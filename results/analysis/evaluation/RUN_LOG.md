# c72 evaluation run log

- 2026-10-27 19:4x qualification matrix rc01_hw_c72_20261027_02 STOPPED 9/10: block 10 loss_full t3 FAIL
  (select_resp_padded drop; SELECT 1,017 ms; OPERATE CROB TIMEOUT points 1,3; restoration verified; ownership safe).
- 19:5x native probe c72_native_20261027_02 PASS (2 READs OK, IIN 0x80 0x00, production unchanged).
- 19:55 evaluation campaign rc01_hw_c72_eval_20261027_01 launched: 64 blocks, 49,408 exchanges; freeze-check 64/64,
  exact-argv dry-run 64/64. Event monitor + data watchdog armed.
- 20:02 e01_d5_r01 COMPLETED rc 0, restoration verified. Data check: 772/772 rows, 0 problems, 0 anomalies; native
  91/134/49 (off, timing_only), padded 141/158/60 (size_only, combined); timed CLRT medians ~5.0 ms sd ~0.9; untimed
  ~2.2-2.8 ms sd ~2-3. Philip told OK to leave. Extractor 8/8, Formby analysis 6/6 tests GREEN.
- 20:09 e02_d10_r01 COMPLETED rc 0, restoration verified. Watchdog anomaly: size_only (T0/P1) master retransmitted
  the connection's FIRST READ request (seq 360306783, 25 B) at +206.5 ms; relay ACK +209.0, response +209.3 ms; all 193
  exchanges OK. Untimed arm, so not a switch hold: relay first-request latency exceeded the master ~200 ms RTO
  (cf. earlier first-response latency memory). Kept in data, counted in the overhead retransmission row, disclosed.
  No action; watch for recurrence or timed-arm occurrence.
- 20:22 e04_d20_r01 timing_only (T1/P0): master retransmitted the connection's FIRST READ at +209.6 ms; switch-released
  ACK +215.7, response +235.9 (= ACK + D20); all 193 OK. Same first-READ pattern as e02 size_only (untimed), where the
  relay's own ACK came at +209 ms, so the relay's cold first-READ service exceeds the ~200 ms master RTO with or without
  the hold. Caveat: in timed arms the relay's genuine ACK arrival is hidden by the hold, so attribution is inferred,
  not measured. 2 of 16 connections so far, both exchange 0. Watchdog now reports the retransmitted exchange index.
- 20:20-20:50 independent code review (code-reviewer agent) of eval_rows/eval_watchdog/formby_eval/eval_figures/
  matrix/driver. Raw rows verified: 3,088/3,088 match relay_wire+master; no leakage; units correct. Fixed test-first:
  HIGH joint GMM used CLRT only (now [mean,var] of CLRT and size); piggyback excluded from descriptive figures/T1 and
  from H; sufficiency gate adds train blocks + clean captures and now fails the driver (exit 3) after writing outputs;
  per-block CIs require every test block (NB and GMM) and T2 reports pooled BA and block-mean BA with its own CI;
  unavailable cells stay visible in T2; pre-registered size/timing falsifiers computed in verdicts.json; extractor
  refuses relay_wire ok=false/failures/interface drops/application failures and checks every input against the
  block's artifact_manifest.json; pre-deployment FF-ANN not computed (stated); F5 min-class recall as hollow markers
  (no line-style clash); F2/F2b redrawn with true sizes and direct labels; F10 dodged + p50/p95 legend; F1/F8 x range
  covers all data; watchdog checkpoints only after a check. Tests: analysis 30/30.
- 21:0x commit-planning finding: retained distinct model stdout (results/models/c72/*/model_stdout.txt) is raw and
  large (up to 734 MB; ~4.1 GB total) and is bound by the running freeze (305 model files). DO NOT touch any freeze-
  bound file (scripts/hardware, scripts/model incl. retained_logs.py, scripts/checks, results/models, results/builds)
  until the campaign is terminal. After it: compress stdout to verified XZ with raw SHA in the retention manifest and
  a restore path (as for model logs), test-first, then stage. Freeze check of e64 config re-run now: see next line.
  -> freeze_gate check (e64 config) at 20:58: OK 0 changed, 0 missing.
- 21:1x prepared (NOT applied; freeze-bound file) stdout-retention change in scratch stdout_retention/: distinct
  model stdout kept as verified XZ (preset 1) with raw SHA/size in a NEW model_stdout_retention.json (the bound
  model_log_retention.json is untouched so launch_command hashes and the 17-driver gate stay valid); restore_run and
  restore_selected rebuild raw stdout byte-exactly before any gate/freeze check; compress-stdout migrates existing
  raw files. 11/11 scratch tests. Apply after the campaign is terminal, then rerun model_summary --enforce and the
  freeze check (both must still pass).
- 21:09 e11_d15_r03 off (T0/P0, no obfuscation): first-READ retransmission at exchange 0 (3rd case; 3/44 connections; arms size_only, timing_only, off). Confirms relay cold first-READ latency > master RTO independent of obfuscation. No action.
- 21:23-22:41 session paused (usage limit). Campaign ran unattended and safely: 24/64 completed, 0 failed, no
  refusal, ownership safe. Monitors re-armed 22:41; watchdog caught up e14-e24: all 772/772 rows, sizes/CLRT/CROB/IIN
  clean; three more first-READ (exchange 0) retransmissions: e17 timing_only, e18 combined, e23 combined.
  Tally 6/96 connections, all exchange 0: off 1, size_only 1, timing_only 2, combined 2 (timed 4/48, untimed 2/48).
- 22:58 FINDING (read-only analysis of existing evidence; no instrumentation): first-request retransmissions.
  7/7 cases are exchange 0 of a fresh connection. The relay's ACK follows the master's TCP retransmission by a near-
  constant 2.1-6.1 ms while the retransmission time varies 206.5-215.6 ms, so the relay acted on the RETRANSMITTED
  copy (not a fixed slow service). Switch port counters (snapshots before/after) show master-port RX minus relay-port
  TX = 1 in all 7 (also 1 in 19/101 non-retransmission trials, so a designed drop exists; 0 in 82/101). Untimed arms
  never show an early relay ACK with a late response. Interpretation: the ORIGINAL first request did not reach the
  relay's processing, most likely absorbed at the switch; mechanism not determined (master-NIC captures and port
  counters only; PLAN forbids causal instrumentation tonight). Present in all arms incl. off (T0/P0, same c72 program),
  and pre-existing: c69 matrix 1/26 connections, c72 qualification 2/25, evaluation 7/109. TCP recovers it every time
  (~206-216 ms); all exchanges OK. Reported against RO3 (no retransmitted request) as a pre-existing first-request
  loss, not attributable to the timing hold.
- 23:11 e29_d5_r08 timing_only: first-request retransmission (8th; off 1, size_only 1, timing_only 4, combined 2; timed 6/58 vs untimed 2/58).
- 23:24 e31_d15_r08 combined + size_only: first-request retransmissions (10 total; off 1, size_only 2, timing_only 4, combined 3; timed 7/62, untimed 3/62).
- 23:37 e33_d5_r09 timing_only: first-request retransmission (11 total; off 1, size_only 2, timing_only 5, combined 3; timed 8/66, untimed 3/66).
- 23:4x interim real-data pipeline check (reps 1-4 train / 5-8 test, labelled interim, registered test blocks untouched): formby 8 min for half the data, all 17 figures rendered, gate FAIL as expected. Fixed F1 readability: 0-30 ms axis plus a separate '>30' overflow bin (0.057% of rows) instead of stretching to the 91 ms max; F8 axis fixed at 30 ms. Tests green.
- 01:05 e46_d10_r12 combined: first-request retransmission (12 total; off 1, size_only 2, timing_only 5, combined 4; timed 9/92, untimed 3/92).
- 01:12 e47_d15_r12 off: first-request retransmission (13 total; off 2, size_only 2, timing_only 5, combined 4; timed 9/94, untimed 4/94).
- 03:41 campaign rc01_hw_c72_eval_20261027_01 COMPLETE 64/64, 0 failed, ownership released safe. Watchdog done: all 64 blocks 772/772 rows; anomalies only first-request retransmissions at exchange 0 (also e55 size_only, e58 timing_only, e62 off). Session was paused ~02:12-03:41 (usage limit); campaign ran unattended.
- 03:4x applied post-campaign stdout retention (scripts/model/retained_logs.py + tests, 11/11): 18 preserved stdout files -> verified XZ (results/models 7.1G->4.0G), raw ignored in .gitignore and restorable by hash. model_summary --enforce after restore: model_gate_passed. Freeze check now reports exactly one change, scripts/model/retained_logs.py (the intended post-campaign edit); every other bound file unchanged.
