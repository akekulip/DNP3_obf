# Generation-safe rearm evidence

**2026-10-16 ~06:30 m6 night outcome (72d85875b directive; partial qualification verdict).**
- Hour-5 gate (03:11) missed: no reviewed m6 successor had passed compile and model by then (a two-hour usage-limit stop fell inside the window), so **no m6 hardware ran**. m5_10 remains the only silicon-qualified-in-part candidate.
- m6 successor `ctl_timing_01/evidence/m6_07` (`3335479b…e142`): N only, E/T byte-identical, N12/E12/T11 on SDK 9.13.1 and 9.13.2, mirror guard PASS. Fixes: RST|ACK validated by exact SEQ while a response is held; busy RST/FIN retried (direction-keyed snapshot); `retry_epoch` cleared only at a proven close by the incarnation that closed; response retransmissions routed through T's release gate in states 5/0xa. Attempts m6_01–m6_06 retained with their review findings (`ctl_timing_01/DESIGN.md`, m6). Source tests pass; model: every driver passes except contention 240/241 (`sweep_SELECT_000ms`: a response retried 3 laps then was lost with no counter; passed on m6_05 and m6_06; undiagnosed), so m6_07 is **not frozen**. m6_05 passed all eight drivers.
- W1 strict verdict: commits `4920206bf`, `d0b238afa` (reviewed; fails closed on 13 reviewed holes; held-OPERATE 800 us gap declared with `--expected-gap`). Strict over m5: FAIL (b2/b3 rejected-incomplete, char b2/b3, held_operate_01).
- W2 isolation endpoint: commit `06ff460a6` (reviewed; 20 s pause with endpoint-local permit; full-length loopback tests pass). Silicon `ctl_m5_stale_iso20_950_01` (commit `e1744034b`): **FAIL**, restore verified. Delivery correct; 2 of 7 old READ tokens rejected after the pause and 2 STALE_BLOCKER in new traffic (13 > 12). Cause: drain test reads generator counters, not pipeline rejections. Not rerun.
- W5 contention probe: offline only (commit `9c66ce69e`), unwired; silicon retry coverage PENDING.
- Writing package: `stage_experiments/seg61_02/evidence/writing_packet_72d85875b/`.
- Rig at end: switch on production `case4_response_path` (restore_verify ok after the isolation block); Vision holds the new `/home/decps/pad58b_isolation_20s_20261016` endpoint directory. Nothing pushed; no default promoted.

**2026-10-15 22:11 m6 continuation started (72d85875b directive): W0 reconcile; held-OPERATE `_01` superseded harness attempt; repeated-SBO b2/b3 rejected-incomplete; S3 not run on m5. Historical 10 s isolation endpoint fixture recorded under `endpoint_barrier_10s/` (binary and library ignored as build outputs; hashes in `manifest/`).**

**2026-10-15 m5 S3 (commits ed9907f89, ec9b35c3d, fc55b0cf2; five adversarial reviews): stale-token isolation for control-timed builds is implemented and fail-closed, but `ctl_m5_stale_tokens_950` is REFUSED at construction: with the 4 s restore allowance and the 1.5 s abort margin, no delay IPG fits both the endpoint's 10,000 ms pause maximum and the old-token lower bound (infeasible by ~0.12 s of READ span). Options for Philip: measure tighter allowances on silicon, or an endpoint with a longer pause. candidate61 unchanged (2.5 s / 10,000 ms).**

**2026-10-15 m5 S4 silicon (m5_10, every block restore-verified; `seg61_02/evidence/m5_silicon_summary.json`): recovery pass (held OPERATE 350, persistence graceful/RST, seven loss classes, protected reconnect); piggyback qualification b1-b3 qualified; repeated-SBO qualification b1 QUALIFIED all four arms, b2 and b3 rejected on the index-127 timing outlier of unresolved origin (SELECT p99 = max 920/917 us; same signature as m4; characterization twins show it at 40, 126-127, 168, plus one late READ at 126, +1,142 us); N contention gate clean on every trial (0 busy drop, 0 exhaustion, 0 stale; 0 retries: the software endpoint cannot produce contention, so the fix is proven on the model and source only). Stale-token isolation (S3) not yet run; S5 held: m5 timing qualification is not fully passed.**

**2026-10-15 m5 S0: shaping comparator judges correctness on full gates (shared failures fail; savings = efficiency only); QUALIFICATION_9c4a2cfdc.md reports p99 and maximum separately, outlier of unresolved origin, retrospective exclusions labelled; ACK_HOLD 14,892 = efficiency measured, correctness not passed.**
**2026-10-15 m5 cycle started: approved plan `PLAN_m5.md`; T0 transfer package committed; next S0.**

**2026-10-15 overnight result (9c4a2cfdc audit): report `core/response_only_rearm/stage_experiments/seg61_02/evidence/QUALIFICATION_9c4a2cfdc.md`.**
- Candidate m4 (`ctl_timing_01/evidence/m4_01`, `35e896eb…79cf`, E `a144cd30…1c10`, N11/E12/T11 both SDKs): Table 4-9 selection cancellation/replacement in N, fail-closed OPERATE lane exhaustion in T. Model suites all pass on the current drivers.
- Silicon on m4, every block restore-verified (`rearm_01/hw/restore_verify.py`): held OPERATE, persistence graceful/RST, seven-class loss and protected reconnect pass; stale-token isolation unmet (diagnostic sized for candidate61); piggyback qualification qualified (3 blocks); repeated-SBO qualification rejected in 3 blocks, each on one timing outlier of unresolved origin near index 127 (ACK ~1 ms late, response on time; also on m3/candidate61). m4 is not fully qualified.
- Asymmetric shaping ACK_HOLD 14,892 (others 59,570): efficiency measured on three matched pairs (-19..-25 % internal frames, -18..-24 % octets, request->ACK +6..+50 us); correctness not passed (shared timing outlier; revised by m5 S0). Not promoted.
- Generation budget, acceptance objectives (v3 artifacts, nearest-rank) and harness control-timed counting fixed; nothing pushed.

**2026-10-15 9c4a2cfdc checkpoint (overnight correctness/qualification/overhead; `DNP3_9c4a2cfdc_Audit.md`).**
- HEAD `9c4a2cfdc` on `main` (= `origin/main`). Philip-owned dirty paths preserved: `WORKING_NOTES.md`, the deleted `DNP3_Implementation_Directive_492013014.md`, root prompt/audit/zip files.
- Candidates: candidate61 `full_04` (`1b2d62d1…65aa`) encoding reference; ctl_timing m3 (`c4819dba…9204`, E `a144cd30…1c10`) full-feature development reference; m4 (N lifecycle correction) planned.
- Live switch at start (2026-10-14 23:39, read-only ps): production `case4_response_path_conf.json` under SDE 9.13.2.
- Open: generation budget undercounts control-timed lanes; SELECT/OPERATE/piggyback/J not gated; abandoned SELECT wedges N; m3 lacks its own silicon recovery qualification; source-only marker regression. Plan: `PLAN.md` section "9c4a2cfdc audit: overnight plan".

**2026-10-14 f0baa724a checkpoint (mechanism completion, `DNP3_Next_Implementation_Prompt_f0baa724a.md` + `DNP3_f0baa724a_Audit.md`).**
- HEAD `f0baa724a` on `main` (= `origin/main`). Dirty paths owned by Philip and preserved: `WORKING_NOTES.md`, the two root prompt/audit files, untracked old evidence and paper corpus. `DNP3_f0baa724a_Reproduction.zip` is not on disk; the audit probes are reproduced from its text.
- Candidate: `seg61_02/evidence/full_04/response_only.p4` SHA256 `1b2d62d1…65aa` (regenerates byte-identically), SDK 9.13.2 bfrt `e32df204…`, p4pp `3306c394…`; strict comparison source `2ad71761…`.
- Live switch (read-only `ps`, 2026-10-14): `bf_switchd` running `case4_response_path_conf.json` (production restore target), matching the recorded state.
- Decisions (Philip, 2026-10-14): normalize all three CLRTs (READ, SELECT, OPERATE) in a separate control-timing candidate while keeping the OPERATE command hold J as its own objective; piggyback gets a response-aware bounded latency (global readiness unchanged); silicon authorized for Gates 2, 3 and 5 with software endpoints only and no relay OPERATE; model gates only after functional changes; the E-stage CRC change is an experiment.
- Gate 1 (acceptance and reproducibility): committed `2cad04ff6`, `d4c785844` after one review and one independent verification.
- Gate 2 (repeated SBO): committed `ab191033f`, `876bc216c`. Silicon `candidate61_repeat_sbo_950_b1_02`, `_b2`, `_b3`: 768/768 cycles verified per cycle; failed `_b1` retained (stale endpoint build). Model `model_repeat_04` 520/520, `model_abandon_03` 15/15. Limitation: an abandoned SELECT stalls the connection until reset.
- Gate 3 (control timing): `ctl_timing_01` m3 (N + T changes, E identical) passes all model suites and, on silicon, normalizes SELECT and OPERATE CLRT (abs p99 55-92 us) with the OPERATE J hold kept (min 2.47 ms) and piggybacked request->response bounded at about 4.1 ms (was 30.1 ms); internal receives per exchange about double. Not a default; candidate61 remains the qualified encoding baseline.
- Gate 4 (CRC experiment): committed `7202358fd`; no stage recovered (E12 on both SDKs, N 11->12), baseline kept.
- Gate 5 (cost and tails): committed `333f3687b` (cost) and `c694dde3d` (tails). Seventeen restored factor runs: the off-arm transit signature at requests 127/255/~275 appears in 4/10 controls and 2/7 runs with Vision tx-frames-irq 64, and survives the change, so NIC TX interrupt batching is ruled out; the tail source stays unresolved. Next factors (adaptive coalescing off, capture buffer, production program on the same traffic) need Philip's go-ahead.
- Final report: `core/response_only_rearm/stage_experiments/seg61_02/evidence/MECHANISM_REPORT.md`. Nothing pushed; no default promoted.

**2026-10-14 candidate61 qualification complete (PLAN steps 1-5).** Report: `core/response_only_rearm/stage_experiments/seg61_02/evidence/QUALIFICATION_REPORT.md`. Later pushed to `origin/main` at `f0baa724a`; no defaults promoted; repeated SBO and control-CLRT normalization remain open (f0baa724a audit); real-relay compatibility and the transit-path tail source remain open.

**2026-10-14 candidate61 step 4 (timing and size evaluation) complete on silicon.** Six interleaved candidate/strict blocks at 59,570 PPS / 950 us (4 arms x 500 READs, rotated), piggyback, and a 14,892-vs-59,570 PPS rate comparison; all restored, production observed after each. Pooled READ abs p99: candidate61 timing_only 54 us, combined 51 us; strict 65 us / 51 us. Bound lengths and growth exact in every trial. ~1.1 ms tails arise in the transit path between Vision's transmit and receive taps (NIC, link or Tofino; endpoints emit on time), occur in untimed arms and equally in the strict build, so they are not caused by the hold or the encoding; the component is undetermined. Results: `core/response_only_rearm/stage_experiments/seg61_02/evidence/STEP4_RESULTS.md`.

**2026-10-14 candidate61 step 3 PASS on silicon: persistence, single loss, reconnect, stale-token and external isolation, held-OPERATE duplicates.** Runs: `candidate61_persistence_graceful_950_01`, `candidate61_persistence_rst_950_01`, `candidate61_loss_core_950_01` (7 classes), `candidate61_reconnect_950_02`, `candidate61_stale_tokens_950_02`, `candidate61_held_operate_350_01`, `candidate61_old_external_950_01`. Every connection conformant at the bound length (61 for the installed tuple, native 49/37 for the unknown reconnect port), SELECT authorizes, OPERATE succeeds once, all restores and pings ok. Two failed attempts retained with harness causes (`reconnect_950_01`, `stale_tokens_950_01`). Timing evaluation (step 4) not run.

**2026-10-14 candidate61 four-arm silicon smoke PASS (`candidate61_fourarm_smoke_03`).** `seg61_02/full_04` (source SHA256 `1b2d62d1...65aa`, SDK 9.13.2) ran on the Tofino through the software endpoints: off and timing_only READ 49 x20 with SELECT/OPERATE 37; size_only and combined READ, SELECT and OPERATE 61, each response one received TCP segment (22 x 61 octets in `in.pcap`, no retransmissions). SELECT authorized OPERATE and OPERATE succeeded in every arm; `check_capture` conformant; coalescible-packet calibration passed with GRO off and restored; generation headroom 65496. All five restore steps returned 0 and production `case4_response_path` was observed afterwards. Two earlier attempts failed closed on harness defects, both fixed and retained: `_01` (argv-list capture command not recognized) and `_02` (calibration tcpdump terminated before its TPACKET_V3 block retired). Persistence, loss, reconnect, held-OPERATE and timing campaigns have not run. Evidence: `core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns/`.

Earlier 2026-10-14 checkpoint (superseded): **2026-10-14 candidate61 checkpoint — stopped by user before silicon.** `seg61_02/full_04` source SHA256 `1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa` compiles on SDK9.13.1/9.13.2 at N11/E12/T11. Compiled-model smoke30/30, native30/30, packets622/622, rearm399/399 and duplicates102/102 PASS. READ and SBO are 61 bytes in size-enabled model tests; **candidate61 silicon verification has not run**. Production `case4_response_path` remains the observed image. Final integration tests/review are pending (latest focused config test: 8 passed, one obsolete status-string assertion failed). Resume with the final test/review checkpoint, then bounded qualified-capture four-arm smoke and verified restoration. The updated root `DNP3_Implementation_Directive_492013014.md` records the full remaining timing-and-size plan; larger campaigns and real-relay work remain pending. Historical strict/all-58 results below are preserved.

**Current status (2026-10-13): strict candidate `rearm_57s` passes every rearm gate on silicon.**

`rearm_57s` is `rearm_56r` plus three changes:
- the IEEE 1815-conforming READ re-encoding (`stage_experiments/read_reencode_01`);
- native SELECT/OPERATE responses (strict policy);
- the early-duplicate OPERATE hold (`stage_experiments/dup_hold_01`).

It was compiled with installed SDK 9.13.2 at N12/E12/T11, passed the mirror guard and is pinned in `sealed_profile.py`. Configs are `config/candidate57s_*.json`, generated by `make_candidate57s.py` and `make_candidate57s_eval.py`. Every run restored all five baseline steps. Every capture was checked with `read_reencode_01/check_capture.py`, and every master-side READ response is a legal two-range 58-octet frame carrying the native points. SELECT and OPERATE responses are native, with an exact Rule 8 echo. The raw c2 capture of the external-replay run holds injected old frames; its filtered `current/` capture is the one checked.

| gate | run | result |
|---|---|---|
| graceful 800 us, 3 same-tuple connections | candidate57s_graceful_800_01 | PASS |
| RST 950 us, 3 same-tuple connections | candidate57s_rst_950_01 | PASS |
| four-arm smoke | candidate57s_fourarm_smoke_01 | PASS |
| six single-loss classes (native control classes for strict) | candidate57s_single_loss_01 | PASS. Its 7th entry, data-ACK at n=2, hit the ACK of the outstation FIN and the new gate rejected it as designed. |
| in-session data-ACK loss (`master_ack_of_padded_data` n=1) | candidate57s_single_loss_02 | PASS. Cumulative ACK 26.8 ms later; growth 180 = 20 x 9. |
| early-duplicate OPERATE (op_j 350 ms > RTO) | candidate57s_dup_hold_350_02 | PASS. Kernel retransmission of the held OPERATE dropped on every connection (OUT_OP_DUP_DROP 0->3, OUT_OP_RELEASE 0->3); one real OPERATE callback each. |
| old-token isolation | candidate57s_old_tokens_03 | PASS |
| old-external replay isolation | candidate57s_old_external_04 | PASS |

Retained failures, each with its cause (harness or fixture, none in the data plane):
- **dup_hold_500_01:** a 500 ms hold exceeded the endpoints' 500 ms OPERATE timeout and select retention. The duplicate was still dropped (OUT_OP_DUP_DROP 0->1).
- **dup_hold_350_01:** the wire gate counted the dropped duplicate as an unmatched sent frame. This led to the opt-in `traffic.expect_held_operate_dup`.
- **old_tokens_01/_02 and old_external_01/_02:** the isolation Vision helpers and local re-evaluation still expected 58-octet SBO responses (`--control-padding` added).
- **old_external_03:** no retained RST archive was unambiguous against that draw's ISNs (documented pool coverage).

**All-58 profile `rearm_57a` (2026-10-13)** = `dup_hold_01/evidence/full_01`: the READ re-encoding plus the endpoint-specific
control G41 padding plus the duplicate-OPERATE hold. Installed 9.13.2 at N12/E12/T11, mirror guard PASS; `candidate57a_*` configs.

Silicon PASS, every restore ok:
- `candidate57a_graceful_800_01`
- `candidate57a_rst_950_01`
- `candidate57a_fourarm_smoke_01`
- `candidate57a_single_loss_01`: core preset, data-ACK at n=1
- `candidate57a_dup_hold_350_01`
- `candidate57a_old_tokens_01`
- `candidate57a_old_external_02`. The retained `_01` found no unambiguous RST archive.

`check_capture.py`: every READ is conformant. Every padded SELECT/OPERATE response fails the Rule 8 exact echo, the disclosed
non-conformance of this profile, which the tested OpenDNP3 accepts.

**Repeated four-arm evaluation, rearm_57s (2026-10-13).** Runs `candidate57s_eval_b1_01`..`b3_01`.

- **Design.** Three blocks of four arms × 500 completed READs, plus one software-handler SBO per arm. Arm order is rotated per block (Latin square). Fixture delays are 5, 3 and 8 ms with seeded start phase, on the emulated separate-ACK fixture, shaping 59,570 PPS and gap 950 us.
- **Gates.** All 12 trials pass every hard gate. Exclusions are 0 by every reason (incomplete, retransmitted, piggyback, missing CLRT). All 12 connections are IEEE 1815 conformant.
- **Precision.** From `eval_summary.py`; the summary is in `eval_57s_summary.json`. The 100 us bound is provisional.

| arm | metric | n | min | median | p99 | max | abs p99 [95% CI] | abs > 100 us |
|---|---|---|---|---|---|---|---|---|
| timing_only | CLRT − gap (us) | 1500 | −923 | 35 | 88 | 93 | 88 [86, 89] | 2 |
| combined | CLRT − gap (us) | 1500 | −923 | 14 | 59 | 1145 | 60 [57, 63] | 4 |
| off | raw CLRT (us) | 1500 | 2189 | 5356 | 8378 | 8523 | n/a | n/a |
| size_only | raw CLRT (us) | 1500 | 2226 | 5358 | 8371 | 8396 | n/a | n/a |

- **Overhead per 500-READ arm.** Loop packets / bytes are about 2.5 k / 0.24 MB with T off, and 0.43 M–0.88 M / 32–64 MB with T on, varying by block with the fixture delay. Master-visible growth is 4,500 octets on padded arms (500 × 9).

**Open finding: sporadic ~1.1 ms release overshoot of one held packet.** There are 6 of 3,000 timed READs (0.2%), and none in block 3.

- In block 2 (3 ms delay), READs 127 and 255 in both timed arms had their ACK about 1.1 ms late (4.63 ms vs median 3.52 ms) while the response left on time, so CLRT collapsed to about 27 us. READ 383 has the same app sequence and was normal.
- In block 1 (combined), READs 237 and 374 had their response about 1.1 ms late, with ACKs on time.
- All commits were genuine: OUT_ACK_COMMIT = OUT_RESP_RELEASE = 500, fallback 0, stale 0.

Not yet attributed. It may be pre-existing; earlier runs had at most 50 READs per connection. A matched rearm_56r block is needed before attributing it, and it is not authorized yet. The 14,892 vs 59,570 PPS comparison has not been run on this candidate.


**Current status (2026-10-12, late): candidate56r passes every rearm gate on silicon.** Build `rearm_56r` is candidate56 plus `stage_experiments/retx_passthrough_01` (N table rows only; E/T byte-identical; installed 9.13.2 N11/E12/T11, mirror guard PASS; compiled model 519/519 retained + 37/37 retransmission checks). Silicon, every run restoring all five baseline steps:

| gate | run | result |
|---|---|---|
| six single-loss classes + one close-recovery case | candidate56r_single_loss_02 (six) + _03 (`master_ack_of_padded`, n=2) | PASS, recovery 0.20–0.23 s, exactly once. **_03 dropped the master's ACK of the outstation FIN (packet 73), not an in-session ACK of padded data**; it is close-recovery evidence. The data-ACK case is the new `master_ack_of_padded_data` class (loss.py, 2026-10-13), not yet run on silicon. |
| RST 950us, 3 same-tuple connections | candidate56r_rst_950_01 | PASS |
| graceful 800us | candidate56r_graceful_800_01 | PASS |
| four-arm smoke | candidate56r_fourarm_smoke_01 | PASS |
| old-token isolation | candidate56r_old_tokens_01 (untracked: `*_token*` gitignore) | PASS |
| old external replay | candidate56r_old_external_01 | PASS |

Why the loss gate needed a data-plane change: candidate56 and the frozen mirror_fix_01 both failed 6/7 identically (`candidate56_single_loss_01`, `baseline_single_loss_01`) because N refused a retransmitted copy of a segment it had already forwarded (no `sequence_guard` row → `first_event` count_* → kind 255 → `read_terminal_t` drop). The external replay gate needed an archive pool (`candidate_external.py`), because the unchanged `fresh_guard` passes a single archive only by chance. `master_ack_of_padded:3` asked for a fourth master ACK that the fixture never sends; n=2 is the reachable occurrence. Not claimed: exactly-once beyond these seven single drops; OPERATE retransmission while the original is still held in T (RTO ≈200 ms ≫ J here).

**DEFECT REPRODUCED ON THE MODEL (2026-10-13): early duplicate OPERATE bypasses T.** On the local 9.13.1 model of `rearm_56r` with T enabled (`op_j` 1 s), an identical OPERATE copy sent 0.10 s or 0.50 s after the original reached the outstation side about 0.115 s later (0.2162 s and 0.6231 s), while the held original was still released at about 0.90 s. That is two copies, one before the deadline, and `outcomes[5]` +1. Two independent runs agree: `stage_experiments/read_reencode_01/evidence/dup_model_01`, `_02`, with driver `read_reencode_01/model_drive_dup.py`. The copies are identical bytes, so which arrival is the duplicate is inferred from timing. Cause, from the source: retx_passthrough_01's `forward_original` row for kind 7 / owner 0xc sends the copy to the wire through `read_terminal_t`, with no `commit_before_t` row. A duplicate after release is forwarded once, as intended. A READ-request early duplicate is inconclusive (the runs disagree). The silicon PASSes above do not cover this case: the silicon RTO is about 200 ms, longer than the J used there. The fix is open: route held-class duplicates to T (directive f813bc089 §3).

Earlier resume status (2026-10-12): candidate55 graceful/RST same-tuple hardware gates and four-arm smoke PASS; each restoration passed. Candidate56 preserves all counters while reducing stages to **N11/E12/T11** on local9.13.1 and installed9.13.2. Mirror/artifact checks and **519/519 compiled-model assertions PASS**; silicon qualification is separate and active. First56RST attempt stopped before traffic on an omitted Vision transitive helper; failed evidence and all five successful restores retained, deployment repaired. A fresh56RST retry is active. Separate bounded10s endpoint fixture is built and pinned; old-token gates now require split READ24/OP23 packet attribution, complete old batches, unchanged current authority and strict zero rejection suffix after the quiet window. Helper tests142PASS. Old external/token and seven-loss hardware gates remain pending. Counter-elision T10 is excluded from integration. Root alone owns hardware; frozen baseline, candidate55, historical evidence and paper preserved. No push.

The unchanged mirror_fix_01 silicon failure was captured before implementation started. Run: ../campaign_hw_vepa/same_tuple_failure_01/. c1/c2 completed20READ+SBO each; c3 repeated the installed tuple after TIME_WAIT and produced5SYNs with no returned packets, rc2 in5.015s. N remained closed phase7/epoch1.

Independent verification: `python3 verify_failure.py`; failure_verification.json records seed/23-point data, exactrealSBO callbacks, per-function padding/native lengths, checksums/CRCs and restoration. c1 READ p99 absolute host CLRT error46us around800us. No ASIC premature-release inference is made.

The original campaign rc1 is the known per-function-length bug: native SELECT/OPERATE37 were collapsed with READ49. Its campaign verdict is not the evidence authority. C3 master.json is empty because no TCP connection opened; result.json and SYN capture establish the failure.

Five restoration steps passed; case4_response_path was read-only confirmed restored. Independent baseline timing/four-arm/native experiments are complete, including an actual native RST archive. Latest restoration is retained in baseline_restored_after_native_rst03.txt. Their strict failures remain retained in CHECKPOINT.md and campaign evidence.

Rearm implementation remains in progress. Candidate-only installer and snapshot adapters preserve baseline port/loopback checks. Delayed app reconfiguration now disables the idle/completed app, replays its full action-selected configuration, reenables it and verifies all other fields/counters unchanged. Fresh endpoint run directories are created while run-label reuse still refuses. All142 helper tests pass; syntax and diff checks pass. Model behavior does not establish hardware timing. Separate N/T experiments preserve candidate55.

**What the old-external replay gate shows, and what it does not (2026-10-13, directive f813bc089 §4).** `candidate56r_old_external_01` replays retained native frames into a quiet current lifetime.

- **Pool.** The candidate archives are the native reference runs (`rearm_native_reference_0*`, listed with sha256 under `old_capture_identity` in its `campaign_run.json`).
- **Selection.** `candidate_external.py::choose_archive` takes the first archive whose old sequence range `fresh_guard` accepts as unambiguous against the new connection's ISNs. It never relaxes the guard.
- **What was used in this run.** The replay logs name `graceful_0` (old ISNs client 1516364257 / server 3420359121) and `rst_0` (2394794731 / 3822847). New ISNs: c1 3204684138 / 813712543, c2 3286275157 / 895302162, c3 3524363339 / 1133390963. That `graceful_0` and `rst_0` were the first pool entries is read from their paths; no rejected candidates are recorded for this run.

The pool is needed because the guard passes a single archive only when the new ISN lands outside the old range. That is roughly a coin flip per direction, and the kernel ISN wraps in about 275 s. The gate therefore shows rejection of an old frame whose range is unambiguous against the current one. It does **not** give universal replay resistance for every random new ISN: an old segment inside the current window, with identical bytes and coordinates, cannot be told apart from a current one (README, "indistinguishable segment").

**Rearm limits.**
- A same-tuple reconnect is admitted only after both FINs and their qualified ACKs, or a qualified RST, with the new client ISN at least two octets ahead of the previous native frontier in the forward half-space.
- Overlap, a half-space jump and an identical ISN all fail closed.
- There is no timeout-based retirement. A lost producer or an exhausted generation (16-bit owner tag, `op_gen`/`gen_alloc` at 0xffff) keeps the tuple closed until a cold reset and redeployment.

This is bounded transparent reconnect, not unrestricted reconnect.

**Authorization recorded 2026-10-13 (Philip, this session).** Authorized:
- the installed-SDK 9.13.2 compile on the switch host;
- loading the corrected candidates (READ two-range re-encoding plus the duplicate-OPERATE hold fix) for bounded silicon runs with software endpoints: persistent READ and SBO, close/rearm, the `master_ack_of_padded_data` loss case, and duplicate OPERATE;
- both control policies, strict first (native SELECT/OPERATE), then all-58.

Conditions:
- SBO uses the software handler only. Physical relay OPERATE is not authorized (attended-only).
- `case4_response_path` is restored and verified after every block.
- No SDK change, no push, no default promotion.

**Real-relay compatibility audit (2026-10-13, directive §5; source reading plus offline capture decode, NOT yet run).**
Every qualification above used namespace endpoints with timestamps, SACK and window scaling OFF. Against the captured
SEL-751 / Linux-master handshake (`protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap`: MSS, sackOK, TS,
wscale 7 / 0), the rearm composites (rearm_56r, rearm_57s, rearm_57a) are predicted to fail:
- **Arming.** N admits the TS-profile SYN and SYN-ACK; it checks MSS only, so `tso`/`oa`/`ob` are opaque.
  `response_only_rearm/make_e.py` rekeyed E's `mode_t` on N's SYN-ACK kind (0xe7) alone, not on E's SH_SYNACK_OK
  shape. So the flow arms (mode=1) while the image registers stay unarmed.
- **Then every offset-8 TS segment hits E's `drop_odd`, in both directions.** This is the reverted `syn_ack_arm_01`
  failure reached by a new path. "Unknown negotiation stays native from the first packet" does NOT hold.
- **E has no native pass on a configured tuple.** Unqualified kinds go to `reject_lifetime`. SACK-bearing ACKs and the
  relay's FIN|PSH|ACK (0x19) close are not admitted by N and would be dropped.
- **Window scaling is not handled on mapped flows.** The reverse-window rows treat raw values as bytes.
Consequence: no candidate may be run against the real relay until this is fixed. The minimal safe step is to arm only
on an exact clean-profile handshake and pass every other tuple native. The bounded P1 profile (exact TS templates,
wscale {0, 7}, SACK neutralized to NOPs) is the follow-up. A model replay of the captured handshake is the first
confirmation.

**Model check of the audit (2026-10-13, `stage_experiments/realrelay_01`, local 9.13.1 model of rearm_57s,
option bytes copied from the SEL-751 capture).** The conclusion holds; the mechanism differs:
- **N drops the relay's TS SYN-ACK (offset 11) itself.** The cause is the offset-11 shape; MSS + NOP padding at
  offset 11 is dropped too. E never arms; the TS SYN passes native (`ts_model_01`).
- **After that the tuple is stuck.** A later clean RST and a clean SYN with new ISNs, and its ACK and READ, are all
  dropped, with N still at phase 2. This is worse than the audit predicted.
- **On a flow that is armed (clean handshake), offset-8 TS segments are dropped by `drop_odd` in both directions**
  (`established_model_01`). N closes a TS READ as answered although E dropped the response.
- **Also dropped:** a SACK-bearing master ACK (`drop_odd`) and the relay's FIN|PSH|ACK. The FIN drop is not `drop_odd`;
  0x19 without options at offset 5 is dropped too.
- **Control:** the clean MSS-only handshake plus READ passes 15/15 (`control_model_02_oracle`).
Real-relay operation therefore needs, at minimum:
1. a native pass for any handshake that does not exactly match a supported template, without wedging the tuple;
2. admission of 0x19 closes.

**CORRECTION (2026-10-13): two `realrelay_01` claims above are unsupported.** In `realrelay_01/model_drive_ts.py`
(modes `ts` and `variants`), every TS SYN-ACK was built without `reverse=True`, so it carried the master's addresses.
The following claims therefore rest on mis-addressed frames and are withdrawn:
- "N drops the relay's TS SYN-ACK (offset 11)";
- "the tuple stays wedged".
The audit's original arm-then-drop path remains untested on the original candidate. What stands comes from correctly
addressed frames in `established_model_01`: on a flow armed by a clean handshake, offset-8 TS segments, SACK-bearing
master ACKs and the relay's FIN|PSH|ACK are dropped. A correctly addressed baseline on rearm_57s is being run with
`realrelay_native_01/model_drive_native.py` (`realrelay_native_01/evidence/baseline_rearm57s_01`).
Correctly addressed baseline result: on rearm_57s, `realrelay_native_01/model_drive_native.py` passes 17/99
(`baseline_rearm57s_01`). Two things fail:
- **The clean flow's close.** The relay's FIN|PSH|ACK is dropped, so the clean flow never reaches phase 0x10f.
- **The whole TS connection that follows.** The SYN (offset 10), the SYN-ACK (offset 11), and every offset-8 ACK,
  request, relay ACK and response are dropped, and registers change.
So rearm_57s cannot carry a real-relay TS connection at all. The fixed build (`realrelay_native_01`, under review)
passes the same driver 99/99.

**Authorization recorded 2026-10-13 night (Philip): 61-octet transport-segmentation candidate, bounded experiment.**
- **Scope.** DNP3 transport segmentation within ONE outgoing TCP packet is authorized; more than one TCP packet per response
  is not. Requests stay unchanged. The strict baseline rearm_57s is preserved.
- **What may not be claimed.** This is not described as the only compliant solution, and not as qualified, until
  demonstrated through the ASIC.
- **Gate order.**
  1. Offline proof of the exact 61-octet READ and SBO encodings. For SBO, transport reassembly must reproduce every
     application octet and pass the exact Rule 8 comparison. FIR/FIN, sequence wrap, link lengths and every CRC are
     verified.
  2. The real OpenDNP3 endpoint gate.
  3. Compile and the integrated model.
  4. Silicon under the existing authorization: software endpoints, no physical relay OPERATE, build and config hashes
     pinned.
- **TCP translation for the actual growth.** READ 49->61 (+12), SBO 37->61 (+24). Retransmissions must reproduce
  identical bytes. Mapping must happen exactly once.
- **Measurements.** Endpoint reassembly latency, timing precision, stages, internal packets/bytes, wire overhead.
- **Restore.** After every block, failed blocks included, case4_response_path is restored and verified. If a restore
  fails or traffic affects anything outside the test, hardware activity stops and the evidence is preserved.
- **Failure handling.** A gate failure is diagnosed and corrected, never replaced by permissive-parser success.
