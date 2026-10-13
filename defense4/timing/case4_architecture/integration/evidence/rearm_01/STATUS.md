# Generation-safe rearm evidence

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
