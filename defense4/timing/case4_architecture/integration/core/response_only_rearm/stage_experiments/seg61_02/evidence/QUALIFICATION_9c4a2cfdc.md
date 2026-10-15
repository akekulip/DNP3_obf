# ctl_timing m4: correctness repairs, recovery and overhead after the 9c4a2cfdc audit (2026-10-15)

Scope: `DNP3_9c4a2cfdc_Audit.md` and `DNP3_Next_Efficiency_Correctness_Prompt_9c4a2cfdc.md`, run unattended overnight on Philip's authorization (software endpoints only, full restoration after every block, no NIC-wide change, no relay OPERATE). Work is on `main`, not pushed; no default was promoted.

**Revised 2026-10-15 (m5 plan, step S0).** Verdicts are stated on the full, unfiltered gates; p99 and maximum are reported separately; the ~1 ms delayed exchange is called a *timing outlier of unresolved origin* until it is localized; every value computed without it is labelled *retrospective exclusion* and never decides a verdict. The shaping comparator (`analysis/shaping_pilot.py`) now fails a pilot on any correctness failure, shared with its baseline or not, and reports savings apart as efficiency only. The ACK_HOLD 14,892 verdict changed accordingly (below). No measurement changed.

**Candidate.** ctl_timing **m4**: `ctl_timing_01/evidence/m4_01/response_only.p4`, SHA256 `35e896eb…79cf`, E byte-identical to candidate61 (`a144cd30…1c10`), N11/E12/T11 on SDK 9.13.1 and 9.13.2, mirror guard PASS. candidate61 (`1b2d62d1…65aa`) stays the encoding reference and m3 (`c4819dba…9204`) the previous control-timing build.

## Bottom line

| | result |
|---|---|
| m4 recovery on silicon | **pass** except stale-token isolation (unmet, harness not adapted) |
| m4 piggyback qualification (3 blocks x 4 arms) | **qualified** |
| m4 repeated-SBO qualification (3 blocks) | **rejected**, each on one timing outlier of unresolved origin near index 127 (ACK ~1 ms late, request->response normal); every other timed exchange within the gate |
| asymmetric shaping (ACK_HOLD 14,892 PPS) | **efficiency measured; correctness not passed (shared timing outlier).** Three matched, order-balanced pairs (5/3/8 ms): -19 to -25 % internal frames and -18 to -24 % octets per exchange, request->ACK median +6 to +50 us; the b2 pilot fails SELECT CLRT on the full gate (920 us), as baselines b1 and the second b1 do |

m4 is therefore **not fully qualified**: its timing gate fails on silicon because of a timing outlier whose origin is not localized. The gate was not loosened and no exchange is excluded from a verdict.

## Repaired (commits on main)

| | commit | what |
|---|---|---|
| generation budget | `8d84cb303` | per-allocator reserves from the T/N code paths: READ, SELECT and OPERATE on the read lane for control-timed builds, OPERATE on its allocator, OPEN and live RESET on both, extra SELECTs; untimed arms OPEN/RESET only. 65 READ + 64 SBO reserves 211/82 (was 83). Refused at preflight for unknown or mislabelled builds; boundary tests per allocator |
| acceptance | `1a79b4a6f` | separate READ, SELECT and OPERATE CLRT precision, piggyback latency (p99 <= pb + 250 us) and observed OPERATE hold (min master-TX->outstation-RX >= J, observation points recorded) verdicts; nearest-rank p99; schema v3 artifacts must carry every objective; loss/reconnect exemptions cap at measurement_only; OPERATE hold recomputed from the bound captures; any GEN_EXHAUSTED drop fails a trial; qualification configs; source-only marker fixed; pktgen seeds no longer called blocker work. Two independent reviews |
| abandoned SELECT | `ea4de18f8` | m4 N rows implement IEEE 1815-2012 §4.4.4.3 Rule 4 / Table 4-9 while a selection is in effect: a READ terminates it, a new SELECT replaces or retries it; an OPERATE for a cancelled or replaced selection is dropped |
| lane exhaustion | `ea4de18f8` | m4 T drops and counts an OPERATE on an exhausted read lane (m3 kept J with an untimed ACK/response; shown in model `control_timing_m3_01_05`) |
| harness | `b19f87877`, `888b589b2`, `6825e0242`, `0a10af282`, `05c93a9eb` | series, loss and reconnect verdicts count a control-timed build's SELECT/OPERATE and its bounded stranded tokens; series READ precision uses the nearest-rank gate; block runner root path |
| restoration | `4d633af50` | `restore_verify.py` after every block: runner restore steps all ok and present, production program running, a fresh read-only snapshot equal to the pre-run snapshot on all 399 non-counter tables, Vision state equal to the recorded baseline, fresh ping |

## Tests

- Lab tree (this checkout, build outputs present): integrated suite **873 passed**, 0 failed.
- Source-only set of the hardware acceptance tests (`HW_VEPA_EVIDENCE_ROOT=/nonexistent pytest -m 'not build_tree and not evidence_tree' protocol/hw_vepa/tests`): 548 passed, 8 deselected, no skip; `test_markers`' nested export of tracked files also passes inside the integrated run.

## Model (compiled m4, current drivers; `ctl_timing_01/evidence/m4_01/model_summary.json`)

control_timing 141/141, select_lifecycle 120/120, smoke 30, packets 622, rearm 399, dup 102, repeat 523. Each PASS is bound to the source SHA and the driver SHA in its `launch_command.json`. m3 negative controls: select_lifecycle fails at the first cancellation; control_timing shows the exhausted OPERATE relayed with J and no lane.

**Open N limitation.** An outstation ACK and response microseconds apart can make N's single work cell busy-drop the response; T's readiness fallback releases the ACK and the response is delivered only after the outstation's TCP retransmission (not normalized; about 3 s on the SEL-751's RTO). Asserted as one of two known paths in the model; never counted as acceptance evidence.

**Unsupported states that remain.** A SELECT whose response never arrives (owner state 9) still needs a reset; a SELECT with the same sequence and different octets is discarded by the outstation and leaves N in state 9; a dropped request (a stale or mismatched OPERATE) leaves its TCP slot outstanding, so that connection must be reset. N has no selection timer (Rule 1 is the outstation's).

## Silicon (m4, 2026-10-15; every block restore-verified)

**Recovery** (`hw_campaigns/ctl_m4_*`):

| gate | run | result |
|---|---|---|
| held OPERATE duplicates, 350 ms | `ctl_m4_held_operate_350_01` | pass |
| persistence, graceful close | `ctl_m4_persistence_graceful_950_02` | pass (`_01` failed on the series precision harness gap) |
| persistence, RST (RESET during hold) | `ctl_m4_persistence_rst_950_02` | pass (`_01` same) |
| seven single-loss classes | `ctl_m4_loss_core_950_02` | pass (`_01`: all seven recovered; three failed only on a READ-only stale-token bound) |
| protected same-tuple reconnect | `ctl_m4_reconnect_950_02` | pass (`_01` failed only on READ-only switch counts) |
| stale-token isolation | `ctl_m4_stale_tokens_950_01` | **unmet**: the diagnostic's old-token window, sized for candidate61's READ-only token population, did not drain before the next READ (3 polls over 5.2 s; candidate61 drained by the first poll). Parked; stranded-token bounds are checked in every other block |

**Timing qualification** (950 us gap, J 2.4 ms, pb 4 ms; absolute CLRT error in us, nearest-rank p99 / maximum; n per kind 64-65, where the nearest-rank p99 is the maximum, so the two columns agree):

| block | arm | READ p99 / max | SELECT p99 / max | OPERATE p99 / max | verdict |
|---|---|---|---|---|---|
| repeat b1 (5 ms) | timing_only | 13 / 13 | **923 / 923** | 52 / 52 | rejected |
| repeat b2 (3 ms) | combined | 14 / 14 | **919 / 919** | 92 / 92 | rejected |
| repeat b3 (8 ms) | combined | 49 / 49 | **921 / 921** | 18 / 18 | rejected |

Retrospective exclusion (not a verdict): without the SELECT at index 127, SELECT p99 would be 15, 13 and 47 us.

Each failure is the SELECT at exchange index 127: its ACK reached the master about 1 ms late while request->response stayed normal. That pattern is consistent with a delay after the switch released, but the origin is not localized, so it is reported as a timing outlier of unresolved origin. The same ~1 ms outlier sits near index 125-127 in retained m3 and candidate61 blocks, and in this rig's untimed off arm (1,172 us on an outstation ACK). Qualification stops a block at its first failing arm, so arm coverage of these three blocks is partial; the characterization twins below record every arm.

Characterization twins (`ctl_m4_char_repeat_sbo_950_b1..b3`, every arm, measurement_only by purpose); absolute CLRT error in us, nearest-rank p99 / maximum (equal at this n); the last column gives the retrospective-exclusion p99 of the affected kind, which decides nothing:

| block | arm | READ | SELECT | OPERATE | timing outlier | retrospective exclusion |
|---|---|---|---|---|---|---|
| b1 (5 ms) | timing_only | 925 / 925 | 10 / 10 | 55 / 55 | READ at index 126 | READ 10 |
| b1 | combined | 22 / 22 | 925 / 925 | 45 / 45 | SELECT at 127 | SELECT 15 |
| b2 (3 ms) | timing_only | 19 / 19 | 23 / 23 | 893 / 893 | OPERATE at 116 | OPERATE 94 |
| b2 | combined | 54 / 54 | 921 / 921 | 92 / 92 | SELECT at 127 | SELECT 10 |
| b3 (8 ms) | timing_only | 47 / 47 | 921 / 921 | 48 / 48 | SELECT at 127 | SELECT 51 |
| b3 | combined | 48 / 48 | 919 / 919 | 13 / 13 | SELECT at 127 | SELECT 47 |

Every timed arm fails its full gate on exactly one exchange about 1 ms off, at index 116-127, of whatever kind sits there. Retrospectively, without that one exchange every arm's p99 would be within 100 us (largest 94 us). Off and size-only arms pass; no arm has a non-timing failure; all 12 arms pass the structural standards check and the exact 61-octet profile.

| piggyback block | request->response p99 / maximum, combined | timing_only | OPERATE hold min, combined / timing_only | verdict |
|---|---|---|---|---|
| b1 | 4,161 / 4,162 us | 4,149 / 4,183 us | 2,483 / 2,443 us | qualified, all arms |
| b2 | 4,150 / 4,152 us | 4,163 / 4,166 us | 2,489 / 2,483 us | qualified, all arms |
| b3 | 4,159 / 4,163 us | 4,153 / 4,154 us | 2,491 / 2,468 us | qualified, all arms |

(p99 over the objective's sample, n 192 per arm; maximum over all 193 complete exchanges in the arm's `timing.json`.)

Piggyback objective 4,250 us (pb + 250 us; a provisional nearest-rank target, not a maximum). Response availability below, near or above pb could not be varied: the software endpoint answers in about 0.3 ms and the fixtures delay only in whole milliseconds on the data path, which produces separate-ACK exchanges. Varying it needs an endpoint response-delay control (ready next step). Separate-ACK responses later than pb stay gap-anchored (the 5 and 8 ms qualification blocks), so readiness was not shortened.

## Overhead: asymmetric shaping (unchanged binary)

Declared before running: stop on a correctness failure or a request->ACK median increase over 1 ms; a pilot is promising only if internal frames and octets per exchange both fall by more than 5 %. Overnight, after the baseline ran, the comparator was refined to excuse a failure the matched baseline also showed and to judge CLRT without the index-127 outlier. **That refinement is withdrawn (S0):** correctness is judged on the full gates, a shared failure fails the pilot, and savings are reported apart as efficiency only.

| | baseline all 59,570 | pilot ACK_HOLD 14,892 |
|---|---|---|
| internal RX frames / exchange | 1,058.6 | 827.2 (-21.9 %) |
| internal RX octets / exchange | 80,286 | 63,670 (-20.7 %) |
| held re-waits / exchange | 423 | 189 |
| internal rate over the traffic interval | 62,387 PPS, 37.9 Mbit/s | 48,722 PPS, 30.0 Mbit/s |
| request->ACK median READ/SELECT/OPERATE | 5,500 / 5,498 / 7,928 us | 5,545 / 5,537 / 7,978 us |
| CLRT p99 = max, READ/SELECT/OPERATE | 56 / **921** / 88 (fails SELECT; retrospective exclusion 54) | 17 / 39 / 51 |
| achieved shaping (read back) | all 59,570 | ACK_HOLD 14,892, all else 59,570 |

Confirmation: three matched pairs, order-balanced (b1 and b3 baseline first, b2 pilot first), fixtures 5/3/8 ms, same endpoint pacing (read pause 25 ms). Summary `m4_shaping_ack14892_summary.json` (`analysis/shaping_pilot.py`, regenerated 2026-10-15 with the S0 comparator): decisions b1 promising, **b2 not_correct** (pilot SELECT 920 us), b3 promising; `correctness_pass` false.

| fixture | frames / exchange base -> pilot | octets / exchange | re-waits | request->ACK median change R/S/O | CLRT p99 = max, pilot R/S/O | full-gate failures base / pilot | J min pilot |
|---|---|---|---|---|---|---|---|
| 5 ms | 1,058.6 -> 827.2 (-21.9 %) | 80,286 -> 63,670 (-20.7 %) | 423 -> 189 | +45 / +40 / +50 us | 17 / 39 / 51 | SELECT / none | 2,490 us |
| 3 ms | 788.8 -> 639.8 (-18.9 %) | 60,861 -> 50,184 (-17.5 %) | 306 -> 159 | +6 / +10 / -2 us | 58 / **920** / 92 | none / SELECT | 2,489 us |
| 8 ms | 1,478.5 -> 1,110.2 (-24.9 %) | 110,519 -> 84,053 (-24.0 %) | 603 -> 234 | +17 / +24 / +43 us | 52 / 53 / 58 | none / none | 2,485 us |

Internal rate falls with the work: 62.4k -> 48.7k, 53.2k -> 43.2k and 74.5k -> 55.9k PPS over the traffic interval. The 920 us value is the timing outlier at index 127 in pilot b2 (retrospective exclusion 47 us); baseline b1 carried the same outlier. The outlier signature used for the retrospective exclusion (index 110-130, CLRT compressed by more than 800 us, response not early) matches exactly the >100 us exchanges in every m4 timed arm and nothing else, and could not excuse an early release; it enters no decision. The saving comes from the ACK lane's re-wait laps (re-waits fall by more than half) while the response lane keeps its 59,570 PPS polling, as the audit's hypothesis predicted: only the held-ACK pass records a_commit, so slower ACK polling moves the ACK and the gap-anchored response together. **Verdict: efficiency measured; correctness not passed (shared timing outlier).** ACK_HOLD 14,892 stays experimental and is to be reconfirmed on m5 after m5 passes correctness, with unchanged acceptance. This is not a capacity or saturation claim.

**ACK_HOLD 3,723 PPS, screening pair only** (`m4_shaping_ack3723_summary.json`; pilot first, then a fresh all-59,570 baseline, 5 ms fixture): frames 1,052.1 -> 778.2 per exchange (-26.0 %), octets -24.4 %, re-waits 420 -> 135, request->ACK median +125 to +220 us, CLRT p99 pilot 44/47/63 us, J min 2,488 us. Against ACK_HOLD 14,892 on the same fixture (827.2 frames, +40-50 us) it saves about 6 % more internal work for about four times the added ACK latency. Not confirmed with repetitions; ACK_HOLD 14,892 is the setting to carry forward.

**Zero-pause robustness, ACK_HOLD 14,892** (`ctl_m4_shape_ack14892_pause0_01`, kept apart from the paired comparison): with read pause 0 the next request follows the previous response (post-READ spacing median 2.2 ms instead of about 27 ms); the same 65 READ + 64 SBO ran in 1.67 s instead of 3.3 s. Per-exchange work is unchanged (826.4 frames, 63,613 octets); the internal rate rises to 95,734 PPS (59.0 Mbit/s) over that interval. CLRT p99 = max READ 15, SELECT **922** (fails; retrospective exclusion of the index-127 outlier: 15), OPERATE 52 us; J min 2,493 us; nothing else failed. No saturation was observed or claimed.

## Restored state

Every block ended with the runner's restore steps all ok and `restore_verify.json` ok: production `case4_response_path` running, 399 non-counter tables equal to the block's pre-run snapshot, Vision state equal to its baseline, ping through the restored path. Final read-only check after the last block (2026-10-15 06:55): `bf_switchd` running `case4_response_path_conf.json` under SDE 9.13.2, and the last block's `restore_verify.json` ok.

## Not done tonight

- Stale-token isolation on m4 (harness adaptation).
- Piggyback response availability below/near/above pb (endpoint response-delay control).
- The index-127 timing outlier of unresolved origin: localization needs NIC/driver experiments that need their own authorization; Ubuntu's 6.8.0-146 i40e source not yet compared with upstream.
- Offline splitting analysis and the residual request->ACK leakage note for Dr. Lin (median request->ACK still tracks the fixture: about 5.5/3.5/8.5 ms for READ at 5/3/8 ms, plus J for OPERATE).
- Real-relay READ, default promotion, push: Philip's decision.
