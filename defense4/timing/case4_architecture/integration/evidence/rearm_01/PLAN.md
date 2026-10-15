# Generation-safe rearm execution

## Current plan — 61-octet READ/SBO and full timing qualification (2026-10-14)

**Steps 1 to 5 are complete (2026-10-14).** Offline verification is green (integrated suite 699 passed, with and without `RESEARCH_PYTHON`) and the bounded four-arm silicon smoke passed as `candidate61_fourarm_smoke_03`; earlier attempts `_01` and `_02` failed closed on harness defects that are fixed and retained. Production `case4_response_path` was restored and observed after every run. Step 3 passed on silicon the same day after Philip's go-ahead. Step 4 (timing and size evaluation) then ran the same afternoon; step 5 (final review and report) is done: `seg61_02/evidence/QUALIFICATION_REPORT.md`. Work was committed on branch `implement/seg61-qualified-20261014`, fast-forwarded into `main` and pushed to `origin/main` at `f0baa724a` on Philip's instruction (2026-10-14); no defaults promoted. The f0baa724a audit (`DNP3_f0baa724a_Audit.md`) reopened the items marked below.

Specification: [implementation directive](../../../../../../DNP3_Implementation_Directive_492013014.md). Exact campaign commands and configurations: [candidate61 hardware runbook](../../core/response_only_rearm/stage_experiments/seg61_02/hw/RUNBOOK.md). Attempt history: [progress ledger](../../core/response_only_rearm/stage_experiments/seg61_02/evidence/progress.json).

### Completed

- [x] Generate the E-only candidate beside `seg61_01`, preserving the strict source, unchanged N/T hashes and replace-back equality. [Generated source](../../core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04/response_only.p4) SHA256: `1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa`.
- [x] Compile the whole composite with unchanged SDK9.13.1 and installed SDK9.13.2. Both pass at **N11/E12/T11**; actual PHV/table/hash and mirror placement are recorded in the [resource review](../../core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04/resource_review.json).
- [x] Pass compiled-model suites: padding-on smoke **30/30**, padding-off/native **30/30**, packet/transport **622/622**, mapper/rearm **399/399**, corrected duplicates **102/102**. Reports are in `seg61_02/evidence/model_smoke_02`, `model_native_01`, `model_packets_04`, `model_rearm_02` and `model_dup_02`.
- [x] Verify model READ49→61 and SELECT/OPERATE37→61, with SBO frames28/19/14 in one TCP payload, preserved application bytes, all64 transport sequences, independent CRC/checksums, reverse/window boundaries, retransmissions, wrap and rearm/stale cases.
- [x] Correct duplicate-READ fixture C to supply actual server ACK/response after observed request delivery, check hold/release and no repeated generation/growth, and check the normalized late request retransmission. Retain failed attempts.
- [x] Implement checker repairs, shared `validate_standards(artifact, context, captures)`, physical capture calibration/offload evidence, generation-headroom prechecks, candidate sealed-profile registration and17 hardware configurations. Final integration review remains open.

### 1. Finish verification before silicon

- [x] Correct the obsolete `candidate61-only` status assertion in `seg61_02/hw/tests/test_candidate61_hw_configs.py`; verify strict configurations explicitly use `profile=strict_comparison` and `standards.packet_boundary_required=true`.
- [x] Regenerate configurations with `seg61_02/hw/build_candidate61_configs.py` after final model evidence. Verify source/build hashes, expected counts and profile/arm lengths, capture flag and sealed-profile artifact pair.
- [x] Rerun the integrated tests and finish the interrupted independent smoke-path review. Result: 699 passed (with and without `RESEARCH_PYTHON`); code-reviewer found no blockers, two MAJOR findings fixed (Vision offload baseline restore, native-arm padding coverage).
- [x] (Demonstrated for all four entry points: `candidate_campaign.py` in step 1, `candidate_series.py`/`candidate_isolation.py`/`candidate_external.py` in `a541ddfa8`, each with a control case and a mutation check.) Before first use of each entry point, demonstrate its shared validator rejects missing, copied, altered or failed evidence, including capture-boundary evidence (end-to-end fail-closed test added in `test_campaign_run.py`). Qualification binds run/trial/connection/arm, source/build/profile/config, checker closure and actual capture hashes; filtered captures require source/procedure provenance.

From the repository root, the integrated verification command is:

```bash
C4=defense4/timing/case4_architecture
E61_EXP="$C4/integration/core/response_only_rearm/stage_experiments"
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
  "$E61_EXP/read_reencode_01/tests" "$E61_EXP/seg61_01/tests" \
  "$E61_EXP/seg61_02/tests" "$E61_EXP/seg61_02/hw/tests" \
  "$C4/protocol/hw_vepa/tests" "$C4/integration/evidence/rearm_01/hw/tests"
```

### 2. Bounded silicon smoke — first hardware milestone

- [x] Review `candidate_campaign.py plan` for `candidate61_fourarm_smoke.json`, then run off/timing-only/size-only/combined through software endpoints:20 READs plus one SELECT/OPERATE pair per arm. Use the exact command in the runbook.
- [x] Before every trial, confirm loaded-artifact identity and generation headroom. Capture incoming frames on Vision's physical switch-facing interface. Snapshot offloads, disable/verify GRO and other receive aggregation, verify LRO/hardware GRO off, and calibrate with deliberately separate coalescible packets through the switch. Retain commands/settings and complete calibration captures; unqualified boundaries fail acceptance.
- [x] Require each transformed response attempt to be one received TCP segment with the complete61-byte image. Verify native application preservation, READ points, SELECT authorization, successful OPERATE callback, CRC/checksum, TCP translation, counters and mapper state.
- [x] Verify restoration after every block, including failure: production program, ports, relay slot, Vision settings/offloads and restored-path ping. Update STATUS/working notes/ledger with the actual result.

Result: `candidate61_fourarm_smoke_03` PASS on all four arms (22 server data segments per arm; size_only/combined 22 x 61 octets, one segment per response; SBO authorized and succeeded; restore and ping ok). `_01` failed on argv-list capture-command parsing (fixed `48f81cb3a`); `_02` failed the combined-arm calibration on a TPACKET_V3 terminate race (fixed `fb244ee9f`).

Expected sizes come from the bound profile and arm:

| Profile/arm | READ | SELECT | OPERATE |
|---|---:|---:|---:|
| Candidate61 off or timing-only |49|37|37|
| Candidate61 size-only or combined |61|61|61|
| Strict comparison, padding on |58|37|37|
| Strict comparison, padding off |49|37|37|
| Unbound native |49|37|37|

### 3. Persistence, recovery and state isolation

- [x] Mixed persistent READ/SBO and at least three successive same-tuple connections for both graceful close and qualified RST, without reseeding/resetting authority.
- [x] All configured single-loss classes, including padded SELECT/OPERATE responses and data ACK; verify intended drop, recovery, application completion and no duplicate effects.
- [x] Protected reconnect, stale token/internal traffic and old external packet isolation. Preserve new-incarnation authority and capture provenance.
- [x] Early/held/late OPERATE duplicates on silicon. Require no premature departure, repeated allocation/growth or duplicate callback. Check headroom and restoration for every block.

Result (2026-10-14, all on silicon, restore and ping ok after every block): `candidate61_persistence_graceful_950_01` and `candidate61_persistence_rst_950_01` PASS (three same-tuple connections each, 61/61/61, no reset/reseed); `candidate61_loss_core_950_01` PASS (seven single-loss classes incl. padded SELECT/OPERATE and master ACK of padded data; exact drop, recovery, callbacks exactly once, growth 288 = expected); `candidate61_reconnect_950_02` PASS (c1 61, c2 unknown port native 49/37, c3 61); `candidate61_stale_tokens_950_02` PASS (c2 ready with one old READ token outstanding); `candidate61_held_operate_350_01` PASS (OUT_OP_DUP_DROP 0->3, OUT_OP_RELEASE 0->3, one OPERATE callback per connection); `candidate61_old_external_950_01` PASS (82 replayed old frames during c2, removed set identical to strict `candidate57s_old_external_04`). Retained failures, all harness: `reconnect_950_01` (c2 checked on c1's port), `stale_tokens_950_01` (missing source pin; calibration sleeps delayed c2 past the old tokens).

### 4. Full timing and size obfuscation evaluation

- - [x] Run **three order-rotated blocks × four arms ×500 READs at59,570PPS/950µs**, preserving matched endpoint/fixture settings and recording achieved hardware rates. Include SBO in every connection.
  - [x] Repeated successful SBO cycles (reopened by the f0baa724a audit, done 2026-10-14): three order-rotated blocks x four arms x 64 cycles on one connection each (`candidate61_repeat_sbo_950_b1_02`, `_b2`, `_b3`; failed attempt `_b1` retained, stale endpoint build). 768 of 768 cycles verified per cycle by `seg61_02/analysis/repeat_sbo_report.py`; control timing in `rearm_01/TIMING_CONTRACT.md`.
- - [x] Measure READ request-ACK/response commit and release timing, OPERATE hold/release, request-to-response latency and full SBO completion. Preserve per-exchange timestamps and callbacks.
- - [x] Run matched strict comparison blocks at the same59,570PPS/950µs with the same qualified physical capture procedure. Keep strict READ58/SBO37 separately identified.
- - [x] Run separately labelled piggyback-ACK measurements. Report request-to-response/SBO completion and fallback behavior; CLRT requires a separate request ACK.
- - [x] After correctness, compare14,892 versus59,570PPS with the candidate, workload and target held fixed to measure precision versus total overhead.
- - [x] Retain per-block signed/absolute target error, p50/p95/p99/max, every tail/exclusion and its exchange/reason, recovery, callbacks, intentional delay versus processing/polling overhead, total internal packets **and bytes**, and external growth. Expected fresh-response growth is `12 × READ +24 × (SELECT + OPERATE)`; report retransmission traffic separately. State the SD convention. Provisional p99 absolute error≤100µs is not a maximum-error guarantee; investigate the retained strict~1.1ms tails using matched captures/counters/host logs. (f0baa724a Gate 5, 2026-10-14: the ~1.1 ms tails are tap-to-tap transit events at requests 127/255/~275 on untimed off arms; Vision tx-frames-irq 256->64 does not move them; source unresolved; `seg61_02/evidence/MECHANISM_REPORT.md`.)

Result (2026-10-14): see `seg61_02/evidence/STEP4_RESULTS.md` and `step4_summary.json`. Pooled abs p99 at 59,570 PPS / 950 us: candidate61 timing_only 54 us, combined 51 us; strict 65 us and 51 us. Lengths and growth exact in every trial. Additional elapsed time (~1.1 ms) is observed between the host transmit and receive capture points; it also occurs with timing disabled and in the strict build, so it is not unique to candidate61. Its component and possible interactions (kernel/NIC queues, qdiscs, capture timestamps, link, switch) remain unresolved; the ~128-exchange period is a lead. Percentiles were interpolated until 2026-10-14; nearest-rank gives the same pooled values and 91 us (not 90.5 us) at 59,570 PPS. 14,892 PPS: abs p99 147 us (47 of 150 over 100 us) with about 3.3x fewer internal packets. Not done: repeated SBO cycles per connection (SBO timing is n = 3 per arm).

### 5. Finish and report

- [x] Review the final changes and evidence; commit coherent verified changes without pushing or promoting defaults. Preserve historical evidence and pre-existing edits.
- [x] Update this plan, STATUS, WORKING_NOTES and the progress ledger with each gate's result and limits. Full completion requires silicon correctness/recovery and matched timing/overhead measurements.

Result: final report `seg61_02/evidence/QUALIFICATION_REPORT.md`. Independent evidence audit reproduced every number from raw captures and corrected the tail-origin inference; code review found no blocker, its MAJOR (`.gitignore` credential re-assertion) and five MINOR findings fixed. Committed on the branch, later fast-forwarded into `main` and pushed at `f0baa724a`; no defaults promoted. Correction (f0baa724a audit): the report's statement that precision deferral is visible in `standards.json` was false at that revision; `build_standards_artifact` dropped it. Fixed by the precision-serialization change of 2026-10-14.

f0baa724a mechanism completion (2026-10-14, on `main`, unpushed): Gates 1-5 done; report `seg61_02/evidence/MECHANISM_REPORT.md`; control-timing candidate `stage_experiments/ctl_timing_01` (m3) normalizes SELECT and OPERATE CLRT on silicon but is not a default.

Real-relay compatibility remains a separate milestone. Equal61-byte payload length leaves plaintext object contents and the one-versus-three DNP3 link-frame structure visible; these tests do not establish comprehensive fingerprint resistance.

## Historical rearm plan — 2026-10-12

Approved in the current conversation on 2026-10-12. Apply tofino-p4. Work directly on main; preserve local edits, frozen source/artifacts/raw captures and paper. One physical switch owner (root); all agents are offline-only. No push.

1. Capture unchanged mirror_fix_01 same-tuple failure first, independent of the defective campaign verdict. Retain c1/c2/c3 captures, endpoint JSON, wire/timing/return codes and N/E/T state; restore case4_response_path.
2. Implement isolated response_only_rearm N/E/T candidate. N owns bilateral close/qualified RST retirement and genuine WorkRecord freedom; no forced clear. E normalization is read-only, accounting is epoch-qualified, first SYNACK arms once. Ordered private CLOSE/OPEN publishes T epoch before new handshake. Reject old Work, external segments, held originals (including OFF/OPERATE), reset events and tokens without changing the new incarnation. Preserve allocators; fail closed before tag alias/exhaustion. Fresh ISNs/nonambiguous sequence ranges required; ambiguous reuse rejected.
3. Repair campaign selected-build validation, extractor/application/integrity/per-function reconnect gates and protected-vs-characterization policy. Persist effective acceptance/config identities. Read diagnostic stale sources19..24; aggregate6 zero is insufficient. Correct piggyback fallback counts. Add per-block p99 absolute READ CLRT error<=100us, adequate eligible denominator and exclusions.
4. Continue frozen-baseline experiments alongside offline rearm. Reconcile pv4 (matching scratch config maxstale5), retain strict subset. Stale diagnostic: six1READ+SBO 3ms/3723, one14892 control, one250ms closegrace control, READ-only ifneeded. Precision: three50READ blocks each5ms/800us,5ms/950us,10ms/950us,25ms/800us at14892 (readiness35ms for25ms); onepause0control. If needed59570 onfailedconditions, verify selectedrate. Fourarms separateACK3x20READ/SBO each; piggyback1x20each with noCLRTqualification; matchingnative reference. Stop matrix expansion there.
5. Qualify complete source/interpreter/model invariants, full9.13.2 composite and compiled mirror guard/resources<=12stages/direction. Silicon: at least3 successive same-tuple protected connections for graceful-close/RST without reset/reseed; retainedoldpacket/token rejection, mapping/padding/checksum/SBO integrity and800/950 precision; allfourarmssmoke. Seven deterministic single-loss classes, exactdrop/recovery<=5s/no duplicate effects. Restore baseline each hardware block. Update concise current PLAN/HANDOVER/WORKING_NOTES checkpoint.

Success requires all gates; source/model/compile/receiver/silicon evidence are separate. Baseline is never overwritten. No physical relay OPERATE in unattended tests.

## 9c4a2cfdc audit: overnight plan (2026-10-15)

Inputs: `DNP3_9c4a2cfdc_Audit.md`, `DNP3_Next_Efficiency_Correctness_Prompt_9c4a2cfdc.md`, `DNP3_9c4a2cfdc_Reproduction.zip` (repo root, untracked; manifest verified). Philip authorized unattended software-endpoint switch blocks under the full restore procedure; no NIC-wide Vision changes, no relay OPERATE, no push.

Execution requirements (Philip, binding):
1. m4 is the correctness target. If m4 misses the hour-5 checkpoint, m3 gets recovery *characterization* and the shaping experiment; m3 is never called fully qualified while abandoned-SELECT recovery is broken. Report which candidate passed each gate.
2. Evidence-based stopping: no repeat of a failed command without a changed hypothesis; parking an approach never removes a required gate.
3. Complete generation budgeting from the actual code paths, with just-enough/one-short tests per allocator and model exhaustion tests.
4. Acceptance enforces separate READ/SELECT/OPERATE precision, the piggyback latency objective and the observed OPERATE hold; missing evidence fails; conformance, timing, recovery and workload coverage stay separate verdicts; historical records unchanged.
5. A model PASS counts only for the exact compiled source, config and driver recorded in its manifest; E stays `a144cd30…1c10`.
6. Complete restoration after every block, including failed ones; on failure stop, preserve state, follow the RUNBOOK recovery.
7. First shaping pair is screening; predeclared budget: request->ACK median increase <= 1 ms and every CLRT/J/piggyback gate passing. Noisy differences are inconclusive.
8. Tail research and splitting only after recovery qualification and the matched overhead comparison.

Milestones:
- [ ] M1 generation budget: per-role, control-timed reserves; boundary tests.
- [ ] M2 acceptance: per-function CLRT, piggyback latency and J verdicts bound to the run; qualification configs; source-only marker; seed label.
- [ ] M3 m4: Table 4-9 cancellation/replacement in N (E unchanged); asserted race/RESET/duplicate/exhaustion model cases; both SDK compiles.
- [ ] M4 silicon: recovery gates + qualification blocks + piggyback availability on m4 (or m3 characterization under the fallback).
- [ ] M5 asymmetric shaping: ACK_HOLD 14,892 with RESP/OP 59,570, screening pair then matched repetitions.
- [ ] M6 optional offline: leakage note, splitting, tail wording.
- [ ] M7 report `seg61_02/evidence/QUALIFICATION_9c4a2cfdc.md`.

Morning deliverable: one identified candidate with enforced acceptance, demonstrated recovery and a measured overhead/latency trade-off, failed gates stated plainly.
