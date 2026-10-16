> Approved by Philip 2026-10-15: "Proceed with this plan incorporating the five amendments above. Implement the smallest verified N-only correction. Preserve E and T byte identity, retain the original failing race, and require successful delivery across spacing, competing connections, duplicates, RESET and reconnect. Qualify the exact compiled successor before reconfirming shaping. Do not change timing gates or exclude outliers to obtain acceptance." The plan text below is copied verbatim from the planning session.

# m5: fix N's ACK/response contention, repair isolation and acceptance, qualify on silicon (from d50ed9b78)

## T0. Transfer package (first execution step; for handover to Philip's corporate Claude account)
This plan lives in the personal account's `~/.claude/plans/`, which the corporate account cannot see. First action
after approval, before any code:
1. Copy this plan verbatim into the repo as `defense4/timing/case4_architecture/integration/evidence/rearm_01/PLAN_m5.md`
   and link it from `rearm_01/PLAN.md` (new section "m5 plan (2026-10-15)").
2. Prepend to `WORKING_NOTES.md` a "TRANSFER — read in this order" block, and update `defense4/timing/case4_architecture/HANDOVER.md`
   "START HERE" (state, next action = S0, the five amendments, open decisions), both linking every file below.
3. Commit as akekulip (no trailer). WORKING_NOTES stays uncommitted (Philip-owned) — the committed PLAN_m5.md and
   HANDOVER.md carry everything; the corporate account reads WORKING_NOTES from the same checkout.
4. Note: pushing is Philip's call; if the corporate account works from a different clone, he must push first
   (local commits after d50ed9b78: 6aad82d9e, 55f3df0ea, plus T0's).

### Read-in-order file index (all repo-relative; C4 = defense4/timing/case4_architecture)
Instructions and audit:
- `CLAUDE.md` (repo rules: commits, frozen paths, barred tools), `~/.claude/CLAUDE.md` is account-global and NOT transferred — the repo `CLAUDE.md` + this plan carry the rules that matter.
- `DNP3_9c4a2cfdc_Audit.md`, `DNP3_Next_Efficiency_Correctness_Prompt_9c4a2cfdc.md`, `DNP3_9c4a2cfdc_Reproduction.zip` (repo root, untracked).
- Philip's directions of 2026-10-15 and the five amendments: section "Context" and "Design" of this plan (no other copy).
State and results:
- `C4/HANDOVER.md` (START HERE), `C4/integration/evidence/rearm_01/STATUS.md` (newest first), `C4/integration/evidence/rearm_01/PLAN.md` (overnight plan + 8 binding execution requirements).
- `C4/integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/QUALIFICATION_9c4a2cfdc.md` (overnight report), `.../seg61_02/evidence/MECHANISM_REPORT.md`.
- m4 build: `.../stage_experiments/ctl_timing_01/evidence/m4_01/` (`response_only.p4`, `resource_review.json`, `model_summary.json`), design `.../ctl_timing_01/DESIGN.md` (m4 section + open N limitation).
- Silicon evidence: `.../seg61_02/evidence/hw_campaigns/ctl_m4_*` (stale tokens failure: `ctl_m4_stale_tokens_950_01/token_window_observer.json`; candidate61 pass for comparison: `candidate61_stale_tokens_950_02/`).
Code to change:
- Generator `.../ctl_timing_01/generate.py` (add `transform_n_m5`), drivers `.../ctl_timing_01/model_control_timing.py`, `model_select_lifecycle.py`, `run_model.py`, `resource_review.py`, `compile_switch_orchestrator.py`.
- N source of truth to read: `.../ctl_timing_01/evidence/m4_01/response_only.p4` lines 19-76 (work cell), 175 (allocate), 314-342 (snapshot/first_event), 428-435 (busy_t/go_new), 440-481 (stage logic, deny gateway 453, busy branch 473); ports 79-81; parser 107-117.
- Source harness: `C4/integration/core/harness/driver.py`, `C4/integration/connection/binding/tests/read_support.py`, `.../binding/tests/test_native_invariants.py:137-159`; model driver `C4/integration/core/model_driver.py`; control plane rows `C4/integration/core/response_only/cp.py`; port map `C4/integration/core/response_only/port_map.py`; prior busy design notes `C4/integration/core/STEP3_DESIGN.md:83-87,403,505`.
- Acceptance: `C4/protocol/hw_vepa/{checks.py,standards.py,campaign.py,hold_check.py}`; budget `C4/integration/core/response_only_rearm/hw/generation_headroom.py`, `H/candidate_campaign.py`.
- Isolation: `H/candidate_isolation.py`, `H/token_window.py`, `H/delay_read_tokens.py`, `H/isolation_gate.py`, `H/snapshot_lifecycle.py`.
- Analysis: `.../seg61_02/analysis/{shaping_pilot.py,m4_summary.py,transit_report.py,repeat_sbo_report.py,cost_report.py}`.
- Configs: `.../seg61_02/hw/build_candidate61_configs.py` → `.../seg61_02/hw/config/ctl_m4_*.json` (add `ctl_m5_*`).
- Hardware wrapper: `H/run_block.sh`, `H/restore_verify.py`, baseline `H/restore_baseline/vision_state_20261015.txt`; runbook `.../seg61_02/hw/RUNBOOK.md`; sealed profile `C4/integration/core/response_only_rearm/hw/sealed_profile.py`.
- Endpoint (for later piggyback work): `C4/integration/evidence/rearm_01/repeat_sbo_endpoint/{build_endpoint.py,sources/SocketGatePad58B.cpp,sources/DecoyGateCommandHandler.h}`, fixtures `C4/protocol/hw_vepa/vision_run.py` (casea: quickack + netem on response lengths).
Commands: `C4/HANDOVER.md` section 6 (suite, model, compile, configs, run_block, analysis).
Account-local items that do NOT transfer: this session's scratchpad scripts (m4_silicon.sh etc. — superseded by run_block.sh), claude-mem/auto-memory notes (`~/.claude/projects/...`). Nothing needed lives only there after T0.

## Context
The overnight report (`seg61_02/evidence/QUALIFICATION_9c4a2cfdc.md`) left m4 as the development baseline with an open N defect: N has one work cell; when an outstation's standalone ACK and its response arrive close together, the response finds the cell busy and `busy_t` drops it (`count_busy[0]`), and delivery then depends on the outstation's TCP retransmission (~3 s on the SEL-751), un-normalized. Philip (2026-10-15):
- Fix the ACK/response contention first, **N only**: E and T byte-identical (61-octet encoding and blocker-based timing unchanged). Delivery and timing protection must not rely on TCP retransmission. Preserve mapper accounting, generation isolation and the OPERATE hold. Smallest verified correction.
- Build a deterministic spacing sweep and keep the **original failing race** as a regression before changing N; prove the fix across spacing, competing connections, duplicates, RESET, reconnect and recovery; compile and qualify the **exact** successor (m5) on silicon.
- Repair stale-token isolation (diagnose by role and generation; qualify isolation during subsequent traffic with a justified cleanup bound) and acceptance alongside.
- Shaping comparator: shared correctness failures must prevent a correctness PASS; packet/byte savings remain separately reportable. Report: p99 and maximum separately; "timing outlier of unresolved origin" instead of "host-tail failure" until localized; full unfiltered results primary; any exclusion labelled retrospective.
- Carry ACK_HOLD 14,892 PPS as experimental; reconfirm savings on m5 only after m5 correctness passes, unchanged acceptance.
- **Do not change timing gates or exclude outliers to obtain acceptance.** Defer splitting and default promotion. Piggyback availability and bounded tail localization come after.
- Silicon: unattended, same terms as the overnight run (software endpoints; `run_block.sh` + `restore_verify.py` per block; stop all hardware on an unverified restore; no NIC-wide Vision change; no relay OPERATE).

Standing rules: `main`; akekulip-only commits, no co-author trailer; no push without Philip's word; no frozen/paper edits; no `git add -f`; >50 MiB logs to ledger; suite exit code gates every commit; code-reviewer on non-trivial diffs; model PASS bound to source+driver SHA.

X = `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments`; P4 = `X/ctl_timing_01/evidence/m4_01/response_only.p4`; H = `.../integration/evidence/rearm_01/hw`.

## Mechanism (traced)
- Work cell `work` (P4:19-76), single, phase 4 free. Stage-0 `go_new(k)` (P4:431-435) **calls `allocate.execute()` before the claim** — every stage-0 attempt consumes one N generation (`counter`, P4:175, capped 0x7ffffffe; generation 0 = unavailable). Claim → passes round port 68 (`n_RETURN_PORT`, bypass_egress=1, never through E); stage-3 pass frees the cell. A READ ACK (kind 10) holds the cell 4 passes, ending `emit_tev(0x0a00)` → T (port 180).
- Busy: P4:473 `else if(m.work_op==8w1){busy_t.apply();}`; `busy_drop` for kinds 1,2,5,6,7,9,11,12 (P4:428-430); pure ACKs (3,10) pass natively. A busy stage-0 pass writes nothing except `allocate` and `count_busy` (owner_t reads; client/server/epoch tables load; application/real/read_app tables match only phase 4) — so retry consumes generations, nothing else; this must be re-verified for the retry path, not assumed.
- Removing busy outright is wrong: the response's `claim_read_rsp` would move the owner before the ACK's laps and abort the ACK. The response must be serialized behind the ACK.
- Model: one N pass ≈ 8-15 ms wall; ACK holds the cell ≈ 59 ms wall; back-to-back response is deterministically busy on the model.
- N stage use: 11 of 12 ingress stages (busy_t/count_busy/snapshot_t/next_stage_t/read_terminal_t in stage index 9; first_event in 10; index 11 free). **Requirement: try to keep N11; N12 acceptable if the whole composite compiles within the physical limit with E and T unchanged and all guards passing. The compiler decides the fit.**

## Design: bounded, validated busy-retry through port 68 (N only)
Scope: response kinds 11 (READ) and 6 (control; 16 if reachable at stage 0). Requests (1,2,5,7,9,12) keep `busy_drop` — request admission and the OPERATE hold unchanged.
1. **Retry form.** On busy, a response becomes an internal retry frame to port 68: the 16-octet loop prefix carrying a retry marker (unused event/reserved combination), the **connection identity** (connection-table match / direction already resolved at stage 0) and the **current epoch** read at the busy pass, and a **lap budget**. Counted `count_busy[2]` per retry.
2. **Strict validation (amendment 4).** The stage-0 exception to the 68-ingress deny gateway (P4:453) requires the complete validated retry form: arrival port 68, exact marker and reserved values, budget in range, epoch equal to the current epoch, connection identity matching. Anything else on 68 at stage 0 stays denied (existing protection against forged internal packets preserved). Tests mutate marker, reserved, budget, epoch, identity and arrival port.
3. **Incarnation isolation (amendment 2, mandatory).** A retry whose carried epoch or connection identity differs from the current incarnation is dropped and counted **before** it can claim the work cell or touch connection state. Tested with RESET and same-tuple reconnect while responses wait. Sequence checks alone do not count as isolation.
4. **Generation accounting (amendment 1).** Trace every `allocate` and register write on the retry path. Preferred: the retry pass does not allocate unless it obtains the cell (split claim-check from allocation if placement allows; e.g. read-only availability check on retry, allocate on success). If not placeable, account explicitly: bounded allocations per retry, included in the N generation budget, with exhaustion behaviour tested.
5. **Budget (amendment 3).** The budget is chosen from measurement, not assumed: measure retry count and waiting time over the spacing sweep, two competing supported connections, duplicate responses and RESET during retry. Exhaustion = counted drop (`count_busy[3]`) and an explicit **failed delivery objective** in acceptance. Success = the supported workload delivers with **zero switch-induced retransmissions and zero exhaustion drops**; a bounded drop replacing an immediate drop is not success.
6. **No E side effects.** Port 68 bypasses E; verify by test that a retry never reaches E's mapper prematurely and produces no duplicate accounting (exact 61-octet image and growth on the eventual delivery; mapper registers unchanged by retry laps).
Generator: `transform_n_m5` in `X/ctl_timing_01/generate.py` (m4 N + these edits); T = `transform_t_m4`; generator asserts E and T byte-identical to m4.

## Steps
### S0. Comparator and report (offline, first commit)
- `X/seg61_02/analysis/shaping_pilot.py` `compare()`: `correct = not failure_kinds(pilot)` computed on the **full unfiltered** gates (no host-tail exclusion in the decision); shared failures → `decision: not_correct`; `new_failures` (pilot − base) reported separately; packet/byte/latency savings reported separately and labelled "efficiency only". Host-tail exclusion values kept only as a labelled `retrospective_exclusion` field.
- `QUALIFICATION_9c4a2cfdc.md`: p99 and maximum as separate columns (maxima computed from retained evidence); "timing outlier of unresolved origin" wording; every "(excluding …)" value labelled retrospective; ACK_HOLD 14,892 verdict = "efficiency measured; correctness not passed (shared timing outlier)". Regenerate `m4_shaping_*_summary.json`. Update STATUS/HANDOVER wording to match.

### S1. Failing regressions and spacing sweep (before changing N; commit with m4 failing evidence)
- Source-level exact harness: extend `core/harness/driver.py` / `connection/binding/tests/read_support.py` (ReadPipeline) with a port-68 FIFO so ACK laps and responses interleave at lap granularity. Tests: response at lap offsets 0..4 after the ACK, for READ/SELECT/OPERATE responses → delivered once, exactly, after the ACK, timed (T RESPONSE event), no busy drop. Expected to **fail on m4**.
- Model sweep `X/ctl_timing_01/model_contention.py`: ACK then response with spacing d ∈ {0, 8, 15, 22, 30, 45, 60, 90, 120} ms wall, each kind; plus two competing connections interleaved, duplicate response during wait, RESET and same-tuple reconnect during wait, loss + recovery. Per point: master gets ACK then exactly one exact 61-octet response without any resend from the outstation, ACK_COMMIT 1 / RESP_RELEASE 1 / no fallback, `count_busy[0]` 0, retry count and wait recorded. Run on m4 → recorded failures (the original race kept as a regression: `model_control_timing.py` race case keeps both paths for m4, only `committed` allowed for m5).

### S2. m5 implementation and model proof
- `transform_n_m5`; generate `m5_01`; compile 9.13.1 local + 9.13.2 switch; `resource_review.py` (N stage count, E/T unchanged, mirror guard); register sealed profile; add m5 to `CONTROL_TIMED_SOURCES`; extend `generation_headroom.workload_reserve` if retries allocate N generations (N's counter is separate from T's lane allocators — account where it applies).
- Model: S1 sweep and edge cases on m5 (all pass), validation-mutation cases, plus control_timing, select_lifecycle, smoke, packets, rearm, dup, repeat. Budget chosen from measured retry counts with a stated margin. code-reviewer on the N diff; commit.

### S3. Stale-token isolation (parallel, offline first)
- Diagnosis (retained evidence): on m4 the READ-lane pktgen `pkt_counter` climbs 5→6→7 and RAW_READ_TIMER_STALE 4→5→6 during the 10 s pause (candidate61: settles at 4 / 3); OPERATE lane identical. Hypothesis to confirm from snapshots: c1 on a control-timed build triggers the READ lane twice (READ and SELECT), so two delayed (2.5 s IPG) batches cannot drain in the fixed window. Report survival by role (READ app 0 / OPERATE app 1) and generation (T lane generation, N epoch/owner).
- Repair `H/candidate_isolation.py` + `token_window.py` for control-timed builds: expected old-token count = triggers × 2k per role from the configured workload; qualify isolation **during subsequent traffic** (old tokens may arrive while c2/c3 run; every one rejected as stale; current authority, owner and generations unchanged; c2/c3 timing and delivery intact), with a cleanup bound derived from the token count and the configured IPG (not a fixed sleep). Unit tests on retained m4/candidate61 evidence. The isolation result stays a separate verdict; no gate weakened.

### S4. Silicon qualification of m5 (unattended, same terms)
`ctl_m5_*` configs (same families as m4): recovery (held OPERATE, persistence graceful/RST, loss core, reconnect, repaired stale tokens), qualification repeated-SBO b1–b3 and piggyback b1–b3, characterization twins. Contention on silicon: report `count_busy[0..3]` and retry counters from every block's snapshots (must be 0 drops, 0 exhaustion); a dedicated silicon contention probe only if the endpoint can produce near-simultaneous ACK/response (else model-only, stated). Full unfiltered verdicts; the timing outlier stays a separate unresolved item, never excluded from a verdict.

### S5. ACK_HOLD 14,892 on m5 (after S4 correctness)
Three matched, order-balanced pairs on m5 with the S0 comparator (shared failures → not_correct; savings reported separately).

### Later (separate gates)
Piggyback availability below/near/above pb (needs an outstation app-level response delay without quickack; currently none exists); bounded tail localization (measured vs attributed). Splitting and promotion deferred.

## Verification
- Every commit: integrated suite exit 0; candidate_endpoint fixtures clean; generator reproduces m1–m5; m5 E and T SHAs equal m4's.
- S1 regressions fail on m4, pass on m5 (both recorded); model PASS only on recorded source+driver SHAs.
- Silicon: every block restore-verified; m5 verdicts from unchanged gates; zero busy drops, zero retry exhaustion, zero switch-induced retransmissions on the supported workload.


## m6 continuation (72d85875b directive, 2026-10-15 night)

Governing directive: `DNP3_m5_Continuation_Prompt_72d85875b.md` (repo root) as amended by Philip on 2026-10-15
(ten-hour overnight budget, candidate freeze, writing-readiness verdict, writing package under
`stage_experiments/seg61_02/evidence/writing_packet_72d85875b/`). This section replaces any competing plan.

Retained m5 record (unchanged by this continuation): the 14-block m5_10 sequence. Held-OPERATE `_01` is a superseded
harness attempt (lifecycle gate confused `retry_epoch` with N's epoch), not a qualification result; repeated-SBO b2
and b3 are **rejected, incomplete** blocks (stopped at the first failing arm), not four-arm qualification blocks;
S3 (stale-token isolation) was not run on m5 (refused by its own plan); S5 not run; retry laps zero on silicon.

Work order (decision points, not promises): W0 reconcile/record; W1 strict aggregate verdict
(`seg61_02/analysis/m5_summary.py --strict`); W2 opt-in 20 s isolation endpoint with an endpoint-local release
permission (`endpoint_isolation_20s/`), then one quiet new-incarnation isolation block on m5_10; W3 N successor
**m6** (`transform_n_m6`): valid RST while a response is held, retry-epoch invalidation only at a proven close,
response retransmission routed through T's release gate (failing-on-m5 source regressions first); W4 dual-SDK
compile and compiled-model gates, select and freeze one successor; W5 silicon contention probe (nonzero retries)
and successor qualification; S5 held unless successor correctness and precision pass. Hour-5 gate: without a
reviewed successor passing compile/model, no improvised hardware candidate. Every commit gated on the integrated
suite in a clean worktree of the staged change.
