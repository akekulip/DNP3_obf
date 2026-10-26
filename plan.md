# SEL-751 response-ready timing completion plan — 2026-10-25

Approved by Philip: “Implement the plan.” This replaces the r150 readiness proposal. Preserve frozen c52
(source8f37f70240ffa03daf887349e5e52a6abf7e32eb4b43ec559e35077902e3dce4), its evidence and completed
padding/loss-targeting/FIN/RST repairs. Physical SEL-751 only; no software outstation. Work directly on main,
commit and push task changes; preserve unrelated files and the two pre-existing deletions.

## Current start point — 2026-10-26

Read `CLAUDE_HANDOVER_20261026.md` first: c68 ran on the SEL-751 at every D (off vs timing+size), all blocks rc 0;
the 100 us criterion is removed. Nothing further is authorized until Philip directs it.

## Claude takeover scope — Philip, 2026-10-25

Philip requested updated working notes and handover, and explicitly said to keep Claude from expanding scope.
Read `CLAUDE_HANDOVER_20261025.md` before acting. Complete this existing plan only. Next: repair the missing
genuine ACK in the v2 abort negative fixture, retain the strict surviving-response gate, then complete the
affected model runs and the already-listed physical blocks. No P4 redesign, historical-tooling cleanup,
new instrumentation/campaigns/profiles, physical J project, package/OS/firmware change, threshold relaxation,
or production-default change. If a required repair crosses these limits, report the concrete blocker to Philip.

## Contract

- READ mixed/integrity, SELECT and OPERATE share one serialized response timing lane. Hold the genuine relay
  ACK until its matching whole response is available, release ACK once, then release response D later.
- D=5,10,15,20 ms. Retain independent OPERATE request hold J=2.4 ms and successful SELECT before OPERATE.
- Latest Philip correction: no exchange deadline or readiness fallback. Retain held originals until their
  matching release or FIN/RST/connection-epoch cleanup. Registers contain state, packets remain in queues.
- Suppress a validated duplicate request only while its original OPERATE request is retained for J or its
  whole response is retained for D. Do not restart D/J, allocate a generation, commit padding twice or execute
  twice. When no original request/response is retained, forward the retry for ordinary TCP loss recovery.
  Short holds do not eliminate retransmissions caused by packet loss.
- Existing whole native TCP responses91/134/49/49 qualify this profile. No synthetic ACK, piggyback feature,
  general TCP reassembly, relay tap/mirror, timestamp recorder, or new packet buffer.
- Preserve READ91→141[50,91], READ134→158[24,134], SBO49→60[28,32], all application bytes/checksums,
  mapping/ACK boundaries and one growth commit per logical response.
- Packet storage stays in held-return182 qid6 ACK/qid4 response queues; registers store ownership/completion.
  Preserve bounded blocker generation/laps, generation/epoch/dedup/FIN/RST guards.
- New profile timing_contract=response_ready_ack_d_v2. set_params keys only gap,op_j,budget,enabled; ns converted once to T256ns units/512ns grid. No da floor,pb bypass,readiness-success or cap.

## Implementation and gates

- [x] Record takeover HEAD and preserve unfinished r150 diff under
  read_complete_01/evidence/timing_response_ready_20261025/; do not overwrite baseline evidence.
- [x] Add opt-in --response-ready-timing generator layer after relay-ts; unselected c52 source stays identical.
- [x] Replace v1 with deadline-free v2 and retained-packet request duplicate suppression.
- [x] Use generation-scoped ACK/response completion; remove deadlines, successful bypasses and obsolete state.
- [x] Update installer/config/readback/checker interfaces together; reject source/profile/parameter mismatches.
  v2 protocol suite: 912 passed / 4 privileged skips; independent review approved.
- [ ] Retain RED c52 counterexamples, then GREEN emitted-source and compiled-model tests for all shapes,
  all D, both arrival orders, late native response, no/wrong/incomplete/stale response, retained request retries,
  duplicates/retransmissions/noextra growth,reset whileheld and all FIN/reconnect regressions.
- [x] SDK9.13.2 compile,pin artifacts before gates,compare actual resources. N/E maximumindex10,
  T≤11occupiedstages,pipe1egress≤4. No inferred stage savings or extra traversal.
- [x] Pass all16 existing required model drivers,with explicit new-contract expectations,plus required
  response_ready driver. Preserve c52 semantics under its profile; no hiddenselectors/readiness masking.
- [x] Complete compiled runtime integration; source/installer and adapter reviews are approved.

## Physical qualification

- [x] Existing frozen supervisor only: ownership/preflight/dry-run/freeze/independent restore for everyblock.
  Unsafe restoration stops hardware. Guarded points{1,3},code1/count1/on200ms/off0 unchanged.
- [x] CombinedD5ms smoke (PASS, rc01_hw_c67_20261025_02): both READs plus one complete successful SELECT/OPERATE.
- [x] Off and size_only reference arms once (run: campaigns 03-06, 1,930/1,930 eligible); timing_only and combined at eachD. Each arm65READ+64SELECT+64OPERATE
  =193; total1930 unique planned reference exchanges. Preserve failed attempts/planned denominators.
- [x] D20ms combined recovery (run: loss_mixed FAILED at t3 OPERATE CROB TIMEOUT; loss_full, graceful, RST, reconnect PASS): identity-targeted mixed/full loss presets,graceful close,RST and all3 reconnect
  connections. No new350ms stress campaign; retain historical record.
- [x] REMOVED 2026-10-25 (Philip): the CLRT precision criterion. It was agent-written, not his; it does not matter
  and is not reported. The visible CLRT (ACK -> response per class, master NIC = adversary vantage) is reported as
  data only; padding/application/SEQ/ACK/generator/loop-port checks remain the block gates.
- [x] c68 (c67 without write-only switch measurement state) on the SEL-751, before (off) vs after (combined) at
  D=5/10/15/20: rc01_hw_c68_20261026_01..04, every block rc 0, restoration verified; visible CLRT table
  read_complete_01/evidence/c68_visible_clrt_20261026.json.
- [x] FIN PASS (campaign 07; mixed-loss failure is separate). FIN closes only after graceful/RST/reconnect blocks pass as wholeblocks,including all planned connections.

## Completion and limits

Physical OPERATE J remains explicitly UNPROVEN by Philip's choice; preserve implementation/model checks.
No kernel attribution without proof, OS/TCP/firmware changes, reboot, keepalive masking or raw TCP master.
No attacker campaign,sizing redesign,paper work or IEEE audit. Record genuine blockers honestly.

- [ ] Clean-checkout reproduction of source/artifacts/model gates/config/readouts.
- [x] Update WORKING_NOTES,CURRENT,STATUS,COMPLETION_RECORD,ACTIVE_CODE_MAP,CLAUDE checkpoints/reproduce entry.
- [ ] Commit/push only task files/evidence; exclude unrelated edits/deletions.

## Execution ledger

2026-10-25: takeover preservation completed. Implementation/model/hardware pending.

2026-10-25: c53 first source/interpreter tests green; SDK9.13.2 compile failed (source01e17381e8cf):
register-value slice condition unsupported and atomic state action exceeds two comparison units. Failure
source/manifest/log retained; successor will use whole-word comparisons and two PHV inputs. No hardware touched.

2026-10-25: c60 source618724c6 compiles within all limits: N/E/T0..10,P1egress0..3. E matchesc52 exactly.
Source18/full188 tests pass; independent source and harness reviews approved. Actual final P1 costs vs c52:
SRAM61→58,TCAM63→61,SALU13→13,crossbar403→396,T PHVcapacity1344→1152bits. No whole-stage saving claimed.
Strict compiled response_ready_01 retainedfail: driver log parsing delayed SELECT ACK to496ms and response576ms;
T correctly expired500ms. Correcting model stimulus timing, not changing500ms. No hardware touched.

2026-10-25: c60replaycounterexampleprovedresp_done duplicatedatstages7/8, so c60isREJECTED despitecompilefit.
c62source569f6461 unifiesallresponseaccessesstage7,OPdiffmetadataearly; compile/layout/bank checksPASS,
source191PASS. Strictcompiledc62_01preACKreplay andlate-response expiry/RSTACK/fresh READPASS;419/421cases,
boundaryconstructionfailedbecauseNlatency pushed490msinjectionpast500. Harnessfixunderway,timernotrelaxed.
All17c62finaldrivers+physicalcampaignsremainrequired. No hardwaretouched. Currentdocumentsupdated.

2026-10-25 latest user correction: v2 removes the 500 ms exchange deadline. Duplicate requests are
suppressed only while the original request or response is actually retained; otherwise retries pass without
new admission/growth/J. c62 v1 strict model passed 694/694, but v1 is superseded and its gate is not borrowed.
c63 v2 implementation is in progress. Four c62 legacy drivers passed; no successor physical run has started.

2026-10-25 v2 progress: API protocol suite 912 passed / 4 privileged skips; legacy installer 89 passed;
independent API review approved (49 fresh targeted tests). Source 13 tests pass, including both arrival orders,
D matrix, no deadline, retained-packet retries, disabled retries, READ shape and SBO function identity.
c63 failed P4 declaration order; c64 lacked disabled retry handling; c65 lacked original shape/function identity.
c66 repairs identity in existing banks but compiled N at stage11 (limit10), so it is rejected. c67 separates
unrelated PHV fields that the SDK packed together; compiling with unchanged runtime logic. T occupies10 stages
and every T state object has one bank. Root updated existing dup/contention/abort model expectations, preserving
cases and requiring actual T-clock timing; 215 associated offline tests passed. No successor hardware run yet.

2026-10-25 c67 is the selected v2 candidate: source e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1.
SDK9.13.2 compile passes; N/E stages0..10, T0..9, pipe1egress0..3, all11Tobjects one physical bank. Source/layout
independent review approved. Smoke model30/30 passed; strict response_ready_01 running. Ten hardware configs
prepared (1,930 reference exchanges), not frozen or launched. Remaining16 model drivers and physical gates pending.

2026-10-25 runtime progress: smoke30/30, packets763/763 pass on c67. Strict_01 passed718/720 before a diagnostic
counter expectation: the completed child0 blocker executes stop_blocking, dropping it without TOKEN_OFF increment.
Independent raw-log review confirms exact ingress/current generation/action, unchanged full state and zero output.
The model-only correction retains all24 probes plus exact branch proof; strict_02 is queued/running. Source and
compiled artifacts remain unchanged. CTL offline suite1002 passed; subsequent focused canary tests132 passed.

2026-10-25 strict compiled gate PASS826/826 on unchanged c67 artifacts (attempt03). Attempt02 exposed an observer
race: the complete blocker frame appeared before its T-clock log line; the wait now requires that clock field.
This is one model-only predicate, with7 focused observer tests passing. Earlier attempts are retained. Remaining
14 original regressions are running sequentially (smoke30/30 and packets763/763 already pass). No hardware yet.

2026-10-25 rearm_02 passes on c67 after a model-only select-module alias repair; rearm_01 exception retained.
The compiled source is unchanged. Dup and the remaining regressions continue sequentially.

2026-10-25 nine model tests now pass: smoke,packets,response_ready,rearm,dup,repeat,select_lifecycle,
control_timing,fin_busy. Remaining8 run with at most2 isolated local model instances; memory/private-network
isolation was checked (196hugepages,72/model; anonymous DMA;32CPUs). No physical switch resource is used.
All old test scenarios remain; repeat/lifecycle now use genuine ACK pairs and actual T-clock proofs. The
finite reset postcheck is preserved by placing the clock proof in the existing committed verdict, rather
than introducing extra reset case names. Current source remains e8565de7; physical qualification pending.

2026-10-25 Claude handover: exact-output-port and prerequisite-stop repairs are implemented/reviewed;
64 focused tests and24 independent probes pass. Fresh repeat03 passes530/530 with all208 planned exchanges
completed; lifecycle02 passes138/138 with all33 exchanges; control_timing02 passes390/390. Policy boundary206
and size-off30 also pass. Contention02 passes453/453 and its postcheck but has a stale repeat dependency.
The v3 gate remains blocked: abandon has no attempt; abort01 has a stale dependency and four absent survivor
proofs. Diagnosis: held negative fixtures omit the genuine ACK, so v2 correctly retains the response; do not
weaken the checker. Source and compiled artifacts remain unchanged c67. No freeze or physical campaign exists.
No new jobs are scheduled after Philip's handover request. Exact next steps and final process/archive state
are in CLAUDE_HANDOVER_20261025.md and its referenced handover snapshot.

2026-10-25 c67 closeout (Philip's disposition): model gate PASS (17/17; abort02 84/84 with the genuine-ACK survivor
fixture, contention03 457/457, abandon01 12/12). Freeze freeze_v3_02 (after the v2-only installer t0_reg fix; campaign
01 was refused pre-write). Physical: smoke PASS; FIN PASS (graceful/RST/reconnect, all three connections); 1,930
reference exchanges observed (the timing verdict then given used the since-removed CLRT criterion; one D10 timing_only
mixed READ had an observed CLRT of 54.104 ms, cause unresolved); mixed-loss SBO recovery FAIL (t3 OPERATE CROB TIMEOUT,
an application failure; recovery times do not measure the select window); physical J unproven. c67 is not
hardware-qualified. Revised scope: bounded hypothesis-specific hardware debugging/retesting of those two failures on
the existing testbed/profiles/guarded operations; preserve failed evidence and thresholds; no new features,
production defaults, relay profiles or instrumentation project.
