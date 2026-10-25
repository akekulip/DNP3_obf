# SEL-751 response-ready timing completion plan — 2026-10-25

Approved by Philip: “Implement the plan.” This replaces the r150 readiness proposal. Preserve frozen c52
(source8f37f70240ffa03daf887349e5e52a6abf7e32eb4b43ec559e35077902e3dce4), its evidence and completed
padding/loss-targeting/FIN/RST repairs. Physical SEL-751 only; no software outstation. Work directly on main,
commit and push task changes; preserve unrelated files and the two pre-existing deletions.

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
- [ ] Pass all16 existing required model drivers,with explicit new-contract expectations,plus required
  response_ready driver. Preserve c52 semantics under its profile; no hiddenselectors/readiness masking.
- [ ] Complete compiled runtime integration; source/installer and adapter reviews are approved.

## Physical qualification

- [ ] Existing frozen supervisor only: ownership/preflight/dry-run/freeze/independent restore for everyblock.
  Unsafe restoration stops hardware. Guarded points{1,3},code1/count1/on200ms/off0 unchanged.
- [ ] CombinedD5ms smoke: both READs plus one complete successful SELECT/OPERATE.
- [ ] Off and size_only reference arms once; timing_only and combined at eachD. Each arm65READ+64SELECT+64OPERATE
  =193; total1930 unique planned reference exchanges. Preserve failed attempts/planned denominators.
- [ ] D20ms combined recovery: identity-targeted mixed/full loss presets,graceful close,RST and all3 reconnect
  connections. No new350ms stress campaign; retain historical record.
- [ ] Each timed reference workload(READmixed,READintegrity,SELECT,OPERATE): planned=eligible,n≥20,
  nearest-rankp99|completeCLRT-D|≤100us. Report first/complete timing,maxima,capture drops/retransmissions;
  verify padding/application/SEQ/ACK/switch counts simultaneously. No successful reference bypass.
- [ ] FIN closes only after graceful/RST/reconnect blocks pass as wholeblocks,including all planned connections.

## Completion and limits

Physical OPERATE J remains explicitly UNPROVEN by Philip's choice; preserve implementation/model checks.
Removing bypasses alone does not prove precision: c52 combined had zero fallbacks and still failed100us.
If precision fails,continue narrow release/queue/capture diagnosis from evidence,without threshold relaxation,
kernel attribution without proof,OS/TCP/firmware changes,reboot,keepalive masking or rawTCP master.
No attacker campaign,sizing redesign,paper work or IEEE audit. Record genuine blockers honestly.

- [ ] Clean-checkout reproduction of source/artifacts/model gates/config/readouts.
- [ ] Update WORKING_NOTES,CURRENT,STATUS,COMPLETION_RECORD,ACTIVE_CODE_MAP,CLAUDE checkpoints/reproduce entry.
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
