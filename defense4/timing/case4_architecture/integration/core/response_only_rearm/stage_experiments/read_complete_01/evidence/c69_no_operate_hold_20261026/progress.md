# c69 — retire fixed OPERATE hold J

Authority: the user approved the plan and said “Implement the plan”. The user selected retirement from the active implementation and requirements while preserving Git history and old evidence; validation ends at compile/model verification. No physical traffic, switch configuration or relay operation is authorized by this task.

Baseline: main at 51f9c9d1851fb031aa3a845774582e7c9b29c6fb. Preserve the two pre-existing deleted root files and all older candidates, freezes, records and paper files. Work remains on main under the existing repository workflow. No history rewrite.

## Contract

c69 is c68 plus opt-in --strip-operate-hold. New contract: response_ready_ack_d_no_j_v3. T parameters are exactly gap, budget, enabled. No op_j or J_operate_hold. N/E source remains byte-identical; common response generation, SELECT/CROB validation, retained-response retry policy, response readiness and actual ACK-commit+D release remain. Remove the separate OPERATE hold domain and its runtime resources rather than setting J to zero.

## Execution ledger

- [x] Generator: 9 focused tests and 195 full tests pass (1 skipped); all 10 legacy identities preserved.
- [x] SDK 9.13.2 second compile passes (99.663 s); first parser-capacity failure retained. p1 ingress stages9→8, SRAM47→36, TCAM51→36; p0 unchanged. Three J banks and five J tables absent.
- [x] Strict profile/setup/readback/headroom integration: new contract and BFRT ABI, no absent-reg reads, no HB queue/port dependency, stale app1 disable+inverse restoration; 28 configs validated offline.
- [x] First discriminating case passes; smoke30/30, packets763/763, full response_ready04 838/838 PASS.
- [x] All17 required drivers now pass; shared v3 gate recomputes model_gate_passed with23 retained model attempts and no blocked reasons.
- [ ] Retain compile artifacts/model logs and reproduce offline from a clean checkout.
- [ ] Independent review, current notes/handover, explicit task-file commit.

Ownership: c69_generator owns the generator and new generated candidate source/profile; c69_setup owns setup/profile/config integration; c69_models owns model drivers/helpers/gate; root owns compile/model launches, reproduction, evidence retention, records and integration. Agents share this checkout and must preserve others' edits.

## Claim boundaries

Fixed J changes an upstream command-to-physical-event measurement by delaying the command, but has no demonstrated physical-fingerprint suppression. Formby’s successful reported physical method used event timestamps; the current c68 solicited CROB traffic is not physical-event evidence. Removing J does not establish the cause or resolution of prior recovery failures. New c69 hardware validation and SER/unsolicited support remain outside this task.

## First compile

Source b958de02f077fe56de7153340bdc0cf22a60d1a0cdf9cf1f151727cc751420b9. SDK 9.13.2 rc3 after93.731s: parser match-register exhaustion for clone tag + kind + reserved select. Original source snapshot, log and manifest retained in m12p_c69_sdk9132/compile_attempt_01 (original output path was compile_local). Ruling: split tag and event validation into consecutive parser states, preserving rejection and forwarding semantics; compile again before any model run.

Final generated source SHA256:5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59. First fresh response_ready model attempt01 launched in the existing private namespace; no hardware traffic.

## First model evidence

response_ready01: immediate OPERATE forwarding/ACK/fullD passes; overall28/30 due fixture comparing observation-only T.outcomes. No functional register changed in that failing probe. response_ready02: next probe cannot inject into omitted legacy port181; launcher now adds181 solely to private no-J negative-probe namespaces. Both failed attempts retained. Smoke01 passes30/30. Packet suite01 running. No P4 change after successful compile.

response_ready04:838/838 PASS, including prompt OPERATE, rejected obsolete tokens, all selected D/order/class cases, common retries, reset/lifetime/generation probes. Remaining serial model batch launched after that successful prerequisite. No P4 changes after compile.

Remaining batch: rearm01 798/798, dup01 308/308, repeat01 526/526 PASS. select_lifecycle01 79/81 stopped on a stale J-only release-count expectation after actual prompt OPERATE forwarding and ACK/fullD had passed. Model driver adaptation is being corrected without changing P4; failed attempt retained.

select_lifecycle02 PASS146/146 after replacing retired-J count with common generations, ACK/response commits and completed OPERATE exchanges. control_timing01 PASS417/417. contention01 passes281cases then stops on stale OP_RELEASE dictionary key in abort_case; no failed packet/timing assertion preceded the exception. Adapt the observed counter-name set to explicit no-J contract without inventing zero events; failed attempt retained.

contention/abort counter adapter: one explicit contract-selected names tuple now covers all four delta paths, preserving raw counter indexes and common-cell requirements; no OP placeholders added. Independent review approved. Remaining batch03 starts contention02 and continues through the remaining required drivers.

FIN model01:191/193, all3connections attempted butfirstACK exhausted32retrybudget while fixture heldNwork phase1. Rawtrace: usefulanchorcount2sample13:21:08.441038; workstillforcedbusy until08.718234; ACK busy_exhausted08.720415; FIN seesreleasedphase4 at08.725007 and completes. Cause: five further syntheticcounterreads after usefulsample eachwaitup to50ms. Fixture-only repair usesexistingincremental model_log_view.wait_for exactFINretry action, thenoneactualbusyworkread andimmediateunlock. Bothpeerpackets, budget32 andstrictzeroexhaust/all3checks preserved. Fin02 launched; P4unchanged.

FIN02 PASS193/193, all3connections completed without retry exhaustion using the repaired observer. Shared model_summary.py --v3 --write --enforce returns model_gate_passed (17required,23attempts);6failed attempts remain explicit. Retention and clean-checkout reproduction remain pending, so scope is not yet marked complete.

## Resume checkpoint

Allimplementation/runtimefiles are stable and both independent reviews approve. Shared model gate PASS17/17 (6339checks),23attempts with6failures preserved. Source5efad5c...998d59, compiler bundle38files/35,681,575bytes, resourcecomparisonverified. Rootexec session34369 is the current single archive_completed.py batch03 (PID2629024); do not run twoarchivers concurrently. Oncefinished rerunarchive_completed.py once to include fin_busy02, then verify all46model logs/23attempts. Commit explicitcode/evidencepaths excluding the two original root deletions and unrelated untracked files, create a temporary detached cleancheckout, run CANDIDATE=c69 reproduce.sh and retainits log. Finalverification/recordsandcommit remain. No hardware model sessions remain; allSDKnamespaceprocesses ended. Do not claim scope_complete until cleancheckout reproductionpasses.

All46 raw logs from all23 attempts have now been archived and round-trip/hash verified; all6 failed attempts remain. Archive bytes 348680764, raw bytes 7579676262. Compiler retention includes38 files (35681575 bytes). Clean-checkout reproduction and final records remain.
