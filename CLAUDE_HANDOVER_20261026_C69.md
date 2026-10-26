# c69 — fixed OPERATE J retired; offline milestone complete

## Authority and stop condition

The current user approved the c69 plan and said “Implement the plan”. They explicitly selected removal of fixed
J from the active implementation/requirements, preservation of Git history and historical evidence, and validation
ending at compile/model. Do not treat earlier agent attributions of a mandatory J hold as current authority.

No hardware runs, remote switch/relay commands, randomized-J replacement, unsolicited/SER implementation,
timestamp rewriting, physical instrumentation or production-default change belongs to this task. The last physical
candidate remains c68, whose full-loss recovery failure is preserved. c69 has not run on hardware.

## Implementation and current evidence

Stage directory: `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments`.
Detailed ledger/reports: `read_complete_01/evidence/c69_no_operate_hold_20261026/` under that directory.

- Candidate: `ctl_timing_01/evidence/m12p_c69_sdk9132`.
- Generated source SHA256: `5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59`.
- Generation: c68 flags plus `--strip-operate-hold`; explicit contract `response_ready_ack_d_no_j_v3`.
- Parameters: exactly `gap`, `budget`, `enabled`. No J field applies to this candidate.
- N/E source is byte-identical to c68. OPERATE forwards through common admission; the relay ACK still waits for
  response readiness and the response follows the genuine ACK decision by full D. SELECT/CROB authorization and
  the retained-response TCP retry policy remain. A genuine retry is not a new transaction generation.
- Removed: three J stateful banks, five dedicated J tables, command clone/hold/deadline domain, OP queue roles,
  unused HB runtime resources and packet-generator app1. Setup explicitly disables stale app1 with normal inverse
  restoration; teardown settles only the actual selected ports.
- SDK 9.13.2 compile PASS on attempt2, 99.663 s. Attempt1 parser match-register failure is retained separately.
- Compiled resources: p0 ingress/egress11/11 unchanged; p1 ingress9→8, egress4 unchanged; p1 SRAM47→36,
  TCAM51→36; stateful tables10→7. Compiler PHV summary also shrinks. Full report is `resource_comparison.json`.
- All 17 fresh required drivers PASS (6,339 checks); shared v3 recomputation returns `model_gate_passed`.
  All 23 attempts remain, including 6 failures. FIN02 passes 193/193 and all 3 connections after a fixture-only
  repair: exact FIN-retry observation replaces slow serial counter sampling while the busy cell is locked.
  Budget32, both peer packets, zero exhaustion and all3 completion checks remain. All 46 logs from all 23 attempts are archived and hash/round-trip verified. Clean-checkout
  reproduction PASS at `6b0b5efa2`: all 374 retained logs restored, all 38 compiler files verified, and the shared
  17-driver gate recomputed. Original and fresh resource reports match exactly. Full results are
  `clean_checkout_verification.json` and `clean_checkout_reproduce.txt` in the ledger directory.

## Reproduction and history

The generator keeps historical c67/c68 P4 identities unchanged. c68 reproduction now selects its generator,
model dependencies and repaired-harness freeze at `51f9c9d18`; older original c68 physical references retain their
`789092c2d`/freeze03 binding. c67 remains pinned to `a4ebbecbe`. Never rewrite old freezes to make them pass.

Reproduce with `CANDIDATE=c69 bash read_complete_01/reproduce.sh` from the stage directory.
It verifies the offline source/profile, model gate and compiler bundle and explicitly reports hardware unevaluated.
The build verifier can check an explicitly selected checkout source root without trusting its original absolute path.
All original artifact and source/include hashes remain required.

Retain failed model attempts as well as passing ones through the existing restoration helper and the c69 dependency
manifest. Do not replace raw traces, fabricate old J events or borrow c68 model passes. The first failed response
attempts exposed checker/fixture issues (observation-only outcome comparison and retired-port test binding); their
original records remain. Synthetic log observations are not BFRT functional registers.

## Physical-time explanation

SER (Sequential Events Recorder) records event timestamps in the device; unsolicited describes an event report sent without a poll. Formby's
physical metric starts at the observed command, not its TCP ACK. Delaying a command affects the later physical
event, while delaying its report does not rewrite its recorded timestamp. Fixed J shifts the upstream timing
distribution; meaningful physical-fingerprint suppression has not been demonstrated. c68's ordinary solicited
CROB exchanges do not measure that event channel. The prior overbroad SER review statement was corrected.

Removing J does not locate the cause of c68's prior OPERATE TIMEOUT or establish its resolution. Retain the known
failure and the distinction between application success, transport delivery, model proof and physical measurement.

Preserve `paper/`, old candidates/captures/freezes, unrelated work and the two pre-existing deleted root files.
Use explicit staging paths, required author/committer identity and no history rewrite.

## Completion and next action

Implementation and retained evidence are committed as `6b0b5efa2`. The clean-checkout verification used the installed SDK9.13.2 and Python3.12 environment; these external prerequisites are not bundled. Generator checks passed 194 tests plus163 subtests; one optional legacy compiled-context test skipped because RESPONSE_READY_CONTEXT was unset. The separate c69 compiler/resource checks passed.

The approved compile/model milestone is complete. No next implementation, experiment or hardware run is part of this scope. c69 has not been deployed, and physical-event fingerprint suppression and the earlier relay recovery failure remain unresolved. Keep those limitations visible; do not turn them into a new task without a new user instruction. No history was rewritten.
