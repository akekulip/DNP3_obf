# Current task: c72 qualification and evaluation (status 2026-10-28)

Resumed 2026-10-27 at Philip's instruction. Done: model gate 17/17; qualification matrix 9/10 (block 10 loss_full
FAIL, restoration verified); Formby-style evaluation campaign 64/64 (Philip-approved scope, results/analysis/
evaluation/). Clean-checkout reproduction (step 3) ran 2026-10-28: compile and model gate reproduced; the frozen
replay tool replays 7 of the 10 qualification blocks, and blocks 06-08 need a decision (HANDOVER item 3). Figures
were redesigned in the P4USE style on 2026-10-28. Remaining: Philip's decisions in HANDOVER.md open items.

Approved scope: current implementation and paper in the shallow layout; historical material in Archive/;
current logs, PCAPs and JSON in results/. Work on main and commit locally. Push only on Philip's explicit instruction
(he asked for one on 2026-10-28); no
history rewrite.

## Completed implementation and cleanup

- Canonical editable p4/response_only.p4 replaces the historical transform chain.
- SDK9.13.2 source97812585…83d887e compiles N10/E10/T8/pipe-1-egress4, based on highest occupied stage+1.
- Changes preserve the protocol contract, add no packet passes, and reduce persistent state by64bits.
- Current build/model/checker/hardware tools use scripts/tests; historical PCAPs are not current prerequisites.
- Captured CROB bytes determine application status; metadata cannot turn TIMEOUT into success.
- Paper relocated without scientific or figure-content changes; standalone build/protected-text checks pass.
- Historical files archived by original tracked/local status. Only SHA-verified XZ duplicates were pruned.

## Remaining work, in order

1. Finish the current c72 package and reviewed source/action bindings. Run model smoke, then all17 required
   scenarios with their full original coverage. Repair demonstrated harness/fixture defects before judging the
   candidate; a real implementation defect requires a new source/compile and a complete new gate.
2. After compile and model gates pass, take a fresh native READ observation, generate the fixed matrix below,
   freeze candidate/profile/artifacts/checkers/configs, and run through existing guarded ownership/restoration.
   Current endpoint binding is one fixed reciprocal master/outstation tuple; no live BFRT IP rebinding.
3. Retain selected current compiler/model/hardware evidence with hashes. Reproduce from a clean checkout with
   Archive unavailable: restore only the selected current evidence, independently compile, recompute the17-model
   gate and replay only the new matrix. A faithfully reproduced hardware FAIL is a valid reproduction outcome.
4. Update HANDOVER.md, results/current.json and the short WORKING_NOTES.md. Verify current tests/static checks,
   paper and explicit staging. Commit locally as akekulip <akekulip@gmail.com>, author and committer, no trailer.

## One fresh SEL-751 matrix

| Workload | Exchanges |
|---|---:|
| D5 combined smoke | 4 |
| D5 four arms | 772 |
| D10/D15/D20 timing_only+combined | 1158 |
| D20 graceful/RST persistence and reconnect | 198 |
| D20 mixed/full loss, seven identity-targeted trials each | 308 |
| Total | 2440 |

Use the existing guarded points{1,3}, command parameters, freeze, host-wide ownership and independent restoration.
Smoke failure stops the larger matrix. Unsafe ownership/restoration stops writes. Later failures remain FAIL;
finish only remaining planned safe trials. No extra matrix, rerun-until-pass campaign or causal instrumentation.

## Boundaries

Four arms use one binary with runtime T/padding flags. Keep response-ready ACK/D, no J or new timing criterion.
CLRT is reported by class as data; piggyback exchanges stay separate. Faithful error delivery is transport evidence,
not successful SELECT authorization or OPERATE. Receiver captures do not prove switch-emitted packet boundaries,
departure timing or protection against physical-event fingerprinting.

No SER/unsolicited/classifier project, new register state, extra passes, timeout/threshold/default changes,
production compatibility work, manuscript revision or speculative diagnosis. Do not resurrect archived tasks.
Original root deletions stay deleted; their last Git bytes are archived. Private Git/agent/session state is preserved.
