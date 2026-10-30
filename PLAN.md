# Current task: c72-derived connection-start loss fix, verified on the SEL-751 (status 2026-10-30)

Set by Philip on 2026-10-29 after his review of `fb5ce81b1`. The detailed plan is
`~/.claude/plans/we-were-on-tract-expressive-planet.md`. c72 stays the reference at tag `c72-validation-final`.
c73 promotion, further cleanup and paper work are parked.

**Done when**, on the exact tested hardware image: the connection-start loss is shown fixed, transaction order is
correct, data and command responses are preserved, and timing and padding work.

## Steps

| Step | Content | Status |
|---|---|---|
| 0 | Record corrections (padding cost scope, select timeout, mirror timing, classifier scope, c73, push state) | done, `1433c5c31` |
| 1 | Strict workload (mixed READ → SELECT → OPERATE → integrity READ) with an order-checking gate; c72 baselines | done, `87b1184cb`, `3f4a0a248` |
| 2 | Reproduce the loss paths on the c72 model by genuine processing | done, `5979e3654` |
| 3 | Smallest fix (c74: const-entry rows only) with regressions | model-qualified; independent P4 review running |
| 4 | Integrate c74 as canonical; `c74_diag_mirror`; focused SEL-751 confirmation | in progress |
| 4b | Before/after padding pcaps | curated extraction stopped by a safety check; retained captures pointed to instead |
| 5 | Offline SELECT/OPERATE wrap replay | stopped by a safety check; handed to Philip |
| 6 | Shareable package: READMEs for the P4 and the master/run scripts, lab-specific settings listed | after the hardware runs |

**c72 baselines** (`results/analysis/strict_cycle/SUMMARY_c72_baseline.md`): strict workload 8/8 trials pass with
the strict order; combined-arm connection starts lose a start frame inside the switch in 5 of 32 connections, as in
the off arm.

**SEL-751 confirmation of c74**, each block registered, frozen, dry-run and restored:
- strict workload at D = 20 and 5 ms, 4 trials each;
- combined-arm connection starts on `c74_diag_mirror`, 32 fresh connections (primary; c72: 5 of 32);
- off-arm connection starts, 32 fresh connections (c72: 5 of 32);
- E3 SELECT-response loss recovery, 3 × 6, and E4b SELECT without OPERATE, 6.

Results are reported as "k of N", or "zero observed in N trials", never as an unconditional loss-free claim.

## Boundaries

- Four arms use one binary with runtime T and padding settings; timing parameters stay gap/budget/enabled. Keep the
  response-ready ACK and D; no J and no CLRT precision criterion. CLRT is reported by class.
- Guarded points stay {1, 3}. Stop writes on unsafe ownership or restoration; no rerun-until-pass.
- Every hardware run states its observable, mechanism, falsifier and trial count before it runs.
- The diagnostic mirror is used for packet presence and content only; its timing equivalence was not established.
- Receiver captures do not prove switch emission boundaries, departure timing or protection against physical-event
  fingerprinting.
- Work on `main`, commit locally as akekulip, explicit staging paths, push only on Philip's word, no history rewrite.
