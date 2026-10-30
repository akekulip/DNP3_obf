# Current task: c75 (request retries only), ACK correctness and the recovery bound (2026-10-30)

Set by Philip's review of `c08c66fac`. Plan: `~/.claude/plans/we-were-on-tract-expressive-planet.md`.
- **c74 status:** a hardware-tested checkpoint with open findings (`results/analysis/c74_confirmation/SUMMARY.md`).
- **c75:** c72 plus the request retries only. It is derived exactly, compiled once and pinned, then qualified on the
  17-driver gate and explicit ACK-behaviour tests (stale handshake ACKs, ACKs behind later READs, window updates
  including zero-window, keepalives, timing on and off, endpoint progress).
- **Hardware:** the eight guarded SEL-751 blocks run on c75 after the offline gates pass.
- **Recovery:** the E3 difference stays unresolved unless new evidence explains it. Recovery blocks declare expected
  outcomes apart from failures that stop execution.
- **Wrap replay:** the SELECT/OPERATE wrap replay stays Philip's item (stopped by a safety check).
- **Parked:** c73, cleanup, paper work and broader campaigns.

## Previous task (completed 2026-10-30): c72-derived connection-start fix (c74)

Set by Philip on 2026-10-29 after his review of `fb5ce81b1` (its plan file has since been rewritten for the c75
phase). c72 stays the reference at tag `c72-validation-final`.
c73 promotion, further cleanup and paper work are parked.

**Done when**, on the exact tested hardware image: the connection-start loss is shown fixed, transaction order is
correct, data and command responses are preserved, and timing and padding work.

## Steps

| Step | Content | Status |
|---|---|---|
| 0 | Record corrections (padding cost scope, select timeout, mirror timing, classifier scope, c73, push state) | done, `1433c5c31` |
| 1 | Strict workload (mixed READ → SELECT → OPERATE → integrity READ) with an order-checking gate; c72 baselines | done, `87b1184cb`, `3f4a0a248` |
| 2 | Reproduce the loss paths on the c72 model by genuine processing | done, `5979e3654` |
| 3 | Smallest fix (c74: const-entry rows only) with regressions | done; independent P4 review: no critical finding |
| 4 | Integrate c74 as canonical; `c74_diag_mirror`; focused SEL-751 confirmation | done, `bffcf6339`, `e540da881`; results in `results/analysis/c74_confirmation/SUMMARY.md` |
| 4b | Before/after padding pcaps | curated extraction stopped by a safety check; retained captures pointed to instead |
| 5 | Offline SELECT/OPERATE wrap replay | stopped by a safety check; handed to Philip |
| 6 | Shareable package: READMEs for the P4 and the master/run scripts, lab-specific settings listed | done, `367b5a842`, `96cdfa4f6` |

**c72 baselines** (`results/analysis/strict_cycle/SUMMARY_c72_baseline.md`): strict workload 8/8 trials pass with
the strict order; combined-arm connection starts lose a start frame inside the switch in 5 of 32 connections, as in
the off arm.

**SEL-751 confirmation of c74** (all eight blocks run; summary in `results/analysis/c74_confirmation/SUMMARY.md`):
- start frames lost: 0 of 64 mirror-observed starts (c72: 10 of 64);
- first-request retransmissions: 0 of 96 fresh connections (c72: 5 of 96);
- strict workload and E4b: all checks pass, as on c72;
- E3: 13/18 against c72's 16/18, which stays open;
- one off-arm duplicate ACK after a forwarded late handshake ACK (registered falsifier);
- one block's final restore failed, then repaired and reconciled.

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
