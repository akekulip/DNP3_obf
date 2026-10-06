# Case 4 implementation plan

Authority: Philip's 2026-10-06 execution prompt and approved plan in the current
session. Execution base: `235e7f01f1c87115455480ebf7c8d94f569c483b`, on `main`.
The canonical capability status and next-session commands remain in
`../audit_current/framework_20261005/STATUS_MATRIX.md` and `HANDOVER.md`.

## Locked decisions

- Compatibility comes first. Verify the accepted trailing-header padding
  profile's calculated 57-byte response; use [28,29] only for that exact profile.
  Keep 49->[28,21] separately labelled, without truncation or removed echoes.
- Keep the 18,360-attempt ceiling. The proposed expanded list has 16,168
  transactions, including warmups, state READs, and prerequisite measurement
  rows. This is bounded engineering validation, not full timing acceptance.
- Normal ACK release commits the complete configured response gap. Readiness
  expiry and post-ACK completion are distinct finite deadlines. Admission must
  account for the full interval and measured recovery/release costs.
- One protected connection and one outstanding association; initial insertion
  capacity is two boundaries for one SELECT/OPERATE pair. Continue translation
  after capacity is reached until verified connection retirement.
- All commits use `akekulip <akekulip@gmail.com>` as both author and committer,
  without other contributor attribution. No branches, push, or history rewrite.

## Dependency order and acceptance

1. Refresh protected hashes and the capability matrix; preserve existing work.
2. Correct contract/clock/request-anchor semantics; add failing recovery and
   association regressions before changing model or P4.
3. Implement independently driven expiry and qualified recovery; prove actual
   packet/register predicates, retransmission behavior, and finite next exchange.
4. Prove endpoint-compatible CROB insertion, exact bytes, statuses, CRCs, and
   finite transport translation independently; keep software evidence distinct.
5. Fit and source-bind recovery, padding, and carving on the intended target;
   reject unsupported schemas and partial activation.
6. Extend the existing BMv2 artifact, preserving its software architecture label;
   repair per-transaction event provenance and deterministic fallback scenarios.
7. Prepare the exact authorized hardware procedure and immutable run list;
   admission or unavailable observation points remain explicit blockers.
8. Produce reproducible analysis, editable mechanism figure, separate working
   paper and claim-to-evidence mapping; preserve the frozen manuscript.
9. Review, verify, commit coherent increments, and update the canonical handover
   with actual evidence levels and all remaining dependencies.

## Baseline findings

Current-source SDE 9.13.2 build_03 verifies source `df599101...`, seven ingress
stages and zero egress. That result is not reusable after source edits.
The fresh framework run found 146 passes, one BMv2 fallback-test failure, and no
skips; response-ready has 49 passing tests. The failed BMv2 test applied the last
transaction's watchdog interval to three transactions; the first completed
normally and register evidence mixed transactions. Repair event provenance and
scenario causality without widening tolerances.

The OFF smoke has 30 main 49-byte responses: median CLRT 2.2319235 ms,
minimum 1.103853 ms, maximum 22.386819 ms. One 58-byte precheck has CLRT
4.268337 ms and remains a separate cohort. These are master-facing observations,
not current holding, padding, or full response-latency evidence.

Live testbed state has not been checked or changed in this implementation turn.
No hardware authorization is inferred from this plan.

## Execution outcome — 2026-10-06

Recovery, packet association, request-anchored admission and control refusal
paths are implemented and independently tested. Recovery build04 binds the
current source to an offline SDE 9.13.1 `e558d01` compile: 10 ingress / 0 egress
stages. Recovery/association/admission is committed as `130aac45baef277fa40cbd2164ee79972ec22be5`.

Bounded CROB padding, response carving and transport repair have software,
endpoint-stack and packet evidence. The production OpenDNP3 gate passes 46
assertions in four cases. Current BMv2 passes all 14 Case 4 cases; its complete
23-test run has 22 passes, one retained legacy timing failure and no skips.
Current joint component build26 fits at 10 ingress / 10 egress stages; it proves
component coexistence, without the complete transport ledger or phase/checksum
integration. These changes and immutable traces are committed as
`0131fbe903256f75511855d456c958d301c6a3a3`.

The exact 16,168-attempt declaration and hardware procedure are prepared but
unexecuted. Full target integration remains blocked by the ledger/PHV limit,
missing deployed-SDK 9.13.2 proof and twelve unavailable admission inputs.
No live testbed connection, experiment, restoration or push occurred. Generic
TCP option/overlap handling, target connection-epoch retirement and autonomous
kernel tail-loss recovery remain unproved.

Separate analysis, editable figures and an evidence-grounded working paper are
prepared. The unchanged strict campaign-v2 checker passes after content/hash-
verified path relocation. All 2,210 protected execution-base files remain
unchanged. Exact newer author text and manuscript promotion remain pending.
The canonical matrix and handover contain the evidence and remaining checks;
`EXECUTION_VERIFICATION.json` beside them preserves the aggregate result and
targeted corrections without turning the original failures into an all-pass run.
