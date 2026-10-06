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

## Remaining-work execution — approved 2026-10-06

Continuation base: `5a816ab26d60da5fa041b19db6d0fbe9d2f21417`, on `main`.
Philip approved the remaining-work plan and then instructed implementation.
The full joint target remains required; no reduced profile substitutes for it.
The frozen corpus and pre-existing local changes remain protected.

| Requirement / audited gap | Owner and implementation | Acceptance / evidence | State |
|---|---|---|---|
| Acquisition overwrites existing evidence | Shared exclusive run reservation; endpoint and BMv2 launchers | Existing destination refuses before side effects; failures durable; sealed inventory | Complete offline; nine sealed inventories verified |
| Owner retires before old held originals return | Recovery phase/count conservation and immutable cookies | Old-cookie drain precedes rearm; lost-original quarantine; no count wrap | Implemented/tested source subset; target compile blocked |
| Lost OP blockers release before J | Deadline-qualified OP commitment | Actual control/packet cases before/at/after J with both blockers absent | Implemented/tested source subset; target compile blocked |
| Reset/full validation/parser-cookie gaps | Qualified reset outcomes and validated internal handoff | Wrong tuple/sequence cannot retire; IPv4/full-profile checks; source-bound compile | Qualified reset/seam tested; actual target producer missing |
| Complete ingress transport/timing integration missing | Bounded preprocessing ledger and explicit dynamic-length handoff | Independent arithmetic, immutable replay, complete joint source/compile; exact failure retained | Partial: software oracle and component compile; full joint incomplete |
| Instrument writers unused/marker unsafe | Bounded management events and separate instrument build | Decoder/wrap/loss tests; endpoint frame unchanged; resource/overhead evidence | Source/decoder tested; instrument compile/physical endpoints blocked |
| SBO retention absent from admission | Explicit selection-budget/context inputs and observation importer | Missing/context-mismatched inputs refuse; normal/fallback costs counted once | Complete offline; measured production inputs unavailable |
| Case4 controller has empty mutation plan | Whole-plan schema validation, source binding, backup/readback/restore | Incomplete candidates refuse; mocks inject failure at each boundary | Complete offline/mock guards; production registry empty |
| Autonomous kernel repair unproved | Isolated pinned endpoint/TCP socket artifact | Kernel-driven loss/retransmission and application outcomes, or exact failure | One isolated Linux/OpenDNP3 socket pair verified |
| Hardware qualification/measurement missing | Existing bounded declaration and guarded runbook | Full 9.13.2 build, measurements, authorization, restored state | Blocked by full target and external prerequisites |
| Conceptual table/size figure/prose defects | Existing policy contract, figure generator and working paper | Explicit explanation-only cases, accurate diagrams/claims, protected-text gates | Working-only updates verified; 13 figure warnings retained; promotion blocked |

Defaults remain 35-to-55 request bytes and 57-to-[28,29] response bytes;
one protected connection/association and two insertion boundaries; 30 ms
readiness expiry; 1 ms configured gap; requested 100 us heartbeat; fixed 40 ms
policy cap. Keep 16,168 attempts under the 18,360 ceiling. Fresh verified
connections are required per control trial/SBO pair; setup consumes the existing
budget and failed setup consumes an attempt. No implicit retry or extra campaign.

Ruling: use candidate processing port 69 only after independent queue/return-path
availability is proved. No blind group-wide recirculation or port substitution.
Bounded processing is at most 16 passes; this is not a physical latency bound.

Ruling: continue independent offline work while full target fit, SDE 9.13.2,
measurement, or live authorization is missing. No hardware contact is authorized
by this continuation. Commit only scoped verified changes using Philip as both
author and committer, without attribution trailers; do not push.

## Continuation outcome — 2026-10-06

Independent offline acceptance is implemented: exclusive evidence reservation,
original ownership/quarantine and deadline predicates, bounded software transport
preprocessing, SBO admission, source-bound controller refusal/rollback,
management-observation decoding, and a pinned real Linux/OpenDNP3 kernel loss
repair pair. Working paper and editable mechanism figure distinguish the proposed
target from the executed software paths. The frozen corpus stays unchanged.

The full target remains unfinished. Recovery core22 and instrument05 fail PHV
placement, and exact-current composite34 also fails. The ingress arithmetic
component alone compiles in six ingress / zero egress stages under local SDE
9.13.1, with 27 warnings. Complete validation, replacement images, replay cache,
handshake/assembly/retirement lifecycle, wire-ACK association and processing
completion still require target implementation. SDK 9.13.2 qualification and
physical measurements depend on the complete fitting source. Actual queued
OPERATE-envelope service and policy-off ownership cleanup remain unproved. No reduced target
or software oracle substitutes for it.

`CONTINUATION_VERIFICATION.json` in the canonical audit directory binds current
source identities, final tests, deliberately excluded legacy network modules,
compiler outcomes, protected hashes and retained failures. The 620-test offline
aggregate is retained as an intermediate run because the source interpreter was
subsequently repaired; final affected tests have separate source-bound verification_03 evidence.
Two overlapping expensive reruns were stopped as redundant and retained as
aborted partial logs, without claiming a suite PASS.
Final source-bound verification_03 passes 69 model/packet and 26 source-parity
tests, zero skips; the separate frozen-P4 recovery suite has 100 passes with
explicit reused-log provenance and an independent root run. Counts overlap
with the 620-test aggregate and are not summed as unique coverage.
The fresh Case 4 BMv2 run is 14/14, zero skips. Historical failed tests and
acquisitions are preserved rather than relabelled by later successful checks.

No current hardware contact, deployment, measurement, physical actuation,
restoration, push or manuscript promotion occurred. Remaining dependencies and
reproduction commands are in the canonical handover. Full Case 4 acceptance is
not achieved.
