# Current status — two-READ candidate (overnight run started 2026-10-22)

One status file, updated in place. Detailed results live in machine-readable evidence; dated history in STATUS.md.
Directive: `Claude_Overnight_Hardware_Compliance_Refactor_Directive.md` (repository root, untracked).

## Objective
One integrated N/E/T candidate: mixed READ 91 -> 141, full integrity READ 247 -> 271 (encoded DNP3 bytes incl.
link headers and CRCs), SELECT/OPERATE 37 -> 61, blocker timing and OPERATE hold J unchanged; protocol behavior
audited against IEEE Std 1815-2012; resources reduced from c25; repository navigation simplified; hardware and
recovery evidence on the selected image.

## Starting state (verified 2026-10-22)
- HEAD = origin/main = 0c475ebc2. Testbed ownership: active False, unsafe_restoration False; no running units.
- c25 source 61f9af0f...; occupied stages (both SDKs): N 12, E 12, T 11, pipe-1 egress 7 (sum 42, a resource
  count, not latency). m11_09: N 11, E 12, T 11, pipe-1 egress 0 (sum 34).
- c25 hardware: padding byte-exact (campaign 02); timing precision FAILED (p99 2.0-3.6 ms vs 100 us);
  recovery blocks NOT run; bare-RST model case non-asserting.

## Scope (Philip, 2026-10-22 night)
Continue ONLY resource reduction and repository cleanup. The IEEE 1815 compliance audit is stopped and left to Philip
(not resumed in any form). No endpoint/request changes, no hardware runs tonight.

## Completion criteria
| # | deliverable | criterion | state |
|---|---|---|---|
| 1 | generator refactor | byte-identical live modes, tests, reproduce.sh | DONE 5671284aa |
| 2 | timing analysis correction | corrected metric, records updated | DONE 4a0b0fc56 (timing still FAILED) |
| 3 | resource reduction | per-control before/after from compiler reports; model gate on the reduced source | DONE m12p_c26 (gate passed; reduction not strict on every resource; see COMPLETION_RECORD 0a) |
| 4 | repository | consistent root docs, code map, search exclusions, verified history moves, fresh-checkout repro | docs + 3 verified moves DONE; fresh-checkout repro pending |
| - | compliance matrix | -- | NOT IN SCOPE (Philip) |
| - | hardware + recovery | -- | NOT RUN tonight |

## Next action
Commit c26 and the navigation changes; run the offline reproduction from a fresh worktree export.
