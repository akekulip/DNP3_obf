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

## Completion criteria
| # | deliverable | criterion | state |
|---|---|---|---|
| 1 | selected candidate | both SDK compiles, v3 model gate on exact source, reproduce.sh | open |
| 2 | COMPLIANCE_MATRIX.md | Q1-Q6 answered with clause/table/page + witness; violations fixed or stated | open |
| 3 | resource table | per-control before/after from compiler reports; reductions validated | open |
| 4 | hardware | four-arm + recovery blocks on selected image, restore verified per block | open |
| 5 | repository | root docs consistent, code map, search exclusions, history map, fresh-checkout repro | open |
| 6 | final status | COMPLETION_RECORD section 0 + closing report | open |

## Work in progress
- W1 IEEE 1815 audit (specialist), W2 timing-analysis correction (specialist), W4 P4 resource probes
  (specialist, scratch only), W7 root docs + search exclusions (specialist), W3 generator refactor (coordinator).

## Next action
Integrate specialist findings as they return; finish W3 refactor with byte-identity gate.
