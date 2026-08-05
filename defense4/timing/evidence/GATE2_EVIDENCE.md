# Gate 2 — compile evidence + verdict

**Verdict: Gate 2 = FAIL (not PASS).** The core **compiles clean** but is **INCOMPLETE** — it does not
yet implement four *required* timing-core safety properties (below). No safety property was removed to
fit; they are simply not yet wired. `READY_FOR_HARDWARE_REVIEW.md` is NOT written; Gate 3 is NOT started.

## Compile (offline, no switch loaded)

| item | value |
|---|---|
| source | `defense4/timing/p4/defense4_timing.p4` |
| source sha256 | `c877bedd7ef6fca1a10eb443cee8a728dc80a4785d3fb7fae075dd78c8e75cac` |
| git SHA (committing source) | recorded in the commit that adds this file |
| compiler | `p4c 9.13.1 (SHA: e558d01)` — `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c` (BF-SDE 9.13.1) |
| exact command | `bf-p4c --target tofino --arch tna -g -o build_final defense4_timing.p4` |
| result | **exit 0, 0 errors, 3 warnings** |
| `context.json` sha256 | `c9512381608e1904f1f8348892a54b508b86b4e41f676ea5b81ae024b57efbd0` |
| `.bfa` sha256 | `84b14da1565de4da94084b9d2906da1ac6adb6c7729c182d6b21ab16225df7fa` |
| logs preserved | `table_summary.log`, `mau.resources.log`, `phv_allocation_summary_0.log`, `gate2_compile_transcript.log` (this dir) |

## Resource report

| ingress stages | egress stages | critical path |
|---|---|---|
| **12 / 12** | 0 | **12** |

CP 12 = fully serial (dependency chain equals the pipeline depth) — it FITS but at the absolute ceiling
with **zero margin**. Any added ingress logic needs bounded ingress→egress redistribution or a same-Tofino
two-pass construction (`IMPLEMENTATION_PLAN.md` Gate 2).

## Warnings (3)

- `tag_clear: unused instance` — **this is the FIN/RST-cleanup gap** (the cleanup RegisterAction is defined
  but not invoked, because FIN/RST are not yet classified/handled).
- 2× `min_parse_depth_accept_loop will be unrolled` — benign TNA parser note.

## Implemented (verified present in source + compile)

Mode params (OFF/D1_EVENT/D2_RESPONSE_DEADLINE/D3_ACK_DEADLINE/D4_DUAL_DEADLINE/FAIL_OPEN);
`T_A=t_A+D_A`, `T_RESP=T_A+D_R` (built + armed on native ACK/RESPONSE, NOT the request);
RESPONSE release predicate with `predecessor_satisfied`; four queues (qids 7/6/5/4); two isolated blocker
roles + token budget/loop with no external token escape; canonical bidirectional flow key; collision
fingerprint → fail open; internal per-transaction generation; queue-resident ACK+RESPONSE holding;
`ack_committed_to_master` set on loopback return; modular sign-bit deadline expiry.

## MISSING — required safety properties NOT yet implemented (→ FAIL)

1. **FIN/RST cleanup** — FIN/RST are not classified; `tag_clear` (+ paired blocker/state teardown) is not
   invoked. (The `tag_clear: unused` warning is this gap.)
2. **Complete pure-ACK predicate** — expected TCP ACK number, expected relay sequence state, and master
   port are not validated (only the TCP-flags shape is checked).
3. **One-shot ACK/RESPONSE admission + duplicate/retransmission idempotence** — a duplicate ACK currently
   re-arms the deadline; no one-shot guard.
4. **Bounded transaction watchdog** distinct from the per-token blocker budget.

Also PARTIAL: stale-generation rejection is enforced for returning tokens but not for data-plane
ACK/RESPONSE packets; combined-response (ACK-bearing RESPONSE) defaults to eventual fail-open rather than
an explicit classify+bypass (spec labels it PROPOSED — acceptable, but not the ideal explicit bypass).

## Next step

Wire the four missing properties, expecting the CP=12 ceiling to force a **two-pass or ingress→egress
redistribution** design (do NOT drop a safety property to fit; do NOT pivot platforms). Re-compile from a
clean committed source, re-audit, and only then re-judge Gate 2. **Complete Defense 4 remains NOT
DEMONSTRATED.**
