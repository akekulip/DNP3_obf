# DCRN ACK-hold — Tofino-1 compile facts (bf-p4c 9.13.1), reconciled 2026-07-21

> **TERMINOLOGY CORRECTION (2026-07-23).** This file predates the rename and uses "Case A/Case B" to mean
> the two **defenses**, which is the mislabel corrected by `CASE_A_TERMINOLOGY.md`. Read, in this file
> only: **"Case A" = Defense 1** (`dcrn_defense1.p4`, hold the pure ACK, event-governed) and **"Case B" =
> Defense 2** (`dcrn_defense2.p4`, hold the response, ACK-relative deadline). Project-wide, Case A/Case B
> are the **device patterns** (separate vs combined ACK), and **Case B is never a synonym for Defense 2**.
> The stage/resource facts below are unaffected by this naming note. See
> `research/END_TO_END_IMPLEMENTATION_PLAN.md` §3.

Case A = dcrn_ackA.p4 (hold pure ACK, event-governed). Case B = dcrn_ackB.p4 (hold response, ACK-relative deadline).

## Stage counts (authoritative — as-shipped hardened builds)
- Case A: **12 / 12 ingress** (+1 egress) — evidence/ackA_9.13.1_hardened/table_summary.log (mtime 20:59, matches current source 20:56)
- Case B: **10 / 12 ingress** (+1 egress) — build_ackB_9.13.1 / evidence/ackB_9.13.1
- NOTE: build_ackA_9.13.1 (pre-hardening, 16:54) reports 11 stages; the FIX1+2+4 hardening added one stage → 12.

## Resource usage used/total (bf-p4c 9.13.1 logs; representative for the hardened build)
| Resource | Case A | Case B |
|---|---|---|
| MAU ingress stages | 12/12 | 10/12 |
| Critical path | 7 | 8 |
| Parser range-match rows | 171/256 | 166/256 |
| SRAM (unit-RAM) | 62/960 | 63/960 |
| TCAM | 0/288 | 0/288 |
| Map RAM | 60/576 | 60/576 |
| Stateful/meter ALUs | 9/48 | 6/48 |
| Stats ALUs | 6/48 | 6/48 |
| Gateways | 35/192 | 34/192 |
| VLIW action slots | 27/384 | 29/384 |
| Logical tables | 48/192 | 48/192 |
| PHV 32-bit | 13/64 | 22/64 |

Headline: stage-bound + parser-bound, NOT memory-bound (SRAM ≤7%, TCAM 0%). No stages left for size+split → SmartNIC (no stage wall) is the fix.

## Per-stage mechanism: see the deck (slide 07) — prologue(0-1) · classify(2) · arm(3) · latch(4) · trigger(5: A=response-event / B=deadline-SALU) · recirc(6-7) · release(8) · commit(9-10) · egress restamp.
Source: p4-dataplane-engineer extraction from resources.json/metrics.json/table_summary.log of build_ackA_9.13.1 + build_ackB_9.13.1.
