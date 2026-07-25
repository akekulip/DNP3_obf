# p2_egress_telem — compile note

**P2 — egress telemetry offload (WS3). **Zero ingress stages saved, as predicted.****

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p2_egress_telem.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 2 |
| **ingress stages** | **12 / 12** |
| egress stages | 1 / 12 |
| critical path length | 12 |
| logical tables | 48 |
| SRAM / map RAM / TCAM | 36 / 36 / 0 |
| stateful ALUs (whole program) | 7 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 5 / 8 |
| ingress + egress parser states | 2 + 6 |
| ingress latency (cycles) | 288 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `caace4e24bab469a9729f14d7973f6b599308f652552716ee86ac5594675e760` |

## Notes

A measured negative, and the expected one: WS1 established that DELETING the whole timestamp bank
leaves P0 at 12 stages, and deletion upper-bounds relocation. P2 lands exactly on that bound.

It is not a stage lever and should not be reported as one. What it does buy is ingress headroom:
ingress goes from 7 registers / 11 counters to 5 / 8, with egress (0 stages used in P0) absorbing
the rest in 1 stage. See EGRESS_OFFLOAD_DESIGN.md for what physically cannot move and why.

## Safety invariants

All six hold in this variant: generation safety, stale/unrelated event rejection, correct deadline
release, timeout/fail-open (the pass-budget watchdog), internal blocker-token isolation, and byte
preservation of the held packet. Per-invariant mechanisms are tabulated in
`../../PACKED_STATE_DESIGN.md` §9 (state machine) and `../../EGRESS_OFFLOAD_DESIGN.md` §7 (offload).
No safety logic was removed to reach this stage count.
