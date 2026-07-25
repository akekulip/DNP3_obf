# p0_baseline — compile note

**P0 — unmodified Part 12 baseline, recompiled here as the controlled reference**

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p0_baseline.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 2 |
| **ingress stages** | **12 / 12** |
| egress stages | 0 / 12 |
| critical path length | 12 |
| logical tables | 44 |
| SRAM / map RAM / TCAM | 36 / 36 / 0 |
| stateful ALUs (whole program) | 7 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 7 / 11 |
| ingress + egress parser states | 2 + 6 |
| ingress latency (cycles) | 284 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `fa073cf691a6beb45fa8ffa61146cf481fc81e42f6cf4640bcb44ae6fe08f947` |

## Notes

Byte-identical to `research/ibspg_hold_response/p4/ibspg_hold_response/ibspg_hold_response.p4`
(same SHA-256, `fa073cf6…`). Reproduces the published 12/12 figure exactly, so every other row
in this directory is measured against a reference produced by the same toolchain on the same day.

Stages 0-9 are each pinned `[n,n]`: the serial state chain is the budget.

## Safety invariants

All six hold in this variant: generation safety, stale/unrelated event rejection, correct deadline
release, timeout/fail-open (the pass-budget watchdog), internal blocker-token isolation, and byte
preservation of the held packet. Per-invariant mechanisms are tabulated in
`../../PACKED_STATE_DESIGN.md` §9 (state machine) and `../../EGRESS_OFFLOAD_DESIGN.md` §7 (offload).
No safety logic was removed to reach this stage count.
