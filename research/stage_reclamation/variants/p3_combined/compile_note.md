# p3_combined — compile note

**P3 — P1 + P2. 8 ingress stages, and the best ingress resource position.**

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p3_combined.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 2 |
| **ingress stages** | **8 / 12** |
| egress stages | 1 / 12 |
| critical path length | 8 |
| logical tables | 48 |
| SRAM / map RAM / TCAM | 35 / 34 / 1 |
| stateful ALUs (whole program) | 6 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 4 / 8 |
| ingress + egress parser states | 2 + 6 |
| ingress latency (cycles) | 196 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `185dc0cc57f835b13c79f7d08190b9887943cdbf0cb128dc527dad1d15a49c1d` |

## Notes

The offload costs P1 nothing: 8 ingress stages and critical path 8, identical to P1 alone.
Ingress is left holding 4 registers and 8 counters (P0: 7 and 11) plus 4 free stages, with the
entire egress pipeline still at 1 of 12 stages. This is the configuration to hand to the size
co-residency work.

## Safety invariants

All six hold in this variant: generation safety, stale/unrelated event rejection, correct deadline
release, timeout/fail-open (the pass-budget watchdog), internal blocker-token isolation, and byte
preservation of the held packet. Per-invariant mechanisms are tabulated in
`../../PACKED_STATE_DESIGN.md` §9 (state machine) and `../../EGRESS_OFFLOAD_DESIGN.md` §7 (offload).
No safety logic was removed to reach this stage count.
