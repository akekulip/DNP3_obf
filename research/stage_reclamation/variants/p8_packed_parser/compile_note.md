# p8_packed_parser — compile note

**P8 — P1 + P7. Still 8 stages: **the parser lever stops paying once state is packed.****

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p8_packed_parser.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 3 |
| **ingress stages** | **8 / 12** |
| egress stages | 0 / 12 |
| critical path length | 8 |
| logical tables | 42 |
| SRAM / map RAM / TCAM | 35 / 34 / 1 |
| stateful ALUs (whole program) | 6 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 6 / 11 |
| ingress + egress parser states | 4 + 6 |
| ingress latency (cycles) | 176 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `44cb07e43c40c9521fce5400b51c9d6835851c74949e08a5bb520b98d4980b29` |

## Notes

The two levers do not add up. Each saves stages against P0 (4 and 1), but together they give 8,
not 7. Once the state machine is packed, nothing is pinned and the binding constraint moves from
the head of the chain to the arithmetic prep feeding it, which the parser change does not touch.

Worth keeping anyway: it is the cheapest variant in logical tables (41-42 vs 44) and the lowest
ingress latency (176 cycles vs P0's 284).

## Safety invariants

All six hold in this variant: generation safety, stale/unrelated event rejection, correct deadline
release, timeout/fail-open (the pass-budget watchdog), internal blocker-token isolation, and byte
preservation of the held packet. Per-invariant mechanisms are tabulated in
`../../PACKED_STATE_DESIGN.md` §9 (state machine) and `../../EGRESS_OFFLOAD_DESIGN.md` §7 (offload).
No safety logic was removed to reach this stage count.

## The third compiler warning, and why it is benign (verified, not assumed)

This variant emits one warning P0 does not:

```
[--Wwarn=uninitialized_out_param] warning: out parameter 'meta' may be uninitialized
when 'IgParser' terminates
```

That is the direct consequence of deleting the zero initialisers for `dequeued` and `budget_zero`.
Parser metadata cannot be written twice on one path, so a field that is set to 1 on a branch must
NOT also be set to 0 in `start`; the compiler's all-zero default has to cover the other path.

Checked in the compiled binary rather than trusted: in `out/pipe/p8_packed_parser.bfa` the two fields occupy
containers `B5` and `B6`, and the ingress parser's `init_zero:` list contains both. The hardware
zeroes them before the parser runs, and only the 1-valued branch states write. A garbage
`budget_zero` would spuriously trip the fail-open watchdog, so this check is load-bearing.
