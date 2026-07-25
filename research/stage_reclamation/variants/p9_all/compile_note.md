# p9_all — compile note

**P9 — P1 + P2 + P7. 8 ingress stages, 1 egress stage.**

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p9_all.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 3 |
| **ingress stages** | **8 / 12** |
| egress stages | 1 / 12 |
| critical path length | 8 |
| logical tables | 46 |
| SRAM / map RAM / TCAM | 35 / 34 / 1 |
| stateful ALUs (whole program) | 6 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 4 / 8 |
| ingress + egress parser states | 4 + 6 |
| ingress latency (cycles) | 176 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `bfb6efcdfab91ddaba5d018124c04367e3dd0b589283197f344894224d40b989` |

## Notes

All three changes together, confirming they compose without interference and without exceeding
the 8 stages P1 reaches alone.

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

Checked in the compiled binary rather than trusted: in `out/pipe/p9_all.bfa` the two fields occupy
containers `B6` and `B7`, and the ingress parser's `init_zero:` list contains both. The hardware
zeroes them before the parser runs, and only the 1-valued branch states write. A garbage
`budget_zero` would spuriously trip the fail-open watchdog, so this check is load-bearing.
