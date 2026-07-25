# p10_prep_fold — compile note

**P10 — P9 plus the prep-chain fold. **Critical path 7**, allocation still 8.**

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p10_prep_fold.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 3 |
| **ingress stages** | **8 / 12** |
| egress stages | 1 / 12 |
| critical path length | 7 |
| logical tables | 45 |
| SRAM / map RAM / TCAM | 35 / 34 / 1 |
| stateful ALUs (whole program) | 6 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 4 / 8 |
| ingress + egress parser states | 4 + 6 |
| ingress latency (cycles) | 180 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `896dc0cf783f1bdb9615571a563d2cb1e81d2238412f3f65a6b046e545a60db0` |

## Notes

Removes two of the three prep levels ahead of the state machine by having G arrive pre-encoded as
`(G/256ns) << 8 | 1` — already in the stored word's alignment with the armed marker set — so
`tbl_build_now` disappears and `dl_cand` becomes one add on two level-0 values.

The dependency chain shortens to 7 but the allocator still uses 8 stages, so this buys no stage.
It is kept for two properties that are improvements in their own right:
  1. NEVER EARLY — the low-byte subtraction now always borrows, so the test becomes
     `trunc(now) > trunc(deadline)` and the observed interval lands in [G, G+256) ns. P0 and P1
     can both fire up to 255 ns early; P10 cannot fire early at all, which is the correct
     direction for a guard interval.
  2. No zero-value hazard: the marker bit rides in `hdr.ib.seq`, so the armed word can never
     collide with the 'do not write' sentinel.

Cost: it changes the host-side encoding of G, which P0's own header already flags as TEST_ONLY
and says belongs in a register or table in a deployment — where it would arrive pre-encoded as
action data and this fold would be free.

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

Checked in the compiled binary rather than trusted: in `out/pipe/p10_prep_fold.bfa` the two fields occupy
containers `B6` and `B7`, and the ingress parser's `init_zero:` list contains both. The hardware
zeroes them before the parser runs, and only the 1-valued branch states write. A garbage
`budget_zero` would spuriously trip the fail-open watchdog, so this check is load-bearing.
