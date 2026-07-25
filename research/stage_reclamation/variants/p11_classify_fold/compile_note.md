# p11_classify_fold — compile note

**P11 — P10 plus single-lookup classification. Critical path 7, allocation still 8.**

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p11_classify_fold.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 3 |
| **ingress stages** | **8 / 12** |
| egress stages | 1 / 12 |
| critical path length | 7 |
| logical tables | 41 |
| SRAM / map RAM / TCAM | 36 / 34 / 2 |
| stateful ALUs (whole program) | 6 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 4 / 8 |
| ingress + egress parser states | 4 + 6 |
| ingress latency (cycles) | 180 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `588224d4825f6434ded465d86bdf5fc25ba2ba2db095ac50866fe50c888a5f2a` |

## Notes

Replaces the nested if/else computing `pkt_class` and `tag_val` with ONE ternary table whose keys
(`dequeued`, `role`, `slot`, `budget_zero`) are all level-0 values. Fewest logical tables of any
variant (41).

It does not reclaim the eighth stage either, and that is the finding: with the chain at 7 and the
allocation at 8, **the last stage is a packing outcome, not a dependency**. `tbl_classify` carries
the range `[0,5]` yet is placed at stage 1, and every table downstream sits one stage above its
own minimum. Chasing it further means fighting the allocator, not the design.

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

Checked in the compiled binary rather than trusted: in `out/pipe/p11_classify_fold.bfa` the two fields occupy
containers `B6` and `B7`, and the ingress parser's `init_zero:` list contains both. The hardware
zeroes them before the parser runs, and only the 1-valued branch states write. A garbage
`budget_zero` would spuriously trip the fail-open watchdog, so this check is load-bearing.
