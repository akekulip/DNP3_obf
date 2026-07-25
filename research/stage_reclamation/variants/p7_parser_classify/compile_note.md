# p7_parser_classify — compile note

**P7 — classify metadata produced in the parser. **1 ingress stage reclaimed on P0.****

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p7_parser_classify.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 3 |
| **ingress stages** | **11 / 12** |
| egress stages | 0 / 12 |
| critical path length | 11 |
| logical tables | 42 |
| SRAM / map RAM / TCAM | 36 / 36 / 0 |
| stateful ALUs (whole program) | 7 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 7 / 11 |
| ingress + egress parser states | 4 + 6 |
| ingress latency (cycles) | 263 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `283152a8d81a9dd8a0e8c1a561d9d7c752635724b24f9bcca46812e91dd722a1` |

## Notes

Independent confirmation of the coordinator's Part 13 finding, on P0 itself rather than on a
program that also adds DNP3 parsing: producing `meta.dequeued` and `meta.budget_zero` in the
parser removes the stage-0 producer table, and with it the edge that pinned the ARM write-driver
table to stage 1. 12 -> 11 stages, 44 -> 42 logical tables.

The 32-bit parser `select` on `hdr.ib.seq` — the construct that was in doubt — is accepted.
Ingress parser states go 2 -> 4. Both fields drop their zero initialiser in `start` and rely on
the compiler's all-zero default, because parser metadata cannot be written twice on one path.

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

Checked in the compiled binary rather than trusted: in `out/pipe/p7_parser_classify.bfa` the two fields occupy
containers `B5` and `B6`, and the ingress parser's `init_zero:` list contains both. The hardware
zeroes them before the parser runs, and only the 1-valued branch states write. A garbage
`budget_zero` would spuriously trip the fail-open watchdog, so this check is load-bearing.
