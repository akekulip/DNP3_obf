# p1_packed_state — compile note

**P1 — packed transaction state (WS2). **4 ingress stages reclaimed.****

## Result (local bf-p4c 9.13.1, `bf-p4c --target tofino --arch tna -g -o out p1_packed_state.p4`)

| metric | value |
|---|---|
| errors / warnings | 0 / 2 |
| **ingress stages** | **8 / 12** |
| egress stages | 0 / 12 |
| critical path length | 8 |
| logical tables | 44 |
| SRAM / map RAM / TCAM | 35 / 34 / 1 |
| stateful ALUs (whole program) | 6 |
| Stats ALUs (whole program) | 11 |
| registers / counters resident in INGRESS | 6 / 11 |
| ingress + egress parser states | 2 + 6 |
| ingress latency (cycles) | 196 |
| PHV allocation | successful, no unallocated slices |
| source SHA-256 | `60910b808076ae90c851647a5ef42d1862e36d607181647893bdf29a146e0f31` |

## Notes

The one change: `reg_gen` + `reg_active` pack into an 8-bit tag register whose SALU returns the
*difference* against the packet's generation, and the armed flag packs into the deadline word as
bit 0 so the age subtraction and the armed test both happen inside the deadline SALU. P0's
gen-compare level, active register level, active-driver level, ACK-qualify level, age level and
separate expiry level collapse into one decode table plus one expiry gateway.

Nothing is pinned any more — every table carries a placement range (`[0,4]`, `[1,5]`, `[3,7]`).
Ingress latency falls 284 -> 196 cycles (-31%).

The single 32-bit packed word the brief proposed was BUILT AND REJECTED by the compiler; see
`salu_probes/probeE_packed_word_REJECTED.p4` and PACKED_STATE_DESIGN.md §0 limit C. The 3 probes
in `salu_probes/` establish the SALU's 2-PHV-input limit, its small-immediate limit, and the
output-expression form that made the collapse possible.

Verified in the binary, not just the source: `out/pipe/p1_packed_state.bfa` shows the deadline
register's crossbar as exactly two PHV inputs `{ 64: meta.now_word, 96: meta.dl_val }`, and the
release predicate compiled to the gateway `0b0***********************00000000` — bit 31 clear
AND low byte zero, i.e. armed-and-due, exactly as designed.

## Safety invariants

All six hold in this variant: generation safety, stale/unrelated event rejection, correct deadline
release, timeout/fail-open (the pass-budget watchdog), internal blocker-token isolation, and byte
preservation of the held packet. Per-invariant mechanisms are tabulated in
`../../PACKED_STATE_DESIGN.md` §9 (state machine) and `../../EGRESS_OFFLOAD_DESIGN.md` §7 (offload).
No safety logic was removed to reach this stage count.
