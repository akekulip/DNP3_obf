# Phase 0 gate 1 — preserved baseline still compiles

Date: 2026-07-28. Local, non-destructive: bf-p4c only, no switch, no bf_switchd.

Command:
```
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH bf-p4c --target tofino --arch tna -g \
  -o <outdir> research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4
```

Compiler: p4c 9.13.1 (SHA e558d01) — matches the recorded baseline SDE.
Source sha256: 812a56facd842dc7e96d631faffead9d88ca9753ac4d19f11f0b9bd809ffc7db

## Result: PASS — no drift from the recorded baseline

```
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 10
  Number of stages for ingress table allocation: 10
  Number of stages for egress table allocation: 0
Critical path length through the table dependency graph: 8
Number of tables allocated: 70
```

| Metric | Recorded baseline | This compile | Match |
|---|---|---|---|
| errors | 0 | 0 | yes |
| warnings | 3 | 3 | yes |
| ingress stages | 10 | 10 | yes |
| egress stages | 0 | 0 | yes |
| critical path | 8 | 8 | yes |
| tables allocated | 70 | 70 | yes |

The three warnings are the known benign set: the struct-wide uninitialised-out-param
TNA notice, and two min_parse_depth_accept_loop unroll notices.

---

# Phase 0 gate 2 — stage reclamation: 10 -> 8 ingress stages

Result read from `p4/build_stripped_9.13.1/pipe/logs/table_summary.log`, independently
re-verified:

```
Number of stages in table allocation: 8
  Number of stages for ingress table allocation: 8
  Number of stages for egress table allocation: 0
Critical path length through the table dependency graph: 8
Number of tables allocated: 57
```

`0 errors, 3 warnings` — the same three benign warnings as the baseline, no new one.

| | baseline | stripped | delta |
|---|---|---|---|
| Ingress stages | 10 | **8** | -2 |
| Egress stages | 0 | 0 | — |
| Logical tables | 70 | 57 | -13 |
| Critical path | 8 | 8 | — |
| SRAM | 61 | 25 | -36 |
| Map RAM | 60 | 24 | -36 |
| TCAM | 1 | 1 | — |
| Meter ALU | 9 | 6 | -3 |
| Stats ALU | 21 | 6 | -15 |
| Gateways | 36 | 30 | -6 |
| PHV containers | 41 (18.3%) | 37 (16.5%) | -4 |
| PHV bits | 593 | 505 | -88 |

## 7 stages is NOT reachable by deletion — the program is at its dependency floor

`Critical path length = 8` with placement at exactly 8 means the limit is now the dependency
chain, not resources: `tag_val -> tbl_build_now -> reg_tag -> tbl_state_decode -> reg_deadline
-> tbl_deadline_expiry -> termination branch -> ts_block_term_w / ts_first_block_w`. Reaching 7
would require deleting the on-chip timestamps — forbidden by design section 13, because the ACK
is held and the relay leg is untappable, so on-chip registers are the only possible measurement
of the hold — or restructuring the deadline chain, which is not a deletion pass.

**The direction's belief that three stages were dispensable was close but not exact: two are
reclaimable by deletion, the third is dependency-bound.** Four ingress stages of headroom now
exist for the dual-release logic (8 of 12 used).

## Attribution and negative evidence

- Deleting the G-selection guard alone gives **9** stages (separate probe compile).
- The counter-object collapse buys the **second** stage.
- The timestamp-predicate float did **not** free a stage. Only one of the four `ev_*` predicates
  is expressible in parser-only fields; the other three each carry a conjunct derived from a
  register or match table, and dropping one would change which event is timestamped. The single
  safe float moved `reg_ts_first_resp_release` from stage 7 to stage 1 and freed a Meter ALU in
  the deepest stage (4/4 -> 3/4) — retained, because a second deadline register needs exactly
  that at the next gate.
- **Negative probe:** collapsing the total-plus-subset counters naively is a hard compile error
  (`cannot share Counter ... not mutually exclusive`). The partition rewrite was mandatory, not
  stylistic. Both originals remain exactly recoverable:
  `ctr_arm == ctr_fresh[2] + ctr_fresh[3]`, `ctr_resp_release == ctr_deq[4] + ctr_deq[5]`.

## Control-plane item carried forward

`context.json` shows `ctr_fresh` (size 16) replicated across stages 0, 5, 6, 7 and `ctr_deq`
(size 8) across 5, 6, 7, each replica carrying the full index range at VPN 0. **Per-index
readback must aggregate across replicas**, and `operations_execute("SyncCounters")` is still
required or counters read 0. The baseline already used this construction for `ctr_bypass` across
2 stages and it passed on silicon; with four replicas it must be confirmed by bfrt readback.

---

# Phase 0 gate 3 — dual-release skeleton compile: FITS at 9 of 12

Independently re-verified from `p4/build_skeleton_9.13.1/pipe/logs/table_summary.log`:

```
Number of stages in table allocation: 9
  Number of stages for ingress table allocation: 9
  Number of stages for egress table allocation: 0
Critical path length through the table dependency graph: 8
Number of tables allocated: 81
```

`0 errors, 3 warnings` — byte-for-byte the same three benign warnings, no new one, and it
compiled on the first attempt. `research/defense2_pktgen/` and `case_a_stripped_baseline.p4`
both verified unmodified.

| Metric | stripped baseline | skeleton | delta |
|---|---|---|---|
| Ingress stages | 8 | **9** | +1 |
| Egress stages | 0 | 0 | — |
| Critical path | 8 | **8** | — |
| Logical tables | 57 | 81 | +24 |
| SRAM | 25 | 35 | +10 |
| Map RAM | 24 | 32 | +8 |
| TCAM | 1 | 2 | +1 |
| Meter ALU | 6 | 9 | +3 |
| Stats ALU | 6 | 7 | +1 |
| Gateways | 30 | 40 | +10 |
| PHV containers | 37 (16.5%) | 44 (19.6%) | +7 |
| PHV bits | 505 | 673 | +168 |
| Tagalong | 1128 b (55.1%) | 1120 b (54.7%) | -8 |

## The second deadline adds WIDTH, not DEPTH

Critical path stays at 8. `reg_d_ack`, `reg_d_resp`, `reg_ackc` and `reg_t_read` all land in
parallel in stage 4 (Meter ALU 4/4), and the two expiry tables land together in stage 5.

The 9th stage comes from a different constraint: the program stopped being dependency-bound and
became **logical-table-ID bound** — Tofino-1 has 16 logical table IDs per stage and the action
block saturates them.

| Logical TableIDs | stage 5 | stage 6 | stage 7 | stage 8 |
|---|---|---|---|---|
| baseline | 16/16 | 16/16 | 6/16 | — |
| skeleton | 16/16 | 16/16 | **16/16** | 10/16 |

The growth is action-block *breadth*: four queue actions instead of two, per-class blocker
loop/terminate structures instead of one, four more counter sites.

## Deferred work, MEASURED by probe compiles (not estimated)

| Probe | Change | Ingress | Critical path |
|---|---|---|---|
| — | the skeleton | **9** | 8 |
| A | delete `reg_t_read` (optional telemetry) | 9 | 8 |
| B | +6 escape-counter branches (terminal states B-H) | **10** | 8 |
| C | exact-predicate sketch (`reg_exp_ack`, `reg_exp_seq`, `reg_txn_state`, 3 extra ternary keys) | **10** | 8 |
| D | B + C + reverse-5-tuple `tbl_session` | **11** | 8 |

- Exact ACK + RESPONSE predicates: **≈ +1 stage**. The `0x3F` flags-mask tightening is
  parser-only and free; the expected-value registers sit in parallel with `reg_tag` and add no
  depth.
- Terminal-state escape counters: **≈ +1 stage** — expensive per unit of code precisely because
  the action block is already logical-table-ID saturated (6 extra counter leaves cost 7 logical
  tables, and 7 logical tables is one stage there).
- Runtime pass budgets as `tbl_guard` action parameters: **+0** (action data only).
- Multi-segment handling: not modelled, cost unknown.

**Honest bound: the skeleton fits at 9/12, and the deferred work measures 11/12 in a sketch that
is deliberately incomplete** (placeholder ack/seq arithmetic, stub one-shot, no segmentation).
Probe D bounds the estimate from below, so Phase 4 has roughly ONE stage of genuine margin. Do
not describe the fit as comfortable. If it goes over, the lever is not the registers — it is
collapsing action-block branches (merging counter leaves, or replacing per-class `if/else` chains
with a classify table whose actions carry the decode), the same lever that bought 10 -> 8.

## Two design decisions to carry forward

1. **`deadline_arm_once` could not be carried over literally**, because a READ-anchored design
   would have to disarm and re-arm the same register in one pass. Idempotency now comes from
   `reg_tag` instead: `tbl_state_decode` splits `CLASS_ARM` by `tag_diff` with the exact-zero
   (retransmit) pattern first, so a duplicate READ writes `DL_NO_WRITE` to both deadlines. That
   is the same `reg_tag` idempotency the baseline used to suppress a duplicate pktgen burst, so
   one test now suppresses the burst *and* pins both deadlines. The fail-safe is preserved: a
   never-written deadline register reads 0, giving an age whose low byte is `0x01`, which can
   never satisfy the expiry mask.

2. **`ack_committed_to_master` is written at level 4 from the packet CLASS**, not from an
   observed forwarding decision. Reviewed and accepted: the dequeued `ROLE_ACK` branch calls
   `to_fwd()` **unconditionally** — no guard, no stale check, no drop path — so there is no P4
   path that sets the state without forwarding the ACK. This matches design §4's own definition
   (committed to the master-facing FIFO, not transmitted on the wire).
   **Fragility to guard:** the invariant breaks silently if anyone later adds a drop or guard to
   that branch. Phase 5 must assert `ctr_deq[CD_ACK_COMMIT]` equals the number of
   `ack_committed_to_master` transitions.

## ⚠ Skeleton limitation — do not run this on hardware expecting keepalive safety

The skeleton's ACK admission is `ack_ok == 1 && ackc_diff != 0`, where `ack_ok` is still the
BASELINE's coarse qualification. The exact predicate (`tcp.seq == EXP_RELAY_SEQ`,
`tcp.ack_no == EXP_ACK`, the `0x3F` mask, one-shot `AWAITING_ACK`) is **deferred to Phase 4**, so
a keepalive arriving while a transaction is live and uncommitted **would still be captured**.
The skeleton is a resource-fit artifact only.
