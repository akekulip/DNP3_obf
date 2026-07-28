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
