# Phase 0 gate 2 — stripped-baseline compile iterations

Local `bf-p4c 9.13.1` (`p4c 9.13.1 (SHA: e558d01)`, `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c`)
on this host. **No switch was touched, no ssh, no `bf_switchd` restart.**

Deliverable: `research/case_a_read_anchored_dual_release/p4/case_a_stripped_baseline.p4`
Canonical build: `.../p4/build_stripped_9.13.1/`, log `.../p4/build_stripped_9.13.1_compile.log`

Every number below is read out of the compiler's own
`pipe/logs/table_summary.log` and `pipe/logs/mau.resources.log`. Nothing is estimated.

---

## Baseline reproduction (control)

The frozen source was recompiled read-only into a scratch directory to confirm the
recorded Phase-0 evidence is reproducible on this host and that the comparison is
apples-to-apples:

```
bf-p4c ... research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4
-> 0 errors, 3 warnings
-> stages 10 ingress / 0 egress, 70 tables, critical path 8
```

Identical to `baseline_table_summary.log`. The frozen tree itself was not modified
(`git status --porcelain research/defense2_pktgen/` is empty).

---

## Iteration 1 — remove the G-selection guard, collapse the counters

Both levers applied at once:

* removed `reg_native_clrt`, `reg_protection`, `reg_t_ack` (+ all their RegisterActions),
  `tbl_clrt_guard`, `tbl_build_clrt_diff`, the four `ctr_response_*` counters, the four
  metadata fields that became unused, and the G-guard tail of the ingress `apply`;
* collapsed the 16 surviving counter **objects** into two indexed arrays
  `ctr_fresh` (16 slots) and `ctr_deq` (8 slots), addressed with compile-time constants.

**Result: 0 errors on the first attempt.** No fix required.

```
stages 8 ingress / 0 egress, 58 tables, critical path 8
```

3 warnings, all three identical to the baseline's (the deliberate
`uninitialized_out_param` on `meta` — the parser write-once idiom — and two
`max_loop_depth` unroll notices). No new warning was introduced.

---

## Iteration 2 — the timestamp-predicate float (the "TRY" lever)

The four write-if-zero timestamp registers are each pinned one stage below whatever
writes their `ev_*` flag. The lever was to re-express those predicates in fields the
**parser** already produced (`dequeued`, `role`, `dir`, `is_pktgen`), which are live at
stage 0.

Auditing the four predicates against the code, **only one is exactly expressible that
way**:

| flag | full predicate | parser-only? | verdict |
|---|---|---|---|
| `ev_resp_release` | `dequeued==1 && role==ROLE_RESP` | **yes** — the dequeued `ROLE_RESP` branch sets it unconditionally | floated |
| `ev_first_block` | `dequeued==0 && role==ROLE_BLOCK && (is_pktgen==0 \|\| txn_active==1)` | no — `txn_active` comes from `reg_tag` (stage 3) | **left alone** |
| `ev_ack_arm` | `dequeued==0 && role==ROLE_ACK && ack_ok==1` | no — `ack_ok` comes from `tbl_state_decode` (stage 3) | **left alone** |
| `ev_block_term` | `dequeued==1 && role==ROLE_BLOCK && (tag_ok==0 \|\| expired \|\| budget_zero)` | no — `expired` comes from `tbl_deadline_expiry` (stage 5) | **left alone** |

Dropping the MAU-derived conjunct from any of the other three **would change behaviour**:
`ev_first_block` would timestamp a token that was *dropped* for having no active
transaction; `ev_ack_arm` would timestamp a *non-qualifying* ACK and destroy the
`G_observed` measurement; `ev_block_term` would timestamp a token that kept looping. Per
the instruction, they were not touched.

`ev_resp_release` was floated. Compiled: **0 errors**.

```
stages 8 ingress / 0 egress, 57 tables, critical path 8
Ingress.reg_ts_first_resp_release : stage 7 -> stage 1
stage-7 Meter ALU : 4/4 -> 3/4
```

**This lever did NOT free a stage.** It freed one Meter ALU in the deepest stage and one
logical table. Recorded as such rather than presented as a stage win.

---

## Why 8 and not 7 — the floor is the dependency chain, not a resource

`table_summary.log` for the final build reports `Critical path length through the table
dependency graph: 8`, and the placement is exactly 8 stages — i.e. the program is **at
its dependency floor**, not resource-limited. The chain is:

```
stage 0  tag_val driver (cond block)
stage 1  tbl_build_now
stage 2  reg_tag            -> meta.tag_diff
stage 3  tbl_state_decode   -> meta.dl_val / meta.ack_ok / meta.tag_ok
stage 4  reg_deadline       -> meta.age
stage 5  tbl_deadline_expiry-> meta.expired
stage 6  blocker-termination branch -> meta.ev_block_term
stage 7  ts_block_term_w / ts_first_block_w
```

The two tables that hold the last stage open are the `ts_first_block_w` and
`ts_block_term_w` call sites, both reported with **min-stage 7**. Their predicates are
the two that cannot be floated (they need `txn_active` and `expired`). Reaching 7 stages
would require either deleting on-chip timestamps — which design §13 explicitly forbids,
because the ACK is held and the relay leg is untappable, so these registers are the only
possible measurement of the hold — or restructuring the deadline/termination dependency
chain, which is out of scope for a deletion pass.

**Honest statement: the stripped baseline is 8 ingress stages. It is not 7.**

---

## Attribution probe A — how much does each lever buy?

Strip the G-guard but keep all 16 individual counter objects
(`probeA_striponly.p4`, scratch build):

```
0 errors -> stages 9 ingress / 0 egress, 58 tables, critical path 8
```

| variant | ingress stages |
|---|---|
| frozen baseline | 10 |
| strip only (G-guard removed, 16 counter objects kept) | 9 |
| strip + counter collapse | **8** |
| strip + collapse + ts float | **8** |

So the two stages are one each: removing the G-guard retires stage 9, and collapsing the
counter objects retires the stage that existed only because Stats-ALU occupancy is
charged per *(counter object, stage)* pair and five consecutive stages sat at 4/4.

---

## Negative probe B — the counter collapse is NOT free-form (hard compile error)

Two of the surviving counters were a *total plus a subset*: `ctr_arm` counted every
forwarded READ while `ctr_arm_clone` counted the fresh subset, and `ctr_resp_release`
counted every release while `ctr_release_deadline`/`ctr_release_fail_open` split it.
Collapsing those naively — keeping the total and the subset as two `count()` sites on the
**same** array, both reachable by one packet — was tested and **fails**:

```
probeB_double_count.p4(966): [--Werror=legacy] error: table tbl_probeB_double_count966
and table tbl_probeB_double_count963 cannot share Counter Ingress.ctr_fresh because use
of the Counter Ingress.ctr_fresh is not mutually exclusive
1 error, 3 warnings generated.
Skipping assembler, assembly file is empty
```

**Rule learned:** all `count()` sites on one Counter object must be mutually exclusive per
packet. This is why both totals were re-expressed as mutually exclusive **partitions**
in the deliverable, with the originals exactly recoverable by addition:

```
ctr_arm          == ctr_fresh[CF_ARM_FRESH] + ctr_fresh[CF_ARM_DUP]
ctr_resp_release == ctr_deq[CD_RELEASE_DEADLINE] + ctr_deq[CD_RELEASE_FAILOPEN]
```

---

## Control-plane consequence to verify before any load

`context.json` shows the collapsed counters are **replicated per stage**, each replica
carrying the full index range at VPN 0:

```
Ingress.ctr_fresh (statistics, size 16) : stage_tables at stages 0, 5, 6, 7   (vpn [0] each)
Ingress.ctr_deq   (statistics, size 8)  : stage_tables at stages 5, 6, 7      (vpn [0] each)
```

This is the same construction the frozen baseline already used for `ctr_bypass` (2
stages, VPN 0 each), which was exercised in the silicon campaign — so it is the
baseline's own proven idiom rather than a new one. It is nonetheless the one behaviour
worth confirming on a bfrt readback before the next gate: a per-index read must aggregate
across stage replicas. Remember `operations_execute("SyncCounters")` is still required —
a P4 Counter reads 0 without it.
