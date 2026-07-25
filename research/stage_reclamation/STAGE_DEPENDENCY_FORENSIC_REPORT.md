# WS1 — Stage dependency forensics: what actually sets the 12-stage ingress budget

Compile-only, local bf-p4c 9.13.1, no switch. Subject: Part 12 `ibspg_hold_response.p4`
(sha `fa073cf6`, 12/12 ingress stages, 0 egress) and the Part 13 candidate `ibspg_dnp3.p4`
(sha `ed72a474`, 11/12 ingress stages).

## Headline

**Ingress depth here is set by the HEAD of the serial chain, not by telemetry, not by counters, and
not by the tail.** Four measurements, each a real compile:

| variant | change | ingress stages |
|---|---|---:|
| P0 baseline | Part 12 unmodified | **12** |
| probe 1 | remove `reg_ts_first_block` (the "documented reclaim lever") | 12 |
| probe 2 | remove the **entire** timestamp bank — all 4 registers, all 4 call sites | **12** |
| probe 3 | remove 3 diagnostic counters (`ctr_arm`, `ctr_block_loop`, `ctr_ack_bypass`) | 12 |
| Part 13 | move classify metadata into the **PARSER** (and add full DNP3 parsing) | **11** |

Everything that deletes work from the *tail* saves nothing. The single change that saved a stage
*added* functionality and moved metadata production into the parser.

**Two pieces of inherited guidance are refuted by measurement and should not be planned against:**
- the Part 11/12 note's "drop `reg_ts_first_block` to reclaim a stage" — probe 1, `[FIX]`;
- the Part 11 note's "dropping 3 counters → 11/12" — probe 3 shows this does not transfer to Part 12,
  whose tail is not Stats-ALU bound in the way Part 11's was. `[FIX]`

## The Part 12 chain, stage by stage

From `table_dependency_summary.log` + `table_summary.log`, with placement ranges `[min,max]`. A range
of `[n,n]` means pinned; a wider range means the compiler had freedom and chose.

| stage | table (src line) | consumes | produces | next dependent | safety-critical? | movable? | removing it shortens the path? |
|---|---|---|---|---|---|---|---|
| 0 | `…307` **[0,0]** L307 | `ingress_port` | `meta.dequeued` | ARM drivers @1 | yes — role/direction | **yes → parser** | **YES — this is the one that works** |
| 0 | `…308` [0,0] L308 | `ingress_mac_tstamp` | `meta.ts32` | deadline math @8 | yes — the clock | partly (parser can carry it) | no (not the pin) |
| 0 | `…309` [0,3] L309 | `hdr.ib.seq` | `meta.budget_zero` | block term @10 | **yes — fail-open** | yes → parser | no |
| 1 | `…313` **[1,1]** L313 | `meta.dequeued`, `hdr.ib.gen` | gen/active/deadline write drivers | `reg_gen` @2 | yes — arm | no (must precede chain) | pinned *by* stage 0's `dequeued` |
| 2 | `…319` [2,2] L319 | write drivers | `meta.gen_now` | mismatch @3 | **yes — generation** | no | no |
| 3 | `…320` [3,3] L320 | `gen_now` | `meta.gen_mismatch` | active driver @4 | **yes — generation** | no | no |
| 4 | `…327` [4,4] L327 | `gen_mismatch`, `budget_zero` | active clear driver | `reg_active` @5 | **yes — fail-open** | no | no |
| 5 | `…332` [5,5] L332 | active driver | `meta.active_now` | ACK qualify @6 | yes | no | no |
| 6 | `…341` [6,6] L341 | `active_now`, slot, gen | `meta.ack_ok`, deadline write driver | `reg_deadline` @7 | **yes — arming rule** | no | no |
| 7 | `…347` [7,7] L347 | deadline driver | `meta.dl_now` | age/armed @8 | **yes — the deadline** | no | no |
| 8 | `…350/351` [8,8] | `dl_now`, `ts32` | `meta.age`, `meta.dl_armed` | expiry @9 | yes | no | no |
| 9 | `tbl_deadline_expiry` [9,9→10] | `age`, `dl_armed` | `meta.expired` | ACT | **yes — release decision** | no | no |
| 9–10 | ACT block (queue assign, forward, drop, term counters, budget decrement) | all of the above | TM decisions | egress | yes | no | no |
| 11 | ts bank + 2 counters, all `[10,11]`/`[11,11]` | event flags | telemetry only | — | **no** | yes → egress | **no — measured, probes 1–3** |

Stages **0–9 are genuinely dependency-bound**: each state register's write driver is computed from the
previous register's read. That serialization *is* the generation-safety property, and it must not be
relaxed to save stages. Stages **10–11 are packing outcomes**, not dependency requirements — with the
ts bank deleted, stage 11 still held only `[10,11]`-range tables, i.e. nothing was pinned there and
the allocator simply spread out.

## Why the parser offload works, precisely

In P0, `…313` (the ARM write-driver table) is pinned to stage 1 **because its gateway reads
`meta.dequeued`, produced by `…307` at stage 0** — a hard serial link at the very head of the chain.
Producing `dequeued` in the parser removes that producer/consumer edge: in the Part 13 candidate the
equivalent ARM table relaxes to `[0,3]`, co-resides in stage 0, and **every downstream link shifts up
one**, giving 11 stages *while also carrying a full DNP3 classifier*.

This is the general lever: **any metadata whose only consumer is a gateway near the head of the chain
should be produced in the parser, not in stage 0.** Candidates remaining in P0 by the same argument:
`meta.ts32` (needs care — it is the clock) and `meta.budget_zero` (a pure header test, easily a parser
`select`).

## Consequences for the other workstreams

- **WS3 (egress telemetry offload) cannot save an ingress stage.** Probe 2 deletes the entire ts bank —
  strictly more aggressive than moving it to egress — and the stage count does not move. Deletion is
  the upper bound on what any offload can buy, so the bound is zero. Egress offload may still be worth
  doing (it frees ingress SRAM/Stats-ALU headroom for DNP3 work and is architecturally cleaner), but it
  must not be claimed as a stage-reclamation lever. `[OPEN]` for the agent to confirm on its own
  variants.
- **WS2 (packed transaction state) is the remaining high-value lever**, because it attacks stages 2–8 —
  the part that genuinely is dependency-bound. Collapsing three serial RegisterActions into one is the
  only change that can shorten the *bound* portion of the chain.
- **Size co-residency (WS4/WS5)** should target the parser and egress, both of which are demonstrably
  outside the binding constraint (egress is 0 stages in P0 and buys nothing when loaded with telemetry).

## Evidence

`forensics/probe_no_block_term_ts.p4`, `probe_no_ts_bank.p4`, `probe_fewer_counters.p4`, each with its
compile log and `out/pipe/logs/`. Stage maps extracted from `table_dependency_summary.log`. The Part 13
comparison is from my own recompile of `ibspg_dnp3.p4`, not from its author's report.

`[OPEN]` Probes 1–3 are deletions, used to establish upper bounds on what removal can achieve. They are
forensic instruments and are **not** proposed variants — none of them is safe to ship, since probes 1–2
delete release-time evidence the gates depend on.
