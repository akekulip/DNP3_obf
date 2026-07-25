# Part 13 pre-work — stage dependency audit of the Part 12 program

Required by the Part 13 directive (§13) *before* adding DNP3 parsing. Off-switch, compile-only.
Subject: `ibspg_hold_response.p4` (Part 12, sha `fa073cf6`), local bf-p4c 9.13.1.

## Headline

**The program is serial-dependency-bound, not resource-bound, and the documented telemetry reclaim
lever buys nothing.** `[OBS]`

| measurement | value |
|---|---|
| ingress MAU stages | **12 / 12** (zero spare) |
| tables per stage | **exactly 1**, in all 12 stages |
| SRAM / TCAM / map RAM | 36 / **0** / 36 |
| **ingress parser states** | **2** |
| egress parser states | 6 |

Two things follow, and they point in opposite directions:

1. There is **no MAU headroom at all** — 12 stages each holding a single table, i.e. a 12-deep serial
   dependency chain. Nothing can be added *in front of* that chain for free.
2. There is **abundant parser headroom** — 2 ingress states used. DNP3 header extraction is nearly
   free in the parser; it is the *classification logic feeding the chain* that costs MAU stages.

## Measured: the telemetry reclaim lever does not work `[OBS]` `[FIX]`

The Part 11 and Part 12 compile notes both record a "reclaim lever held in reserve: drop
`reg_ts_first_block` (+ its event flag)". **Measured, it reclaims zero stages.**

```
variant_no_first_block.p4  (reg_ts_first_block, ts_first_block_w and ev_first_block fully removed)
bf-p4c 9.13.1 → EXIT=0, 0 errors
Number of stages for ingress table allocation: 12      <-- unchanged from 12
```

Artifacts: `stage_budget/variant_no_first_block.p4`, `stage_budget/compile.log`,
`stage_budget/out/pipe/logs/table_summary.log`.

**Superseding note:** the "drop a timestamp register to buy a stage" guidance in the Part 11/12 notes
is withdrawn *for this program*. It was inherited from Part 11 (where stage 12 was driven by Stats-ALU
counter density) and never re-measured for Part 12, whose last stage is reached by dependency depth
instead. Do not budget Part 13 against it.

## The chain, stage by stage `[OBS]`

From `table_dependency_summary.log`, mapping placed tables back to source lines:

| stage | source | what it does | load-bearing? |
|---:|---|---|---|
| 0 | 303–309 | classify: `dequeued`, `ts32`, `budget_zero` | yes — everything downstream reads these |
| 1 | 313 | ARM sets `gen`/`active`/`deadline` write drivers | yes |
| 2–3 | 319, 320 | `reg_gen` RMW, then `gen_mismatch` | yes — generation safety |
| 4 | 327 | `active` clear driver (stale/budget termination) | yes — fail-open |
| 5 | 332 | `reg_active` RMW | yes |
| 6 | 341 | ACK qualification (needs `active_now`) | yes — arming rule |
| 7 | 347 | `reg_deadline` RMW | yes — the deadline itself |
| 8 | 350, 351 | `dl_armed`, `age = now − deadline` | yes |
| 9 | `tbl_deadline_expiry` | ternary sign-bit expiry decision | yes |
| 9–10 | 359, 363 … | ACT block (queue assignment, forward, drop) | yes |
| 11 | ts bank | 4 timestamp registers | **telemetry** — but removing one frees no stage |

Every link in stages 0→9 is a genuine data dependency: each state register's write driver is computed
from the previous register's read. This is the Part 9/11 discipline (one RegisterAction, one
unconditional call site, driven by upstream metadata) and it is what makes the mechanism
generation-safe. **It must not be relaxed to save stages.**

## What Part 13 actually needs to add, and where it lands

| new work | natural home | MAU stage cost |
|---|---|---|
| DNP3 link/transport/application header extraction | **parser** (2 of many states used) | ~0 |
| function-code / direction / payload-length classification | parser select + gateways | low, but must land **before** stage 1 |
| `exp_ack = req.seq + req.payload_len` | action, early stage | ~1 if it cannot share stage 0 |
| `flow_id = CRC16(5-tuple)` | MAU Hash unit | ~1, and must precede the chain |
| admitted-flow → slot lookup | exact-match table | ~1, must precede the chain |

Naively that is **+2 to +3 stages ahead of a chain that already fills all 12** — the central Part 13
risk, now quantified rather than guessed.

## Recommended approach for Gate 13.2 `[DESIGN]`

1. **Push classification into the parser.** The measured 2-state ingress parser is the only real
   headroom the program has. Classify DNP3 role by parser `select` on the extracted function code and
   set metadata there, so the MAU sees a pre-computed role byte exactly like today's synthetic
   `hdr.ib.role` — which keeps the existing 12-stage chain *unchanged in shape*. This is the single
   most valuable structural move available.
2. **Keep one fixed slot for 13.2–13.7.** Parts 9, 11 and 12 all validated with a single synthetic
   slot. Deferring `flow_id` hashing and the slot-lookup table removes the two most expensive new
   stages, and multi-flow slot mapping becomes its own gate after the chain is known to fit.
3. **Do not pay for it out of** fail-open, generation safety, token isolation, or parser validation —
   the directive forbids it, and each is load-bearing per the table above.
4. If it still does not fit, isolate the exact dependency from `table_dependency_summary.log` before
   changing anything, and prefer restructuring mutually-exclusive paths (the Part-9-era fix that took
   a 17-deep chain down to 9) over deleting safety logic.

`[OPEN]` The +2/+3 estimate is an informed projection from the table above, not a compile result.
Gate 13.2's first compile is what converts it into a measurement.
