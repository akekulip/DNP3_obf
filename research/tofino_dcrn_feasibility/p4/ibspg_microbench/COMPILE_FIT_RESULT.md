# IBSPG microbench — compile-only fit result (Part 2)

**Status: COMPILED — local bf-p4c 9.13.1 fit PASS. Not yet compiled on-switch (9.13.2), not yet
configured, not yet tested on silicon.**

## Build

- Source: `p4/ibspg_mb.p4`  sha256 `6baecac9c336b3c8ad1a80fa0d751230f0313cc900b08084437f46a947f9cc68`
  (PORT_L=68 recirc; HELD routed purely by the drain bit — no ingress-port dependency, so on-chip
  pktgen stimulus on the recirc port works; **6/12 ingress stages** after this simplification)
- Compiler: `p4c 9.13.1 (SHA: e558d01)`  (`/home/philip/bf-sde-9.13.1`, host gambit)
- Command (identical idiom to `queue_microbench`):
  ```bash
  PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
    bf-p4c --target tofino --arch tna -g -o compile/out ibspg_mb.p4
  ```
- Result: **0 errors, 2 warnings** (both benign `min_parse_depth_accept_loop` unroll pragmas — same
  as queue_microbench). Assembly generated and placed (`compile/out/pipe/ibspg_mb.bfa`, 46 KB).

## Resource usage (from `compile/out/pipe/logs/`)

| Resource | Used | TF1 budget | Note |
|---|---|---|---|
| Ingress stages | **6 / 12** | 12 | simplified drain-only HELD routing |
| Egress stages | **0** | 12 | egress bypassed (`bypass_egress=1`), pass-through |
| Logical tables | 27 | — | mostly gateways + action tables |
| SRAM blocks | 22 | 48/stage pool | counters + register RAM |
| TCAM | 0 | — | no ternary match |
| **Stateful ALU (Meter ALU)** | **2** | 4/stage | exactly `reg_drain` + `reg_gen` — one stateful table each |
| **Stats ALU** | **9** | 4/stage | exactly the 9 event counters |
| PHV | tiny (~15 containers) | 4096 bits | negligible |
| Ingress parser TCAM rows | 4 | — | eth + ibspg_h only |

On-switch bf-p4c 9.13.2 (decps@10.10.54.81): **identical — 6/12 ingress, 0 egress, 0 errors**, same
source sha256. No 9.13.2 drift. Loadable artifacts (bfrt.json, ibspg_mb_abs.conf, pipe/tofino.bin,
pipe/context.json) staged at `/home/decps/ibspg_mb/build_9132/`; launch via
`/home/decps/ibspg_mb/launch_ibspg.sh`.

Per-stage SALU/Stats: stage0 Stats=1; stage2 SALU=1 (`reg_gen`); stage4 SALU=1 (`reg_drain`),
Stats=4; stage5 Stats=4; stage6 Stats=1. The design's central constraint — **one stateful table
per register, executed once per packet with a predicated write** — is confirmed by SALU=2 (not the
4–5 that the naive multi-branch access produced, which failed placement).

## What this fit does and does NOT establish

- **DOES:** the IBSPG datapath (role classify → gen arm/read → drain read-modify-write → qid
  assignment to Q_BLOCK/Q_HOLD on port L → drain-gated release / re-hold) is expressible on
  Tofino-1 and fits comfortably (7/12 stages, 2 SALU). Ample headroom for the DNP3-integration phase.
- **DOES NOT:** say anything about whether strict priority actually starves Q_HOLD, whether the
  blocker ring stays gap-free, or whether drain releases the held packet. Those are **silicon**
  questions (Parts 4–10). Compilation is necessary, not sufficient.

## Fixes made during bring-up (recorded for reproducibility)

1. Register/counter index "too complex" → use a plain `bit<2>` metadata slice `hdr.ib.slot[1:0]`
   as the array index (NUM_SLOTS=4), not a masked expression.
2. Table placement could not co-locate 4 `reg_drain` RegisterActions → consolidated to **one**
   read-modify-write RegisterAction per register with a predicated write driven by pre-computed
   metadata flags (`drain_write`/`drain_val`, `is_arm`). SALU dropped to 2.
3. Ternary assignment inside an action ("conditions in an action must be simple comparisons") →
   set the metadata flag via a gateway `if` instead of `?:`.
