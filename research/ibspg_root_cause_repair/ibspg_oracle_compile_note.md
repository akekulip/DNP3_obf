# ibspg_dequeue_oracle — compile note

Compile-only Tofino-1 (TNA) instrumentation that records, **on-chip and at
sub-microsecond resolution**, the ORDER in which packets dequeue from two TM
queues on an internal loopback port L. Built to replace ssh-polling (too coarse)
for the later strict-priority-ordering experiment. **Not run on hardware.**

- Compiler: `bf-p4c` from `bf-sde-9.13.1` (`/home/philip/bf-sde-9.13.1/install/bin`)
- Command:
  ```
  PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
    bf-p4c --target tofino --arch tna -g -o compile/out ibspg_dequeue_oracle.p4
  ```
- Result: **0 errors, 2 warnings** (both the benign compiler-inserted
  `min_parse_depth_accept_loop` unroll notice — no source issue).
- First-compile success — no placement iterations were needed (the placement
  discipline from prior builds was applied preemptively).

## Source provenance (sha256)

```
eeb6de94fa3f7059372fb60beebbbb6366c9c51b8bf7c1f873f92228313b6201  ibspg_dequeue_oracle.p4
83ad7c9e674321263687bd99634166e00db0bd32e3226a7090c18aff8dd84ef5  ibspg_trace_read.py
```

## Timestamp field used

`ig_intr_md.ingress_mac_tstamp[31:0]` — captured at the ingress MAC, i.e. the
instant the looped-back packet re-enters ingress right after dequeue, so it is
the best on-chip proxy for dequeue time. Nanosecond units on Tofino-1; the low
32 bits (~4.29 s span) are ample for a microbench and are what the trace array
`trace_ts` stores. `ig_prsr_md.global_tstamp[31:0]` would also have compiled;
`ingress_mac_tstamp` was chosen because it is captured earliest (closest to the
dequeue event). The reader computes per-event `dt = ts[i]-ts[i-1]` with a 32-bit
wrap mask.

## Ingress resource usage (from `compile/out/pipe/logs/resources.json`)

**Ingress stages used: 3** (of 12 physical). Egress is empty.

| Stage | SRAM | Map RAM | TCAM | SALU (Meter ALU) | Stats ALU | Gateways | Logical tables |
|------:|-----:|--------:|-----:|-----------------:|----------:|---------:|---------------:|
| 0     | 8    | 8       | 0    | 1                | 3         | 4        | 9              |
| 1     | 0    | 0       | 0    | 0                | 0         | 1        | 1              |
| 2     | 14   | 14      | 0    | 4                | 3         | 6        | 7              |
| **Σ** | **22** | **22** | **0** | **5**          | **6**     | **11**   | **17**         |

- **TCAM: 0** — no range/ternary match; all decisions are gateways / exact.
- **SALU (stateful/Meter ALU): 5** — matches the ~4-5 estimate exactly:
  - stage 0: `reg_event_ctr` (the monotonic event-index RMW)
  - stage 2: `trace_ts`, `trace_seq`, `trace_role`, `reg_overflow`
  - This is the load-bearing pattern: the event index is read in stage 0, then
    the three arrays are written at that **dynamic index** two stages later.
    The 2-stage gap is the natural read-then-index-write dependency; 3 of the 4
    stage-2 Meter ALUs are the trace-array writes (well within the 4-per-stage
    budget).
- **Stats ALU: 6** — the six PACKETS counters:
  - stage 0: `ctr_block_enq`, `ctr_hold_enq`, `ctr_nonibspg`
  - stage 2: `ctr_trace_overflow`, `ctr_block_deq`, `ctr_hold_deq`
- **SRAM / Map RAM: 22 each** — almost all is stateful register storage (each
  trace array = 2 SRAM + 2 map RAM units; counters + event/overflow registers
  make up the rest). Tiny absolute footprint.

## PHV (from `phv_allocation_summary_0.log`)

- **MAU-group containers used: 15 (6.7 %)**; bits used **199 / 4096 (4.86 %)**,
  of which **186 ingress / 13 egress**.
- `pa.characterize.log` "Containers used: 41" includes tagalong/POV/parser
  containers; the 15-container MAU figure is the meaningful pressure number.
- PHV allocation succeeded; there is no PHV pressure.

## Placement fixes applied preemptively (why it compiled first try)

None were needed *reactively*, but these were built in from the start (from the
register/table-placement-fit lessons of prior dcrn/queue builds):

1. **One RegisterAction per register, each executed at most once per packet.**
   Every register (`reg_event_ctr`, `reg_overflow`, `trace_role/seq/ts`) has a
   single RegisterAction and a single call site.
2. **The three trace writes are each in their own guarded `if` block**
   (`if (meta.in_range==1) { trace_X_w.execute(...); }`) so the compiler places
   the three SALUs independently rather than bundling them into one action.
3. **The only 32-bit magnitude compare (`ev < TRACE_LEN`) is an isolated gateway**
   that just sets an 8-bit `in_range` flag; every downstream gate is then a cheap
   8-bit equality — keeps the gateway predicate well under the 44-bit budget
   (constraint class 1).
4. **All flags widened to `bit<8>`** (`in_range`) — constraint class 3
   (sub-byte fields next to 32-bit register outputs invite SuperCluster
   failures).
5. **Saturating event counter** (`if (v < TRACE_LEN) v = v+1`) caps at
   TRACE_LEN=512 so an over-long run reads back a well-defined overflow instead
   of wrapping the index; it is a magnitude compare, not the class-8 `v==0`
   sentinel, so it is safe.

## What the trace means (for the reader / later run)

- Fresh host packet (`ingress_port != PORT_L`) → enqueued to its queue on
  PORT_L (BLOCK→qid7, HOLD→qid1), `bypass_egress=1`.
- Looped-back packet (`ingress_port == PORT_L`) → it just dequeued → stamped
  into `trace_role/seq/ts[evt_idx]` and dropped (single pass, never re-enqueued).
- So `trace_role[0..event_ctr-1]` in index order **is the dequeue order**.
  `ibspg_trace_read.py` prints it as e.g. `BLOCK BLOCK ... HOLD` and reports
  whether any HOLD preceded the last BLOCK (i.e. whether strict priority was
  absolute).

## Constants (pinned by the run, recompile to change)

`PORT_L=9w8` (dev_port 8, pipe 0), `PORT_VISION=9w9`, `PORT_HULK=9w11`,
`QID_BLOCK=5w7`, `QID_HOLD=5w1`, `TRACE_LEN=512`. Roles: BLOCK=1 (ethertype
0x88C1), HOLD=2 (0x88C0); roles 3/4/6 reserved (dropped for now).
