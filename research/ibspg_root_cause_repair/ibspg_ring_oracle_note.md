# ibspg_ring_oracle — compile + reader note

Compile-only extension of the on-chip TM dequeue-ORDER oracle. Adds a
control-plane-selectable **RING mode** (BLOCK tokens self-replenish) and a reader
that analyses inter-dequeue timestamp gaps. **No hardware was touched** — this is
a `bf-p4c` compile + a `py_compile` lint only. `bf_switchd` was not started, no
program was loaded, no bfrt session was opened.

## Files

| file | sha256 |
|---|---|
| `ibspg_dequeue_oracle.p4` (source copied + extended, UNCHANGED) | `eeb6de94fa3f7059372fb60beebbbb6366c9c51b8bf7c1f873f92228313b6201` |
| `ibspg_ring_oracle.p4` (new) | `1452f0256229f18bc91fb95b9d1de8b24c02dd48da1c835786ea4ffebb5e78c5` |
| `ibspg_trace_read2.py` (new reader) | `5e7b6274521863b969141100778da920c3fb003d5c7cf5606cee59858ecd6b11` |

## Compile

```
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o compile_ring/out ibspg_ring_oracle.p4
```

**Result: 0 errors, 2 warnings** (both are the benign default
`min_parse_depth_accept_loop will be unrolled` parser-loop notices that the
baseline oracle also emits; not related to this program's logic).

## Resource table (Tofino-1, bf-p4c 9.13.1)

| metric | ring oracle | baseline oracle (for reference) |
|---|---|---|
| ingress stages used | **4** (stages 0–3) | 3 |
| egress stages | 0 (egress control empty) | 0 |
| SALU (Meter ALU / RegisterActions) | **6** | 5 |
| Stats ALU (counters) | **8** | 6 |
| SRAM | **28** | 22 |
| Map RAM | 28 | 22 |
| TCAM | **0** | 0 |
| Gateways | 14 | — |
| VLIW instr | 11 | — |
| PHV containers | **17** (8b:9, 16b:4, 32b:4) | 15 |

SALU placement (Meter ALU): **stage 0** = `reg_event_ctr` + `reg_mode` (2), **stage 2**
= `trace_role` + `trace_seq` + `trace_ts` + `reg_overflow` (4). Stats ALU placement:
stage 0 = `ctr_block_enq`, `ctr_hold_enq`, `ctr_nonibspg`; stage 2 = `ctr_block_deq`,
`ctr_block_expiry`, `ctr_block_loop`, `ctr_hold_deq`; stage 3 = `ctr_trace_overflow`.

The trace core (`reg_event_ctr`, `reg_overflow`, `trace_role/seq/ts`, the in-range
guard, one-RegisterAction-per-register discipline) is **byte-identical** to
`ibspg_dequeue_oracle.p4`. The extra ingress stage (stage 3, cheap: 2 SRAM + 1
Stats ALU) appears because the RING decision chain — record `trace_seq` (stage 2) →
`seq -= 1` → `to_block()` — adds a read-then-write dependency on `hdr.ib.seq`, and
`ctr_trace_overflow` is pushed one stage later. Still 4/12 ingress stages, ample
headroom.

## New counters (exact names, all single-entry PACKETS counters)

| counter | fires when |
|---|---|
| `ctr_block_loop` | a RING BLOCK token dequeued with budget remaining → re-enqueued to Q_BLOCK (one per loop pass) |
| `ctr_block_expiry` | a BLOCK token dequeued with `seq == 0` → budget exhausted, dropped (RING termination) |

Existing counters kept: `ctr_block_enq`, `ctr_hold_enq`, `ctr_block_deq`,
`ctr_hold_deq`, `ctr_trace_overflow`, `ctr_nonibspg`. Total 8.

Semantic note (FINITE mode is preserved): with `reg_mode == 0`, a dequeued BLOCK
always takes the drop branch and increments `ctr_block_deq` (or `ctr_block_expiry`
if the injected `seq` was 0), HOLD increments `ctr_hold_deq`, single pass, no
re-enqueue — identical dequeue-order semantics to the baseline oracle. The only
difference past 512 events (trace overflow) is that the ring oracle still runs the
drop-vs-loop / counter block, whereas the baseline stopped at the overflow tally;
on a normal sub-512 run the two are indistinguishable. The reader's
`ctr_block_deq + ctr_hold_deq == event_ctr` invariant from the original reader is
NOT enforced here because in RING mode loop passes are recorded as events but do
not increment the deq counters.

## How `reg_mode` is set (control plane)

`reg_mode` is a 1-entry `Register<bit<8>, bit<1>>` read once per dequeued packet by
a read-only RegisterAction. Default value is 0 (FINITE). To switch to RING, the
control plane writes index 0 to 1. bfrt idiom (run on the switch, all-pipes or the
loopback pipe):

- **bfrt table name:** `pipe.Ingress.reg_mode`
- **key:** `$REGISTER_INDEX = 0`
- **data field:** the register's single field (`Ingress.reg_mode.f1`) — set to `1`
  for RING, `0` for FINITE.

```python
import bfrt_grpc.client as gc
t = bi.table_get("pipe.Ingress.reg_mode")
tgt = gc.Target(device_id=0, pipe_id=0xffff)   # all pipes; loopback L = dev_port 8 = pipe 0
key  = t.make_key([gc.KeyTuple("$REGISTER_INDEX", 0)])
data = t.make_data([gc.DataTuple("Ingress.reg_mode.f1", 1)])   # 1 = RING, 0 = FINITE
t.entry_add(tgt, [key], [data])
```

(If the SDE rejects the fully-qualified field name, use the short field name
`reg_mode.f1`; the reader's `_get_table` / `_flatten_max` helpers already tolerate
both the `Ingress.<reg>.f1` and `<reg>.f1` spellings.)

## Reader (`ibspg_trace_read2.py`)

`py_compile`-clean on python3 and python3.8. Reads `reg_event_ctr`, `reg_overflow`
and all 8 counters, dumps `trace_role/seq/ts[0..event_ctr-1]` decoded
(1→BLOCK/B, 2→HOLD/H), and does the timestamp-gap analysis:

- `dt[i] = (ts[i] - ts[i-1]) & 0xffffffff` (unsigned 32-bit wrap-safe);
- prints event count, min/mean/median/p95/max dt, a log-scale histogram;
- flags **large gaps** (`dt > large_mult × median`, default 3×, with a near-zero-median
  fallback to `3× mean` then `1`) as empty-gaps, annotating a gap after a BLOCK
  dequeue as "Q_BLOCK went EMPTY"; reports the large-gap count and the max gap (ns,
  since `ingress_mac_tstamp` is ns on TF1);
- reports the longest contiguous run of small dt (continuous backlog).

**Counter-read fix:** both registers and counters are read with
`gc.Target(device_id=0, pipe_id=0xffff)` (all pipes) + `$REGISTER_INDEX` /
`$COUNTER_INDEX`, and the per-pipe list result is collapsed to the live value. The
original `ibspg_trace_read.py` read counters with a pipe-scoped target (`pipe_id=0`)
which returned "Entry not found"; the all-pipes target resolves it.

Fails loudly (nonzero exit) on: bind failure (2), `reg_overflow > 0` (3),
`event_ctr == 0` (4). The gap math is validated by a synthetic-trace self-test
(empty-gap detection, 32-bit wrap, longest-small-run, near-zero-median fallback —
all pass).

## Hardware statement

No switch, `bf_switchd`, bfrt session, or Hulk/Vision host was touched. This task
ran `bf-p4c` (offline compiler) and `py_compile` only. The reader is written to run
on the switch **later**, under explicit authorization.
