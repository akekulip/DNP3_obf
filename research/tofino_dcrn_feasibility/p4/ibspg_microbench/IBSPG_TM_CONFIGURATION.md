# IBSPG microbench — static TM configuration (Part 1)

All TM configuration is installed **once at initialization**; **no per-transaction control-plane
operation** occurs during a run. The bfrt idioms below are copied from the proven
`queue_microbench_setup.py` on this exact SDE (9.13.2 on-switch / 9.13.1 local), so the
strict-priority primitive reuses a construction already demonstrated to starve LOW with HIGH on
this silicon.

## 0. Ports (MEASURE before any silicon run — do not trust the stated mapping)

| Symbol | Role | dev_port | How fixed |
|---|---|---|---|
| `PORT_VISION` | master-facing (protected) | **dp9** per direction | **measure**: per-port RX while pinging Vision |
| `PORT_HULK` | outstation-facing (protected) | **dp11** per direction | **measure**: per-port RX while pinging Hulk |
| `PORT_L` | internal loopback (blocker ring + hold) | **dp68 recirc (primary)** | internal; no cable |

The GATE-1 lesson is binding: a stated host↔port mapping was previously inverted. Before Part 4,
read `tf1.tm.counter.eg_port` / `$PORT_STAT` RX per dev_port while generating a known probe from
each host, and pin `PORT_VISION`/`PORT_HULK` to the measured ports (recompile the P4 constants if
they differ). `PORT_L` is internal and needs no measurement, but its strict-priority behavior is
itself under test (Part 4).

### Loopback port L — primary and fallback

- **Primary: pipe-0 recirc `dp68`.** Fully internal (no host link to disturb), byte-preserving
  (the deparsed frame re-ingresses unchanged — same mechanism the frozen recirc-hold used),
  already recirc-capable. Enable exactly as queue_microbench does:
  ```python
  pc = bi.table_dict["tf1.pktgen.port_cfg"]
  pc.entry_mod(tgt, [gc.KeyTuple("dev_port", 68)],
      [pc.make_data([gc.DataTuple("pktgen_enable", bool_val=True),       # only if pktgen-seeding
                     gc.DataTuple("recirculation_enable", bool_val=True)])])
  ```
  Port-group for dp68: `pg_id=17, pg_port_nr=0` → `pg_queue = 0*8 + qid`.
- **Fallback: a confirmed-free physical port in MAC-near loopback** (strict priority is *proven*
  on a physical port — dp9 HIGH starved LOW in queue_microbench). Idiom from `dp8_loopback.py`
  (delete then re-add with loopback at creation — a live entry rejects the mode change):
  ```python
  port.entry_del(tgt, [port.make_key([gc.KeyTuple("$DEV_PORT", P)])])
  port.entry_add(tgt, [port.make_key([gc.KeyTuple("$DEV_PORT", P)])],
      [port.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                       gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                       gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
                       gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_MAC_NEAR"),
                       gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
  ```
  Selected only if Part 4 shows recirc-port strict priority does not fully starve Q_HOLD.

## 1. Queues on port L

| Queue | qid (P4 `ig_tm_md.qid`) | strict priority | purpose |
|---|---|---|---|
| **Q_BLOCK** | `7` | **HIGH** | continuously-occupied internal blocker ring |
| **Q_HOLD** | `1` | **LOW** | the held REAL packet, queue-resident |

`pg_queue = pg_port_nr*8 + qid`. On dp68 (pg_port_nr=0): Q_BLOCK→`pgq=7`, Q_HOLD→`pgq=1`, `pg_id=17`.

## 2. Strict-priority scheduling (the primitive under test) — install once

Exactly the `queue_microbench_setup.py` idiom (`tf1.tm.queue.sched_cfg`, verified by readback;
`min_priority` reads back `'7'` for HIGH, `'LOW'` for LOW on this SDE):

```python
tgt0  = gc.Target(device_id=0, pipe_id=0)                 # TM tables use pipe 0
q_cfg = bi.table_get("tf1.tm.queue.sched_cfg")
PG_L  = 17                                                 # dp68 port-group

def set_pri(qid, pri):                                     # pri = "HIGH" | "LOW"
    pgq = 0*8 + qid
    q_cfg.entry_mod(tgt0,
        [q_cfg.make_key([gc.KeyTuple("pg_id", PG_L), gc.KeyTuple("pg_queue", pgq)])],
        [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                          gc.DataTuple("min_priority", str_val=pri)])])

set_pri(7, "HIGH")     # Q_BLOCK
set_pri(1, "LOW")      # Q_HOLD
# MANDATORY readback (queue_microbench discipline): re-read both and assert '7'/'LOW'.
```

## 3. Shaping — off by default; variant C only

Baseline (variants A/B): **no shaper** on Q_BLOCK or Q_HOLD (pure strict priority). Variant C adds
a Q_BLOCK max-rate shaper *only* to test whether a shaped, persistently-backlogged blocker keeps
`dequeue_rate < loopback_replenish_rate`. Idiom (PPS/UPPER, from queue_microbench dp68 HOLD cap):
```python
q_shape = bi.table_get("tf1.tm.queue.sched_shaping")
q_shape.entry_mod(tgt0, [q_shape.make_key([gc.KeyTuple("pg_id",17),gc.KeyTuple("pg_queue",7)])],
    [q_shape.make_data([gc.DataTuple("unit", str_val="PPS"),
                        gc.DataTuple("provisioning", str_val="UPPER"),
                        gc.DataTuple("max_rate", val=BLOCK_SHAPE_PPS),
                        gc.DataTuple("max_burst_size", val=16384)])])
q_cfg.entry_mod(... qid 7 ..., [scheduling_enable=True, max_rate_enable=True])
```

## 4. Queue depth / buffer

No explicit pool/depth carving exists in the harness (only `max_burst_size=16384` cells on shaping
entries). The microbench uses default queue buffering and *reads* `usage_cells`/`watermark_cells`.
Same here: default depth; occupancy is measured, not carved. Flagged as a limitation if Q_BLOCK
overflow (token drop) is observed — then a depth/backlog cap is added and documented.

## 5. Internal blocker-token marker (visibility, Part 7)

- **BLOCKER_TOKEN** frames use ethertype **`0x88C1`** (distinct from `0x88C0` used by
  HELD/DRAIN/ARM) and a reserved source MAC **`02:00:00:00:0B:0C`**. Either alone unambiguously
  identifies a token in a capture.
- **Evidentiary bar:** capture on `PORT_VISION` and `PORT_HULK` for the whole run must show
  **zero** frames matching `ether proto 0x88C1` (or that src MAC); dp9/dp11 TX == REAL count
  exactly; the loopback port's counters carry the token traffic. Any token on a protected port is a
  test FAIL, not relabeled (per `INTERNAL_TOKEN_THREAT_AND_VISIBILITY_MODEL.md`).

## 6. Blocker seeding (once)

- **Primary — Tofino pktgen one-shot on dp68** (on-chip origin → zero external footprint): a
  one-shot app emits N token frames (ethertype 0x88C1, role=BLOCKER, slot, gen) into the pipe; the
  P4 routes them to Q_BLOCK; they self-loop until drained. Uses `tf1.pktgen.{pkt_buffer,app_cfg}`
  as in queue_microbench (`trigger_timer_periodic` → here a one-shot batch; account for the 6-byte
  pktgen dst-MAC prepend in the template).
- **Fallback — one-time host seed:** N token frames sent once from a host; they enter the ring and
  never egress a protected port thereafter. (A one-time *inbound* seed is not an egress-visibility
  violation, but pktgen is preferred for zero external footprint.)

## 7. Registers / state at init

`reg_gen[slot]`, `reg_drain[slot]` initialize to 0 (P4 `Register(..., 0)`). Slot arming is a
data-plane ARM frame (role=6), not a control-plane write. First prototype drives fixed slot 0.

## 8. Restoration (MANDATORY after every hardware experiment)

The microbench conf is the restore target. Procedure (from `GATE_C_AND_ROLLBACK.md`):
```bash
sudo pkill -x bf_switchd
sudo nohup bash /home/decps/queue_microbench/launch_mb.sh &     # restores queue_microbench_abs.conf
sleep 18                                                        # cold init
pgrep -x bf_switchd >/dev/null && echo UP || echo DOWN
tr '\0' ' ' < /proc/$(pgrep -x bf_switchd|head -1)/cmdline | grep -o 'conf-file [^ ]*'   # expect queue_microbench_abs.conf
```
Verify: exactly one bf_switchd; Vision `10.10.54.19` (retains `192.168.10.1`); Hulk `10.10.54.158`;
no residual pktgen app / blocker ring / capture / probe process; loopback port restored to
`BF_LPBK_NONE` if the physical fallback was used.

## Summary of the one-time init sequence

1. (measure & pin PORT_VISION/PORT_HULK) → 2. enable dp68 recirc (+pktgen if seeding on-chip) →
3. `set_pri(Q_BLOCK,HIGH)`, `set_pri(Q_HOLD,LOW)` + readback → 4. (variant C only) Q_BLOCK shaper →
5. seed N blocker tokens → 6. run experiment → 7. **restore**.
