# Four-queue oracle — pre-flight reconnaissance

2026-07-28, read-only. Switch confirmed running the proven Defense 2 program, exactly one
`bf_switchd`, conf `/home/decps/defense2_pktgen_compile/pktgen_abs.conf`.

## Hardware supports every requirement of the oracle

Verified in the switch's own `bf_rt_tm_tf1.json`:

| Need | Table / field |
|---|---|
| Preload / release control | `tf1.tm.queue.sched_cfg` → **`scheduling_enable`** |
| "occupancy > 0" evidence | `tf1.tm.counter.queue` → **`usage_cells`**, **`watermark_cells`** |
| "zero queue drops" | `tf1.tm.counter.queue` → **`drop_count_packets`** |

Keys are `pg_id`,`pg_queue`; dp8 maps to `pg_id=2, pg_port_nr=0` (read from hardware earlier this
session), so the four oracle queues are `pg_queue` 7/6/5/4.

## ⚠ dp11 (Hulk) is NOT configured — this is why Hulk's NIC is dark

`$PORT` readback on the running program — **only three ports are configured**:

| dp | up | enable | speed |
|---|---|---|---|
| 8 (loopback) | True | True | 25G |
| 9 (Vision) | True | True | 25G |
| 64 (relay) | True | True | 1G |

dp11 has no entry at all. Correspondingly, on Hulk `enp59s0f0np0` reads
`DOWN ... <NO-CARRIER,BROADCAST,MULTICAST,UP>` (MAC `3c:fd:fe:e5:f9:90`).

**This is a missing port configuration, not a dead link.** The oracle's own setup script must add
dp11 at 25G; Hulk's NIC should then come up. Prior work (IBSPG Parts 9/11, the shadow classifier)
used dp11↔Hulk, so the cable is expected to be present.

**Contingency if dp11 does not link after configuration:** fall back to injecting and capturing on
dp9 (Vision) with the oracle EtherType `0x88C2`, which still never reaches the relay because the
oracle P4 has no path to dp64. Record the deviation prominently — it is weaker isolation than the
Hulk-only path and must not be glossed.

## Access facts (corrected)

Lab hosts are reached as **`decps@`**, not `philip@` (`philip@10.10.54.158` → permission denied).
Hulk has `tcpdump` and `python3`. `~/.lab_env` is **not** present on Hulk, so the
`echo "$SSHPASS" | sudo -S` idiom recorded in project memory needs the password supplied from
gambit, or key-based passwordless sudo confirmed, before raw-socket injection can run.
