# Silicon gate — four-queue control plane configures and reads back correctly

2026-07-28, Tofino-1 (`decps@10.10.54.81`). Program `case_a_dual_release_skeleton` loaded, control
plane configured, verified, then the switch was **restored to the proven Defense 2 program**.

## Result: 43 PASS / 0 WARN / 2 FAIL on `--config`; 40 PASS / 2 FAIL on a following `--verify-only`

The two FAILs are the **same two in both runs** and are readback limitations, not
misconfigurations:

```
FAIL  pktgen port_cfg dp68 readback   entry_get: UNIMPLEMENTED, 'Entry not found in
                                      table:tf1.pktgen.port_cfg Oper...'
FAIL  pkt_buffer readback             entry_get: UNIMPLEMENTED, 'Entry not found in
                                      table:tf1.pktgen.pkt_buffer Op...'
```

`UNIMPLEMENTED` is the gRPC server declining to implement `entry_get` for those two tables — the
**writes succeeded** (no error was returned on the write path, and the Defense 2 program has used
the identical writes on silicon through all its gates). These are write-only from BFRT's
perspective in SDE 9.13.2. Treat as a known limitation and verify those two by behaviour
(token admission counts) rather than by readback.

## ★ The headline: the four-level strict-priority ladder configures and READS BACK correctly

This is the configuration that silently degraded in the earlier IBSPG work, where `max_priority`
was never set and `min_priority` is inert — producing a fair split instead of strict priority.

| queue | qid | max_priority | min_priority | sched_en | port | pipe | mapping |
|---|---|---|---|---|---|---|---|
| Q_ABLOCK | 7 | **7** | LOW | True | 8 | 0 | pg_id=2 pg_port_nr=0 pg_queue=7 |
| Q_ACK | 6 | **6** | LOW | True | 8 | 0 | pg_id=2 pg_port_nr=0 pg_queue=6 |
| Q_RBLOCK | 5 | **5** | LOW | True | 8 | 0 | pg_id=2 pg_port_nr=0 pg_queue=5 |
| Q_RESP | 4 | **4** | LOW | True | 8 | 0 | pg_id=2 pg_port_nr=0 pg_queue=4 |

`strict ordering ABLOCK>ACK>RBLOCK>RESP` — PASS, asserted from the readback, not from what was
written. All four writes took the full read-modify-write path (`queue_write_path: rmw` for each),
so the rate flags survived. New facts read off the hardware: `ingress_qid_count = 4`,
`ingress_qid_max = 32`, and dp8 maps to `pg_id=2, pg_port_nr=0` (read, not guessed).

## The SDE finding confirmed on real hardware

`packets_per_batch_cfg = 127` (→128 tokens in ONE batch) was **accepted by the driver and read
back as 127**, with `increment_source_port` written False and verified False. This confirms on
silicon what was derived from the SDE source: 128 tokens in a single batch is legal, and the
conditional bound that would have capped the batch at 60 tokens does not apply.

## Everything else that passed

- `tbl_guard` A word `0x002DC600` (2 999 808 ns, error −192 ns) and R word `0x00C65D00`
  (12 999 936 ns, error −64 ns) — **exactly** the values computed offline. `S = R − A =
  10.000128 ms`.
- The const blocker table verified on silicon: `0x0000 &&& 0xFFC0 → Ingress.set_ack_blocker`,
  `0x0040 &&& 0xFFC0 → Ingress.set_resp_blocker`, default `Ingress.set_blk_drop`.
- Parser value_set `f1 = 0x01 &&& 0xFF` at `prsr_id=17, pipe=0` — mask is EXACT `0xFF`, so the
  `0xE1` clone marker cannot alias to app_id 1.
- Mirror sid 7 → dp68, `$direction = INGRESS`, `$session_enable = True`.
- Ports: dp9 25G RS-FEC up, dp64 1G FEC-none AN-force-disable up, dp8 `BF_LPBK_MAC_NEAR`.
- `app_enable = False` (native mode) — the pipeline was configured but never armed.

## What this gate does NOT establish

**The dequeue oracle was not run.** This validates that the four-queue ladder *configures* and
reads back correctly; it does **not** prove dequeue ORDER on the wire. Phase 2 proper still needs
synthetic role injection (ABLOCK / HELD_ACK / RBLOCK / HELD_RESP) from Vision or Hulk over ≥100
randomized trials, and the `run/` injector for that does not exist yet.

Also still open: the budget horizon numbers printed by the script use the P4's `10 µs per pass`
assumption, which `../phase0/budget_horizon_review.md` shows is ~6× too slow (silicon says
1.715 µs). The printed "30 ms / 130 ms" horizons are really ~5.14 ms / ~22.30 ms. Measure with
`--loop-us` during Phase 1.

## Restore — completed and verified

| Step | Evidence |
|---|---|
| Skeleton stopped | `skeleton stopped`, no `bf_switchd` remaining (bracket-trick guard) |
| Defense 2 relaunched | PID 451939, `p4_name: dnp3_timing_normalizer_pktgen` |
| Control plane re-run | `--config --mode native`: ports [9,64] up, dp8 MAC loopback, `strict_priority_verified: true`, mirror sid 7→68, value_set added, port_cfg all three flags, pkt_buffer 60 B, `packets_per_batch_cfg=63` (K=64) |
| Left quiescent | `app_enable: false`, `trigger_counter/batch_counter/pkt_counter` all 0 — matching the recorded pre-existing state |

**Honest caveat:** a cold `bf_switchd` restart zeroes all counters and registers, so the runtime
state that existed before this session is gone. Everything was at zero except `ctr_bypass[0]`,
which now reads 5 from ambient traffic. The program, its control-plane configuration and its
quiescent state are restored; the counter history is not recoverable and was not preserved.

## Two harness bugs hit and fixed (negative evidence)

1. `pkill` as `decps` cannot kill a root-owned `bf_switchd` — `Operation not permitted`. The
   Defense 2 program was never at risk; the swap simply did not happen. Needs `sudo`.
2. **Self-match:** `pgrep -f bf_switchd` matches the invoking shell's own command line, so a
   guard clause saw "something running" when nothing was. Every process check in
   `swap_to_dual.sh` / `restore_defense2.sh` now uses the `[b]f_switchd` bracket trick. A third
   bug — `set -u` tripping on an unset `LD_LIBRARY_PATH` **after** the old program was stopped —
   left the switch briefly with nothing loaded; the scripts now use `${LD_LIBRARY_PATH:-}`.
