# RESUME HERE — Case A READ-anchored dual release

**State saved 2026-07-29 ~02:00.** Branch `research/case-a-read-anchored-dual-release`, HEAD
`416f70a`, pushed. Working tree clean. **Switch left on the proven Defense 2 program, verified.**

---

## THE ONE COMMAND TO RUN NEXT

```bash
cd /home/philip/Projects/DNP3/research/case_a_read_anchored_dual_release
./run/run_four_queue_oracle.sh --shaper-sweep
```

Prerequisite: the four-queue dequeue oracle must be loaded first (see "Load / restore" below) —
the runner deliberately refuses to load it itself. The runner's EXIT/INT/TERM/HUP trap restores
Defense 2 and verifies five facts, and that path has now worked three times including from a real
failure.

**Philip is picking up from his own comments on the last exchange — read those first; they may
redirect this.**

---

## Where the work actually stands

### Done and verified

| Step | Result |
|---|---|
| Design corrected | `design/CASE_A_READ_ANCHORED_DUAL_RELEASE.md` — R=13 ms (12 is below p99=12.607), full-width ternary on `packet_id`, keepalive predicate, external FIFO ordering, absolute deadlines |
| Phase 0 gate 1 | frozen Defense 2 recompiles identically (10/0/70, path 8) — no drift |
| Phase 0 gate 2 | stage reclamation **10 → 8** ingress. 7 is NOT reachable: critical path 8 == stage count means dependency-bound |
| Phase 0 gate 3 | dual-release skeleton **fits at 9/12**, critical path unchanged at 8. Deferred Phase-4 work measured by probe compiles at **11/12** — about one stage of real margin |
| Both compile gates | 9.13.1 local and 9.13.2 on-switch, identical allocation, no drift |
| Silicon config gate | 43 PASS / 2 FAIL. Four-queue `max_priority` 7/6/5/4 configures AND reads back; `packets_per_batch_cfg=127` accepted. The 2 FAILs are `entry_get UNIMPLEMENTED` readback limits on `tf1.pktgen.port_cfg` / `pkt_buffer`, not misconfigurations |
| Oracle built | on-chip, 4 ingress / 0 egress, no external dependency at all |
| Two pilot defects | fixed and verified: three-value trace accounting (513 → 513/512/1) and mandatory trial isolation (5/5 tests) |

### NOT established — say this plainly

**Nothing about dequeue ORDER.** No control has ever produced an interpretable trace. Two pilot
runs both failed for harness reasons, never for a scheduling reason.

- **Pilot 1** (host-based, Hulk/dp11): 5/5 INVALID. dp11 link is dark — `Link detected: no`.
  Frames never entered the switch. The whole Hulk path was then dropped in favour of the on-chip
  oracle. Hulk artifacts retained as superseded evidence.
- **Pilot 5** (on-chip, five controls): 0/5 clean. **Two defects, now fixed** — the dp8 port
  shaper leaked 4 packets past an armed gate (`PPS/1/0`, burst 0 accepted and read back as 0), and
  trials were not independent (control A left 124 backlogged; B1's traced delta of 252 = A's 124 +
  its own 128).

Accepted status of pilot 5: **harness and shaper-characterization only.** Controls B1–D must not
be re-run until a clean common release gate exists.

---

## The immediate question the sweep answers

Does any dp8 **port-level** shaper setting give a zero-leak preload? Exactly five, equal
priorities, screen once then **5/5 consecutive repeats**:

```
PPS:1:0   PPS:1:1   PPS:0:0   BPS:1:0   BPS:1:1
```

Pass = `event_ctr_before_release == 0`, total occupancy 128, every queue > 0, zero drops, pktgen
count 128, everything drains after the single release write.

**My prediction, for calibration:** the pilot leaked 4 packets in ~3.3 ms ≈ 1200 pps against a
configured 1 pps. If that is a fixed hardware minimum burst, `PPS:1:1` and `BPS:1:1` should be
*worse* (they explicitly permit a burst), leaving `PPS:0:0` and `BPS:1:0` as the only real
candidates — and `PPS:0:0` may be read by the driver as "unlimited" rather than "zero". **A
negative sweep is the expected branch, not a surprise**, and it is what justifies the predefined
fallback:

```
Q_GATE > Q_ABLOCK > Q_ACK > Q_RBLOCK > Q_RESP
```
released by one register-controlled termination of `Q_GATE`. That needs a P4 change and is a
separate gated step. **Do not** use sequential queue-enable writes; that was ruled out because
enable-write skew (~1.7 µs drain vs driver write latency) would make control-plane ordering
masquerade as scheduling.

---

## Load / restore

```bash
# load the oracle (destructive — displaces Defense 2)
ssh decps@10.10.54.81 'sudo /home/decps/fqo/swap_to_dq.sh'

# restore only, safe to run any time (converge-to-known-good, does NOT cycle a healthy switch)
./run/run_four_queue_oracle.sh --restore-only
```

Restore target is **`dnp3_timing_normalizer_pktgen`** from
`/home/decps/defense2_pktgen_compile/` — NOT the inline program, whatever project memory says.
Verified facts: `p4_name`, `strict_priority_verified=true`, `app_enable=false`, exactly one
`bf_switchd`, dp8 shaping restored.

dp8's original shaper state: `max_rate_enable=False, max_rate=25010000, BPS, burst 9216,
BF_SPEED_25G`.

---

## Harness traps this session actually hit — do not rediscover these

1. **`pgrep -f bf_switchd` OVERCOUNTS** — returned **3** for one daemon (the launcher command line
   contains the string, and so does the invoking shell). Count with **`pgrep -cx bf_switchd`**;
   use the `[b]racket` trick only for `pkill -f`.
2. **`set -u` + unset `LD_LIBRARY_PATH`** aborted a swap *after* the old program was stopped,
   briefly leaving nothing loaded. Always `${LD_LIBRARY_PATH:-}`.
3. **`pkill` as `decps` cannot kill root-owned `bf_switchd`** — needs `sudo` on the switch.
4. **`usage_cells` is a LIVE GAUGE, not a latched statistic**, and it is writable. Zeroing it
   before draining would certify a switch still holding traffic. Cleanup order is asserted:
   disable pktgen → line rate → drain → reset.
5. **`usage_cells` counts CELLS, not packets.** The sweep marks a setting UNDECIDED if occupancy
   disagrees with the P4 packet counters.
6. Lab hosts are **`decps@`**, not `philip@`.

---

## Standing constraints

No dp11, no Hulk, no external capture, no sudo capabilities on hosts. Never a per-queue shaper as
the global gate. Do not touch `research/defense2_pktgen/` or `research/ibspg_root_cause_repair/`
(both are frozen evidence). Do not start the 160-trial campaign until five controls are
interpretable. Reservoir depth (K) and recirculation empty gaps remain **separate** evidence — a
pass here must never be read as vindicating K=1.

Full narrative: `evidence/four_queue_oracle/PILOT5_RESULT.md`, `PILOT_01_RESULT.md`,
`evidence/SWITCH_RESTORE_STATE.md`.
