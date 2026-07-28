# Switch restore state — captured BEFORE any hardware action

Captured 2026-07-28 on `decps@10.10.54.81` (ufispace), read-only, before anything was loaded or
restarted.

## What is actually running right now

| Item | Value |
|---|---|
| `bf_switchd` PID | **447452** (uptime 05:41 at capture) |
| Conf file | `/home/decps/defense2_pktgen_compile/pktgen_abs.conf` |
| P4 program name | **`dnp3_timing_normalizer_pktgen`** (the proven Defense 2 build) |
| Artifacts | `/home/decps/defense2_pktgen_compile/build_switch_9.13.2/` (bfrt.json, pipe/context.json, pipe/tofino.bin) |
| Pipe scope | `[0,1,2,3]` |
| SDE | `/home/decps/Downloads/bf-sde-9.13.2` (bf-p4c 9.13.2, SHA `1baf055`) |
| Host uptime | 4 days |
| Free disk on `/home` | 81 G |

## ⚠ Correction to project memory

The memory note `defense2-request-triggered-pktgen` records *"Switch RESTORED to inline +
verified"*, and the Defense 2 implementation report names
`/home/decps/timing_inline/launch_tn_inline.sh` (`dnp3_timing_normalizer_inline`) as the rollback
target. **That is not what the switch is running.** The launcher
`/home/decps/defense2_pktgen_compile/launch_pktgen.sh` was modified 2026-07-28 15:35 and the
pktgen program has been loaded since. The live state is authoritative.

**Restore target for this work is therefore `dnp3_timing_normalizer_pktgen`**, not the inline
program and not `queue_microbench`.

## Exact restore command

```bash
#!/bin/bash
export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH
tail -f /dev/null | "$SDE_INSTALL/bin/bf_switchd" \
  --install-dir "$SDE_INSTALL" \
  --conf-file /home/decps/defense2_pktgen_compile/pktgen_abs.conf \
  --init-mode=cold --status-port 7777 \
  > /home/decps/defense2_pktgen_compile/pktgen_switchd.log 2>&1
```
i.e. `nohup /home/decps/defense2_pktgen_compile/launch_pktgen.sh &`

**A cold restart wipes the runtime control plane.** A faithful restore is not just relaunching
bf_switchd — it must be followed by re-running the Defense 2 control-plane setup
(`setup/dnp3_timing_normalizer_pktgen_setup.py`) and verified with a native poll before the
switch is considered returned to its prior state.

## Other launchers present (do NOT load these by accident)

`timing_inline/launch_tn_inline.sh`, `timing_final/launch_tn.sh`, `part9..part15/launch_*.sh`,
`ibspg_mb/launch_ibspg*.sh`, `queue_microbench*/launch_*.sh`, `dnp3_shadow*/launch*.sh`,
`decoy_paper3/launch_gf_v2b.sh`, `dcrn_m1/launch_*.sh`, `oracle/launch_*.sh`,
`sdnp_tofino/launch_sdnp.sh`.

## Rule for this branch

Every hardware step records: what was running before, what was loaded, and confirmation that the
above restore was performed and verified afterwards. No step leaves the switch in a state other
than the one captured here.

---

## Hardware action log

### 2026-07-28 — on-switch compile gate (NON-DESTRUCTIVE, no load, no restart)

Staged `p4/case_a_dual_release_skeleton.p4` to `/home/decps/case_a_dual/p4/`
(sha256 `77bffe70a5b8455ab33e82835b460832b4319e5a9cc8a98f089a4514a1554f9f`, verified identical on
both ends) and compiled it with the switch's own bf-p4c 9.13.2 (SHA `1baf055`).

**Result: 0 errors, 3 warnings, 9 ingress / 0 egress, critical path 8, 81 tables — IDENTICAL to
the local 9.13.1 allocation. No 9.13.1 -> 9.13.2 drift.** Compile gate §22 satisfied on both SDEs.

`bf_switchd` PID **447452 was never touched** — confirmed still running the same command line
before and after, uptime advancing normally (05:41:02 -> 05:42:45). Only `bf-p4c` ran. Nothing
was loaded, no config changed, the Defense 2 program remains live.

Artifacts left on the switch (inert, staged for a later gated load):
`/home/decps/case_a_dual/build_switch_9.13.2/` and `/home/decps/case_a_dual/compile_9.13.2.log`.

### Host availability at this point

| Host | Address | State |
|---|---|---|
| Vision (master, dp9) | 10.10.54.19 | UP |
| Hulk (dp11) | 10.10.54.158 | UP |
| SEL-751 relay | 192.168.10.7 | not reachable from gambit (different subnet — expected; reached via Vision) |

Both injection hosts are available, so the Phase 2 four-queue dequeue oracle is feasible once a
control plane exists for the skeleton.
