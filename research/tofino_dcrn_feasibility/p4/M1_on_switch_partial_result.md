# M1 (on-switch, partial) — DCRN loads + runs on real Tofino-1 silicon

_Date: 2026-07-20. Switch `decps@10.10.54.81` (`ufispace`), SDE 9.13.2. Vision was POWERED OFF this
session, so only Hulk + the switch were available → the dp8↔dp9 byte-identical round-trip + DNP3
timing normalization could NOT be run (needs Vision as master). Everything achievable without Vision
was done. A co-resident program (the 14-day run that owned the chip) was displaced with Philip's
authorization and **restored afterward.**_

## What was proven on hardware (partial M1)

1. **Compile on 9.13.2** — `bf-p4c 9.13.2` (SHA 1baf055), 0 errors, 9/12 ingress stages, identical fit
   to local 9.13.1 (see `M1_local_compile_result.md`). Byte-identical source both machines.
2. **DCRN LOADS on real Tofino-1 silicon** — `bf_switchd` cold-loaded `dcrn.conf` and bound
   `p4_name: dcrn` from `dcrn_build/pipe/{context.json,tofino.bin}` + `bfrt.json`; bfruntime gRPC up on
   `:50052`. No `Failed to find BfRtInfo`. Evidence: `build_switch_9.13.2/dcrn_switchd_load.log`.
3. **Full control plane installs cleanly** (`dcrn_setup.py --policy P1_FIXED`, exit 0) — this resolves
   ALL the "confirm at M0" bfrt name unknowns the controller flagged:
   - `Binding with p4_name dcrn successful`
   - host ports dp8/dp9 configured via `$PORT` (25G / RS-FEC)
   - **recirc enabled on dp68** via `tf1.pktgen.port_cfg`
   - **TM `max_rate` shaper installed** — `tf1.tm.queue.sched_shaping` + `sched_cfg`, dp68 qid5,
     10000 PPS (the exact 9.13.2 TM table/field names WORK — previously an M0 unknown)
   - `fc_allowlist` entry (FC 0x01 READ → `DcrnIngress.fc_allow`) installed
   - **all 256 `bounded_target` entries installed** (key `meta.bkt_idx`, action
     `DcrnIngress.set_deadline`, data `di`) — FIXED = 503 ticks = 33 ms ✓
   (register re-seed stays disabled — the P4 constructor cold-seeds; the `.f1` field name was not
   exercised and remains the one un-confirmed control-plane string.)
4. **dp9 / Hulk links** — `$PORT` read: dp9 `PORT_UP=True`, 25G/RS-FEC. dp8 `PORT_UP=False ENABLE=True`
   (Vision off → link-down, as expected; the port is admin-enabled and ready for when Vision returns).
5. **Pipeline is LIVE on silicon** — the `events` counter (`DcrnIngress.events`) read from hardware
   showed `PASSTHRU` climbing **23 → 29** in response to a deterministic ARP/ping burst from Hulk to
   10.0.1.10 (in-subnet → dp9 ingress → classified non-DNP3 → transparent forward). The ingress apply
   block executes and counts real wire traffic.

## What is NOT done (Vision-blocked, deferred)

- dp8↔dp9 **byte-identical wire forwarding** of a full DNP3 request/response (M1's forwarding
  acceptance) — needs Vision as the master (`run_master.py`) on dp8.
- M2+ (recirc-hold flatten-to-target, clock-refresh probe Q2, dual-case, fail-open, rig timing eval).
- **Host-side caveat:** Vision's documented data NIC `enp59s0f0np0` (Intel, MAC 3c:fd:fe:cc:5d:c0) is
  GONE; Vision now shows down `enp59s0np0sX` breakout interfaces (Netronome/Corigine SmartNIC MAC
  00:15:4d). Vision's data-plane must be sorted out (or it may just be that Vision is off) before the
  wire test — plan the Vision-side bring-up when it is powered on.

## Shared-chip handling (done correctly)

- Chip was owned by **a co-resident program** (its own conf, up 14 days, root, NO live controller),
  reached via that program directly — not the auto-load service (which was already `masked`+inactive;
  left masked = found state).
- Displaced with a targeted `pkill -x bf_switchd`; loaded DCRN via `launch_dcrn.sh`; ran the partial;
  then **restored the co-resident program** via its own launch script — verified back up, its program
  reloaded, `server started`.
- **Restore caveat (flagged):** the co-resident program got a fresh COLD restart → any runtime tables its
  own controller installed at its original bring-up are NOT re-applied by my relaunch; if it needs them,
  its owner must re-run its controller. I restored its data plane, not its runtime control-plane state.

## Verdict
**Partial M1 = PASS on real hardware.** DCRN compiles on 9.13.2, loads on the ASIC, brings up its full
control plane (every bfrt name confirmed), links Hulk at 25G, and processes live wire traffic. The only
outstanding M1 item is the dp8↔dp9 byte-identity round-trip, which is blocked solely on Vision being
powered off — not on any DCRN or switch problem.
