# H3 physical-SEL BOR OPERATE — attended-session runbook

**Attended, gated session.** Every SELECT/OPERATE frame is built only by `h3_harness/relay_operate_guarded.py`
(hard, tested: index 6 = breaker-close and every set != {1,3} refused). Testbed currently rests on the proven RRC.

## Topology / fixed facts
- Driver host **gambit** (10.10.54.133) drives over SSH. Switch **decps@10.10.54.81** (SDE 9.13.2).
  Master leg = **Vision decps@10.10.54.19**, iface **enp59s0f0np0** = 192.168.10.1 (dp9).
  Relay = physical **SEL-751 192.168.10.7:20000** (dp64), link master=1/outstation=0 — the outstation.
- v2 binary sha256 **33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa**; load conf
  **/home/decps/rrc_bor_build_v2/out/defense4_rrc_bor_unified12_nomodel_abs.conf** (absolute paths — the
  relative-path conf fails: bf_switchd loads with no BfRtInfo). dp10-aware setup in `/home/decps/rrc_bor_build_v2/control/`.
- BOR deadlines **A=20 ms (--op-a-ms 20), R=24 ms (--op-r-ms 24)**; R≥A and both > J_max+native(14).
  **`--read-len 0`** required (the D3-only read_len field is unused in D4; its default 18 fails the check).
- Points: **{1,3} = RB02/RB04, audit-proven empty fanout in all setting groups. NEVER index 6 (RB07→OUT102 breaker close).**

## Exact commands

**Emergency rollback (restores proven RRC from live snapshot):**
```
ssh decps@10.10.54.81 'bash /home/decps/rrc_bor_build/rollback_rrc.sh'
```
**Disable BOR/pktgen immediately (keeps program loaded, BOR off):**
```
ssh decps@10.10.54.81 'cd /home/decps/rrc_bor_build_v2/control && \
  export SDE=/home/decps/Downloads/bf-sde-9.13.2 SDE_INSTALL=$SDE/install LD_LIBRARY_PATH=$SDE_INSTALL/lib \
  PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages; \
  DEFENSE4_HW_AUTHORIZED=1 python3 defense4_rrc_bor_unified12_setup.py disable-bor --grpc localhost:50052'
```

**Load v2:**
```
ssh decps@10.10.54.81 'sudo /home/decps/d3/swap_generic.sh \
  /home/decps/rrc_bor_build_v2/out/defense4_rrc_bor_unified12_nomodel_abs.conf rrc_bor_v2'
```
**Configure-all** (set `--j-set` per pass: `"6"` for the single-txn J=6 ms gate; `"2"`,`"6"`,`"12"` for the fixed passes; `"2 4 6 8 10 12"` for randomized):
```
ssh decps@10.10.54.81 'cd /home/decps/rrc_bor_build_v2/control && \
  export SDE=/home/decps/Downloads/bf-sde-9.13.2 SDE_INSTALL=$SDE/install LD_LIBRARY_PATH=$SDE_INSTALL/lib \
  PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages; \
  DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=/home/decps/d4_build/control/defense4_caseA_setup.py \
  python3 defense4_rrc_bor_unified12_setup.py configure-all --grpc localhost:50052 \
    --mode D4 --op-a-ms 20 --op-r-ms 24 --j-set "6" --read-len 0'
```
Require `RESULT: PASS (n_fail=0 n_warn=0)`, running sha == 33fa3a77, dp10 loopback up. Arm watchdog BEFORE load:
```
ssh decps@10.10.54.81 'rm -f /home/decps/rrc_build/hw_campaign.marker; setsid nohup bash \
  /home/decps/rrc_bor_build/watchdog_rrc.sh 1800 /home/decps/rrc_build/hw_campaign.marker \
  /home/decps/rrc_bor_build/rollback_rrc.sh 60 >/dev/null 2>&1 &'
# stand down after H0 passes:  ssh decps@10.10.54.81 'touch /home/decps/rrc_build/hw_campaign.marker'
```

## Capture — interface mapping
- **Master-facing (confirmed):** on Vision, `sudo tcpdump -i enp59s0f0np0 -w /tmp/h3_master.pcap "host 192.168.10.7 and tcp port 20000"`. Start it DETACHED (`setsid … </dev/null &`) — a plain background `&` in an ssh one-liner hangs the session.
- **Relay-facing / dp68 mirror (ASSUMPTION — resolve at rig):** mirror session 7→dp68 is configured, but no host is confirmed cabled to dp68 for capture (Vision's spare NIC enp59s0f1np1 is DOWN; Hulk unreachable). To get the internal **T0+J** release, cable a host to dp68 (or tap the dp64↔relay link), bring its NIC up promiscuous, and `tcpdump -i <iface> -w /tmp/h3_mirror.pcap`. Without it, only the master-facing observable (ACK@T0+A, echo@T0+R) is captured; T0+J stays inferred.

## Preflight gate (run after arming captures/watchdog, before OPERATE)
```
MIRROR_CAP_HOST=<host-on-dp68> MIRROR_CAP_IFACE=<iface> SYN_PCAP=/path/master.pcap \
  bash defense4/size/native_parity/h3_harness/preflight_checks.sh   # exit 0 = all pass
```
Checks: driver enforces exactly {1,3}; RB02/RB04 zero fanout; all outputs OPEN; watchdog+snapshot+rollback armed; both captures running; TCP timestamps absent from the SYN.

## ⚠ Precondition that needs root at the rig
**TCP timestamps are currently ENABLED** on Vision (`net.ipv4.tcp_timestamps=1`) — verified negotiated on the wire.
The anti-subtraction guarantee (J unobservable) requires them OFF; with them ON the relay's TSval leaks T0+J.
Before any OPERATE, as root on Vision: `sudo sysctl -w net.ipv4.tcp_timestamps=0`, then re-run preflight (check 6 must PASS).

## Attended gates (STOP/rollback on any failure — never scale to 1000 in the first session)
1. Arm watchdog → load v2 → configure-all (`--j-set "6"`); require full hardware readback (sha, dp10, n_fail=0). Stand watchdog down.
2. 10 READs + 10 SELECT-only (`relay_sbo_operate_guarded.py --select-only --count 10`). Confirm forwarding + [28,21].
3. Confirm all relay outputs OPEN (`check_all_outputs.py`).
4. Run preflight_checks.sh → ALL PASS (incl. TCP-ts absent, both captures).
5. **Exactly ONE** guarded {1,3} SELECT→OPERATE at fixed J=6 ms: `relay_sbo_operate_guarded.py --count 1 --j-label J=6ms`.
6. Immediately: RB02/RB04 changed only internally as expected; **every physical output still OPEN**; inspect BOTH captures.
7. Only if txn-1 passes: 10 txns each at J=2, 6, 12 ms (reconfigure `--j-set` per pass). Re-check outputs each batch.
8. STOP for timing + duplicate-release analysis before any larger campaign.
Abort+rollback on any unexpected point, output-state change, missing capture, duplicate OPERATE, readback mismatch, timing failure, or loss of relay reachability.

## Dry-run bytes (socketless, exact frames) — `h3_harness/relay_sbo_operate_guarded.py --dry-run`
Saved: `evidence/hw_campaign_20260813T172014Z/h3_operate/h3_operate_dryrun_bytes.txt`. Object = G12V1 qual 0x17, count 2, points 01+03 (both decoys). SELECT func 0x03, OPERATE func 0x04, each 45 B.

## Remaining assumptions / open items
- **dp68 mirror capture host is unresolved** — the relay-facing T0+J leg needs a cabled/promiscuous host or a link tap.
- **TCP-timestamp disable needs root on Vision** (sudo password) — not doable headlessly; an attended step.
- The earlier ad-hoc 30-txn OPERATE run (commit f2c38d2) showed echo−ACK=R−A=4.00 ms on the master-facing RELEASE timing, but ran with TCP timestamps ON, so it does NOT establish J-unobservability; this gated run with timestamps OFF is what establishes the anti-subtraction claim.
- Load/configure fixes baked in above: absolute-path conf, `--read-len 0`.
