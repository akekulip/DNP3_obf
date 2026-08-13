# H3 physical-SEL BOR OPERATE — operator runbook

**You run this at the rig.** It loads the corrected two-loopback binary and drives guarded
`{1,3}` SELECT→OPERATE at the physical SEL-751 to prove the on-silicon BOR hold
(OPERATE released at T0+J; ACK at T0+A; echo at T0+R; anti-subtraction: echo−ACK = R−A,
independent of J).

## Safety (non-negotiable)
- Control frames target **only DNP3 BO index 1 (RB02) and 3 (RB04)** — proven empty-fanout in all
  setting groups. The driver **cannot** emit index 6 (RB07 → OUT102 breaker close) or anything else
  (`relay_sbo_operate_guarded.py` aborts, exit 2, before opening a socket — verified).
- **Read the relay's physical outputs before and after every batch.** If `TRIP` or any `OUT10x/OUT40x`
  ever reads **1**, STOP and run the ROLLBACK immediately.
- ROLLBACK (always available, restores the proven RRC + forwarding from the live snapshot):
  ```
  ssh decps@10.10.54.81 'bash /home/decps/rrc_bor_build/rollback_rrc.sh'   # confirm the staged path first
  ```

## Facts
- Switch `decps@10.10.54.81` (SDE 9.13.2). Vision `decps@10.10.54.19` = master leg 192.168.10.1 (iface `enp59s0f0np0`, confirm). Relay 192.168.10.7:20000 (dp64), link master=1/outstation=0.
- v2 binary sha256 **33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa**, conf `/home/decps/rrc_bor_build_v2/out/defense4_rrc_bor_unified12_nomodel.conf`, dp10-aware setup `/home/decps/rrc_bor_build_v2/control/`.
- BOR deadlines: **A=20 ms, R=24 ms** (R≥A and both > J_max(12)+native(2)=14 — the setup's `--op-r-ms` default of 4 would FAIL fail-closed validation).

---

## 0. Stage the guarded driver on Vision + prove the guard (from gambit)
```
scp defense4/size/native_parity/h3_harness/{dnp3_wire.py,relay_operate_guarded.py,relay_sbo_operate_guarded.py} \
    decps@10.10.54.19:~/native_parity/
python3 defense4/size/native_parity/h3_harness/test_relay_operate_guard.py   # must print GUARD TEST PASSED
ssh decps@10.10.54.19 'cd ~/native_parity && python3 relay_sbo_operate_guarded.py --indices 6 --count 1'  # must ABORT exit 2
```

## 1. Baseline relay outputs (must be 0 / OPEN)
```
ssh decps@10.10.54.19 'python3 ~/native_parity/check_all_outputs.py'   # expect all OPEN; record it
```

## 2. Arm the detached watchdog on the switch (auto-rollback if the load wedges)
```
ssh decps@10.10.54.81 'setsid nohup bash /home/decps/rrc_bor_build/watchdog_rrc.sh \
    1200 /home/decps/rrc_build/hw_campaign.marker /home/decps/rrc_bor_build/rollback_rrc.sh 60 \
    >/dev/null 2>&1 & echo armed pid=$!'
```

## 3. Load v2 (cold swap — briefly interrupts forwarding)
```
ssh decps@10.10.54.81 'sudo /home/decps/d3/swap_generic.sh \
    /home/decps/rrc_bor_build_v2/out/defense4_rrc_bor_unified12_nomodel.conf rrc_bor_v2'
```

## 4. configure-all v2 (dp8 RRC ladder + dp10 BOR ladder, full J codebook)
```
ssh decps@10.10.54.81 'cd /home/decps/rrc_bor_build_v2/control && \
  SDE=/home/decps/Downloads/bf-sde-9.13.2 SDE_INSTALL=$SDE/install \
  LD_LIBRARY_PATH=$SDE_INSTALL/lib \
  PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages \
  DEFENSE4_HW_AUTHORIZED=1 D4_CASEA_SETUP=/home/decps/d4_build/control/defense4_caseA_setup.py \
  python3 defense4_rrc_bor_unified12_setup.py configure-all --grpc localhost:50052 \
    --mode D4 --op-a-ms 20 --op-r-ms 24 --j-set "2 4 6 8 10 12"'
```
**Require:** `RESULT: PASS (n_fail=0 n_warn=0)`, running sha == `33fa3a77…`, dp10 loopback up.

## 5. Stand the watchdog down (H0 passed)
```
ssh decps@10.10.54.81 'touch /home/decps/rrc_build/hw_campaign.marker'
```

## 6. Regression (no OPERATE): confirm no RRC regression + outputs still 0
```
ssh decps@10.10.54.19 'cd ~/native_parity && python3 relay_read_g10_23.py 25 && python3 relay_sbo_2crob_loop.py 25'
ssh decps@10.10.54.19 'python3 ~/native_parity/check_all_outputs.py'   # still all OPEN
```
Expect [28,21] segmentation, byte-exact reassembly, all outputs 0.

## 7. Start master-facing capture (Vision), then the guarded OPERATE — START SMALL
```
ssh decps@10.10.54.19 'sudo timeout 120 tcpdump -i enp59s0f0np0 -w /tmp/h3_operate_master.pcap \
    "host 192.168.10.7 and tcp port 20000" &'
ssh decps@10.10.54.19 'cd ~/native_parity && python3 relay_sbo_operate_guarded.py --count 10 --gap-ms 100'
ssh decps@10.10.54.19 'python3 ~/native_parity/check_all_outputs.py'   # MUST be all OPEN — else ROLLBACK
```

## 8. Scale up only if step 7 is clean and outputs stayed 0
- Fixed-J passes (re-run step 4 with `--j-set "2"`, then `"6"`, then `"12"`; ≥50 each) then randomized `--j-set "2 4 6 8 10 12"` for ≥1000. Re-check outputs after each batch.

## 9. Analyze (pull pcaps back to gambit)
```
scp decps@10.10.54.19:/tmp/h3_operate_master.pcap defense4/size/native_parity/evidence/hw_campaign_20260813T172014Z/h3_operate/
```
From the master-facing pcap prove per transaction: T_ACK,out = T0+A (~20 ms), T_echo,out = T0+R (~24 ms),
echo−ACK = R−A (~4 ms) **independent of J**; every echo [28,21]; SUCCESS status; no TCP-ts.
(Relay-facing T0+J needs the dp68 mirror capture — locate its capture host if you want the internal release confirmation too.)

## 10. Closeout
- All gates + outputs-stayed-0 pass → leave v2 running (or ROLLBACK to RRC if you want the relay back to baseline).
- Any forwarding/timing/duplication/output-assertion failure → ROLLBACK immediately (command at top).
