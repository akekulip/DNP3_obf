# HW campaign working notes (defense4-size-native-parity-crc-split)

Driver = gambit (10.10.54.133). Switch = decps@10.10.54.81 (SDE 9.13.2, grpc localhost:50052,
status 7777). Vision = decps@10.10.54.19. Relay SEL-751 = 192.168.10.7:20000 (link master=1,
outstation=0). Evidence dir = this directory.

## Live baseline (measured Phase-1 reconnaissance, read-only)
- Loaded now: `defense4_rrc_kernel` from `/home/decps/rrc_build/defense4_rrc.conf`;
  RRC tofino.bin sha256 = 4ebd66896638f4790952e473aaf9f6c5b3f1839f3ae8f17006b09c27ba6bb5bb.
- LIVE tbl_params (from_hw): mode=4 (D4), d_ticks(D_A)=1999872=0x1E8400 (~2ms),
  da_dr=21999872 -> D_R=20000000=0x1312D00 (20ms), budget=18000, read_len=0 (retired), shape_enable=1.
- PRE: mgid 0x2849 -> node 0x2851 (RID1, dp9) + node 0x2852 (RID2, dp9). Both egress dp9.
- Queues qid7/6/5/4 strict ladder (watermarks nonzero -> live traffic flowing).
- Ports: dp8 loopback/hold-ring, dp9 Vision/master, dp64 relay leg, dp68 pktgen (pipe0).

## Unified BOR program (Phase 5 H0 target)
- Staged at /home/decps/rrc_bor_build/out/ ; conf defense4_rrc_bor_unified12.conf ;
  program name = defense4_rrc_bor_unified12 ; tofino.bin sha256 =
  550b5b974b0cfde5eb4754fc4fbaa2a893b1f57201d36f0b228d1292dc2f0777 (VERIFIED == expected).
- DEFECT: unified conf references model_json_path .../share/.../aug_model.json which DOES NOT EXIST.
  The working RRC conf has NO model_json_path key. FIX: load a corrected conf without that key.
- Unified setup script (repo): defense4/size/native_parity/p4/defense4_rrc_bor_unified12_setup.py
  (1031 lines) — NOT yet staged on switch. [digest pending from subagent]

## ROLLBACK (safety net) — must restore EXACT snapshot, NOT 0x8000 defaults (invariant #2)
- Faithful restore = configure-all --mode D4 --d-a 0x1E8400 --d-r 0x1312D00 --budget 18000
  --master-ip 192.168.10.1 --relay-ip 192.168.10.7  (master-ip is load-bearing: tbl_session keys on it).
- Base script = repo copy defense4/size/native_parity/p4/defense4_rrc_setup.py (cleaner SAFE-ORDER
  configure-all, forwards --read-len 0/--budget/--master-ip/--relay-ip/--poll-ms, rejects sub-ms).
  d3.BUDGET_DEFAULT=18000 already matches live budget.
- swap_generic.sh (/home/decps/d3/swap_generic.sh) cold-loads a conf (sudo pkill + tail -f /dev/null
  stdin hold + detached + sleep 40). RRC conf = /home/decps/rrc_build/defense4_rrc.conf.

## DNP3 drivers (stage to Vision; run from Vision, source 192.168.10.1)
- READ (H1/H3): defense4/size/native_parity/hw/relay_read_g10_23.py — 23-pt G10V2, 49B native,
  RRC split [28,21]. func 0x01 asserted.
- 2-CROB SELECT (H2, NON-ACTUATING): defense4/size/readsbo_normalizer/relay_sbo_2crob_loop.py —
  func 0x03 asserted, refuses 0x04/0x05, reads pts 0/1 before+after (must stay OPEN). 45B req -> 49B echo.
- NEVER RUN: defense4/size/readsbo_normalizer/relay_sbo_operate.py (sends OPERATE 0x04 — actuates).
- [28,21] wire analysis: defense4/size/native_parity/analyze_rrc_pcaps.py (needs scapy; run on gambit
  with $RESEARCH_PYTHON against fetched pcaps). Pairs req/resp by TCP semantics; reports seq [28,21],
  arrival [21,28], all_reassemble_49B, timing (req->ack, ack->resp CLRT, req->resp).
- Master must use qualifier 0x17 (allow_one_byte) for multi-CROB — drivers already emit 0x17.

## SDE env (remote python)
export SDE=/home/decps/Downloads/bf-sde-9.13.2 ; SDE_INSTALL=$SDE/install
LD_LIBRARY_PATH=$SDE_INSTALL/lib
PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages
DEFENSE4_HW_AUTHORIZED=1 ; D4_CASEA_SETUP=/home/decps/d4_build/control/defense4_caseA_setup.py

## Phase checklist — ALL COMPLETE, H0+H1+H2 PASS
- [x] Phase 0 recon
- [x] Phase 1 snapshot-live -> live_rrc_snapshot.json (recipe D4/D_A=0x1E8400/D_R=0x1312D00/budget18000)
- [x] Phase 2 rollback rewrite + LIVE VERIFY: readback-diff MATCH, relay+3x49B READ
- [x] Phase 3 baseline: 25 READs [28,21], CLRT 20.003ms, outputs OPEN, reg_tag=0
- [x] Phase 4 watchdog armed (deadline+marker + switchd-absence)
- [x] Phase 5 H0 PASS (n_fail=0 n_warn=0), sha 550b5b97, after fixing 4 setup defects:
      (1) --d-a/--d-r/--poll-ms args ; (2) codebook range key low=/high= + entry_get readback ;
      (3) symmetric MAU tables need 0xffff device target (was pipe-0 -> INVALID_ARGUMENT) ;
      (4) configure-all did not bring up dp8/dp9/dp64 ports -> added d3.config_ports.
      Also conf fix: dropped nonexistent model_json_path (aug_model.json).
- [x] Phase 6 H1(a) defenses OFF: 100/100 native 49B single-seg (no replicas); (b) shaping: 200/200 [28,21],
      RID1==RID2==200, 0 source-copy escapes, 400/400 segments valid IP+TCP csum, CLRT 4.0ms.
- [x] Phase 7 H2: 120 2-CROB SELECT (non-actuating, pts OPEN before+after), echoes [28,21] 120/120,
      0 escapes, 240/240 valid csum, resp group 12; READ-vs-SELECT CLRT 4.0 vs 4.001ms (equal).
- [x] Phase 8 closeout: final configure-all PASS, unified LEFT RUNNING (full defense), watchdog disarmed.

FINAL STATE: defense4_rrc_bor_unified12 running (sha 550b5b97), forwarding, shape ON, all outputs OPEN.

## HARD SAFETY
1. NEVER OPERATE / actuate. SELECT-only. Verify both pts OPEN before+after every SELECT.
2. Rollback from LIVE snapshot, never 0x8000. Fail closed on any unreadable load-bearing field.
3. Detached watchdog armed BEFORE unified load; disarm only after H0 passes.
4. Stop + roll back on FIRST failed gate. Leave unified running only if H0+H1+H2 all pass.
5. Save all raw evidence here. Report only measured values.
6. commit as akekulip, branch only, no AI attribution. Never modify frozen P4/caseA sources.
