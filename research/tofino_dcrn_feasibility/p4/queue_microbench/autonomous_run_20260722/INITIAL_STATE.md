# INITIAL_STATE.md — autonomous run 2026-07-22 (verified, not assumed)

Snapshot taken read-only at run start. Restore target for any displacement = **the queue
microbenchmark** (NOT `decoy_paper3`).

## Git
- Branch `research/caseA-ditto-queue`, HEAD `03ef4cb`.
- `e7e7223` (size-pattern builder v1) present. Tags `d1-telem-v1-verified`, `d2-telem-v1-verified`.
- Uncommitted (do NOT touch): `dnp3_split_harness/split_server.py` (pre-existing M); untracked
  `autunomous.md` (this charter), D1/D2 telem compile `out/` artifacts, `dnp3_queue_microbench_snapshot.zip`.
- `queue_microbench.p4` source sha256 `0239af8f58d8a014`.

## Switch (decps@10.10.54.15, read-only)
- `bf_switchd` **RUNNING** on `/home/decps/queue_microbench/out/queue_microbench_abs.conf`
  (program = queue microbench). gc-switchd `masked/inactive` (leave masked).
- Loaded `tofino.bin` sha256 `fbddefa750827ebf`; `context.json` sha256 `5ede4a5fb964da08`.
- Register state (from HW): **cover_mode=0 (OFF)**, **telemetry_enable=0**, mech_reg=0, window_active=0,
  hold_passes_reg=20474 (stale from last burst point; irrelevant at cover=OFF). **pktgen app1 enable=False
  (metronome OFF).** No external cover can transmit.
- SDE 9.13.2 at `/home/decps/Downloads/bf-sde-9.13.2`. On-switch Defense-2 telem parity build staged at
  `/home/decps/dcrn_m1/build_ackB_telem_9132` (compile-only; NOT loaded).

## Rig
- **Hulk 10.10.54.158 UP; Vision 10.10.54.19 UP** (two-host rig available this run).

## Compilers
- Local `bf-p4c 9.13.1 (e558d01)`; on-switch `bf-p4c 9.13.2`. Research python 3.12 (scapy 2.7.0).

## Corpus available (charter §6.7 scopes)
- Base 3-device fingerprint: `Traffic Trace/{SEL751,AB1400,ION7550}.pcap` (+ `*L.pcap` long captures).
- Multi-CROB / control (incl. **real SBO**): `dnp3_multicrob_harness/captures/{multi_crob_sbo,
  multi_crob_sbo_test_c,multi_crob_test_a,multi_crob_test_b,multi_crob_negative_test_d}.pcap`.
- Zeek `Traffic Trace/dnp3.log` (SEL flow role cross-check).

## Rollback (from SWITCH_ROLLBACK_RUNBOOK.md, adjusted per charter §3/§17)
- Restore = relaunch the queue microbench on `/home/decps/queue_microbench/out/queue_microbench_abs.conf`
  (NOT decoy). The exact relaunch command + a preserved copy of the current conf/build must be captured
  before any load (Phase-5 preflight). gc-switchd stays masked.

## Do-not-modify (charter §3)
`dcrn_defense1.p4`, `dcrn_defense2.p4`, their frozen setups + telemetry copies, `split_server.py`,
archived evidence, previous compiler artifacts, previous run results, existing tags. New dirs only.
