# FINAL_STATE.md — autonomous run 2026-07-22 → 2026-07-23

## Hardware (shared Tofino-1, decps@10.10.54.81)
- **Program loaded:** `queue_microbench` (baseline), `bf_switchd` on
  `/home/decps/queue_microbench/out/queue_microbench_abs.conf`, cold init.
- **Control state (readback):** `cover_mode = 0` (cover OFF), `telemetry_enable = 0` (telemetry
  OFF), `pat_idx_reg = 0` (no active pattern), no pktgen app (metronome OFF).
- **Trace program** `queue_microbench_trace_v1` is STOPPED (was loaded only during the Phase-5
  window). Its staged build remains non-destructively under
  `/home/decps/queue_microbench_trace/` for reuse; it is **not** running.
- **Co-resident work:** untouched (this run displaced only the queue microbench, per the
  restore-target instruction — never `decoy_paper3`, which was left alone).

## Hulk (decps@10.10.54.158)
- tcpdump processes killed (0 remaining). No macvlan/netns/NIC-flag changes were made this run
  (plain capture on `enp59s0f0np0` only). Temp pcaps remain in `/tmp` on Hulk (harmless; can be
  removed at leisure) — all evidence already copied to the repo.

## Repository (branch `research/caseA-ditto-queue`)
- **Frozen Case-A timing defenses** `dcrn_defense1.p4` / `dcrn_defense2.p4`, their setups, and the
  telemetry copies: **untouched** (not loaded, not measured this run).
- **New/changed this run** (all under `research/tofino_dcrn_feasibility/p4/queue_microbench/`):
  - `queue_microbench_trace_v1.p4`, `queue_microbench_trace_setup.py`, `harness/*` (generator,
    collector, analyzer, tests), `size_pattern_builder/*` (v1.1), `autonomous_run_20260722/*`
    (logs, gates, results, evidence).
  - **Analyzer fix:** `harness/mb_trace_analyze.py` — wrap-robust reorder check (32-bit tstamp).
  - **Regression test:** `harness/test_trace_harness.py::test_wrapping_tstamp_not_reorder`.
    20/20 harness tests pass.

## Result status
- **Level-1 trace-driven size normalization: PASS on Tofino-1 silicon.** 3 reproducible
  telemetry-ON runs (150 frames each): 150 released = 150 emitted = 150 recorded, 0 loss, 0
  reorder, every output 128 B; wire pcaps confirm `{128:150}`. Size MI 0.91 → 0.00 bits. A/B
  confirms telemetry is measurement-only. Details: `HARDWARE_RESULT.md`,
  `MORNING_EXECUTIVE_SUMMARY.md`, `AGGREGATE_RESULT.json`.
- **Gates:** A PASS (blocking DNP3 corpus bug fixed + retracted; 5 stats conditions) · B PASS
  (local 9.13.1 compile, 3 stages) · Phase-4 on-switch 9.13.2 parity · C 16/16 · Phase-5 HW PASS.

## Not done (needs explicit authorization — `next_phase_allowed = false`)
- Level-2 live DNP3/TCP classification (an actual inline defense) + physical SEL-751 rig.
- Corpus expansion (more independent flows/device) for flow-generalizable device/ACK-mode leakage.
- Joining the size axis with the timing defense on one program (touches the frozen timing path).
- Any further switch load/reload.

## How to reproduce (if re-authorized)
1. Stage + load `queue_microbench_trace_v1` on the switch (`launch_trace.sh`); restore =
   `launch_mb.sh`.
2. Switch collector: `python3.8 harness/mb_trace_collector.py --run-id N --out /tmp/traceN.jsonl
   --seconds 110 --expect 150 --seed-telemetry` (drop `--seed-telemetry` + set
   `telemetry_enable=0` for the OFF arm).
3. Hulk driver (after collector subscribes): `/tmp/run_trace.sh N 150 1234 8` (TX
   `enp59s0f0np0`→dp8, RX capture `enp59s0f0np0`←dp9, filter `ether proto 0x0800 and greater 100`).
4. Analyze: `harness/mb_trace_analyze.py --pcap traceN.pcap --digest traceN.jsonl --tx-expected 150`.
