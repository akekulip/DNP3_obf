# HARDWARE_RESULT.md — Level-1 trace-driven size normalization on Tofino-1

**Program:** `queue_microbench_trace_v1` (bf-p4c 9.13.2, on-switch build) · **Silicon:** Intel
Tofino-1 (decps@10.10.54.15) · **Traffic source:** Hulk (decps@10.10.54.158), dp8 ingress,
dp9 hairpin return · **Date:** 2026-07-23 · **Restore target after run:** the queue microbench
(`launch_mb.sh`) — restored and verified (see §Rollback).

This is the **SIZE component** of the locked joint size-and-time architecture, validated in
isolation. It is explicitly **not** a live inline DNP3 defense and makes **no** timing, device,
operation, ACK-mode, or SBO indistinguishability claim (see §Scope).

## Hypothesis (from CANDIDATE_SELECTION.md)
Padding every base-corpus frame to a single 128 B state on Tofino-1 silicon removes the
packet-size signal (output-size histogram → one value; MI(size; device/op) → 0) with zero loss,
zero reordering, zero queue growth, zero external cover, at a bounded per-direction overhead —
validating the SIZE axis separately from the event/deadline timing defenses (Defense 1/2).

## What was run
- **1 smoke** (run_id 900, 6 frames, telemetry OFF): 5 supported inputs (60/66/89/120/120 B) →
  each **exactly 128 B**; 1 unsupported oversize (200 B → 219 B on wire, ethertype 0x88B7) →
  **fails open, forwarded unchanged**. Evidence: `evidence/smoke900.pcap`.
- **4 campaign runs** (run_id 1004–1007), each **150 frames** drawn from the empirical base
  distribution (`campaign_base_distribution.json`, seed 1234, 400 ms spacing, 2.5 pps):
  - **1004, 1005, 1006 — telemetry ON** (learning-digest measurement enabled).
  - **1007 — telemetry OFF** (A/B control arm).

The 150-frame trace carries **11 distinct input sizes** (60, 66, 76, 88, 89, 91, 101, 103, 108,
115, 120 B) — the native packet-size signal.

## Result — every telemetry-ON run is a clean PASS

| run | telem | digest records | released Δ | emitted Δ | loss | reorder | all target=128 | qid | release_reason | hold_ns max |
|----:|:-----:|---:|---:|---:|:--:|:--:|:--:|:--:|:--:|:--:|
| 1004 | ON | 150 | 150 | 150 | 0 | 0 | ✅ | 1 | SIZE_NORM | 0 |
| 1005 | ON | 150 | 150 | 150 | 0 | 0 | ✅ | 1 | SIZE_NORM | 0 |
| 1006 | ON | 150 | 150 | 150 | 0 | 0 | ✅ | 1 | SIZE_NORM | 0 |
| 1007 | OFF | 0 | 150 | 0 | 0 | 0 | ✅ (wire) | 1 | — | — |

- **Completeness (switch-side, authoritative):** for every ON run, `run_id_records == ctr_released Δ
  == ctr_digest_emit Δ == 150`, sequence numbers 0–149 **contiguous, 0 duplicate, 0 missing** →
  **zero loss, zero reorder** (see reorder note below). `selected_state=1`, `qid=1`, all
  `release_reason = SIZE_NORM`, `hold_ns = 0` (single pass, no queuing delay).
- **Wire (Hulk-side pcap, independent):** runs 1005, 1006, and the OFF run 1007 each captured
  **150 frames, output histogram `{128: 150}`** — every emitted frame is physically 128 B on the
  wire. (Run 1004's return was captured on the wrong NIC due to a mid-experiment port-speed change;
  its switch-side digests are complete and 1005/1006/1007 pcaps confirm the wire independently.)

### Reorder note (analyzer fix)
The digest `ingress_tstamp` is a **32-bit** nanosecond counter that wraps ~every 4.3 s and so
wraps **13–14 times** in a 60 s run. The analyzer originally sorted on the raw wrapped value,
which scrambled order and produced a spurious `reorder_ok:false` on clean runs. Fixed in
`harness/mb_trace_analyze.py` to walk in send order (seq) and detect a real reorder as a
wrap-corrected backward inter-arrival step (> 2³¹); genuine wraps are small forward gaps. After
the fix the **unwrapped** ingress timestamp is **strictly increasing with seq in all three ON
runs** → frames processed in exact send order = no reorder. Locked with a regression test
(`test_wrapping_tstamp_not_reorder`); **20/20 harness tests pass**.

## Size-signal removal (the core finding)
- **Native input-size histogram (11 sizes, LEAKS):** `{60:38, 66:18, 76:19, 88:3, 89:19, 91:19,
  101:6, 103:6, 108:6, 115:13, 120:3}` (run 1005).
- **Shaped output-size histogram (1 size, NO LEAK):** `{128: 150}`.
- **Empirical mutual information (bits):** native MI(input_size; device) = **0.909**, MI(input_size;
  operation) = **1.892** → shaped MI(output_size; device) = **0.0**, MI(output_size; operation) =
  **0.0**. Because the output is a single constant value, MI with any label is 0 **by construction**
  — a genuine, label-invariant constant-feature property, not a finite-sample artifact.

## A/B: telemetry is measurement-only (zero datapath effect)
Turning the learning digest ON (1004–1006) vs OFF (1007) changes **nothing** on the datapath:
same 150 releases, identical output-size distribution (`{128:150}` on the wire in both), `hold_ns=0`
in both. The only difference is digest emission — **150 digests when ON, 0 when OFF**
(`ctr_digest_emit Δ` = 150 vs 0, `ctr_released Δ` = 150 in both). The A/B success criterion
(identical output distribution, completeness only when ON, no timing shift) is met.

## Reproducibility
Three independent digest-complete ON runs (1004, 1005, 1006) with the same trace produced
**bit-for-bit identical acceptance**: 150/150/150, 0 loss, 0 reorder, all 128 B. §13.5 satisfied.

## Per-direction padding overhead (run 1005, cover OFF)
| direction | n | mean input | mean pad | max pad | total pad |
|:--:|:--:|:--:|:--:|:--:|:--:|
| 1 | 94 | 73.2 B | 54.8 B | 68 B | 5153 B |
| 2 | 56 | 97.2 B | 30.8 B | 62 B | 1724 B |

The single-128 B state trades higher padding for the cleanest possible size-removal instrument
(a two-state pattern pads less but re-introduces a size→operation signal — see
CANDIDATE_SELECTION.md). Overhead is far below the 211 ms RTO ceiling at DNP3 rates.

## Rollback (switch restored — verified)
`bf_switchd` relaunched on `queue_microbench/out/queue_microbench_abs.conf` (`launch_mb.sh`).
Readback on the restored program: **`cover_mode = 0` (cover OFF)**, **`telemetry_enable = 0`
(telemetry OFF)**, `pat_idx_reg = 0` (no active pattern), **no pktgen app started (metronome
OFF)**. Hulk tcpdump killed; no Hulk NIC flags were changed this run (plain tcpdump capture only).
The shared Tofino is back to its authorized pre-experiment baseline.

## Scope and honest caveats
- **Level-1 = declared input-size class, not live DNP3/TCP.** Frames are synthetic 0x88B7 replay
  frames whose `input_size_class` is the datapath key; the switch strips the 19 B replay header and
  pads to 128 B. This validates the size-normalization **dataplane mechanism** on silicon; it is
  **not** a live inline defense parsing real DNP3/TCP.
- **Only the SIZE channel is addressed.** Direction, packet count / transaction structure,
  timing/CLRT, ACK mode, and SBO structure are **not** hidden — out of scope for the size
  component; they require the timing defenses (Defense 1/2) and/or the future cover architecture.
  **No READ-vs-SBO or device indistinguishability is claimed.**
- **Corpus is small (Gate A).** The base corpus is 3 flows = 1 device per flow, so device- and
  ACK-mode-level MI is corpus-descriptive, not flow-generalizable. The size-channel removal claim
  is a constant-feature property and is unaffected; generalization of device/operation leakage
  needs more independent flows per device.
- **Rate/coverage:** 150 frames/run at 2.5 pps; not a high-rate or physical-SEL-751 test. DNP3
  reassembly / multi-fragment handling is untested (all base responses single-fragment).
- The two frozen Case-A timing defenses (`dcrn_defense1/2`) were **not** touched, loaded, or
  measured in this run.

## Evidence (all under `autonomous_run_20260722/evidence/`)
`smoke900.pcap`; `trace1004.jsonl`, `trace1005.jsonl`+`trace1005.pcap`+`trace1005_result.json`,
`trace1006.jsonl`+`trace1006.pcap`+`trace1006_result.json`, `trace1007.pcap`;
`AGGREGATE_RESULT.json` (machine-readable consolidation of all four runs). Harness + analyzer:
`harness/` (20/20 tests pass).
