# AUTONOMOUS_RUN_LOG.md — 2026-07-22

Timestamped checkpoints. Verified against real artifacts (source/compiler/pcap/register/counter/log),
not agent assertions.

## CP0 — Setup + initial state (DONE)
- Read the charter (`autunomous.md`, 1014 lines) + authoritative files (CASE_A_QUEUE_DESIGN §0,
  QUEUE_MICROBENCH_IMPLEMENTATION_REPORT §0.5, RESUME_STATE/WORKING_NOTES top, SIZE_PATTERN_BUILDER_REPORT,
  e7e7223 source).
- Recorded initial state: `INITIAL_STATE.md` + `run_manifest.json`. Switch = queue microbench,
  cover=OFF/telemetry=0/metronome OFF (HW-verified). Hulk+Vision UP. Corpus: base 3-device + multi-CROB
  (real SBO). Restore target = queue microbench.
- Decision: proceed Phase 1 (builder v1.1). Switch untouched.

## CP1 — Phase 1: builder v1.1
(in progress)

## CP1 — Phase 1: extractor v1.1 (DONE, verified)
- Rewrote `size_pattern_builder/extract_inventory.py` -> schema 1.1.0. Corrections applied: flow in the
  transaction key (device,capture_id,flow,transaction_id) + capture_index; chronological order by
  (ts,capture_index); full TCP/IP metadata (flags/seq/ack/ihl/dataofs/phase); strict pure-ACK
  (payload==0 & ACK & !SYN&!FIN&!RST) + ACK-role separation; per-transaction ack_mode_observed;
  data-only retransmission + identical-capture duplicate detection (distinct pure ACKs kept);
  explicit size metrics (capL2_no_fcs / eth_min / with_fcs / wire_occupancy / ip_len / tcp_pl / dnp3).
  RAW + ANALYSIS inventories per scope (base/long/multicrob), documented dedup policy.
- Evidence (ran `extract_inventory.py --scope all`): base raw=9415 analysis=9316 (99 retx/dup
  suppressed); long raw=64111; multicrob raw=98 (real SBO/CROB). **KEY v1.1 CORRECTION:** ack_mode is
  per-transaction — SEL-751 = 300 separate / 298 combined (NOT purely separate); AB1400/ION7550 ~99.9%
  combined. Base capL2 sizes: 54-127 B, 15 distinct.
- Next: generate_candidates.py v1.1 + evaluate_candidates.py v1.1 + tests (delegated, will verify by run);
  corrected report; Gate A + PI review. Switch untouched.

## CP1b — authoritative reading for Phase 3 (impl report §14/§15/§16.5)
- §14 "Level 1 — trace-driven obfuscation evaluation" IS the Phase-3 target: trace-driven, wire-size +
  timing scope, NO live TCP master, NO checksum surgery; pad up to shared states; measure size-leakage
  reduction + overhead. Matches charter §9.
- §16.5 step 2a: the cover=OFF pacer in the loaded microbench is a dcrn_defense2-style absolute-deadline
  recirc-hold. For the SIZE experiment (charter §9.4) I will release directly through the REAL queue OR
  use the hold only as a labelled instrument (timing separated from the real Defense 1/2 results).
- PHASE-3 PADDING FEASIBILITY (charter §6.12/§9.1, impl §14): the loaded P4 pads to COMPILE-TIME 128/256
  headers — a single fixed width CANNOT normalize variable 54-127 B inputs. Level-1 approach = EXACT-MATCH
  on the finite observed input-length set (base corpus = 15 sizes) selecting a finite set of compile-time
  pad headers (or power-of-2 pad headers combined) to hit ONE target (e.g. 128). Synthetic trace-replay
  frame carries the input-size class; no runtime arbitrary resizing. This is the new P4
  `queue_microbench_trace_v1.p4` (Phase 3), NOT a change to the loaded microbench.
- Superseded claims NOT to revive: "TM scheduler paces sparse flow" (refuted); "SEL = purely separate-ACK"
  (v1.1 shows ~50/50 per transaction); single fixed pad width normalizes arbitrary lengths (false).
- Status: generator/evaluator/tests v1.1 delegated (running); will verify by running before Gate A.
