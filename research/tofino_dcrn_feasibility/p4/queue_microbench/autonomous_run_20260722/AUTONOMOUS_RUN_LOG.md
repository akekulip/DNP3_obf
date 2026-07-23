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

## CP2 — Phase 1 builder v1.1 ACCEPTED (verified) + committed
- Independently VERIFIED (re-ran everything): 16/16 tests OK; 12 candidate filenames == candidate_id;
  single-state leakage invariant HOLDS (single128 -> MI(device/op/ackmode/dir)=0 CI[0,0], grouped
  balanced accuracy = chance 0.333/0.500/0.500; single_state_invariant_holds=True); per-direction
  overhead from actual packets (single128 cover=OFF master->out 102.5 B/txn 0.82 kbps, out->master
  26.4 B/txn 0.21 kbps); two-state candidates LEAK operation (two_state_round8 op bal-acc 0.657>chance);
  ranking sensitivity + Pareto {single128, two_state_round8, ack_data_split}.
- Corrected report written (v1.1). Stale v1 flat files removed (in git @ e7e7223). Bulk inventories
  gitignored (regenerable); inventory_summary.json committed.
- Committed builder v1.1 = 89ffef3 (author akekulip, clean). GATE A review launched: DNP3/ICS protocol
  audit (power-systems-expert) + measurement/stats audit (research-scientist), parallel; I integrate ->
  BUILDER_V11_REVIEW.md.

## CP2b — Phase-3 padding-feasibility design (candidate-independent prep, charter §9.1)
- Loaded queue_microbench.p4 pads with TWO fixed compile-time headers pad_s1_h(64B)/pad_s2_h(192B),
  classifies by synthetic UDP dport, has the validated digest telemetry + recirc hold + cover modes.
- For the likely Level-1 baseline single128 (pad every frame to 128 B), the pad delta = 128 - input_len
  VARIES (1-74 B over the 15 base input sizes) -> a single fixed pad width cannot do it (charter §6.12).
  DESIGN (compile-safe): the new queue_microbench_trace_v1.p4 carries a trace-replay header declaring the
  input-size class; option (A) POWER-OF-2 pad headers {1,2,4,8,16,32,64 B} selected by the bits of the
  delta (<=7 headers, any delta 0-127); option (B) exact-match class->one-of-15 fixed pad headers.
  Both are finite + compile-time; validate by local bf-p4c 9.13.1. Original synthetic record preserved.
- Classification for Level-1 = the trace-replay header (NOT full live DNP3/TCP parsing). Telemetry =
  reuse the digest (run_id/seq/input_size/target/state/device/op/dir/txn/ts/reason/qid), A/B gated,
  measurement-only. Cover OFF, no metronome. Release direct through the REAL queue (or hold as a
  labelled instrument). This is Phase 3 (gated behind Gate A + Phase-2 selection); not implemented yet.

## CP3 — Gate A: measurement/stats audit returned CONDITIONAL PASS
- Independent re-run reproduced evaluation.json bit-identically. Core sound: MI plug-in estimator
  correct; constant-feature MI=0 genuine; GroupKFold has NO train/test flow leakage; balanced-accuracy +
  chance null correct; §6.11 overhead is per-transaction (v1 bug fixed), arithmetic exact, 1 Hz cadence
  correct; Pareto dominance correct. Decision-relevant finding ROBUST to permutation null + flow-grouped
  bootstrap: single128 = zero SIZE-channel leak (base corpus); two_state trades padding for a real
  OPERATION leak (MI 0.071, bal-acc 0.657, flow-grouped CI [0.055,0.081]).
- 5 conditions (must-fix before paper; do NOT change the single128 selection): (1) flow-group the MI
  bootstrap / add permutation-null p; (2) state finite-sample MI bias, MI<=2e-4 bits ~ 0; (3) grouped-BA
  CI = LOGO(6 folds)+t not k=2 z=1.96; (4) ranking/Pareto leakage axis = max MI over {device,operation,
  ack_mode} not device-only; (5) scope "single128 leaks zero" to the SIZE channel + fix distinct-sizes
  count (14/15 not 15/16); add the 6-flow/3-device finite-sample caveat.
- Awaiting the DNP3/ICS protocol audit; will apply both sets of conditions, re-verify, write
  BUILDER_V11_REVIEW.md, then Phase 2 (select single128).

## CP4 — Gate A: DNP3/ICS protocol audit returned CONDITIONAL PASS w/ a BLOCKING retraction — FIXED
- FINDING (verified vs tshark + locked ground truth): the earlier v1.1 "SEL-751 ~50/50 separate/combined"
  was FALSE — a corpus-contamination artifact. extract_raw filtered only on port 20000; each base pcap
  also carries 10.0.0.2 (a shared COMBINED device, 904 pkts in SEL751.pcap) which got mislabeled. Real
  SEL-751 (10.0.0.1) = 299/299 = 100% SEPARATE (matches ACK_DELAY_POLICY §5.A + CASE_A_TERMINOLOGY).
- FIX applied (extract_inventory.py): (a) filter each scope to its DECLARED outstation IP (10.0.0.2
  removed); (b) master app-CONFIRM no longer opens a transaction. Re-ran --scope all + VERIFIED:
  10.0.0.2 gone; SEL=299 separate/0 combined; AB1400/ION7550 combined; per-device RESPONSE max SEL 120
  / AB1400 108 / ION7550 115 (base named max = 120, NOT 127 — 127 was the interloper). single128 still
  fits P4 + covers 120; candidates regenerated; 16/16 tests still pass.
- Report REWRITTEN: retraction stated; per-device maxima corrected; "zero leak" scoped to the SIZE
  channel; SEL needs no ACK-mode filler (100% separate); coalescing/segmentation/multi-fragment limits
  documented; finite-sample caveat added.
- Stats auditor RESUMED to apply its 5 rigor conditions to evaluate_candidates.py on the clean corpus
  (flow-grouped MI bootstrap + permutation null; MM bias; LOGO grouped-BA CI; aggregate-MI Pareto axis).
- NEXT: verify stats pass, finalize leakage table, write BUILDER_V11_REVIEW.md (both dims), then Phase 2
  (select single128). Switch untouched.
