---
name: ack-timing-phase1-implemented
description: Phase-1 bounded response-time normalization is BUILT + validated in dnp3_split_harness (timing_policy.py + split_server hook); key empirical findings from executing ack_delay.md
metadata: 
  node_type: memory
  type: project
  originSessionId: c3ef1508-9e17-4f79-bd13-7384aa7ff5ab
---

Executed `ack_delay.md` (2026-07-14). **Phase 1 done & verified; Phase 2 scaffolded, rig-deferred.**
Builds on [[ack-timing-normalization-study]] and [[meeting-2026-07-14-ack-timing-direction]].

**What was built (all in `dnp3_split_harness/`):**
- `timing_policy.py` — reusable policy: `ReleaseScheduler`/`TimingProfile`/`TimingDecision`/
  `FlowTimingState`/`BypassReason` + Phase-2 `plan_ack_response_release()` + `wait_until()`.
  Correct design enforced: `actual_release = max(response_ready, request_arrival + target_delay)`,
  class-independent sampling (NOT native+jitter), per-flow FIFO, 5 fail-open bypasses.
- `split_server.py` — timing hook before `_send_chunks` (insertion point); native mode is
  WIRE-IDENTICAL (hold=0, only adds `timing_decisions.jsonl`). New CLI: `--timing-mode
  native|fixed|bounded --target-delay-ms/--target-min-ms/--target-max-ms/--timing-seed
  --max-hold-ms/--max-queue-depth/--strict-safety/--rto-safe-ms`.
- Tests: `tests/test_timing_policy.py` (22/22 PASS), `tests/loopback_smoke.py` (byte-identity
  ALL PASS; visible time -> target). Scripts: `run_timing_experiment.py`, `characterize_ack_traces.py`,
  `rto_probe.py`, `ack_separation_probe.py`, `attacker_eval.py`.
- Reports: `reports/ack_timing_implementation_report.md` (the §11 capstone) + ack_trace_*,
  rto_probe_*, ack_separation_*, attacker_eval_*, timing_experiment_results.*; `profiles/*.json`.

**Key EMPIRICAL findings (load-bearing for next steps):**
- Trace ACK behavior (22,988 txns): SEL-751(10.0.0.1) 100% SEPARATE-ACK, ACK->resp gap ~12.9ms
  median (the Formby CLRT fingerprint); AB1400(10.0.0.12)/ION7550(10.0.0.11)/ref(10.0.0.2)
  COMBINED (gap ~0). Requests are READ(fc1)+DIRECT_OPERATE(fc5); responses fc129.
- **TCP RTO measured ≈211 ms** (Linux TCP_RTO_MIN, `ss` backend) — NOT the assumed 200; safe
  hold ~105 ms. Targets 10-30 ms are safe. (loopback; rig is authoritative.)
- **Normalization floor MUST exceed native latency (~16 ms) or it's a no-op**: uniform[10,15]
  does nothing (native already >15ms); need >=~20-25ms. Pick target >= native p95.
- **Residual leakage survives timing defense**: response SIZE (37/54 vs 37/61 B) + ACK-mode are
  untouched (no byte-preserving padding this phase) -> all-features device-ID stays ~0.90 even
  after timing normalization (native 0.897). Timing defense closes the TIMING channel only.
- Detect-the-defense: constant-target highly detectable (AUC 0.99); bounded jitter less so
  (0.887) -> normalization-vs-stealth tradeoff.

**RIG MATRIX NOW DONE (2026-07-14 late):** ran the deferred Vision↔Hulk matrix. Deployed
`dnp3_split_harness/` to both rig hosts first (they only had the pre-split combined dir).
7 configs × 30 integrity-poll reps = **930 timed txns, 0 miss / 0 bypass / 0 reset**,
byte-preservation PASS all. Fixed pins exactly (fixed-25 → 25.000 ms server-side,
median=p95=p99=max); full and CRC-split identical. **Wire tcpdump (Hulk eno1, sudo — lab pw
works via `sudo -S` over ssh stdin; DNP3 rides the 1G mgmt net eno1): 0 retransmit / 0 reset /
0 dup-ack / 0 ooo; fixed-25 wire req→resp 25.36 ms ±0.1 ms.** Confirms 25 ms hold << RTO
(~211 ms). Report `reports/rig_timing_matrix_results.md`; artifacts `reports/rig_timing/`.
**Scope caveat (important):** rig outstation is the *replay server*, so native≈1 ms NOT
real-device ~16 ms → this validates mechanism+safety+byte-preservation+TCP-health on real hw,
NOT device size/timing-leak closure (still needs physical SEL-751/AB1400/ION7550).

**Phase-2A (§5A) NOW RIG-VALIDATED (2026-07-14):** ran the socket ACK-separation probe on the
rig (server on Hulk :20051, client on Vision; capture via **server-side tcpdump on Hulk eno1** —
the probe's own tshark capture returns empty under sudo-over-ssh, so use external tcpdump).
Swept app-write delays 0–50 ms (1808 txns): **delaying the write induces a pure TCP ACK before
the response — NO forging — sharp threshold at 40 ms (Linux delayed-ACK timeout, kernel 6.8)**;
≤38 ms COMBINED (piggyback), 40 ms 0.93, ≥42 ms 1.00; 0 resets; raw-packet verified. Bounds
Phase 1 (10–25 ms targets stay combined, CLRT gap ~0) and enables Phase-2 gap manipulation by
holding ≥40 ms (natural separate ACK, no P4 recirc) at cost of a ≥40 ms visible floor. Report
`reports/ack_separation_rig_results.md`; artifacts `reports/ack_separation_rig/`.

**Still remaining:** Phase-2B live ACK/response INDEPENDENT delay (needs to act on the
kernel-owned pure ACK → still rig/P4); real-device leak-closure run (physical SEL-751/AB1400/
ION7550); then P4/Tofino port.

**Before/after + ACK-fingerprinting + educational HTML added 2026-07-15 (full re-audit clean):**
Re-audited ack_delay.md vs code: §1-11 all present, 22/22 tests pass, rig reports real
(rig_timing 930 txns, ack_separation_rig 1808 txns @ 40ms threshold). Added 3 new deliverables:
- `trace_before_after.py` → `reports/trace_before_after.{csv,json,md,png}`: drives the SHIPPED
  timing_policy over the REAL per-txn native timings (characterization CSV). Combined devices:
  req→resp native ~16ms → fixed-25/bounded[20,30]. SEL-751 gap: ack-delay-only −8ms (12.2→4.2),
  response-delay-only +8ms (→20.2), gap-normalized→20.0 (CV→0). Panel-3 = ECDF (delta-safe).
- `ack_fingerprint_eval.py` → `reports/ack_fingerprint_eval.{json,md}` + `ack_fingerprint_clusters.png`:
  ACK-based device fingerprint before/after, capture-level split, sklearn RF+LR + KMeans/Agglom
  (ARI/NMI/purity). **KEY FINDING: gap-normalization does NOT defeat ACK fingerprinting** —
  ack_only RF acc UNCHANGED 0.810→0.810 (native→implemented), kmeans ARI 0.654→0.658, because a
  SEPARATE ACK STILL EXISTS (pinning its gap ≠ hiding the mode). Only the `plus_ackmode` what-if
  (hide ACK mode too, NOT byte-preserving) drops ack_only→0.400 chance, ARI→0.000; even then SIZE
  leaks (all→0.500>0.400 from ION7550 61B). Scatter (req→ACK, gap) plane shows SEL-751 stays its
  own cluster after the implemented defense.
- `reports/ack_delay_master_report.md` (everything-in-one narrative incl. socket program +
  how-ACK-delayed for combined vs separate) and `reports/ack_delay_tutorial.html` (self-contained
  326KB animated educational page: combined/separate ACK anims, interactive 40ms delay→ACK-mode
  slider, hold-until-deadline viz, before/after toggle w/ real numbers, both real PNGs embedded
  base64; dark oscilloscope theme; verified via headless chrome, JS clean, 22 balanced sections).
Delivered the HTML to Philip. See [[ack-timing-normalization-study]] [[split-pad-timing-policy-study]].

**Audit + 3 fixes applied 2026-07-14 (3-agent independent audit of ack_delay.md vs code):**
Audit verdict: Phase 1 complete/honest, Phase 2 scaffolded-not-wired (5B is a scheduling
calculator — a user-space app CANNOT move a kernel-owned pure TCP ACK, so ack-delay/independent/
gap modes are inherently rig/P4 work, not a wiring TODO). Fixes: (1) `attacker_eval.py` now runs
sklearn RF+GB — **sklearn 1.3.2 IS on host system `python3`** (`~/.local/lib/python3.8`), only the
research venv lacks it; run with `python3 attacker_eval.py`. Trees corroborate: native GB 0.917 /
RF 0.889 vs logreg 0.897, all stay ~0.87-0.92 defended. RF/GB now also run in detect-the-defense
(constant-25 AUC RF/GB 0.999 vs LR 0.990) and permutation importance (resp_size/req_size dominate;
trees credit timing feats slightly more than linear LR). Run ≈2min. (2) `timing_policy.TimingDecision` +
`split_server` now capture all 6 mandated timestamps (added `send_start_ns`/`send_complete_ns`
stamped around `_send_chunks` in `serve_once`; `_apply_timing` returns the decision, logs after
send). (3) report [20,30] figure was NOT stray — it's from `tests/loopback_smoke.py` (bounded
20-30), distinct from the §6 matrix (bounded 15-25); added source attribution. 22/22 tests still
pass, byte-identity ALL PASS.
