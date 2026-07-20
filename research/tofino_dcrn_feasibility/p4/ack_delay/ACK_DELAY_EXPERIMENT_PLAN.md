# ACK-Delay Experiment Plan — conditions, topologies, metrics, attacker eval, acceptance

Section-27 items 3 (file-by-file plan), 7 (local compile plan), 8 (switch gate) + Section-25
`ACK_DELAY_EXPERIMENT_PLAN.md`. Synthesised from the research-scientist review. Design only.

## 1. Claims as falsifiable hypotheses (pre-registered)
| ID | Claim | Refuted if | Rig |
|---|---|---|---|
| C-MECH | The switch enforces controlled ACK/response timing (not uncontrolled recirc) | release cause is MAX_PASS, or delay variance ≥ target | T2→T3 |
| C-SAFE | No transport/byte harm | any policy-induced drop/reset/retransmit(Δ>0)/ordering violation; byte mismatch | T2→T3 |
| C-A | Case A collapses ACK→response to a small common bounded band, minimal added req→resp latency | defended CLRT still separable, or added latency > declared bound | T3 (T4 efficacy) |
| C-B | Case B moves ACK→response to a common bounded band, device-independent, RTO-safe | assigned target correlates with device/size; deadline-miss/RTO events | T3 (T4 efficacy) |
| C-NOCHAN | The hold creates no new device-correlated size/timing channel | corr(size, scheduler_error) or corr(size, added_latency) ≠ 0 | T3 |
| C-RESID | ACK mode + response size survive as residual channels the defense does not close | post-defense joint classifier drops to chance | T3/T4 |

C-RESID is **expected confirmed** (residuals remain) — pre-registering it keeps the paper honest.

## 2. Experiment matrix E0–E5 (§15) — unit of analysis = the independent HARDWARE RUN
≥3 independent hardware runs (5 preferred) per efficacy condition for a between-run CI; transactions
inside a run are autocorrelated and count only toward mechanism/rare-event power.

| Exp | Policy | Traffic | Proves | Runs |
|---|---|---|---|---|
| **E0** | Native/bypass | all 3 devices | native CLRT/size/retransmit baseline + transport noise floor (ION7550 has native retransmits → score Δ-over-native) | ≥3/dev (T3), ≥3 (T4) |
| **E1** | Case A, **fixed** guard | SEL751 separate | ordering machine: ACK-before-response, response not artificially delayed. **Calibration only — a constant guard is itself a fingerprint** | ≥2 |
| **E2** | Case A, **common-bounded** guard | SEL751 separate + ≥3 SEL751 config profiles | real Case-A efficacy: within-separate CLRT bal-acc → 1/k AND detect-the-defense AUC ≈ 0.5 | ≥3–5 |
| **E3** | Case B, **fixed** target | SEL751 separate | deadline enforcement; release caused by deadline not MAX_PASS. **Calibration only** | ≥2 |
| **E4** | Case B, **common-bounded** target | SEL751 + profiles | Case-B efficacy + RTO-safety + device-independence of assigned target | ≥3–5 |
| **E5** | Combined extension (request-relative) | AB1400 + ION7550 | combined req→resp shaping — **reported SEPARATELY, never folded into CLRT** | ≥3 |

**De-degeneracy fix (critical):** the current corpus has ONE separate-ACK device → a CLRT-only device
classifier is degenerate. Populate the separate-ACK class with **≥3 SEL751 config profiles** (poll
interval / Class-0 point count / event buffering — anything that plausibly moves native CLRT), each
its own `profile` with disjoint base + "L" captures for the grouped split. Optionally augment with
Formby's published per-device CLRT stats (labelled literature-augmented, never as rig-measured).

## 3. Formby-style attacker evaluation (§19) — exact
- **Feature families:** `clrt_mean`, `clrt_var`, `clrt_hist` (~200 bins, edges frozen from pooled
  native BEFORE defended data is seen), at observation windows W ∈ {1, 5, 10, 25, 50, 100} txns.
  **Plus** (mandated by the "Case A relocates the signal" finding) a **`req→ACK` feature set** and a
  **joint `(req→ACK, ACK→resp, size)`** classifier — CLRT-alone is too weak and would hide Case A's
  relocation. Separate non-CLRT families (`ack_mode`, `size`) quantify the residual (C-RESID).
- **Classifiers:** interpretable primary (nearest-centroid + multinomial logistic, reuse
  `attacker_eval.py`) + a strong-attacker upper bound (RF/GBM; report UNAVAILABLE, never fabricate, if
  sklearn absent). Standardise on train folds only.
- **Grouped split — never split same session/run/replay-sequence across train/test.** Group key =
  `(hardware_run_id, tcp_session_id/4-tuple+ISN, replay_sequence_id, source_capture_id)`; splitter =
  `GroupKFold`/`LeaveOneGroupOut`; canonical primary = train on base capture, test on disjoint "L".
- **Metrics:** balanced accuracy (primary), macro precision/recall, full confusion, per-profile
  breakdown (never pooled). Report `n_independent_hardware_runs` and `n_classifier_resamples`
  **separately** — resamples are pseudo-replication. Success = post-defense bal-acc within CI of
  chance = 1/k **AND** a distributional-equivalence test (two-sample KS / energy distance) showing the
  defended per-profile CLRT distributions actually coincide.
- **Combined transactions:** CLRT missing by definition → **exclude from the CLRT classifier; never
  zero/sentinel-fill.** Analyse ACK mode in a separate binary analysis (it is the dominant device
  signal here and the defense does not change it → the primary residual).

## 4. Calibration (§11–12) — from data, without device-specificity (anti-circularity)
Native CLRT is used **only to set safe bounds** (readiness lower, RTO upper), **never to shape the
target** (else the "common" target is secretly SEL751-shaped). Target **shape** is a policy choice
(uniform over a band).
- **Case B band [a,b]:** a = native CLRT p95 (SEL751 ≈ 17 ms) + scheduler guard → **a ≈ 20–25 ms**;
  b ≤ safely below *measured* effective RTO and operational tolerance → **b ≈ 40–50 ms**. Discrete band
  e.g. {25,30,35,40}(–50) ms. Dr. Lin's 33 ms sits correctly inside it.
- **Case A guard band:** [g_min, g_min+w], g_min = minimum reliable ordering guard from the GATE-5
  microbench (single-digit ms expected), w = 2–5 ms so the defended CLRT is a *small distribution*, not
  a constant.
- **Target index:** a **global** transaction counter over ALL eligible flows indexing a preloaded,
  seeded register sequence — never per-flow, per-IP, per-size, per-mode. Record `seed`, `sequence_id`,
  `global_txn_index` per txn; empirically verify `corr(assigned_G, device) ≈ 0` and
  `corr(assigned_G, size) ≈ 0` as a **first-class E4 pass condition.**

## 5. Size / segmentation channel (§14)
Compute per policy with CI: `corr(size, scheduler_error)`, `corr(size, observed_CLRT)`,
`corr(size, added_latency)` — all ≈ 0 required (a size→latency dependence re-creates a device channel
through the defense). **Caveat:** current captures have only 2 discrete single-segment sizes per device
→ use Mann-Whitney U + effect size (not Pearson over 2 levels), and **introduce a controlled larger,
multi-segment response sweep** before claiming C-NOCHAN or segment-safety. Segment checks: seq
monotonicity, no inversion/dup/drop, reassembly success, byte-identical DNP3 payload (compare payload
hash exactly; account for checksum offload; never compare capture timestamps as bytes).

## 6. Metrics schema (§18) — the per-transaction record (add the 7 traceability fields)
Base set (from spec §18) + **added:** `global_txn_index`, `target_seed`, `sequence_id`, `rto_observed`
(per session), `config_profile_id`, `capture_point`/`observer_id`/`clock_source`, `payload_sha256`/
`tcp_seq_first`/`tcp_ack`. Manifest-level: `commit_hash`, `bf_p4c_version`, `sde_version`,
`queue_config_id`, `ethtool_offload_state(tso/gso/gro/lro)`, `native_retransmit_baseline`,
`run_start_epoch`. Primary timing = `request→ACK`, `ACK→response`, `request→response`; **primary
Dr. Lin metric = CLRT = ACK→response** (never call `request→response` CLRT).

## 7. Topologies (§16) & the file-by-file implementation plan (§27 item 3)
Progression T0→T4. **Reuse existing tooling** where possible.

| Stage | What | Files (new / changed) |
|---|---|---|
| **T0 local compile** | bf-p4c 9.13.1 Case-A build; resource report | `p4/ack_delay/dcrn_ackA.p4` (new, Case-A variant), `p4/ack_delay/build_local.sh` |
| **T1 scratch fwd** | on-switch 9.13.2 transparent forwarding + rollback | reuse `dcrn.conf`/`launch_dcrn.sh`; controller `p4/ack_delay/ackA_setup.py` (new) |
| **T2 single-host hairpin** | validated dp8/dp9/dp68 + VEPA macvlans; real pydnp3 + device payloads | reuse this session's rig recipe (`hulk_setup_full.sh`, `dp8_loopback.py`); `run_master.py --suppress-startup-unsolicited` (flag, §8 below) |
| **T3 Vision↔Hulk** | authoritative master-facing external capture; physical NICs; offloads recorded | rig scripts; `ethtool` offload manifest |
| **T4 physical device** | SEL751 behind the switch = authoritative separate-ACK CLRT test; AB1400/ION7550 combined | (hardware acquisition — Philip) |

Python reference model + tests (§25 tests/): `p4/ack_delay/refmodel/ack_state_machine.py` (executable
Case A/B state machine to validate ordering/zero-inversion in simulation), and `tests/` — policy
tests, state-transition tests, target-selection tests (corr(G,device)=0), fail-open tests, parser
classification tests, conformance vs the P4 behaviour. Analysis reuse: `extract_payloads.py`,
`split_server.py`, `attacker_eval.py`, `ack_fingerprint_eval.py`, `characterize_ack_traces.py`,
this session's `ba_dev.py`/`split_ba.py`/`clrt_baseline.py`.

## 8. `run_master.py` startup flag (§6) — gate the unsolClassMask change
The current `run_master.py` change that clears `unsolClassMask` (added this session for READ-only
replay) MUST move behind an explicit `--suppress-startup-unsolicited` flag: default = normal pydnp3
behaviour; flag documented; the experiment manifest states when it is used and why
("Startup unsolicited enablement was disabled because the replay server contains only captured Class-0
request-response mappings"). **This is a required change before the next replay run.**

## 9. Local compile plan (§27 item 7)
1. Author `dcrn_ackA.p4` (Case-A variant of `dcrn.p4` per STATE_MACHINE §5).
2. `PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH bf-p4c --target tofino --arch tna -g -o OUT dcrn_ackA.p4`.
3. Record: errors, warnings, **stage count (≤12 hard limit; current DCRN 9–11)**, critical path,
   table/SRAM/TCAM, power. Iterate on fit (Case A est. 10–12 stages — the fit-risk case).
4. Author `dcrn_ackB.p4` as a **compile-time variant** (not a runtime mode) once the clock fix design
   is settled; compile separately. No switch touch for any of this.

## 10. Switch-touch gate (§27 item 8, §24)
**No authorized switch window exists** (the co-resident program owns the chip; the last window was
restored this session). Before ANY switch touch: record current program + port + TM config; prepare
rollback + cleanup; show the exact commands; **request explicit GO.** The first switch window (GATE 4
→ then GATE 2 probe) does one gated change only, collects evidence, restores the co-resident program,
verifies normal forwarding, and stops. Sequence once authorized: **transparent-forwarding + rollback
(GATE 4) → the 2×2 clock-vs-pacing probe C1–C4 (attribute the 38–100 ms, validate the egress-stamp/
pacing fix) → Case-A microbenchmark E1 (event-governed, fixed guard, zero-inversion) → Case-B after the
clock fix.** Each gate stops and reports before the next mechanism.
