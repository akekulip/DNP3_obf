# Implementation Roadmap — Staged Path to a Publication-Ready System

_The staged roadmap requested by the spec. Each phase names its precondition, deliverable, success
bar, and the byte-preserving/future-phase boundary. Research/design only until Phase 1 is authorized.
2026-07-13._

## Phase 0 — Baseline measurement (precondition for everything)
- **Do:** (a) **Measure the effective TCP RTO** on Vision (for timing holds) and Hulk (for split tail)
  — `sysctl net.ipv4.tcp_retries2`, `ip route … rto_min`, and the observed request→first-retransmit
  delta. (b) **Replicate the dual leak** (E1/E1′): ≥30 repetitions per N for both response *size* and
  *timing*, bootstrap CIs on the slopes; add the **Class-0 read-plane point-count sweep** (the
  database-size channel the study is named for, currently unmeasured).
- **Deliverable:** a replicated leak dataset with within-N variance + CIs; the measured RTO values.
- **Success bar:** R² with a real within-N σ (not the n=1 line); RTO values with backoff confirmation.
- **Why first:** every downstream claim, budget, and optimization is gated on this (Precondition #0).

## Phase 1 — Software split + timing (byte-preserving; buildable now)
- **Do:** implement the application-layer policy engine in the replay/split server — per-flow FIFO,
  monotonic-deadline release, split-only / timing-only / split+timing modes, target profiles,
  measured-RTO-fraction watchdog, immediate-release fallback, reproducible seeds, residual-size-leak
  telemetry (Python 3.8, dependency-free).
- **Deliverable:** the engine + a rig run per mode.
- **Success bar (the splitting bar):** byte-preservation asserted, DNP3 CONFIRM, 800-measurement
  count, **0 retransmits / 0 resets / 0 reorder**, timing-channel β/MI driven into the permutation-null
  band, split paced so it survives a mid-path capture.
- **Boundary:** byte-preserving; no padding, no CRC recompute, no proxy.

## Phase 2 — Safe padding investigation (mostly a negative result to confirm + a future design)
- **Do:** confirm the parser-level padding negative result on the rig; measure whether inert decoy
  read-plane points (if a gateway/RTAC can expose them) are distinguishable from real points [H];
  design (not deploy) the encrypted-tunnel padding architecture and its differential-privacy shaping
  budget.
- **Deliverable:** a documented negative result + a future tunnel-padding design + the inert-point
  distinguishability measurement.
- **Success bar:** the negative result reproduced; the distinguishability question answered with data.
- **Boundary:** tunnel padding and endpoint-cooperating mechanisms are **future / protocol-modifying**
  — designed here, not built in the byte-preserving phase.

## Phase 3 — Tofino pacing / gap normalization (in-phase hardware)
- **Do:** Tofino Stage 1 (classify + telemetry) + Stage 2 (pace already-split chunks, normalize
  inter-frame gaps via TM); the split itself is created upstream (software/DPU).
- **Deliverable:** the P4 Stage-1/2 pipeline + a Hulk/Vision hardware run.
- **Success bar:** in-network chunk pacing + gap normalization at line rate, byte-preserving, 0
  retransmits; resource fit within the stage/queue/SALU budget.
- **Boundary:** Tofino cannot create the split or do first-packet absolute delay in-phase.

## Phase 4 — Absolute-delay hardware (DPU/FPGA, and the Tofino recirc-hold as research)
- **Do:** first-response absolute delay on **BlueField** (Accurate Send Scheduling) or **FPGA**
  (calendar queue) — the native homes; optionally prototype the **Tofino recirc-hold** as a research
  artifact (currently unbuilt/unmeasured).
- **Deliverable:** a measured absolute-delay timed-release element + the Tofino recirc-hold
  feasibility result (positive or negative).
- **Success bar:** ms-scale absolute delay with sub-ms scheduling error; the recirc-hold either works
  within bf-p4c limits or is documented as infeasible (a valid result either way).

## Phase 5 — Multi-device evaluation
- **Do:** obtain a second DNP3 stack and/or a real relay/RTAC; run the device-classification attackers
  (device-disjoint CV), the detect-the-defense/beacon attacker, and a cross-device anonymity-set /
  fleet-shaping study.
- **Deliverable:** the classification and beacon results with confidence intervals.
- **Success bar:** any device-identity/classification wording earns its evidence (≥2 stacks); the
  anonymity-set benefit demonstrated on a shaped fleet.

## Phase 6 — Publication-ready integrated system
- **Do:** integrate split + timing (+ future tunnel padding as the size story) into one policy engine
  with the multi-objective Pareto (privacy vs latency / bandwidth / hardware) and per-platform
  operating points; write the paper around the **decision policy + the two negative results + the
  measured dual-channel leak**.
- **Deliverable:** the integrated system, the Pareto frontiers, and the manuscript.
- **Success bar:** the honest asymmetry (timing closeable, size residual) supported end to end;
  correctness bar met for every reported operating point; no claim exceeds its evidence tier.

## Dependency graph
```
Phase 0 (measure RTO + replicate leaks) ── gates ─▶ everything
Phase 1 (software split+timing) ──▶ Phase 3 (Tofino pace) ──▶ Phase 4 (absolute delay HW)
Phase 2 (padding negative + tunnel design) ──▶ (future protocol-modifying phase)
Phase 5 (multi-device) ── gates ─▶ any classification claim
Phase 1..5 ──▶ Phase 6 (integrated system + paper)
```
