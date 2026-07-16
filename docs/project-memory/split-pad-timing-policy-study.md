---
name: split-pad-timing-policy-study
description: "Split/pad/timing combined-policy DNP3 study — the dual-channel leak, the padding negative result, and the when/how decision policy"
metadata: 
  node_type: memory
  type: project
  originSessionId: 62e3e612-b15f-440c-86bd-58db8d47cd63
---

Nine-agent + hostile-reviewer research/design study (2026-07-13, per `when_how.md`, Dr. Lin) on
**WHEN to split, pad, and normalize timing, and HOW to combine them** for DNP3 obfuscation against a
passive on-path observer. Builds on [[ack-timing-normalization-study]]. RESEARCH/DESIGN ONLY; no code
changed; byte-preserving phase. Artifacts in repo-root `research/split_pad_timing_policy/` (19 spec
deliverables + final_synthesis.md + measured_evidence.md + GROUNDING.md + 9 agent_reports).

**The study's spine (measured this session, scapy over existing multi-CROB sweep PCAPs, no code
changed):** CROB count leaks on **BOTH** channels — **size 14.6 B/CROB R²=0.9999** (37→256 B, N=1→16,
even cleaner than timing) AND **timing ~0.18–0.21 ms/CROB R²≈0.99**. Read-plane size ∝ point count
(~5.7 B/pt). **Same n=1-per-N / one-device caveat as the timing study.**

**The core, publishable finding — an asymmetry + two negative results:**
- **Timing is closeable now** (class-independent normalization; un-averageable, unlike jitter which a
  repeated-poll observer averages away).
- **Size is NOT closeable in-phase:** split **preserves total bytes** (sum-the-chunks recovers size) and
  at finest granularity the chunk count = CRC-block count ∝ size, so split **relocates** the leak to
  packet count / creates a **beacon**; and **NO byte-preserving DNP3 padding exists at any layer**
  (measured invalid-index dead end, generalized to the parser: no length field, 7-qualifier whitelist,
  no NUL/padding object; valid filler = real data/control). Closing size needs a FUTURE encrypted-tunnel
  phase (~+590% bw per control response).

  **⚠ SUPERSEDED for READ responses (2026-07-15, rig-validated):** the "no byte-preserving padding" result
  is about *frame-level byte-stuffing*. **Application-level padding via extra REAL Class0 input points DOES
  work** and is byte-legitimate: give the OpenDNP3 outstation configured-but-inert points → its own Class-0
  response grows to a common size, valid CRCs (native), master decodes all, no error, no reset. BUILT in
  `run_outstation.py` (`--pad-analog/--pad-binary/--pad-counter`; also switched configure_stack to per-type
  `DatabaseSizes` — AllTypes returned all db_size slots so size tracked db_size not point counts). RIG:
  devA 214 B (40 pts) vs devB 361 B (80 pts); devA + 40 pad pts = **361 B byte-identical to devB**, 0
  resets. See [[ack-timing-phase1-implemented]], `reports/pad_rig_results.md`. (Closes the READ-plane size
  channel; device-ID 0.90→0.797 effect still a trace-feature sim — one rig ≠ three devices. Control-plane
  size / tunnel arguments unaffected.)

**Combined policy:** shape the read plane aggressively (split B1 paced + timing normalization), **bypass
the control plane by default** (control = lowest-privacy-value + highest-safety-cost; read plane =
high-value + low-risk) via an operator criticality allowlist; record residual size leakage; fail open.

**Load-bearing corrections (respect in any paper):**
- Master reassembles ANY byte-offset split (stream-oriented link parser); **CRC-block alignment is a
  defense/auditability choice, NOT a reassembly requirement.**
- A split survives the wire via **PACING, not TCP_NODELAY** (autocorking/GSO re-merges a zero-delay split).
- RTO budget is **THREE inequalities** (initial hold < RTO; each per-hop gap < RTO; cumulative <
  5 s app/10 s SBO) — NOT one cumulative-vs-RTO sum. **bpc=1 is feasible** (measured 0-retransmit
  1.41 s split). Split binds on **Hulk tail-RTO**; timing hold binds on **Vision request-RTO**. Measure both.
- **Threat-model caveat (reviewer's #1 attack):** cleartext DNP3 lets a full-DPI observer read CROB
  count off the payload → the metadata defense targets a **no-DPI observer** now, full value only under a
  **future tunnel**; and the cleartext in-network primitives (FC-parse, CRC-split) don't survive
  encryption (shaping relocates to endpoints). The **A0 direct-payload-read baseline** is the single most
  important missing experiment.
- Software engine = **per-flow FIFO deque** (not a global min-heap); target host **Python 3.8**. Tofino
  can PACE split chunks but **cannot CREATE the split** (needs TCP-seq rewrite). BlueField ASS / FPGA
  calendar queue = native absolute-delay homes.

**Reviewer (Agent J): major-revision** — held on 8/9 attack points, all new citations verified, codename
clean; the blockers (RTO model, threat-model reconciliation, malformed matrix rows) and should-fixes were
applied. bibliography.bib = 115 (101 prior + 14 new verified: wang2015seeing, juarez2014critical,
nagle896, tcp7, seg-offloads, panic, hxdp, liu-bluefield2, mlx5, NSGA-II/III, Zitzler, pymoo, Haimes).

**Next experiments:** A0 direct-read baseline (most important) + measure effective RTO (Vision+Hulk) +
replicate n=1/N leaks (E1/E1′ ≥30/N) → one defended split+timing run. **No defense built/run yet.**
