# Final Synthesis — ACK-Bearing DNP3 Response Timing Normalization

_The spec's §13 closeout, after the Agent-G skeptical-reviewer pass and the corrections it
required. Reviewer verdict: **major-revision** — sound direction, real measured leak, honestly
verified literature, reference-grade evaluation plan; the required fixes (rescope "device-identity"
→ configuration/complexity; mark the n=1-per-N sweep as unreplicated; "designed to remove", not
"destroys"; provisional not "measured" budget; safe watchdog; add the Class-0 DB-size and
normalizer-detectability experiments; add Traffic Morphing; fix the NetWarden venue and the β-power
number) have been applied across the deliverables and the HTML briefing._

## Evidence-class legend
**[M]** measured this session · **[S]** standard-defined · **[P]** paper-reported (abstract-level) ·
**[V]** vendor/kernel-documented · **[I]** engineering inference · **[H]** untested hypothesis.

## Final recommendation

**Recommended mechanism:** Byte-preserving, release-timing-only **response-time normalization** —
release each shapeable outstation response at `max(response_ready, request_time + target)`, with
`target` drawn from a **class-independent** distribution, under a strict budget with immediate-
release fallback. [I, grounded in predictive-mitigation theory [P]]

**Recommended terminology:** "Byte-preserving in-network **response-time normalization** of a DNP3
outstation's **device-configuration** processing-time leak." Say *device-configuration /
request-complexity*, **not** *device-identity/fingerprint* (identity needs ≥2 stacks). Reserve
"fingerprint" for the attack we counter (Formby CLRT) and the future cross-device result.

**Software implementation:** Application-layer absolute-deadline scheduler inside the existing
replay/split server (`monotonic_ns` + one `sleep`; no thread-per-packet, no busy-wait). Configurable
target distributions; strict budget + immediate-release fallback; full telemetry; reproducible
seeds; CSV/JSON export. Kernel/eBPF/DPDK/timing-wheel machinery is **cited to reject** (over-scaled
for DNP3's rate). [I/V] — *designed, not yet built or run.*

**Hardware implementation:** Native pacing/gap-normalization on Tofino/DPU/FPGA [V/P], but these
bound *rate*, not *latency*. First-packet **absolute** delay is native on **BlueField** (Accurate
Send Scheduling) [V] and **FPGA** (calendar queue) [P] — the honest hardware homes. On **Tofino 1**
it is reachable only via an **unbuilt recirculation + timestamp-deadline loop** [I]: de-risked
future work, never a result. NetWarden/ditto are the closest published Tofino precedents [P].

**Safety budget:** Bound every per-packet hold and the cumulative per-transaction latency below the
master's **effective TCP RTO** — which **must be measured on Vision** first; the ~200 ms figure is
the Linux `TCP_RTO_MIN` floor [V], not universal. Operating point 15–25 ms; hard release-watchdog
≤ 0.5× the *measured* RTO (never a fixed 150 ms guessed against 200 ms). DNP3 timers (5–60 s) are a
backstop, not the binding constraint. [S/V/I]

**Traffic classes to bypass:** Application CONFIRM (M→O) [S]; unsolicited responses [S]; any control
(SELECT/OPERATE/DIRECT_OPERATE) flagged critical by an **operator criticality allowlist** —
default-bypass all control function codes unless explicitly whitelisted, because DNP3 fields encode
operation *type*, not physical *criticality* [S/I]. Shape: Class-0/event READ responses (full);
SELECT/OPERATE responses only to a fixed N-independent deadline under the allowlist.

**Target distribution:** A **class-independent** schedule — constant, uniform-within-budget,
**bucketed** (Köpf–Dürmuth) [P], **size-decorrelation** (the *hypothesized* headline policy, to be
confirmed — its latency advantage over constant-time is a pre-registered test), or **decoy-match**.
The common target must exceed the worst native time to stay non-averageable. [P/H]

**Deadline-miss behavior:** Fail **open** — release immediately and record a policy miss/bypass when
the safety margin is insufficient. Safety dominates privacy. [I, per spec §7D]

**Attacker model:** Passive on-path observer reading unencrypted DNP3, no inject/block, **repeated
polling** (the SCADA case). Attacker ladder A1–A8: threshold → template → RF → GBM → SVM → 1D-CNN →
**defense-aware (A7)** → **repeated-observation averaging (A8)**. The averaging attacker is the
instrument that makes normalization-beats-jitter measurable and is **attacker-model-dependent**. [I/P]

**Security metrics:** Classifier accuracy/BA/F1/AUC drop + Privacy Gain (McNemar/DeLong); regression
β & R² before/after; **conditional** MI `I(T; N | size)` (KSG + bootstrap CI) — *not* marginal, since
the size channel stays open in the byte-preserving phase; Wasserstein-1 / KS / JS to the target
distribution; A8 averaging half-life M½. [I/P]

**Performance metrics:** Added latency (mean/median/p95/p99/max), SBO transaction time, poll-cycle
time, throughput, CPU/memory; the **privacy-vs-latency Pareto** with a shaded safe-operating region
(added latency < measured-RTO margin ∧ correctness = 100%). [I]

**Main novelty:** The **combination** — a *measured* OT **device-configuration** processing-time leak
+ release-timing-only **byte-preserving** mechanism + a **live-DNP3/TCP-RTO** correctness bound +
in-network pass-through. NetWarden shows byte-preservation alone is not new; the anchor is the
measured OT leak and its normalization. [I]

**Main weakness:** The flagship leak is **n = 1 per N-level** (unreplicated) and sits on **control**
responses the safety rule bypasses, while the *database-size* channel the study is named for (Class-0
read plane) is **unmeasured**; no defense has been run; the Tofino realization is unbuilt; a lone
shaped device is a **beacon**; device-classification needs ≥2 stacks not yet available. [stated plainly]

**Immediate next experiment:** After **measuring the effective RTO on Vision**, run **E1′** — a
*replicated* (≥30/N) **Class-0 read-plane response-time vs. static point-count** sweep (the
safe-to-shape, DB-size channel) with bootstrap CIs — then **E2** (one defended run: β→0, MI in the
permutation-null band, byte-preservation, 0 retransmits/resets). [H → to become M]

**Evidence confidence:** The *measured relationship* is **high** as a single-device 10-point line,
**medium** as a general/replicated law (n=1/N). Transport & DNP3 constraints: **high** ([S]/[V],
source-verified). Literature: **high** integrity (metadata/abstract-level, no full texts; 2 preprints
flagged). Software design: **high** as design, **unvalidated** as built. Hardware: **high** for
native DPU/FPGA, **low/inference** for the Tofino recirc-hold. The defense's efficacy: **untested**.

## What is measured vs. claimed (the one-line discipline)
- **Measured fact [M]:** piggyback 9/9; req→ACK 0.239 ms, req→response 1.014 ms; CROB↔time slope
  0.179/0.214 ms/CROB, R² 0.9985/0.9954 (n=1 per N).
- **Standard/vendor [S/V]:** DNP3 timers 5–60 s; no link ACK; `TCP_RTO_MIN` floor; TM bounds rate;
  BlueField/FPGA absolute-delay native.
- **Paper-reported [P]:** CLRT is an ICS fingerprint; jitter is averageable; predictive mitigation
  and bucketing bound leakage; NetWarden/ditto in-network shaping.
- **Inference [I]:** the traffic-class table; the recirc-hold affordability; the software scheduler.
- **Hypothesis [H]:** the defense removes the leak; P6 dominates jitter at lower latency; DB-size
  correlation; cross-device classification.
