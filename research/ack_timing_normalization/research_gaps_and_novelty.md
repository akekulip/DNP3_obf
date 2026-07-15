# Research Gaps, Novelty, and Risk — Skeptical Assessment

_Synthesis of Agent A's novelty analysis (RQ8) and the study team's findings, written to
anticipate a hostile IEEE/ACM reviewer. Agent G (skeptical senior reviewer) reviews this and
every other deliverable in the synthesis pass; surviving caveats are folded back here. This is a
positioning/assessment artifact — no code was changed._

---

## 1. The contribution statement (what survives review)

> A **byte-preserving, release-timing-only** normalization defense **designed to remove** a
> **measured device-configuration processing-time leak** — a linear
> processing-time↔request-complexity signal (R² = 0.9985 / 0.9954 on a real OpenDNP3 outstation,
> *one sample per level; replication with CIs pending*) — in a **live DNP3/SCADA** session,
> deployable as an **in-network bump-in-the-wire**, under a correctness-and-stealth budget set by
> the master's **effective TCP RTO** rather than any application timer. (No defense has been
> executed yet — "remove" is the design target, to be demonstrated by the planned defended runs.)

Four things make it novel against the verified state of the art:

1. **The wedge is the combination, not "byte-preserving" alone.** NetWarden (USENIX 2020) already
   does in-network, timing-only, non-padding shaping on Tofino, so byte-preservation by itself is
   not novel. What is unoccupied is the *combination*: a **measured OT device-configuration leak**
   as the target + **release-timing-only byte-preserving** mechanism (DNP3's block CRCs and
   live-master transparency forbid the padding every WF defense relies on) + a **live-DNP3/TCP-RTO
   correctness bound** + **in-network pass-through**.
2. **A measured ICS leak is the target — with honest limits.** We target a specific,
   regression-recoverable relationship we measured (β = 0.179–0.214 ms/CROB, R² > 0.99, **n = 1
   per N-level — a 10-point line, not yet a replicated law**) and aim to drive **I(processing_time;
   request complexity | size) → 0** (conditional, per Agent F). Formby et al. (NDSS 2016) showed
   the CLRT leak *exists* and is an *attack*; no published work provides the byte-preserving
   in-network defense that removes it. We aim to close that loop (replication E1 + a defended run
   E2 are the evidence still owed).
3. **Normalization/anonymity-set vs RAINCOAT's randomization/misdirection.** Different locus,
   leaked quantity, and mechanism from the nearest same-lab prior work (differentiation table in
   `literature_review.md` Tier 1 and Agent A §1). This is defensible and structural.
4. **In-network per-packet timing normalization is impractical in general but tractable for
   OT/SCADA.** ditto/Pacer show general in-network per-packet absolute-delay normalization is
   costly; our traffic is single-digit-kbps, small-frame, sub-second-cadence, so a
   held-frame/recirc-deadline approach that is prohibitive for datacenter TCP becomes cheap here.
   That inversion is itself a paper-worthy systems framing.

## 2. The reviewer's attacks, and our honest answers (the Seven Hunts)

**H1 — "Does response time actually correlate with database size?"** For **CROB count**, yes,
decisively and *measured*: SELECT-resp R² = 0.9985, OPERATE-resp R² = 0.9954, 3× swing over
N = 1→16. For **database size** specifically, we have not yet varied the outstation's point-count
DB and re-measured — that experiment is in `evaluation_plan.md` (T2). **Do not claim DB-size
correlation from the CROB sweep alone**; claim the measured CROB-count correlation and frame
DB-size as the corroborating experiment. Formby (NDSS 2016) and TIDF (NPC 2025) support that the
broader processing-time↔complexity leak generalizes, but that is *their* result, not ours yet.

**H2 — "Is the defense distinguishable from ordinary traffic shaping?"** Partly a framing risk.
Mechanically, a constant/bucketed release schedule *is* a form of traffic shaping; the novelty is
the **constraint set** (byte-preserving, live-protocol RTO-bounded, in-network, device-identity
target), not the primitive. Lead with the constraint set and the measured ICS leak, not the
scheduler. ditto owns "Tofino line-rate WAN obfuscation"; do not re-tread it.

**H3 — "Do fixed/bounded delays create a NEW fingerprint?"** Real risk, on two vectors.
*(a) Signature of the target itself:* a fixed constant-time target makes every response identical,
but the transition to it, or a poorly chosen bucket set, can be a signature (an always-exactly-
15.00 ms response is as unusual as the native distribution). *(b) The normalizer is a beacon
(the sharper vector, per the skeptical review):* the deployment is a single bump-in-the-wire in
front of one outstation, so "shaped vs. unshaped" traffic is trivially separable — the protected
device becomes **more** identifiable in an open-world/cross-device setting, not less. The
anonymity-set argument requires a **fleet** shaped to a common distribution, which again needs the
≥2-device asset. Mitigations: evaluate the **defense-aware attacker (A7)** and report residual
**I(released_time; class | size)**; prefer a *class-independent distribution* (uniform-within-budget
or decoy-match) over a degenerate constant; and add a **"detectability-of-the-normalizer"**
experiment (can an attacker separate shaped from unshaped traffic?) to the evaluation. These are
experiments (P3 vs P4 vs P7, plus the detectability test), not assertions.

**H4 — "Can the attacker average away the randomization?"** This is the crux of the
normalization-vs-jitter claim (RQ4). Additive i.i.d. jitter is **averageable** — the sample mean
over n polls converges to T_c + μ with error ∝ σ/√n, recovering the class (Crosby TISSEC 2009,
Brumley–Boneh 2005). Distribution-matching normalization makes the released distribution
**class-independent**, so averaging converges to the *same* target for every class and recovers
nothing. **Caveat: the claim is attacker-model-dependent** — it holds for the repeated-poll
passive observer (the SCADA case), not necessarily a single-shot observer. State the model. Agent
F's **A8 repeated-observation attacker** is the instrument that makes this *measurable* (finite
samples-to-halve for jitter, unbounded for normalization).

**H5 — "Is one software outstation enough?"** No — and we must not pretend otherwise. The
single-device rig supports an **information-theoretic / regression** claim (kill I(T;N) on this
device; C1 in the claim ladder). A **device-classification** claim (C2/C3) needs **≥2 stacks**
(a second DNP3 implementation and/or a real relay/RTAC). Agent F's claim ladder prevents the
over-reach; the evaluation plan flags the second device as the single highest-value missing asset.

**H6 — "Is the P4/Tofino implementation realistic?"** Honestly mixed. Native **pacing/gap
normalization** on Tofino is real (TM + published schedulers). First-packet **absolute delay** —
the mechanism that actually kills the measured leak — is **not a native Tofino primitive**; it is
reachable only via a **recirculation + timestamp-deadline loop** that is *unbuilt and unmeasured
on our chip*, hits bf-p4c gateway/range limits, and rests on standard token-bucket behavior rather
than an Intel-published TM latency model. It is *affordable* here (DNP3 rate math) but its costs
are **engineering inference**. BlueField (Accurate Send Scheduling) and FPGA are the honest
"native" homes. Position Tofino absolute-delay as **future work with a de-risking argument**, not
a demonstrated result.

**H7 — "Is the operational risk acceptable?"** The crown-jewel leak sits on **control responses**
(SELECT/OPERATE), so killing it means shaping control-side *timing*. Safe on the response-timing
axis (huge timer margins), but the element **must never delay a control it cannot prove
non-critical**, and DNP3 fields encode operation *type*, not physical *criticality* (Agent C §8).
Mitigation: default-conservative operator allowlist (all control FCs bypass unless whitelisted);
safety dominates privacy; the read plane is fully shapeable at zero safety cost and carries the
continuously-sampled (higher-value) leak anyway.

## 3. What is already known / borrowed / adapted / new

| Bucket | Content |
|---|---|
| **Already known** | CLRT/processing-time is an ICS fingerprint (Formby, TIDF); jitter is averageable (Crosby, Brumley–Boneh); scheduled release bounds timing leakage (predictive mitigation, bucketing, Pump); distribution-matching hides a class (Traffic Morphing, Surakav); in-network shaping is feasible on Tofino (ditto, NetWarden). |
| **Directly borrowed** | The `release = max(ready, deadline)` predictive-mitigation schedule; Köpf–Dürmuth bucketing as size-decorrelation; the privacy-vs-overhead Pareto and DP framing (NetShaper); the WF attacker suite (DF, k-fp, Tik-Tok) as our adversary bar. |
| **Adapted to DNP3** | The distribution-matching objective transplanted from **sizes** (where WF operates) to **release timing** (the only byte-preserving axis here); the RTO/CONFIRM correctness bound as the live-protocol constraint WF never faces; the traffic-class shape/bypass table gated by DNP3 semantics + an operator criticality map. |
| **Technically new** | The byte-preserving × release-timing-only × live-DNP3-RTO-bound × in-network four-way design point (empty in prior work); the measured R²>0.99 CROB-count processing-time leak on a real outstation and its normalization; the "impractical-in-general-but-cheap-for-OT" recirc-hold framing. |
| **Engineering (not research) contribution** | The software timing-policy scheduler in `split_server.py`; the extended `analyze_ack.py` feature/metric export. Necessary, rig-validatable, but not by itself a paper. |

## 4. What would be required for a strong IEEE/ACM paper

1. The **measured leak + its normalization**, with **I(T;N|size)** (conditional, not marginal —
   Agent F's key caveat: the size channel is *not* closed in the byte-preserving phase) reported
   alongside the regression β/R², before and after each policy. **Resolve the strategic tension
   the review surfaced:** the R²>0.99 leak we measured sits on **SELECT/OPERATE control
   responses**, which the safety rule *bypasses by default* — while the freely-shapeable **Class-0
   read plane** (the higher-value continuously-sampled channel, and the one the study's
   "database-size" framing implies) is the **unmeasured** one. The primary defended target must
   therefore be a **replicated Class-0 read-plane point-count sweep** (E1'), not only the control
   sweep; otherwise the demonstrable result is on the traffic you are told not to shape.
2. The **normalization-beats-jitter** result made quantitative via the A8 averaging attacker
   (samples-to-halve), not asserted.
3. A **≥2-device** gesture for any device-classification claim (else scope strictly to the
   single-device information-theoretic result).
4. The **privacy-vs-latency Pareto** with the shaded safe-operating region (added latency <
   measured-RTO margin ∧ correctness = 100%) and the pre-registered P6-vs-P2 test.
5. Honest platform framing: software now; BlueField/FPGA as native hardware homes; **Tofino
   absolute-delay as de-risked future work**, not a claimed result.
6. Correctness evidence at the splitting bar: identical measurements, DNP3 CONFIRM, 0
   retransmits / 0 resets, byte-preservation asserted.

## 5. Do-not-overclaim list (integrity guardrails)

- Do **not** claim information-theoretic privacy without stating the assumptions and the
  attacker model; the guarantee is class-conditional-independence under a repeated-poll observer.
- Do **not** claim DB-size proportionality from the CROB sweep; that is a separate experiment.
- Do **not** call the measured configuration-complexity leak a "device-**identity**" fingerprint;
  device identification needs ≥2 stacks. Reserve identity/fingerprint language for that result.
- Do **not** present the **n = 1-per-N** sweep as a replicated near-deterministic law; the R²
  values describe a 10-point line until E1 replicates them with confidence intervals.
- Do **not** describe the normalization primitive as "implemented / software-validated" or the RTO
  budget as "measured" — the primitive is designed and the budget is provisional until run/measured.
- Do **not** label the Tofino recirc-hold as implemented or measured.
- Do **not** claim a specific relay (e.g. SEL-751A) latency capability without vendor docs.
- Do **not** present a single PCAP / single device as a general timing fingerprint.
- Do **not** treat the two arXiv ICS items (Jeon 2016, Ahmed 2024) as peer-reviewed.
