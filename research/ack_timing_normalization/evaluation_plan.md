<!-- Deliverable authored by Agent F (security-evaluation & statistical-methodology specialist) on this study (2026-07-13), grounded in GROUNDING.md + measured_timing_data.md and integrated by the synthesizing lead. Research/design artifact only — NO harness source code was changed. Every cited work was merged into paper_matrix.csv + bibliography.bib. Reviewed in the Agent-G skeptical pass; see research_gaps_and_novelty.md for surviving caveats. -->

# Agent F — Security-Evaluation & Statistical-Methodology Plan
## (Section 10: Attacker Model + Complete Evaluation Methodology for ACK-Bearing DNP3 Response Timing-Normalization)

_Design-only artifact. No code was modified. All rig numbers referenced here are the
**measured facts** in `measured_timing_data.md` (this rig, this session): SELECT-response
slope **0.179 ms/CROB (R²=0.9985)**, OPERATE-response slope **0.214 ms/CROB (R²=0.9954)**,
baseline req→ACK 0.239 ms, req→response 1.014 ms, 9/9 piggyback. Every methodology citation
below was verified this session against a primary source (see `## BIBTEX`); works I only saw
as metadata are labelled. Cross-checks the framing in
`docs/ack_timing_obfuscation_research.md` §5–6._

---

## 0. Bottom line for the lead

1. **The honest headline is single-device and information-theoretic.** The crown-jewel
   result — timing linearly encodes request complexity (β≈0.18–0.21 ms/CROB, R²>0.99) and a
   timing-normalization defense drives that leak to statistical noise — needs **exactly one
   physical device with varied configuration**. It is fully supportable on the current rig.
   Frame it as `I(processing_time; N_CROB / response_size) → 0`, not as "device
   fingerprinting."
2. **A device-*type* classification claim (T1) is NOT supportable with one device.** It needs
   **≥2 distinct DNP3 stacks** (ideally ≥3). With one stack, "classification accuracy" is
   config-classification, not fingerprinting. This is the reviewer trap; the plan scopes every
   claim to the diversity it actually has.
3. **Two attackers decide the paper's strength:** the **defense-aware** attacker (A7, trained
   on obfuscated traffic — the security-eval standard, per Carlini et al. 2019) and the
   **repeated-observation averaging** attacker (A8). A8 is the one that empirically separates
   *randomization* (averageable, privacy → native as polls M→∞) from *normalization*
   (not averageable) — this is the RAINCOAT differentiation made measurable.
4. **The Pareto claim (P6 size-decorrelation dominates P2 jitter) is a hypothesis to TEST,
   not to assume.** The plan pre-registers it with an explicit null and equivalence margins.

---

## 1. Claim ladder and honest scoping (the reviewer trap, handled first)

A reviewer at ToN/TDSC/NDSS will reject a general fingerprinting claim built on one PCAP /
one device. We therefore separate three claims by the diversity each requires, and only assert
what the data supports.

| Claim | What it says | Minimum data to support it | Status on current rig |
|---|---|---|---|
| **C1 (timing↔config leak + closure)** | On this outstation, processing time encodes CROB count / DB-size proxy (β,R² measured); the defense removes it (`I(T;N)→0`) | **1 device × K configs** (N-sweep), repeated polls | **Supportable now** — this is the headline |
| **C2 (policy ordering / Pareto)** | Size-decorrelation reaches equal privacy at lower latency + lower averageability than jitter | Same 1 device, full policy sweep | **Supportable now** (as a tested hypothesis) |
| **C3 (device-type fingerprint + suppression)** | Timing distinguishes device *models/stacks*; the defense collapses the anonymity set | **≥2 (ideally ≥3) distinct DNP3 stacks** × configs × load, grouped CV across devices | **NOT supportable with one stack** — scope as preliminary/future |

**Diversity ladder** (state which rung each experiment stands on):
- Rung A — 1 device, K configs → **C1** (MI/regression). *We are here.*
- Rung B — 2 devices × K configs → gestural cross-device + preliminary **C3** ("two stacks,
  illustrative").
- Rung C — ≥3 stacks × configs × load levels, grouped CV → general **C3** (follow-on paper).

**Rig-specificity caveat.** Absolute times (0.24/1.01 ms) are specific to this OS/NIC/TCP
stack (Linux 6.8, i40e, `NOP-NOP-Timestamp`). The **transferable** claim is the *structure*
(linear-in-N, near-deterministic), and even that is one implementation. Report the structure,
not the constants, as the finding; report constants as rig context.

---

## 2. Hypothesis table (pre-registered before defended-trace collection)

Freeze this before collecting any post-defense data. Endpoints, directions, and equivalence
margins are declared in advance (pre-registration mindset).

| ID | Hypothesis (H1) | H0 (null) | Endpoint / statistic | Test | Primary? | Decision rule |
|---|---|---|---|---|---|---|
| **HA** | Native timing encodes N: β_native>0, R²_native high | β=0 (no timing–N relation) | slope β (ms/CROB), R² | OLS + LRT vs intercept-only; bootstrap CI on β | primary | reject H0 (already ~certain: R²>0.99) |
| **HB** | Defense (P3/P5/P6) removes the timing leak: `\|β_obf\|` negligible, `I(T;N)_obf ≈ 0` | leak persists (`\|β_obf\|` ≥ margin) | β_obf, KSG `I(T;N)_obf` | **TOST equivalence** on β (margin ±0.02 ms/CROB = 10% of native); permutation-null test for MI | **primary** | conclude closure iff 90% CI(β_obf) ⊂ ±margin **and** MI_obf within permutation null band |
| **HC** | Best attacker's accuracy/AUC drops under defense | Acc_obf = Acc_native | best-attacker Acc, AUC, PrivacyGain | McNemar (paired), DeLong (AUC) | primary (needs ≥2 stacks) | reject H0; report PG with CI |
| **HD** | Jitter (P2) is averageable; normalization (P3/P6) is not | both averageable equally | PG(A8) vs M slope; M½ | regression of PG on log M; compare slopes | **primary** | P2 slope<0 (PG→0), P3/P6 slope≈0 |
| **HE** | P6 dominates P2: equal privacy at **lower** p95 added latency | latency equal at equal privacy | Δ p95 latency at matched privacy | paired bootstrap on Pareto-matched points | primary | reject H0 in P6's favor |
| **HF** | Defense preserves correctness | defense breaks a session | retransmits, resets, timeouts, byte-preservation | exact (0-tolerance) counts | primary (gate) | any violation = fail regardless of privacy |
| **HG** | Distribution matches declared target (P3/P4/P7) | distribution ≠ target | W1, KS-D, JS to target | KS two-sample; bootstrap CI on W1/JS | secondary | small W1/JS, KS non-reject |

Equivalence margins, the attacker roster, the feature set, and the primary endpoints are all
**declared here and not changed after seeing defended data.**

---

## 3. Attacker models (weakest → strongest)

**Shared threat model (all attackers).** Passive, on-path observer. Reads unencrypted DNP3
headers and TCP/IP; **does not inject, block, or modify**. Knows the DNP3 protocol and can time
packet arrivals at its vantage point. Extracts a per-exchange feature vector, aggregated per
session. Escalations: A7 additionally **knows the defense and its parameters** (Kerckhoffs;
trains on post-defense traces); A8 additionally can **observe M repeated polls** of the same
(device, config). Closed-world by default for T1; an open-world variant adds an "unknown"
reject class.

**Common feature vector** (per request→reply exchange; aggregate to session-level order
statistics / percentiles; all obtainable without decoding payloads):

| # | Feature | Rationale |
|---|---|---|
| f1 | request→ACK delay (ms) | TCP/NIC/OS turnaround; stack-class tell (0.24 ms ⇒ server-class) |
| f2 | **request→response (processing) delay (ms)** | **the crown-jewel leak** — linear in N |
| f3 | piggyback indicator (bool) + per-session piggyback ratio | software vs embedded discriminator |
| f4 | inter-frame gap stats within a multi-fragment response (mean, std, min, max, count) | segmentation-timing signature; CPU regen speed |
| f5 | CONFIRM latency: master→outstation confirm round + outstation continuation-after-CONFIRM delay | multi-fragment handshake signature |
| f6 | fragment count / APDU count / link-frame count / TCP-segment count | config + DB-size proxy |
| f7 | on-wire size proxies: total bytes, #segments | **residual size channel — see honesty note §4.4** |
| f8 (derived) | two largest processing delays per session (SELECT/OPERATE isolate) | exactly what the N-sweep isolated |

| Attacker | Model | Feature use | Represents | Role in eval |
|---|---|---|---|---|
| **A1** | **Threshold classifier** | single feature (f2 mean), one boundary | trivial script observer | floor baseline |
| **A2** | **Statistical template matcher** | per-class empirical density (KDE/histogram) of the feature vector; classify by nearest template / max-likelihood (1-NN in distributional distance) | non-learning statistical adversary | no-training baseline |
| **A3** | **Random Forest** | full engineered vector | standard tabular WF attacker (k-FP lineage) | main workhorse |
| **A4** | **Gradient boosting (XGBoost/LightGBM)** | full engineered vector | strongest tabular learner | expected best on aggregates |
| **A5** | **SVM (RBF)** | full engineered vector (scaled) | different inductive bias (CUMUL lineage) | robustness across model class |
| **A6** | **Temporal neural (1D-CNN)** | raw per-packet timing/direction *sequence* (fragment train + CONFIRM latencies) | Deep-Fingerprinting / Tik-Tok lineage | **upper bound; included only with justification (below)** |
| **A7** | **Defense-aware (adaptive)** | best of A3–A6, **retrained on obfuscated traffic** at known defense params | Kerckhoffs adversary; the security-eval standard | **primary** — prevents overstating protection |
| **A8** | **Repeated-observation / averaging** | aggregates M polls; uses sample/trimmed mean or MLE of per-poll f2 | patient reconnaissance adversary | **primary** — defeats i.i.d. jitter, exposes averageability |

**A6 justification (why a neural model is warranted here, not gratuitous).** Our leak has
*sequential* structure a flat feature vector under-uses: the multi-fragment CONFIRM handshake
serializes fragments, so the ordered sequence of (inter-frame gap, continuation-after-CONFIRM)
latencies is itself informative (f4/f5). A 1D-CNN over the raw timing/direction sequence is the
established way to exploit exactly this (Sirinam et al. 2018; timing-feature utility shown by
Rahman et al. 2020). **Guardrail:** with our small per-exchange feature count, a deep model can
overfit; A6 is reported as a *ceiling* under strict grouped CV (§7), and we report **whether it
beats A4** — if it does not, we do not deploy it as the headline attacker.

**A8 — the averageability instrument (novel axis).** For an attacker with M i.i.d. polls of one
(device, config), the variance of the mean-timing estimator falls as σ²/M (√M SNR gain). Report
best-attacker PG (or regression R²) **as a function of M ∈ {1, 5, 10, 30, 100, 300}**. Define
the **averaging half-life M½** = polls needed to recover half the native leak the defense
removed. Expected contrast (to TEST, HD): additive jitter (P2) → M½ finite, PG→0; constant-time
(P3), bucketing (P5), size-decorrelation (P6) → M½ = ∞ (residual is deterministic-per-class,
not random-per-poll, so averaging cannot recover it).

---

## 4. Tasks and metrics

### 4.1 T1 — device-type classification (needs ≥2 stacks; scope accordingly)
Metrics: **accuracy, balanced accuracy, macro-F1, ROC-AUC** (one-vs-rest macro and micro).
Chance line = 1/K (balanced) and the majority-class rate (report both). Significance:
**McNemar's paired test** (McNemar 1947) on the *same* test exchanges comparing the
native-trained attacker vs the obfuscated attacker's predictions; **DeLong's test** (DeLong et
al. 1988) for paired AUC differences with its variance-based CI. Effect size: Δaccuracy with
Wilson CI, Cohen's *h* for the two proportions.

### 4.2 T2 — database-size / CROB-count regression (the single-device anchor)
The attacker regresses observable timing → N (or DB-size proxy). Metrics:
- **MAE** (in CROB units, via inverse of the fitted map) and **RMSE**;
- **R²** and **slope β (ms/CROB) with 95% bootstrap CI** — β is *literally* what the attacker
  exploits; native target β∈[0.179, 0.214], R²>0.99;
- **Spearman ρ** (monotonicity, robust to the exact functional form).

Success (HB): defense drives **β_obf into ±0.02 ms/CROB via TOST equivalence** (10% of native
slope, pre-declared) **and** MAE_obf → the trivial "predict-the-mean" MAE (the no-information
baseline). Significance: paired bootstrap over exchanges for β and R²; a **likelihood-ratio /
nested-F test** for "does adding N improve the timing model over intercept-only?" (native: yes,
overwhelmingly; obf target: no).

### 4.3 Mutual information (information-theoretic core)
Estimate **`I(observable_timing ; Z)` for Z ∈ {N_CROB, response_size, DB-size proxy, device
identity}** with the **KSG k-nearest-neighbor estimator** (Kraskov, Stögbauer & Grassberger
2004) — the standard continuous MI estimator, data-efficient and adaptive, appropriate for our
continuous timing vs discrete/continuous Z (use the KSG variant for mixed discrete–continuous
Z). Protocol:
- report MI in **bits** (log₂), consistently;
- **k-neighbor sensitivity**: report k ∈ {3,5,7}; KSG is near-unbiased but the estimate must be
  stable across k;
- **bootstrap percentile CI**, B≥2000 (Efron & Tibshirani 1993);
- **permutation null**: shuffle Z labels ≥1000× → null MI distribution → one-sided p-value.
  "Closure" (HB) = MI_obf falls **inside the permutation-null band** (indistinguishable from
  independence), not merely "small."

**Estimator caveat (state it in the paper).** Native `I(T;N)` is *near-deterministic*
(R²>0.99); kNN MI estimators are known to be unstable / biased for near-deterministic couplings.
Mitigation: (a) report the interpretable β/R² alongside MI as the primary readout; (b) add a
robustness cross-check with a **binned/adaptive-partition MI** and note agreement/disagreement;
(c) rely on the permutation null for the *obf* side (where the relationship is destroyed and
KSG is well-behaved). Do **not** present MI as a differential-privacy guarantee — it is an
empirical information measure.

### 4.4 Distributional distance to a declared target
For shaping policies (P3/P4/P7), measure the post-defense timing distribution against a
**declared target**: **Wasserstein-1 (W1, in ms)** (Peyré & Cuturi 2019 for computation and the
W1 duality), **Kolmogorov–Smirnov statistic D** + two-sample KS test, and **Jensen–Shannon
divergence** (Lin 1991) between per-class post-defense distributions (want JS→0: classes
indistinguishable). W1 is reported twice: **W1(obf, native)** = "how far it moved" and
**W1(obf, target)** = "how well it hit the target." For P3 (constant-time) the target is a point
mass, so W1 reduces to mean absolute deviation. For P7 (decoy-match) the target is the decoy
device's *native* distribution. Bootstrap CIs on W1 and JS.

**Honesty note on the size channel.** In the byte-preserving, timing-only phase, **response
size is NOT hidden** (f7 is still on the wire). N is therefore recoverable from *size* even
after the timing channel is closed. The defended, well-defined target is the **timing channel**:
`I(processing_time; N/size) → 0`. We must state explicitly that (i) the timing primitive closes
the *incremental* timing leak, and (ii) the size channel is the separate job of the
CRC-splitting/padding primitive (characterized, constrained per prior multi-CROB results). We
therefore report **`I(T; N | size)`** (timing's *marginal* contribution beyond size) as well as
the marginal `I(T; N)`, so the claim is not silently inflated.

### 4.5 Privacy Gain (unifying scalar)
`PrivacyGain = (Acc_native − Acc_obf) / (Acc_native − Acc_chance)`, reported **per attacker
(A1–A8) and per task**, with bootstrap CI. Interpretation: PG=1 → attacker reduced to chance
(ideal); PG=0 → no protection; **PG<0 → the defense *helped* the attacker** (a real failure mode
if the defense injects a new artifact — must be checked, not assumed away). For T2 use an MI /
R²-based analogue: `PG_MI = 1 − I_obf/I_native`.

---

## 5. Policy comparison (Section 6): P0–P8

Each policy is measured on the **same axis grid**:
(1) **privacy benefit** = PrivacyGain and MI drop;
(2) **attacker residual info** = post-defense `I(T; target)` and best-attacker Acc/AUC;
(3) **averageability** = PG-vs-M slope and M½ under A8;
(4) **added latency** = mean / median / p95 / p99 / max and ×baseline;
(5) **deadline-miss behavior** = policy-bypass rate (fraction released immediately because
    `candidate_release − request_time > budget`) and TCP-RTO-overshoot rate;
(6) **correctness** = byte-preservation, DNP3 CONFIRM present, 0 retransmits / 0 resets / 0
    timeouts.

| Policy | Mechanism | Kills which leak | Averageable? (A8) | Latency profile | Residual leak |
|---|---|---|---|---|---|
| **P0 native** | none | — | — | 0 | full leak (β,R² native) |
| **P1 fixed delay Δ** | add constant Δ | shifts *mean* only | not averageable, **but** β unchanged ⇒ **does NOT reduce the N-leak** | +Δ constant | full N-correlation persists — a deliberately weak baseline |
| **P2 additive jitter** (RAINCOAT-style randomization baseline, B2) | i.i.d. noise ~ dist | obscures a single sample | **YES** — M½ finite, PG→0 as M→∞ | +E[jitter]+var | mean recoverable by A8; residual `I(T;N)` after averaging |
| **P3 constant-time** (V1) | pad every response to fixed deadline D≥worst-case | **eliminates** processing-time channel | **NO** | +(D−t_proc), max | information-theoretic ≈0; highest latency |
| **P4 bounded randomized normalization** (V2) | release ~ U[ready, request+budget], support **N-independent** | max emission entropy under a latency cap | **NO iff support is N-independent** (design it so) | ≤ budget | small if support fixed; leaks if budget tracks N |
| **P5 bucketed** (k-anonymity) | quantize release to a device/config-independent bucket grid | reduces `I(T;N)` to log₂(#buckets the class spans) | not averageable *within* a bucket; bucket index leaks if N crosses buckets | ≤ bucket width | which-bucket, coarsened |
| **P6 size-decorrelation** (V4, the punchline) | schedule release so `t_proc ⟂ size`; target `I(T;size)→0` | **kills the size↔time correlation** at lower latency than P3 | **NO** (deterministic decorrelating map) | lower than P3 | timing marginal ≈0; **size channel remains (separate primitive)** |
| **P7 decoy-match** | shape timing to impersonate a decoy device's native distribution | device-identity via imitation | not averageable (imitates a real fixed distribution) | depends on decoy (decoy must be ≥ our worst case) | "which device" collapses to decoy |
| **P8 inter-frame-gap normalization** | normalize gaps within multi-fragment responses / CONFIRM-continuation timing | segmentation-timing signature (f4/f5) | not averageable | +gap padding | pairs with CRC-splitting; first-response latency untouched |

**Key qualitative contrasts the experiments must make legible:** P1 is a *trap* (adds latency,
removes nothing); P2 is the honest randomization baseline that A8 breaks; P3 is the expensive
gold standard; **P6 is the hypothesized sweet spot**; P5 is the cheap coarse option; P7/P8
target the identity/segmentation channels respectively.

---

## 6. Privacy–latency Pareto frontier + safe operating region

- **Axes.** x = **added p95 latency (ms)** (operationally binding; also plot mean and max);
  y = **privacy** = best-attacker PrivacyGain (min over A1–A8 of Acc ⇒ max PG), with an
  MI-based twin plot (`PG_MI`).
- **Points.** Sweep each policy's knob: P1 Δ; P2 jitter σ; P3 D; P4 budget; P5 bucket width;
  P6 decorrelation granularity; P7 decoy; P8 gap. Each (policy, setting) is a point; draw the
  **non-dominated (Pareto) frontier**.
- **Third dimension = averageability.** Color/annotate each point by M½ (A8). A defense that
  looks Pareto-good but has small M½ is *not* actually good — this is the axis prior WF Pareto
  plots omit and our A8 supplies.
- **Safe operating region (shaded).** `{ added p95 latency < RTO_margin AND correctness = 100% }`
  where `RTO_margin` = a fraction (e.g. 0.5×) of the **effective RTO measured on the master
  (Vision)** — do **not** assume 200 ms; measure it (`sysctl net.ipv4.tcp_retries2` + observed
  RTO in a capture). Correctness = 0 retransmits, 0 resets, 0 timeouts, byte-preservation
  asserted. Points outside the region are drawn but marked infeasible.

**The pre-registered Pareto hypothesis (HE), stated as a test not a belief:**
> H1: at matched privacy (matched best-attacker PG), **P6 (size-decorrelation)** achieves
> **lower p95 added latency** than **P2 (additive jitter)**, **and** P6's M½=∞ vs P2's finite
> M½.
> H0: no latency difference at matched privacy.
Test: pair P6 and P2 points at matched PG (interpolate along each frontier), paired bootstrap on
Δp95-latency; report the CI and BH-adjusted p. **Report the result even if H0 is not rejected**
— a null here is itself a finding (jitter would then be competitive, undercutting the
normalization thesis, which we must be willing to say).

---

## 7. Statistical design

### 7.1 Sample size / power (sketch with worked numbers)
- **T2 regression (anchor).** Detecting native β>0 is already near-certain (R²>0.99). The
  binding requirement is **establishing β_obf≈0 via TOST** within margin ±0.02 ms/CROB. With
  N-grid {1,2,3,4,5,6,8,10,12,16} (spread s_N≈4.7) and measured residual σ_resid≈0.03 ms
  (implied by the current fit), `SE(β) ≈ σ_resid / (s_N·√n_total)`. Getting the 90% TOST CI
  half-width (~1.64·SE) below the 0.02 margin needs `SE(β) ≤ 0.012`. The closed form returns a
  fractional n_total, which is a **degenerate artifact** — a regression needs at least as many
  samples as parameters, and σ_resid is itself only trustworthy once replicated. So the honest
  statement is: **β-closure is not the binding constraint** (it is satisfied by a modest number of
  reps once σ_resid is known); the real sample-size floor is set by the MI/distributional test
  below. The minimum sane design is **≥3 N-levels × R reps** with R fixed by the MI floor, not the
  β formula. **This whole calculation is moot until E1 replicates the sweep and reports a real
  within-N σ_resid — the current σ comes from an n = 1-per-N fit.**
- **MI / distributional floor.** KSG MI CI and KS/W1 estimates scale ~1/√n. To bound
  `I(T;N)_obf < 0.05 bits` with a tight bootstrap CI and to power a KS two-sample test against a
  small effect, target **n ≥ 300–500 exchanges per (device, config, policy) cell**, i.e.
  **R ≥ 30 repeated polls per N** across the grid. This also feeds A8 (needs many polls per
  cell).
- **T1 classification (≥2 stacks).** McNemar sample size for detecting an accuracy drop:
  `n_disc ≈ (z_{α/2}√(2·p̄) + z_β√(4·p̄²−(Δ)²))² / Δ²` on discordant pairs. A large drop
  (0.90→0.50) needs only ~30–50 test exchanges; a subtle drop (0.90→0.85) needs several hundred.
  Set **test-set floor ≥ 200 sessions per class** to power the subtle comparisons.

### 7.2 Cross-validation (leakage is the killer)
- **Stratified k-fold (k=5 or 10)** for balanced per-class estimates.
- **Grouped by session/capture (GroupKFold on session id): mandatory.** All exchanges from one
  poll/session go entirely to train *or* test. Exchanges within a session share device state,
  clock phase, and (for stochastic policies) the same jitter draw — un-grouped CV leaks and
  inflates accuracy. For **T3 linkage** and **C3 (device-type)**, split by **disjoint
  device/config groups** in train vs test (a device seen in training must not appear in test),
  otherwise "fingerprinting" is memorization.
- **Nested CV** for A3–A6 hyperparameters (inner loop tunes, outer loop estimates) to remove
  optimistic tuning bias.
- **A7 defense-aware protocol:** train A7 on *obfuscated* traces at the known defense params,
  under the same grouped CV, and report A7 as the primary security number (Carlini et al. 2019:
  a defense must be evaluated against an attacker that knows it).

### 7.3 Repetitions, seeds, traceability
- Stochastic policies (P2, P4, P7) and stochastic learners (A3–A6) both need seeds. Run
  **≥5 policy seeds × ≥5 learner seeds** for stochastic cells; report mean ± variance across
  seeds *and* folds. Deterministic policies (P1, P3, P5, P6, P8) need learner seeds only.
- **Every number → (config + seed + git commit)**, per `experiment-reproducibility.md`. Record
  environment (`pip freeze`), the TCP option signature, the **measured effective RTO on Vision**,
  poll interval, and dataset hash for each capture. Hydra-style output dirs
  `{policy}_{config}_{timestamp}` with `.hydra/config.yaml` + `overrides.yaml`.

### 7.4 Confidence intervals, effect sizes, multiple comparisons
- **CIs:** bootstrap percentile (Efron & Tibshirani 1993) for MI, R², β, PG, W1, JS (B≥1000;
  B≥2000 for MI); **DeLong** CI for AUC; **Wilson** CI for accuracies/proportions.
- **Effect sizes over bare p-values:** Δaccuracy+CI, Cohen's *d*/*h*, MI-drop in bits+CI,
  β+CI, W1 in ms — always alongside (not instead of) tests.
- **Multiple comparisons:** the family is 9 policies × 8 attackers × 3 tasks + Pareto pairings.
  Control **FDR at q=0.05 with Benjamini–Hochberg (1995)** across the family of pairwise policy
  comparisons; report raw *and* BH-adjusted p. The **primary** endpoints (HB closure, HD
  averageability, HE Pareto) are pre-registered so they are not diluted by the exploratory grid.

---

## 8. Traffic configurations

| Axis | Levels | Purpose |
|---|---|---|
| Request type | Class-0 integrity READ (large); Class-1/2/3 event READ; SELECT; OPERATE (SBO) | exercises f2 and the CONFIRM handshake (f4/f5) |
| **N_CROB** | {1,2,3,4,5,6,8,10,12,16} (measured grid; extend if possible) | the leak axis for T2/MI |
| DB-size proxy | vary point count / event backlog | moves the processing-time baseline (DB-size interpretation) |
| Load | idle vs concurrent polling | tail behavior (p95/p99), load-dependence of the leak |
| Fragmentation | single- vs multi-fragment response | activates CONFIRM/inter-frame features (f4/f5), P8 |
| Repetition | **R ≥ 30 polls per cell** | MI/distributional estimation + A8 averaging |
| **Devices/stacks** | 1 (have) → 2 (gestural C3) → ≥3 (general C3) | gates which claim (C1 vs C3) |

Held constant and recorded: master host, network path, OS/NIC, TCP options, poll interval,
git commit. Vary one axis at a time for attribution; full-factorial only where affordable.

---

## 9. Metric lists (Section 10 deliverable)

**Correctness metrics (gate — any failure voids the privacy result, HF):**
- byte-preservation `b"".join(chunks) == original` asserted per response;
- DNP3 CONFIRM present for every multi-fragment read; SOE/measurement count = native (e.g. the
  800-measurement rig bar);
- **0 TCP retransmits, 0 RST, 0 DNP3 session timeouts**;
- Zeek/Bro `dnp3` analyzer parses clean (valid CRCs, legal FCs, intact sequence).

**Performance metrics:**
- added latency per exchange: mean, median, **p95, p99, max**, and ×baseline (~1 ms);
- end-to-end poll completion time; throughput (exchanges/s);
- **policy-bypass rate** (released-immediately fraction) and **RTO-overshoot rate**;
- multi-fragment compounded added delay (per-fragment × n_frag, each still < RTO);
- policy compute overhead (software) / resource footprint (Tofino/DPU — future).

**Security metrics:**
- T1: best-attacker accuracy, balanced accuracy, macro-F1, ROC-AUC (+ McNemar, DeLong);
- T2: MAE, RMSE, R², slope β + 95% CI, Spearman ρ (+ TOST equivalence, LRT);
- MI: `I(timing; {N, size, DB, identity})` and `I(T;N|size)` via KSG + bootstrap CI +
  permutation p (all tasks);
- Distributional: W1 (ms), KS-D + test, JS to declared target (+ bootstrap CI);
- **PrivacyGain** per attacker/task (+ CI); **averaging half-life M½** (A8);
- T3: linkage AUC (grouped, disjoint devices/configs).

---

## 10. Reproducibility checklist (per `experiment-reproducibility.md`)
- [ ] Seeds set (random/numpy/torch, `PYTHONHASHSEED`); ≥5 policy × ≥5 learner seeds for
      stochastic cells.
- [ ] Hydra config + overrides saved per run; output dir `{policy}_{config}_{timestamp}`.
- [ ] Environment captured (`pip freeze`, scapy/sklearn versions, OS/NIC, TCP option signature).
- [ ] **Effective RTO measured on Vision** and recorded (not assumed 200 ms).
- [ ] Dataset/capture SHA-256 recorded; N-grid, poll interval, request types logged.
- [ ] Every reported number traceable to (config, seed, git commit).
- [ ] Analysis plan (this doc §2 hypotheses + margins) frozen before defended-trace collection.
- [ ] Attacker training code, feature extractor, and MI/W1/KS scripts versioned; CV = GroupKFold
      by session (device-disjoint for C3/T3).

---

## 11. Threats to validity
- **Single device / single rig (C1/C2).** MI/regression closure is a per-device claim; the
  structure (linear-in-N) is one implementation. Do not generalize to "DNP3 devices."
- **One stack ⇒ no device-type claim (C3).** Any T1 number on one stack is config-, not
  device-, classification. Needs ≥2 (ideally ≥3) stacks + device-disjoint CV.
- **KSG bias near determinism.** Native `I(T;N)` near-deterministic ⇒ MI estimate unstable;
  mitigated by β/R² as primary, binned-MI cross-check, permutation null for the obf side.
- **Clock/measurement resolution.** Sub-ms timing needs the observer's timestamp resolution and
  jitter characterized; report capture-clock precision; the vantage point matters (on-path vs
  edge).
- **Adaptive-attacker completeness.** A7 must be genuinely re-tuned on obf traffic
  (Carlini et al.): a weak A7 fakes strong privacy. Report A7 tuning effort.
- **Size channel not closed (timing-only phase).** Report `I(T;N|size)` so timing's marginal
  contribution is not conflated with total leakage.
- **Deployment realism.** Software-scheduling results (the immediate deliverable) precede any
  Tofino/DPU line-rate claim; keep them labelled as software validation, not hardware.

---

## 12. Recommended experiment sequence (minimal set that could refute the thesis)
1. **E1 (refutes C1 if it fails):** native N-sweep, R≥30/N, confirm β/R² and native
   `I(T;N)`, `I(T;size)`. *Expected: reproduces the measured leak.*
2. **E2 (primary, HB):** apply P3, P5, P6 on the same grid; TOST β-closure + permutation-null MI.
   *Refutes the defense if MI/β not driven into the null band.*
3. **E3 (primary, HD):** A8 averaging sweep M∈{1…300} for P2 vs P3/P6; estimate M½.
   *Refutes the normalization-vs-randomization thesis if P2's M½ is large or P6's is finite.*
4. **E4 (primary, HE):** knob sweeps → Pareto frontier + safe region; test P6 vs P2 at matched
   privacy. *Refutes the punchline if jitter matches P6 on latency.*
5. **E5 (correctness gate, HF):** rig run (0 retransmits/resets/timeouts, byte-preserved,
   measurement count = native) for every policy setting used in E2–E4.
6. **E6 (C3, needs ≥2 stacks — future/gestural):** T1 device-type with device-disjoint CV;
   report as preliminary until ≥3 stacks.

**Added after the skeptical-review pass (must run before the paper's headline claims):**
7. **E1′ (the database-size channel the study is named for — currently unmeasured):** replicated
   sweep of **Class-0 integrity-read response/serialization time vs. outstation static point
   count** (distinct from the CROB-count control sweep). This is the *safe-to-shape,
   continuously-observed* channel and should be the **primary defended target**; the control-side
   CROB leak is bypassed by default under the safety rule, so a paper resting only on it
   demonstrates a result on traffic the design says not to shape.
8. **E7 (detectability of the normalizer — the "beacon" risk):** train an attacker to separate
   **shaped vs. unshaped** traffic, and test whether a lone shaped device becomes *more*
   identifiable in an open-world / cross-device setting. The anonymity-set benefit requires a
   fleet shaped to a common distribution; quantify how far a single-device deployment is from it.
9. **Precondition for all budgets — measure the effective RTO on Vision** (`sysctl
   net.ipv4.tcp_retries2`, `ip route … rto_min`, and the observed request→first-retransmit delta)
   before any shaped rig run; every budget/watchdog value is provisional until this is done.

---

