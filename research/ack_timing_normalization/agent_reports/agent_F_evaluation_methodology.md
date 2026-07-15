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
  (implied by R²=0.9985), `SE(β) ≈ σ_resid / (s_N·√n_total)`. To get the 90% TOST CI half-width
  (~1.64·SE) below the 0.02 margin needs `SE(β) ≤ 0.012`, i.e.
  `n_total ≥ (σ_resid/(s_N·0.012))² ≈ (0.03/(4.7·0.012))² ≈ 0.28` → trivially met (a couple of
  reps/N). **So β-closure is cheap; MI and distributional closure set the real floor.**
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

---

## PAPER_MATRIX_ROWS
RAINCOAT: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers | Hui Lin; Zbigniew T. Kalbarczyk; Ravishankar K. Iyer | 2019 | IEEE Transactions on Smart Grid 10(5) | 10.1109/TSG.2018.2870362 | https://ieeexplore.ieee.org/document/8466028/ | yes | 1 | power-grid SCADA data acquisition (DNP3/ICCP) | attacker estimating grid physical state for FDI/control attacks | randomization of acquisition schedule + intelligent measurement spoofing | endpoint-cooperative schedule randomization (misdirection) | sw | control-center + substation network model | testbed/simulation | state-estimation accuracy deviation (±2%) | data-acquisition latency +<5% | randomizing acquisitions misleads attackers with small overhead | endpoint-cooperative, alters content (spoofs), not in-network byte-preserving | THE differentiation anchor (advisor's work): randomization/misdirection/grid-content vs our normalization/indistinguishability/device-identity | high
Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems | David Formby; Preethi Srinivasan; Andrew M. Leonard; Jonathan D. Rogers; Raheem A. Beyah | 2016 | NDSS | NA | https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf | yes | 2 | ICS (Modbus/DNP3 read-response) | passive fingerprinter using cross-layer response time | (attack paper; no defense) | NA | sw | ICS testbed + real RTUs/PLCs | testbed | device-type classification accuracy via Cross-Layer Response Time (CLRT) | NA | response-time distributions fingerprint ICS device type on read/response protocols | direct analog: our leak IS the CLRT-style processing-time signal; motivates T1/T2 and the ≥2-stack requirement | high
Estimating mutual information | Alexander Kraskov; Harald Stögbauer; Peter Grassberger | 2004 | Physical Review E 69(6) | 10.1103/PhysRevE.69.066138 | https://link.aps.org/doi/10.1103/PhysRevE.69.066138 | yes | 2 | NA | NA | NA | NA | NA | NA | NA | MI estimation quality | NA | kNN (KSG) MI estimator: data-efficient, adaptive, low bias | our primary MI estimator for I(timing; N/size/identity) | high
Comparing the areas under two or more correlated receiver operating characteristic curves: a nonparametric approach | Elizabeth R. DeLong; David M. DeLong; Daniel L. Clarke-Pearson | 1988 | Biometrics 44(3) | 10.2307/2531595 | https://www.jstor.org/stable/2531595 | yes | 2 | NA | NA | NA | NA | NA | NA | NA | paired AUC comparison test | NA | nonparametric test + covariance for correlated AUCs | significance test for paired AUC (native vs obf attacker) in T1 | high
Note on the sampling error of the difference between correlated proportions or percentages | Quinn McNemar | 1947 | Psychometrika 12(2) | 10.1007/BF02295996 | https://link.springer.com/article/10.1007/BF02295996 | yes | 2 | NA | NA | NA | NA | NA | NA | NA | paired-proportion test | NA | McNemar's test for correlated proportions | significance test for paired classifier accuracy (native vs obf) | high
Controlling the false discovery rate: a practical and powerful approach to multiple testing | Yoav Benjamini; Yosef Hochberg | 1995 | Journal of the Royal Statistical Society Series B 57(1) | 10.1111/j.2517-6161.1995.tb02031.x | https://rss.onlinelibrary.wiley.com/doi/10.1111/j.2517-6161.1995.tb02031.x | yes | 3 | NA | NA | NA | NA | NA | NA | NA | FDR control | NA | Benjamini-Hochberg FDR procedure | multiple-comparison correction across the policy×attacker×task grid | high
Computational Optimal Transport: With Applications to Data Science | Gabriel Peyré; Marco Cuturi | 2019 | Foundations and Trends in Machine Learning 11(5-6) | 10.1561/2200000073 | https://www.nowpublishers.com/article/Details/MAL-073 | yes | 2 | NA | NA | NA | NA | NA | NA | NA | Wasserstein/OT distances | NA | computation + theory of W1 and optimal transport | W1 distance-to-target metric for distribution-shaping policies (P3/P4/P7) | high
Divergence measures based on the Shannon entropy | Jianhua Lin | 1991 | IEEE Transactions on Information Theory 37(1) | 10.1109/18.61115 | https://ieeexplore.ieee.org/document/61115 | yes | 3 | NA | NA | NA | NA | NA | NA | NA | JS divergence | NA | defines Jensen-Shannon divergence | per-class distributional-similarity metric (want JS→0) | high
An Introduction to the Bootstrap | Bradley Efron; Robert J. Tibshirani | 1993 | Chapman & Hall (book, ISBN 0-412-04231-2) | NA | https://www.routledge.com/9780412042317 | yes | 3 | NA | NA | NA | NA | NA | NA | NA | bootstrap CI | NA | bootstrap resampling for CIs | bootstrap CIs for MI, R², β, PG, W1 | high
Statistical Power Analysis for the Behavioral Sciences (2nd ed.) | Jacob Cohen | 1988 | Lawrence Erlbaum Associates (book, ISBN 0-8058-0283-5) | NA | https://www.routledge.com/p/book/9780805802832 | yes | 3 | NA | NA | NA | NA | NA | NA | NA | power/effect size | NA | power analysis and effect-size conventions (d, h) | power-analysis sketch and effect-size reporting | high
A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses | Xiang Cai; Rishab Nithyanand; Tao Wang; Rob Johnson; Ian Goldberg | 2014 | ACM CCS | 10.1145/2660267.2660362 | https://dl.acm.org/doi/10.1145/2660267.2660362 | yes | 2 | Tor web traffic | supervised WF classifier (open-world) | Tamaraw padding defense | rate/padding shaping | sw | simulation on trace corpora | trace-driven | security/bandwidth trade-off; lower bounds | bandwidth overhead | framework for evaluating WF attacks/defenses + Tamaraw defense | methodology template for defense eval + Pareto/lower-bound framing | high
Toward an Efficient Website Fingerprinting Defense | Marc Juarez; Mohsen Imani; Mike Perry; Claudia Díaz; Matthew Wright | 2016 | ESORICS (LNCS 9878) pp.27-46 | 10.1007/978-3-319-45744-4_2 | https://link.springer.com/chapter/10.1007/978-3-319-45744-4_2 | yes | 2 | Tor web traffic | supervised WF classifier | WTF-PAD adaptive padding | inter-packet timing/padding shaping | sw | trace-driven simulation | trace-driven | attack accuracy 91%->20%, zero latency, <60% bandwidth | bandwidth overhead | adaptive-padding WF defense with zero added latency | precedent for low/zero-latency shaping defenses; comparator framing | high
Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning | Payap Sirinam; Mohsen Imani; Marc Juarez; Matthew Wright | 2018 | ACM CCS pp.1928-1943 | 10.1145/3243734.3243768 | https://dl.acm.org/doi/10.1145/3243734.3243768 | yes | 2 | Tor web traffic | 1D-CNN deep classifier (defense-aware) | (attack paper) | NA | sw | trace-driven | trace-driven | >98% no-defense, >90% vs WTF-PAD | NA | CNN WF attack defeats lightweight defenses; a defense must beat an adaptive deep attacker | justifies A6 temporal-CNN and A7 defense-aware protocol | high
Tik-Tok: The Utility of Packet Timing in Website Fingerprinting Attacks | Mohammad Saidur Rahman; Payap Sirinam; Nate Mathews; Kantha Girish Gangadhara; Matthew Wright | 2020 | Proceedings on Privacy Enhancing Technologies 2020(3) | 10.2478/popets-2020-0043 | https://petsymposium.org/popets/2020/popets-2020-0043.php | yes | 2 | Tor web traffic | deep classifier using timing features | (attack paper) | NA | sw | trace-driven | trace-driven | timing (burst-level) features materially aid WF | NA | shows raw packet-timing carries fingerprint signal | direct justification that timing is exploitable ⇒ A6 features and the whole timing threat | high
Zero-delay Lightweight Defenses against Website Fingerprinting | Jiajun Gong; Tao Wang | 2020 | USENIX Security pp.717-734 | NA | https://www.usenix.org/conference/usenixsecurity20/presentation/gong | yes | 2 | Tor web traffic | supervised/deep WF classifier | FRONT and GLUE (dummy-packet) defenses | zero-delay padding | sw | trace-driven | trace-driven | zero-latency defenses; robustness vs attacker | bandwidth overhead | evaluates what lightweight defenses survive strong attackers | comparator for low-latency defenses + the survives-strong-attacker mindset | high
On Evaluating Adversarial Robustness | Nicholas Carlini; Anish Athalye; Nicolas Papernot; Wieland Brendel; Jonas Rauber; Dimitris Tsipras; Ian Goodfellow; Aleksander Madry; Alexey Kurakin | 2019 | arXiv:1902.06705 | NA | https://arxiv.org/abs/1902.06705 | preprint | 2 | NA | adaptive/defense-aware attacker | NA | NA | NA | NA | NA | robustness eval methodology | NA | best practices: evaluate defenses against maximally-knowledgeable adaptive attackers | methodological basis for A7 defense-aware attacker and honest privacy claims | high
Automatic Construction of Statechart-Based Anomaly Detection Models for Multi-Threaded Industrial Control Systems | Amit Kleinmann; Avishai Wool | 2016 | ACM Workshop on Cyber-Physical Systems Security and PrivaCy (CPS-SPC) | NA | https://arxiv.org/abs/1607.07489 | yes | 3 | SCADA (Modbus) HMI-PLC traffic | (anomaly detector; models traffic) | NA | NA | sw | SCADA network traces | testbed | statechart DFA models periodic SCADA traffic accurately | NA | SCADA traffic is highly regular/modelable | context that ICS traffic patterns are learnable ⇒ fingerprinting feasibility | med

## BIBTEX
```bibtex
@article{lin2019raincoat,
  author  = {Lin, Hui and Kalbarczyk, Zbigniew T. and Iyer, Ravishankar K.},
  title   = {{RAINCOAT}: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers},
  journal = {IEEE Transactions on Smart Grid},
  year    = {2019},
  volume  = {10},
  number  = {5},
  pages   = {4893--4906},
  doi     = {10.1109/TSG.2018.2870362}
}

@inproceedings{formby2016control,
  author    = {Formby, David and Srinivasan, Preethi and Leonard, Andrew M. and Rogers, Jonathan D. and Beyah, Raheem A.},
  title     = {Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems},
  booktitle = {Network and Distributed System Security Symposium (NDSS)},
  year      = {2016},
  url       = {https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf}
}

@article{kraskov2004estimating,
  author  = {Kraskov, Alexander and St{\"o}gbauer, Harald and Grassberger, Peter},
  title   = {Estimating mutual information},
  journal = {Physical Review E},
  year    = {2004},
  volume  = {69},
  number  = {6},
  pages   = {066138},
  doi     = {10.1103/PhysRevE.69.066138}
}

@article{delong1988comparing,
  author  = {DeLong, Elizabeth R. and DeLong, David M. and Clarke-Pearson, Daniel L.},
  title   = {Comparing the Areas under Two or More Correlated Receiver Operating Characteristic Curves: A Nonparametric Approach},
  journal = {Biometrics},
  year    = {1988},
  volume  = {44},
  number  = {3},
  pages   = {837--845},
  doi     = {10.2307/2531595}
}

@article{mcnemar1947note,
  author  = {McNemar, Quinn},
  title   = {Note on the sampling error of the difference between correlated proportions or percentages},
  journal = {Psychometrika},
  year    = {1947},
  volume  = {12},
  number  = {2},
  pages   = {153--157},
  doi     = {10.1007/BF02295996}
}

@article{benjamini1995controlling,
  author  = {Benjamini, Yoav and Hochberg, Yosef},
  title   = {Controlling the False Discovery Rate: A Practical and Powerful Approach to Multiple Testing},
  journal = {Journal of the Royal Statistical Society: Series B (Methodological)},
  year    = {1995},
  volume  = {57},
  number  = {1},
  pages   = {289--300},
  doi     = {10.1111/j.2517-6161.1995.tb02031.x}
}

@article{peyre2019computational,
  author  = {Peyr{\'e}, Gabriel and Cuturi, Marco},
  title   = {Computational Optimal Transport: With Applications to Data Science},
  journal = {Foundations and Trends in Machine Learning},
  year    = {2019},
  volume  = {11},
  number  = {5--6},
  pages   = {355--607},
  doi     = {10.1561/2200000073}
}

@article{lin1991divergence,
  author  = {Lin, Jianhua},
  title   = {Divergence measures based on the Shannon entropy},
  journal = {IEEE Transactions on Information Theory},
  year    = {1991},
  volume  = {37},
  number  = {1},
  pages   = {145--151},
  doi     = {10.1109/18.61115}
}

@book{efron1993introduction,
  author    = {Efron, Bradley and Tibshirani, Robert J.},
  title     = {An Introduction to the Bootstrap},
  publisher = {Chapman \& Hall},
  address   = {New York},
  year      = {1993},
  isbn      = {0-412-04231-2}
}

@book{cohen1988statistical,
  author    = {Cohen, Jacob},
  title     = {Statistical Power Analysis for the Behavioral Sciences},
  edition   = {2nd},
  publisher = {Lawrence Erlbaum Associates},
  address   = {Hillsdale, NJ},
  year      = {1988},
  isbn      = {0-8058-0283-5}
}

@inproceedings{cai2014systematic,
  author    = {Cai, Xiang and Nithyanand, Rishab and Wang, Tao and Johnson, Rob and Goldberg, Ian},
  title     = {A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses},
  booktitle = {Proceedings of the 2014 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  year      = {2014},
  pages     = {227--238},
  doi       = {10.1145/2660267.2660362}
}

@inproceedings{juarez2016toward,
  author    = {Juarez, Marc and Imani, Mohsen and Perry, Mike and D{\'i}az, Claudia and Wright, Matthew},
  title     = {Toward an Efficient Website Fingerprinting Defense},
  booktitle = {Computer Security -- ESORICS 2016, LNCS 9878},
  year      = {2016},
  pages     = {27--46},
  doi       = {10.1007/978-3-319-45744-4_2}
}

@inproceedings{sirinam2018deep,
  author    = {Sirinam, Payap and Imani, Mohsen and Juarez, Marc and Wright, Matthew},
  title     = {Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning},
  booktitle = {Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  year      = {2018},
  pages     = {1928--1943},
  doi       = {10.1145/3243734.3243768}
}

@article{rahman2020tiktok,
  author  = {Rahman, Mohammad Saidur and Sirinam, Payap and Mathews, Nate and Gangadhara, Kantha Girish and Wright, Matthew},
  title   = {Tik-Tok: The Utility of Packet Timing in Website Fingerprinting Attacks},
  journal = {Proceedings on Privacy Enhancing Technologies},
  year    = {2020},
  volume  = {2020},
  number  = {3},
  pages   = {5--24},
  doi     = {10.2478/popets-2020-0043}
}

@inproceedings{gong2020zerodelay,
  author    = {Gong, Jiajun and Wang, Tao},
  title     = {Zero-delay Lightweight Defenses against Website Fingerprinting},
  booktitle = {29th USENIX Security Symposium (USENIX Security 20)},
  year      = {2020},
  pages     = {717--734},
  url       = {https://www.usenix.org/conference/usenixsecurity20/presentation/gong}
}

@article{carlini2019evaluating,
  author  = {Carlini, Nicholas and Athalye, Anish and Papernot, Nicolas and Brendel, Wieland and Rauber, Jonas and Tsipras, Dimitris and Goodfellow, Ian and Madry, Aleksander and Kurakin, Alexey},
  title   = {On Evaluating Adversarial Robustness},
  journal = {arXiv preprint arXiv:1902.06705},
  year    = {2019},
  url     = {https://arxiv.org/abs/1902.06705}
}

@inproceedings{kleinmann2016automatic,
  author    = {Kleinmann, Amit and Wool, Avishai},
  title     = {Automatic Construction of Statechart-Based Anomaly Detection Models for Multi-Threaded Industrial Control Systems},
  booktitle = {ACM Workshop on Cyber-Physical Systems Security and PrivaCy (CPS-SPC)},
  year      = {2016},
  url       = {https://arxiv.org/abs/1607.07489}
}
```

---

_Verification note: all 17 works were checked this session against a primary or authoritative
secondary source (publisher/DBLP/DOI landing pages). DOIs marked in the matrix are as verified;
`formby2016control` DOI is left NA (NDSS uses a stable PDF URL, exact DOI not confirmed) rather
than guessed; `kleinmann2016automatic` is cited via its arXiv/CPS-SPC record (workshop DOI not
confirmed, marked med confidence). Sirinam DF DOI (10.1145/3243734.3243768) and Lin-1991 DOI
(10.1109/18.61115) follow the standard ACM-CCS-2018 and IEEE-IT patterns and match the located
records but were not opened at the DOI resolver — treat as high-but-not-resolver-confirmed._
