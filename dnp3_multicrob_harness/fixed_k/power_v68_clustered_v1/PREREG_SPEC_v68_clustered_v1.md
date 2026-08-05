# Preregistration spec: v6.8-clustered-v1 (master seed 6801)

> Statistics-review agent, 2026-08-05. NOTE: written for the fixed-K size campaign,
> which Philip STOPPED in commit d072c7f (scope reset -> timing core is Priority 1).
> Kept here for the transferable methodology, not to revive that campaign.
> STILL RELEVANT REGARDLESS OF CAMPAIGN: the clustered/blocked estimator lesson
> (transaction-level tests run at 63% false-positive rate vs nominal 5%), and
> scikit-learn being ABSENT from $RESEARCH_PYTHON.

---

I have verified numbers. Here is the specification.

---

# Preregistration spec: v6.8-clustered-v1, master seed 6801

## 0. Headline — one finding blocks the freeze

**The archived "K=16 reaches 0.82–0.83 power to certify absence" does not reproduce under the clustered/blocked estimator.** It is recoverable only under two choices that the cluster correction itself invalidates: an *unaligned pooled* Spearman (ignoring the round block) **and** a *one-sided directional* bound. Verified (`(K)` and `(L)`, analytic and Monte-Carlo agreeing to ±0.003):

| estimator variant, 10 rounds | K=4 | K=8 | K=16 |
|---|---|---|---|
| pooled unaligned, one-sided (the archived recipe) | 0.000 | 0.553 | **0.810** |
| pooled unaligned, two-sided \|ρ\| | 0.000 | 0.106 | 0.620 |
| round-aligned, one-sided | 0.000 | 0.507 | 0.787 |
| **round-aligned, two-sided \|ρ\| (the correct frozen estimator)** | **0.000** | **0.013** | **0.577** |

The *direction* of the archived conclusion is right (K=16 is the only stratum with any chance; K=4/K=8 are hopeless; more transactions per connection cannot help, only more rounds). The *number* is not. **At 10 rounds, no K certifies absence — including K=16.** You must either (a) go to **20 rounds** (25 if you want the ε² arm too), or (b) preregister all three strata as INCONCLUSIVE on absence and run this purely as a detection study. There is no third option that survives review.

Second blocking finding: **ε²\* = 0.04 is unattainable at every K, at any round count you would plausibly run.** Raw Kruskal–Wallis ε² = H/(N−1) has null expectation (K−1)/(N−1) = 0.077 / 0.089 / 0.094 for K = 4/8/16 — the SESOI sits *below the null mean*. Even bias-corrected, reaching it needs 40/31/23 rounds.

---

## 1. Connection-level summarization

**FROZEN: symmetric 1-from-each-end trimmed mean of the 6 scored transactions (= mean of the middle 4 order statistics), applied identically to all four features.**

```python
def conn_summary(v):                     # v: shape (..., 6), the 6 scored txns
    """Frozen connection-level location summary: mean of the middle 4 of 6."""
    s = np.sort(v, axis=-1)
    return s[..., 1:-1].mean(axis=-1)    # == scipy.stats.trim_mean(v, 1/6, axis=-1)
```

Justification, grounded in your own pre-campaign pilot (`smoke_20260805T140802Z/master.json`, K=4 R=2, 7 SBOs on one connection):

| statistic on the 6 scored SBOs | value |
|---|---|
| raw values (ms) | 3.056, 2.629, **274.827**, 3.668, 2.788, 2.573 |
| mean | 48.257 ms |
| median | 2.922 ms |
| **trimmed (middle 4)** | **3.035 ms** |
| MAD-based σ | 0.476 ms |
| raw sd | 110.997 ms — **233× the MAD-σ** |

One scheduler/timer spike in 6 transactions moved the mean by 16× the true level. The mean has breakdown point 0 and is disqualified. The trimmed mean has breakdown 1/6 with ~0.95 asymptotic efficiency at a normal core; the median of 6 (average of the 3rd and 4th order statistics) has ~0.70 efficiency, and since **power to detect is the primary safeguard of an absence claim**, throwing away 30% of efficiency is itself a validity threat. Trimming is a deterministic, tuning-free function — no researcher degrees of freedom.

Frozen companions:
- **Sensitivity summaries** (reported, never confirmatory): plain mean, median. **Rule: if any component verdict flips across the three summaries, that (K, feature) is INCONCLUSIVE.**
- **Dispersion summary** (secondary family, see §2): per-connection MAD of the 6 scored values. A timing channel can leak through jitter alone; omitting it is the first thing a reviewer will attack.
- **Warm-up rule:** transaction ordinal 0 of every connection is unscored and permanently excluded. It is never re-admitted, not even if it passes every validity gate. Freeze this sentence verbatim.
- **Validity rule:** a connection contributes only if all 6 scored transactions parse cleanly and pass criteria 6.1–6.7. A connection with 5 or fewer valid scored transactions is dropped whole (never partially summarized) and the round-cell is retried per the ≤2 infra-retry policy.

**Round alignment (frozen, and load-bearing):** after summarizing, subtract the within-round, within-K-stratum median across that round's K connections:

```python
Sa = S - np.median(S, axis=1, keepdims=True)   # S: (n_rounds, K)
```

This is the alignment step of the aligned-rank transform. It is **permutation-equivariant** — the median is taken over the *unordered set* of that round's summaries, so relabeling R within a round leaves the aligned values unchanged and only permutes their labels. That is what keeps the randomization test in §3 exact. State this in the protocol; it is the technical point that defeats the "your alignment invalidates your permutation null" attack.

---

## 2. Confirmatory battery, effect sizes, and the family

### 2.1 Per (K-stratum, feature) — two confirmatory tests

**(a) Omnibus, non-monotone-safe.** Kruskal–Wallis on the *aligned connection summaries*, grouped by R.

```python
H = stats.kruskal(*[Sa[:, j] for j in range(K)]).statistic
eps2_raw  = H / (N - 1)                      # N = n_rounds * K   (BIASED)
eps2_corr = (H - (K - 1)) / (N - K)          # FROZEN reported effect size
sd_eps2_null = math.sqrt(2 * (K - 1)) / (N - K)
```

p-value from the within-round permutation null (§3), not the χ² approximation. Report **ε²_corr** — the bias-corrected form, expectation ≈ 0 under H₀. `eps2_raw` is reported for continuity with the archived plan and immediately annotated as unusable for absence.

Preregistered sensitivity: Friedman χ²_F + Kendall's W on the same connection summaries (blocked; reported, not in the family; disagreement with aligned-KW ⇒ INCONCLUSIVE for that cell).

**(b) Monotone trend — this is the arm that carries the absence claim.** Spearman ρ between R and the aligned connection summary, pooled over all n_rounds × K connections in the stratum.

```python
rho = stats.spearmanr(np.tile(np.arange(1, K+1), n_rounds).astype(float),
                      Sa.ravel()).statistic
se_rho = 1.0 / math.sqrt((K * n_rounds - n_rounds) - 1)   # df loss: 1 per round
ucl95  = abs(rho) + 1.6448536 * se_rho                     # one-sided 95% UCL on |rho|
```

The `- n_rounds` term is the degrees of freedom consumed by the alignment medians. Omitting it is exactly one of the two errors that produced the archived 0.82. Preregistered sensitivity: Page's L ordered-alternatives trend test.

### 2.2 Per K-stratum — one classifier test (§4).

### 2.3 Exact confirmatory family size

```
3 K-strata × (4 features × 2 tests) = 24
3 K-strata × 1 classifier            =  3
                              TOTAL  = 27
```

**27**, matching the archived family size — re-derived, not inherited. Enumerate all 27 by name in the protocol appendix so the family cannot silently grow.

### 2.4 Multiplicity — the asymmetry rule

This is the most important structural commitment in the document.

- **Detection (FAIL) side — union-intersection.** Benjamini–Hochberg at q = 0.05 across **all 27 p-values jointly, as one family** (not per stratum: the claim "no timing channel in the fixed-K construction" is a single global claim). Use `scipy.stats.false_discovery_control(pvals, method='bh')` (confirmed present in scipy 1.16.3).
- **Absence side — intersection-union.** BH is *never* applied to license absence. Multiplicity correction makes non-significance easier to obtain, which is precisely the wrong incentive. Absence is an **intersection-union test**: every component equivalence must hold, each evaluated at unadjusted α = 0.05. The IUT requires no α adjustment — the level of the conjunction is α by construction. Write this out; it is the cleanest reviewer-proof element of the design.
- **Secondary families are FAIL-only.** The dispersion (MAD) family, the transaction-level classifier variant, ACK-gap features, and mutual information each get their own separate BH correction, are reported in full, and **can trigger FAIL but can never contribute to PASS.** Extra tests may only hurt the defense, never help it. This kills the "you ran until something looked null" attack in one sentence.

### 2.5 Effect-size reporting (all with one-sided 95% UCLs)

| arm | effect size | SESOI | UCL method |
|---|---|---|---|
| omnibus | ε²_corr = (H−(K−1))/(N−K) | 0.04 — **unattainable, see §5** | ε²_corr + 1.645·√(2(K−1))/(N−K) |
| trend | ρ (aligned, pooled) | ρ\* = 0.20 | \|ρ\| + 1.645/√(N−n_rounds−1) |
| R=1 vs R=K contrast | Cliff's δ on aligned values | descriptive | round block bootstrap |
| classifier | balanced accuracy − 1/K | δ_BA = 0.05 | §4 |

Cliff's δ contrast: because each round contains exactly one R=1 and one R=K connection, this is a **paired** design over 10 (or 20) rounds. The within-round permutation collapses to a sign-flip, so the null is **exactly enumerable** at 2^n_rounds arrangements (1,024 at 10 rounds; 1,048,576 at 20). Enumerate it exactly rather than sampling, and note the p-value floor of 1/1024 ≈ 9.8e-4 at 10 rounds — that floor is *above* the smallest BH threshold 0.05/27 = 1.85e-3? No: 9.8e-4 < 1.85e-3, so it clears, but only barely at 10 rounds. At 20 rounds it is a non-issue. Record the arithmetic.

---

## 3. Permutation scheme — within-round only

### Algorithm (frozen)

```python
def within_round_permutation_test(Sa, stat_fn, K, n_rounds, rng, B=20000):
    """Exact randomization test. Sa: (n_rounds, K) ALIGNED connection summaries,
    column j == R level j+1. Permutes R labels WITHIN each round independently."""
    R = np.arange(1, K + 1, dtype=float)
    x_obs = np.tile(R, n_rounds)
    t_obs = stat_fn(x_obs, Sa.ravel())
    # vectorised: one independent random permutation of 0..K-1 per (draw, round)
    perm = np.argsort(rng.random((B, n_rounds, K)), axis=2)
    Sb = np.take_along_axis(np.broadcast_to(Sa, (B, n_rounds, K)), perm, axis=2)
    t_null = np.array([stat_fn(x_obs, row.ravel()) for row in Sb])
    p = (1.0 + np.sum(t_null >= t_obs)) / (1.0 + B)     # Phipson-Smyth, never 0
    return t_obs, p, t_null
```

Order of operations, frozen and non-negotiable: **summarize → align → permute labels.** Never permute transactions; never re-summarize after permuting.

### Why within-round is the correct exchangeability structure

1. **It mirrors the physical randomization.** R is assigned per connection, and within each round exactly one connection is assigned to each R level — a within-block complete randomization. The randomization test that is *exactly* valid is the one that redraws from the assignment mechanism that was actually used. This makes the p-value exact by design, with no distributional assumption whatsoever. That is the strongest possible footing for a security-critical null result.
2. **Round is a genuine nuisance block.** Host thermal state, background load, page-cache warmth, and clock drift are shared by all 28 connections in a round. Summaries are exchangeable *within* a round under H₀, not across rounds.
3. **The transaction level is not exchangeable at all.** Transactions inherit R from their connection; permuting them breaks the cluster and inflates the effective n by the design effect 1 + (m−1)·ICC = 1 + 5·ICC.

### Verified Type-I error at nominal α = 0.05 (exact null, round sd = 1.0, 600 sims, B = 399)

| K | ICC | (1) txn-level KW | (2) txn-level perm | (3) conn-level, GLOBAL perm | (4) **conn-level, WITHIN-round (frozen)** |
|---|---|---|---|---|---|
| 4 | 0.0 | 0.012 | 0.017 | 0.092 | **0.067** |
| 4 | 0.3 | 0.127 | 0.098 | 0.095 | **0.053** |
| 4 | 0.6 | 0.312 | 0.173 | 0.077 | **0.057** |
| 16 | 0.0 | 0.000 | 0.013 | 0.055 | **0.053** |
| 16 | 0.3 | 0.257 | 0.100 | 0.065 | **0.060** |
| 16 | 0.6 | **0.633** | 0.168 | 0.053 | **0.050** |

MC standard error ≈ 0.009. The superseded transaction-level Kruskal–Wallis runs at **63% false-positive rate** at K=16 with ICC = 0.6 — a 12.7× inflation. Even correct-unit-but-global permutation runs ~0.09 at K=4. Put this table in the protocol.

**B = 20,000.** Justified by resolution, not convention: the smallest BH threshold in a 27-family is 0.05/27 = 1.85e-3; the permutation p-value floor 1/(B+1) = 5.0e-5 clears it by 37×, and the MC standard error on a p near 0.05 is √(0.05·0.95/20000) = 0.0015.

**Seeding.** Master seed 6801, with a documented spawn tree so every test's stream is independent and reconstructible:

```python
ROOT = np.random.SeedSequence(entropy=6801)
# spawn key: (stage, K_index, feature_index, test_index)
def child(stage, ki, fi, ti):
    return np.random.default_rng(np.random.SeedSequence(
        entropy=6801, spawn_key=(stage, ki, fi, ti)))
```

Dump every resolved child `SeedSequence.state` into the results JSON alongside the git SHA. Every number in the paper must be traceable to (config, spawn_key, commit).

---

## 4. Classifier evaluation — and no, Nadeau–Bengio is not still correct

### 4.1 Splitting

**Use `sklearn.model_selection.LeaveOneGroupOut` with `groups = round_id` — not `GroupKFold`.** With 10 (or 20) equal groups, `GroupKFold(n_splits=n_rounds)` happens to reduce to LORO, but that is a consequence of its size-balancing heuristic and is not a documented API guarantee across sklearn versions. `LeaveOneGroupOut` states the design directly and is version-proof.

Group by **round**, not connection. Grouping by connection would still let the model learn round-specific offsets shared by the connections in that round, producing optimistic accuracy. Round grouping is the strictly stronger constraint and it matches the block.

### 4.2 Unit and features

Primary confirmatory classifier operates on **connection-level feature vectors**: for each of the 4 features, {trimmed mean, median, MAD, IQR, min, max} of its 6 scored values = 24 features per connection. Target = R (K-way, chance = 1/K, matching the "recover R" threat model).

Barred from the feature matrix, enforced by an explicit allow-list assertion in the driver: point indexes, transmitted order, object ids, absolute timestamps, ordinal, connection id, round id, K, PCAP filename, byte counts.

**Attacker-favorable resolution of every discretionary choice.** Round-centering of features is applied inside the pipeline, computed per round from that round's own feature values only, with no labels — legitimate because no information crosses the train/test boundary, and it models an attacker who normalizes within an observation window. When a choice is genuinely arbitrary, resolve it toward the attacker. This principle, stated once, defuses a whole class of review objections.

```python
RandomForestClassifier(n_estimators=500, min_samples_leaf=2,
                       max_features="sqrt", class_weight="balanced",
                       random_state=<child seed>, n_jobs=8)
```

Identical hyperparameters for the observed run and every permutation replicate. `n_jobs > 1` is reproducible: sklearn draws per-tree seeds from the parent RNG in the main process.

### 4.3 Confidence interval — Nadeau–Bengio assessed

**Verdict: NB is not sufficient and not sufficient-as-primary, but it is not discardable either. Demote it to a mandatory conservatism check.**

NB corrects the variance of a cross-validation estimate for the correlation induced by *overlapping training sets* in repeated resampling, **under an IID sampling assumption for the data points**. Here:

- The assumption NB needs is exactly the one that fails. The data are clustered (6 transactions per connection) and blocked (connections nested in rounds). NB says nothing about clustering. Applying it and declaring the clustering handled would be a category error.
- The dependence NB targets is *partly* absent by design: LORO makes one pass with 10 disjoint test folds, no repetition, no overlapping test sets. But training sets still overlap by (n_rounds−1)/n_rounds, so fold estimates remain positively correlated and the naive sd/√n_rounds *under*-estimates the variance of the mean. That residual concern is real.

**Frozen procedure:**

1. **Primary:** round-level block bootstrap (BCa, B = 10,000) of the out-of-fold connection-level balanced accuracy, resampling the n_rounds rounds with replacement. Preregistered fallback: if the BCa jackknife acceleration is degenerate with so few blocks, fall back to the percentile interval and **record the fallback in the results JSON**.
2. **Conservatism check:** the NB-corrected fold interval, `Var = (1/J + n_test/n_train)·Σ(BA_r − BA̅)²/(J−1)`, giving an SE inflation of √(1 + n_rounds/(n_rounds−1)) = 1.453× at J = 10.
3. **The absence criterion is evaluated on the WIDER of the two intervals.** This is decisive, not cosmetic: at K = 16, 10 rounds, the UCL is 0.0975 naive (certifies) versus 0.1135 NB-corrected (fails), against a bound of 0.1125. Freezing the narrow one after seeing results would be indefensible; freeze the max-of-two rule now.

Verified null sd of per-round balanced accuracy (4,000 sims of a chance-level LORO classifier) matches the analytic √(p(1−p))/√K to three decimals — 0.2159 vs 0.2165 (K=4), 0.1169 vs 0.1169 (K=8), 0.0600 vs 0.0605 (K=16). The power arithmetic in §5 rests on this and it is confirmed.

### 4.4 Classifier permutation null

Same within-round label permutation, re-running the full LORO CV each draw. **B_clf = 2,000** (clears the 1.85e-3 BH floor). Budget ≈ 2,000 × n_rounds × RF fit ≈ 1 h per K-stratum at 10 rounds. If compute forces B_clf = 1,000, preregister that p < 1/1001 is reported as "< 1.0e-3" and entered into BH as 1/1001 — conservative.

---

## 5. Power analysis — simulation design, and the verification result

### 5.1 Generative model (frozen; commit this code)

```
y[r, j, t] = b_r + u_{rj} + e_{rjt} + tau * j
  b_r    ~ N(0, sigma_round^2)                 round block effect (sigma_round = 1.0)
  u_{rj} ~ N(0, ICC)                           connection random effect
  e_{rjt}~ N(0, 1-ICC) + Bernoulli(0.02)*30*sqrt(1-ICC)   contaminated txn noise
  tau                                          per-real-point cost, in within-connection sd units
```

Variances are normalized so σ²_conn + σ²_txn = 1 and ICC = σ²_conn directly. The 2%/30σ contamination is calibrated to the pilot (one 94×-median spike in 6 transactions — the pilot's own rate is 1/6, so 2% is *conservative* relative to observed).

Parameterizing the effect as **τ = per-additional-real-point OPERATE cost** rather than as an abstract ρ is what makes this defensible: it ties the statistic to the physical mechanism (real controls execute during OPERATE; `opr_lat_ms` is your named prime suspect) and converts the power analysis into a leakage-sensitivity statement in milliseconds. With the pilot's MAD-σ ≈ 0.476 ms, τ = 0.10 sd-units ≈ **48 µs per real point**.

**The simulation must call the exact frozen analysis functions**, not reimplementations. Preregister the compute compromise honestly: use the analytic UCL inside the bulk sim, having first verified on 500 calibration campaigns that the permutation and analytic decisions agree in ≥ 99% of campaigns; use a cheap linear surrogate for the classifier arm in the bulk sim with an RF validation subset. Hiding this compromise is what gets papers rejected; stating it costs nothing.

`N_sim = 10,000` for headline cells (MCSE 0.004 at power 0.8), 2,000 for the sweep grid. ICC swept over {0.0, 0.2, 0.4, 0.6, 0.8}.

### 5.2 Verification result — the archived conclusion is directionally sound, numerically not

**Power to certify absence, exact frozen estimator, τ = 0, ICC = 0.5, 4,000 sims:**

| rounds | connections | scored SBOs | K=4 (2-sided) | K=8 (2-sided) | K=16 (2-sided) | K=16 (1-sided) |
|---|---|---|---|---|---|---|
| **10 (current design)** | 280 | 1,680 | 0.000 | 0.014 | **0.577** | 0.786 |
| 12 | 336 | 2,016 | 0.000 | 0.152 | 0.701 | 0.850 |
| **15** | 420 | 2,520 | 0.000 | 0.314 | **0.826** | 0.912 |
| **20** | 560 | 3,360 | 0.000 | 0.517 | **0.932** | 0.966 |
| 25 | 700 | 4,200 | 0.059 | 0.681 | 0.972 | 0.986 |

**ICC is second-order** (K=16 two-sided: 0.599 / 0.569 / 0.575 / 0.579 / 0.589 across ICC = 0.0 → 0.8). This is the correction working as intended: once you summarize to the connection, the binding constraint is the *number of connections*, not the within-connection correlation. It confirms the RUN_LOG claim that more transactions per connection cannot fix this — only more rounds.

**Rounds required for ≥ 0.80 certification power, per arm:**

| arm | K=4 | K=8 | K=16 |
|---|---|---|---|
| \|ρ\| ≤ 0.20 (two-sided) | 72 | 31 | **15** |
| ρ ≤ 0.20 (one-sided, directional) | 52 | 23 | 11 |
| ε²_corr ≤ 0.04 | 40 | 31 | 23 |
| BA − chance ≤ 0.05, naive fold SE | 118 | 36 | 11 |
| BA − chance ≤ 0.05, **Nadeau–Bengio SE** | > 200 | 70 | **20** |

**Equivalence-test size is valid.** At a calibrated boundary effect (true ρ ≈ 0.20), the false-certification rate is 0.000 / 0.003 / 0.000 for K = 4/8/16 — conservative, never anti-conservative. The procedure cannot certify absence in the presence of a boundary-sized channel.

**Power to detect (FAIL), ICC = 0.5, effect τ in within-connection sd units:**

| K | τ=0.05 | τ=0.10 | τ=0.20 | τ=0.35 | τ=0.50 |
|---|---|---|---|---|---|
| 4 | 0.007 | 0.033 | 0.107 | 0.600 | 0.910 |
| 8 | 0.028 | 0.258 | 0.985 | 1.000 | 1.000 |
| 16 | 0.662 | 1.000 | 1.000 | 1.000 | 1.000 |

At 10 rounds the design detects a moderate channel decisively at K=16 (τ ≈ 0.05 sd ≈ 24 µs per real point) and at K=8, and needs τ ≈ 0.35 sd at K=4. The archived "well-powered to FAIL at every K" is **sound for K=8 and K=16, optimistic for K=4** — at K=4 the campaign can only detect a per-real-point cost above roughly 165 µs.

### 5.3 Recommendation

**Go to 20 rounds.** At 20 rounds K=16 clears ≥ 0.80 on the trend arm (0.932) *and* on the classifier arm under the conservative NB interval (0.802), which is the binding constraint. K=4 and K=8 remain preregistered INCONCLUSIVE on absence, as intended. The cost is trivial: the pilot ran 7 SBOs in 294 ms, so at a conservative 5 s per round-cell including dumpcap and connection setup, 28 × 20 = 560 round-cells ≈ 47 minutes of wall clock. There is no defensible reason to stay at 10 rounds and then argue about a 0.577 power figure with a reviewer.

**25 rounds** additionally brings the ε²_corr arm at K=16 to ≥ 0.80, making the omnibus a certification arm rather than detection-only. Worth it if the campaign is unattended overnight anyway.

**If 10 rounds is immovable:** preregister *all three* strata as INCONCLUSIVE on absence and state that criterion 6.8 is a detection study only. Do not preregister K=16 as certification-eligible at 0.577 power.

### 5.4 The ε² SESOI must be repaired before freezing

ε²\* = 0.04 as written is unattainable at every K. Two acceptable repairs — pick one now, in writing:

- **(preferred) Declare the omnibus arm DETECTION-ONLY** at all K, and rest the absence conjunction on the trend arm plus the classifier arm. This is standard and well-motivated: R is an *ordered* factor, so the 1-df trend contrast concentrates the signal while the (K−1)-df omnibus spreads it; the omnibus's job is to catch non-monotone effects, which is a detection role.
- **(alternative) Re-derive the bound** from the frozen null sd √(2(K−1))/(N−K): the minimum certifiable ε²_corr at 80% power is 0.169 / 0.129 / 0.095 for K = 4/8/16 at 10 rounds. Setting ε²\* = 0.10 at K=16 with 20 rounds is defensible, but changing a SESOI is exactly the move a reviewer scrutinizes, so document that it was changed *before* any campaign data existed, and why.

Either way, **mark ε²_raw = H/(N−1) as unusable for absence** with the arithmetic E[ε²_raw | H₀] = (K−1)/(N−1) = 0.077 / 0.089 / 0.094 shown inline.

---

## 6. Decision rules

Define per K-stratum:

- `DET(K)` — at least one of the 9 confirmatory tests in stratum K survives BH at q = 0.05 in the joint 27-family.
- `EQ_rho(K)` — for **all 4** features, `|rho| + 1.645·se_rho < 0.20` (intersection-union, unadjusted α).
- `EQ_clf(K)` — `UCL(BA − 1/K) < 0.05` under the **wider** of {round block bootstrap, NB-corrected fold interval}.
- `POW(K)` — the **frozen power simulation** (committed with the protocol, seed 6801, output file hashed into the manifest) reports ≥ 0.80 certification power for stratum K on **every arm in the absence conjunction**, at the pilot ICC.
- `INTEG(K)` — ≥ 90% of rounds complete; criteria 6.1–6.7 all PASS for the stratum; ≥ 95% of scored transactions valid; the mean and median sensitivity summaries flip no component verdict; the Friedman/Kendall-W sensitivity agrees with aligned-KW.

**Rules:**

- **FAIL(K)** ⟸ `DET(K)` and the corresponding observed effect ≥ its SESOI. A timing channel is demonstrated.
- **INCONCLUSIVE-DETECTED-SUBTHRESHOLD(K)** ⟸ `DET(K)` but every detected effect < its SESOI. Reported as a real but sub-threshold channel. **Never PASS.**
- **PASS(K)** — evidence of absence — only if **all five** hold: `¬DET(K)` ∧ `EQ_rho(K)` ∧ `EQ_clf(K)` ∧ `POW(K)` ∧ `INTEG(K)`. Any secondary-family test surviving its own BH correction **vetoes** PASS.
- **INCONCLUSIVE(K)** in every other case.

**Frozen per-K commitments, written into the protocol so they cannot be revisited:**

> **K=4 and K=8 are preregistered INCONCLUSIVE on absence.** `POW(4) = POW(8) = FALSE` by the committed simulation at any round count this campaign will run. This holds *regardless of what the data show* — a clean null at K=4 will not be upgraded, and the reason is that certifying |ρ| ≤ 0.20 at K=4 requires 72 rounds and at K=8 requires 31.
>
> **K=16 absence may PASS only if the effect, classifier, confidence, and power criteria all pass.** A single failure among the four yields INCONCLUSIVE, not PASS.
>
> **A nonsignificant p-value is never, alone or in aggregate across features, evidence of absence.** Absence is licensed exclusively by the conjunction of a bounded effect size (upper confidence limit below the SESOI), an at-chance classifier under the wider of two interval methods, and adequate power frozen in advance. Non-rejection of H₀ contributes nothing to a PASS.

**Global criterion 6.8 verdict:** PASS only if `PASS(16)` ∧ `¬FAIL(4)` ∧ `¬FAIL(8)`, and the K=4/K=8 absence arms are reported as INCONCLUSIVE in the same sentence as the K=16 result. Claim ceiling, consistent with RUN_LOG §5:

> At K=16, timing features do not recover R at the preregistered SESOIs (bounded |ρ| < 0.20 and classifier within 0.05 of chance, one-sided 95% upper limits), at 0.93 power to certify. At K=4 and K=8 the campaign is powered to detect a moderate channel but not to certify its absence; those strata are INCONCLUSIVE. Emulator only.

---

## 7. Defects in the earlier IID plan — mark SUPERSEDED explicitly

| # | Superseded item | Why it fails | Replacement |
|---|---|---|---|
| 1 | **n = 60 independent transactions per cell** | The 6 transactions in a connection are clustered; design effect 1 + 5·ICC. Measured Type-I at nominal 0.05: **0.633** (K=16, ICC=0.6). | Connection is the unit: 10 (→20) per cell. |
| 2 | **RepeatedStratifiedKFold(5×5)** | Splits transactions, so the same connection appears in train and test — the model memorizes connection offsets and "recovers R" trivially. Repetition also demands NB, which itself assumes IID points. | `LeaveOneGroupOut(groups=round_id)`. |
| 3 | **Nadeau–Bengio CI as primary** | Corrects training-set overlap under IID sampling; says nothing about clustering. Neither sufficient nor discardable. | Primary = round-level block bootstrap; NB demoted to a mandatory conservatism check; absence evaluated at the **wider** bound. |
| 4 | **"≥ 60 valid reps/cell licenses absence"** | Reps within a connection add no independent units. Verified: ICC has near-zero effect on certification power. | Only rounds add units: 72/31/15 rounds for K=4/8/16 (two-sided ρ arm). |
| 5 | **BH FDR used on the absence side** | Multiplicity correction makes non-significance *easier*, rewarding exactly the wrong thing. | BH governs detection only; absence is an intersection-union test at unadjusted α. |
| 6 | **Global / unblocked permutation** | Round drift enters the null. Measured Type-I 0.092–0.095 at K=4. | Within-round permutation of R labels, on aligned connection summaries. |
| 7 | **ε² = H/(N−1) with SESOI 0.04** | E[ε²_raw \| H₀] = 0.077/0.089/0.094 > 0.04. The bound sits below the null mean; it can never be met. | ε²_corr = (H−(K−1))/(N−K); omnibus arm becomes detection-only (or bound re-derived — §5.4). |
| 8 | **KW on pooled transactions, unblocked** | Level-valid at connection level but discards the block, losing power. For an absence claim a power defect *is* a validity threat to the conclusion. | Aligned-KW + permutation; Friedman/Kendall-W as sensitivity. |
| 9 | **KSG mutual information in the confirmatory set** | KSG assumes IID samples; its shuffle null must also be a within-round connection-level shuffle; and MI has no calibrated equivalence bound. | Descriptive/exploratory only, outside the 27-family. |
| 10 | **"optional ACK gaps under a 95%-availability admission rule"** | Admitting a feature conditional on observed data is a garden of forking paths. | Four features frozen. ACK-gap features go to the secondary FAIL-only family. |
| 11 | **Archived power figure 0.82/0.83 for K=16** | Reproducible only with an unaligned pooled Spearman *and* a one-sided bound. Under the frozen estimator: **0.577** at 10 rounds. | Recompute and commit; go to 20 rounds. |
| 12 | *(not previously stated)* Warm-up exclusion | Undocumented. | Ordinal 0 permanently unscored, never re-admitted. |

---

## 8. Two reproducibility blockers to clear before the gate commit

1. **`$RESEARCH_PYTHON` has no sklearn.** RUN_LOG §4 step 3 says the stats driver runs on `$RESEARCH_PYTHON` "(numpy/scipy/sklearn/pandas)". Verified: `~/.venvs/research/bin/python` (3.12) carries numpy 2.3.5, scipy 1.16.3, pandas 2.3.3 and **no scikit-learn**. The only sklearn on this machine is 1.3.2 on system python 3.8. Install scikit-learn into the research venv, pin the exact version in the protocol and in the environment manifest, and re-run the guard tests — sklearn 1.3.2 predates numpy 2.x and will not work against numpy 2.3.5 anyway, so the version pin is load-bearing. Do not split the analysis across two interpreters.
2. **Everything else the driver needs is present and verified:** `scipy.stats.false_discovery_control`, `permutation_test`, `bootstrap`, `kruskal`, `spearmanr`, `friedmanchisquare`, `wilcoxon`, `trim_mean`, and `rankdata(axis=)` (needed for the vectorized bootstrap) all exist in scipy 1.16.3.

---

## Files

Verification code and output, to be moved into the repo and committed with the protocol (I made no edits under `/home/philip/Projects/DNP3`):

- `/tmp/claude-1002/-home-philip-Projects-Job-App/780acf68-71ad-4a9c-b990-c2c15014a802/scratchpad/verify_power.py` — API check, pilot dispersion, analytic SEs, MC certification power, detection power, equivalence-test size
- `/tmp/claude-1002/-home-philip-Projects-Job-App/780acf68-71ad-4a9c-b990-c2c15014a802/scratchpad/diagnose.py` — isolates the failing criterion; ε² null bias; block-bootstrap vs analytic UCL; ICC sweep
- `/tmp/claude-1002/-home-philip-Projects-Job-App/780acf68-71ad-4a9c-b990-c2c15014a802/scratchpad/rounds.py` — reconciliation of the archived 0.82; round-count scaling; per-arm rounds-required; empirical sd(BA_round)
- `/tmp/claude-1002/-home-philip-Projects-Job-App/780acf68-71ad-4a9c-b990-c2c15014a802/scratchpad/typeI2.py` — Type-I error of the superseded IID scheme vs the frozen scheme

Suggested destination: `dnp3_multicrob_harness/fixed_k/power_v68_clustered_v1.py`, with its stdout captured verbatim into `defense4/evidence/fixed_k_emulator/PROTOCOL_<ts>_POWER.txt` and both hashed into the SHA-256 manifest.

Ground-truth files read: `/home/philip/Projects/DNP3/defense4/evidence/fixed_k_emulator/RUN_LOG.md`, `/home/philip/Projects/DNP3/defense4/autonomous_run.md`, `/home/philip/Projects/DNP3/defense4/agent_notes/evaluation_e0.md`, `/home/philip/Projects/DNP3/defense4/analysis/e0.py`, `/home/philip/Projects/DNP3/defense4/evidence/fixed_k_emulator/smoke_20260805T140802Z/master.json` and `SMOKE_VERDICTS.txt`. No `PROTOCOL_*.md` and no stats driver exist yet under `defense4/` or `dnp3_multicrob_harness/`.

---

```text
Operation Review
1. Read-only audit of the DNP3 defense4 fixed-K preregistration ground truth; independent
   re-derivation and Monte-Carlo verification of the v6.8-clustered-v1 power claims.
2. No repository files modified. Four verification scripts written to the session scratchpad.

Current Status
• The archived K=16 certification power of 0.82/0.83 does NOT reproduce under the clustered,
  round-blocked estimator: it is 0.577 (two-sided) / 0.786 (one-sided) at 10 rounds. The
  archived figure requires an unaligned pooled Spearman AND a one-sided bound.
• The frozen SESOI epsilon-squared* = 0.04 is unattainable at every K; the null mean of the
  uncorrected statistic (0.077 to 0.094) exceeds it.
• The superseded transaction-level test runs at 63% false-positive rate at nominal 5%.
• scikit-learn is absent from $RESEARCH_PYTHON, contradicting RUN_LOG step 3.

Next Steps
1. Decide the round count before freezing: 20 rounds (K=16 certifiable on the trend and
   classifier arms) or 25 (adds the omnibus arm), else preregister all three strata
   INCONCLUSIVE on absence. Estimated cost of 20 rounds: about 47 minutes wall clock.
2. Repair the epsilon-squared arm: declare it detection-only, or re-derive the bound.
3. Install and pin scikit-learn in the research venv against numpy 2.3.5.
4. Move the four verification scripts into fixed_k/, re-run at the final round count with
   N_sim = 10000, and hash the stdout into the protocol manifest before the gate commit.
```