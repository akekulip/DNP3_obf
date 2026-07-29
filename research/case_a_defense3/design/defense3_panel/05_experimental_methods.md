# Panel Memo E — Experimental Methods and Statistics

**Role:** experimental-methods and statistics reviewer (`meeting_direction.md` §4.E)
**Scope:** calibration/evaluation separation, sample size, design, metrics, falsification.
**Status:** analysis only. No code, no hardware.
**Branch / commit:** `research/case-a-defense3-fixed-ack-delay` @ `56349d3`
**Corpus of record:** `evidence/corrected_v2/cwi/out_C3/native_transactions.csv`
(n=100, md5 `dcff677db157a52a7077e5e55e409a3c`)

---

## 0. Three measured facts that drive everything below

Recomputed from the corpus, not quoted:

**F1 — the "n=100 steady-state" corpus is not all steady-state.** Sorted by
`read_ts_epoch`, transaction index 0 has `clrt_ms = 21.695`, and it is the **sample
maximum**. Excluding it, n=99, max = **12.089 ms**. That single first-poll observation
— 1% of the sample — moves the "D that clamps 100%" from **13 ms to 22 ms (41% of the
parameter)** and the mean added latency from 10.76 ms to 19.57 ms. The existing
`D_selection_curve.txt` D=22 recommendation is a one-point artifact of pooling a
connection-cold poll into a steady-state corpus.

**F2 — the polling schedule dominates every effect the study wants to measure.**
Campaign C1 (inter-poll median 275.25 ms, sd 23.567 ms — response-relative) versus C3
(400.00 ms, sd **0.028 ms** — absolute): median CLRT 27.26 ms vs 1.36 ms, Mann-Whitney
p = 1.7e-15, common-language effect size **A = 0.987**, Hodges-Lehmann shift
**25.03 ms**. The schedule confound is **8.3x larger than the largest D in the §14 grid
(3 ms)**. An arm-correlated schedule difference does not bias the result slightly; it
buries it.

**F3 — the two observables are statistically independent, and READ→ACK is strongly
autocorrelated.** Steady subset (n=99): Spearman rho(READ→ACK, CLRT) = **-0.010,
p=0.920**. Lag-1 autocorrelation: CLRT **-0.033** (effectively i.i.d., n_eff ≈ 106),
READ→ACK **+0.618** (n_eff ≈ **23** at n=99, decaying to ~0 by lag 6). Consequence:
"n ≥ 100" buys ~100 independent CLRT samples but only ~23 independent READ→ACK samples.
Any CI on READ→ACK computed as if i.i.d. is **~2.1x too narrow**.

---

## 1. Calibration versus evaluation

### 1.1 The violation that exists today

`research/case_a_fixed_ack_delay/evidence/D_selection_curve.txt` was computed on
`out_C3`. If `out_C3` (or a re-run under the same conditions labelled "native") is also
the native evaluation arm, **D is fitted and tested on the same campaign**. This must be
stated and fixed, not silently re-used.

### 1.2 Prescribed split

| Campaign | Purpose | n | Arms | Data may be used for |
|---|---|---|---|---|
| **CAL** | lock D, estimate `p_pred(D)`, verify regime | native only, **n ≥ 300** | 1 | choosing D, powering EVAL, predicting clamp fraction |
| **EVAL** | all reported results | **n ≥ 300 per arm** | native, D1, D2, D3@{1,2,3 ms} | every number in the report |

CAL and EVAL are separate captures, separate directories, separate CSVs, never
concatenated (§14: "Do not mix unrelated campaigns or append to existing CSV files").
CAL runs first, completes, and is frozen before any EVAL packet is sent.

### 1.3 Selection rule for D — pre-registered, deterministic

§14 already fixes the grid at D ∈ {1, 2, 3} ms. Treat that as pre-registration by fiat
and **do not change it after seeing EVAL**. CAL's job is then not to choose D but to
(a) verify the grid brackets the native distribution and (b) predict the clamp fraction.
Write the rule down before CAL as:

```
p_pred(D) = ECDF_CAL_steady(D)          # steady subset only, cold prefix removed
D_grid    = {1, 2, 3} ms                # fixed by directive §14
D_extra   = ceil(q99(CLRT_CAL_steady))  # ONE optional extra arm, rule stated in advance
```

`D_extra` exists because the fixed grid is knowingly weak (see §5.5); computing it from a
stated quantile rule on CAL is legitimate, computing it from EVAL is not. Do **not** use
`max(CLRT_CAL)` as the rule — the max is not an estimable quantity (§2.2).

**Interpretation to state up front, from CAL:** D=1 ms lies **below the measured minimum
native CLRT (1.0208 ms)**; predicted clamp fraction 0.000. That arm is a
**positive control for the mechanism** (does the hold fire, is the deadline accurate?)
and a **negative control for the defense** (zero information destroyed — the transform is
a bijection an adversary knowing D inverts exactly). Frame it that way in the report;
it is a designed control, not a failure.

### 1.4 Proving D was not tuned on EVAL

Four artefacts, all mechanical:

1. **Commit-before-collect.** `analysis/defense3_locked_config.json` containing
   `{D_grid, p_pred(D), tau, epsilon, cold_prefix_m, primary_metrics, tests}` plus the
   **SHA-256 of every CAL CSV**, committed on the branch. The commit timestamp must
   precede the first EVAL pcap's first-packet timestamp. Record both in the report.
2. **One-way analysis dependency.** `analysis/analyze_defense3.py` reads D and tau from
   the locked config; it must contain no code path that derives a threshold from the
   EVAL arm it is scoring. State this as a code-review checkbox.
3. **Frozen CAL hash re-verified** at analysis time and printed in the output header.
4. **Report both.** Publish `p_pred(D)` from CAL next to `p_obs(D)` from EVAL. Agreement
   is evidence the regime did not drift; disagreement is a finding, not a reason to
   re-pick D. (Power for that comparison: §2.4.)

---

## 2. Sample size

### 2.1 Where n = 100 is sufficient

* **Location shift on READ→ACK.** Predicted shift = D against sd 0.390 ms → Cohen's d =
  2.56 (D=1), 5.12 (D=2), 7.69 (D=3). Power > 0.9999 **even at n_eff = 23**. n=100 is
  over-powered by orders of magnitude.
* **Deadline error / release tail.** Prior silicon work measures ~23 ns spread; host-pcap
  resolution ~1-2 µs dominates. n=30 gives a mean-error SE of ~0.4 µs. n=100 is ample.
* **Falsification regression (§6).** Detects a 1% response-coupling slope at 55σ with
  n=30 (see §6.2). n=100 is ample.

### 2.2 Where n = 100 is **not** sufficient

Nonparametric bootstrap on the steady CLRT (5,000 resamples), 95% CI width:

| Statistic | n=100 | n=300 | n=1000 |
|---|---|---|---|
| median | ±0.38 ms | ±0.20 ms | ±0.13 ms |
| p90 | **±1.91 ms** | ±1.51 ms | ±1.18 ms |
| p95 | **±1.30 ms** | ±0.67 ms | ±0.51 ms |
| p99 | **±2.78 ms** | ±2.21 ms | ±0.72 ms |
| max | **not estimable** | not estimable | not estimable |

The max row is the important one: the bootstrap cannot exceed the empirical max, so its
CI is a **lower bound artefact**, not an estimate. Any D justified by "covers the observed
max" is justified by an unbounded quantity. Do not do it.

### 2.3 The binding constraint: the residual (unclamped) subset

The scientifically interesting transactions are the ones the defense **fails** to clamp —
they carry `c = C_out + D` exactly. That is a rare event at useful D:

| D (ms) | p_clamp (n=99) | Wilson 95% @ n=100 | half-width | n for ±0.05 | n for ±0.03 | n for 100 residual samples |
|---|---|---|---|---|---|---|
| 1 | 0.000 | [0.000, 0.037] | 0.018 | — | — | 100 |
| 2 | 0.616 | [0.512, 0.700] | 0.094 | 364 | 1010 | 261 |
| 3 | 0.848 | [0.756, 0.899] | 0.072 | 198 | 549 | 661 |
| 5 | 0.889 | [0.802, 0.930] | 0.064 | 152 | 422 | 900 |
| 7 | 0.960 | [0.888, 0.978] | 0.045 | 60 | 166 | 2475 |

At n=100 and D=2 ms the clamp fraction is known only to **±9.4 percentage points** — the
report would have to say "between 51% and 70% of CLRTs were destroyed", which is not a
result anyone can compare against Defense 2.

### 2.4 Regime-drift detection (CAL vs EVAL agreement, §1.4.4)

Minimum detectable difference in clamp fraction at 80% power, D=2 ms: **0.193 at n=100**,
0.111 at n=300, 0.079 at n=600. At n=100 the drift check is nearly useless.

### 2.5 Recommendation

**n = 300 successful transactions per EVAL arm, n = 300 for CAL.** Cost at the
400 ms absolute schedule: 2.0 min of polling per arm, **12 min total** for six arms,
before reload/settle overhead. n=600 costs 24 min. There is no resource argument for
n=100. If the panel keeps n=100, the report must carry the ±9.4 pp clamp-fraction CI
in the abstract, not in an appendix.

`p_clamp` is a per-transaction Bernoulli; treat n as the number of **successful,
steady-state, non-excluded** transactions, and pre-register the exclusion rules so the
denominator is not chosen after the fact.

---

## 3. The connection-cold problem

**Recommendation: force it in a dedicated arm, exclude it from the steady arms by a
pre-registered rule, report both. Never pool.**

### 3.1 Why not "exclude and forget"

The cold state is a real device behaviour (memory: connection-cold median ~25.3 ms vs
steady ~1.4 ms) and it is the regime where the CLRT leak is **largest and most
device-distinctive**. Silently dropping it makes the defense look better than it is. It
is also the regime where Defense 3 is guaranteed to fail: a cold CLRT of 21.7 ms passes
through D=1/2/3 ms essentially untouched (`C_out = c - D`).

### 3.2 Why not "pool"

F1: pooling one cold poll into 100 changes the derived D by 41%. Pooling also breaks
every i.i.d. assumption in §2 — the pooled sample is a two-component mixture whose
mixing weight is set by how often the harness reconnects, i.e. by the harness, not the
device.

### 3.3 Prescribed handling

1. **Steady arms.** One TCP connection per arm. Discard the first **m** transactions
   after connection establishment, `m` fixed from CAL (in C3, only index 0 is elevated →
   `m = 1`; use `m = 3` as a safety margin and state it). Discarded rows stay in the CSV
   with `excluded_reason = "connection_cold_prefix"` — deleted rows are unauditable.
2. **Cold arm (forced).** A separate campaign that **deliberately** reconnects: ≥ 30
   fresh TCP connections per treatment, first poll only, ≥ 60 s idle between connections.
   n=30 gives a median CI of roughly ±20% — adequate to state the failure, inadequate to
   quantify a defense. Label it exploratory.
3. **Reporting.** Every distribution table gets a `regime` column with values
   `steady` / `cold`. A pooled row may appear **only** if the mixing weight is stated and
   justified by an operational polling model.
4. **Never** justify a D from a pooled max.

---

## 4. Experimental design

### 4.1 Randomized complete block

* **Treatment factor (6 levels):** `native`, `defense1`, `defense2`,
  `defense3_D1`, `defense3_D2`, `defense3_D3`.
* **Block:** one contiguous time window containing **exactly one run of every arm**, in a
  randomized order. B = 10 blocks × 30 transactions per arm per block = **300 per arm**.
* **Randomization:** permutation of the 6 arms drawn independently per block from a
  recorded seed. Publish the seed and the **realized** order table; a design that cannot
  be replayed is not a design.
* **Rationale:** thermal drift, relay internal state, and background load are all
  slowly-varying. Blocking removes any monotone time trend from the arm contrast; a
  "run all native, then all defended" schedule aliases the trend onto the treatment.

### 4.2 Held constant (the control list)

Poll period and phase; master process, host, kernel, TCP options, and socket settings;
DNP3 object/variation and Class-0 request bytes; relay configuration (**never touched** —
§17); capture points, capture tool, snaplen and timestamp source; switch port config,
queue priorities, shaper, K=64 reservoir depth; ambient traffic on the protected link;
time of day within a block.

### 4.3 The reload confound and how to remove it

Arms differ in switch program (`native` / `defense1` / `defense2` / `defense3`), so a
`bf_switchd` reload is nested inside the treatment. Two mitigations, both required:

1. **Make D a runtime-writable register**, not a compile-time constant. Then D=1/2/3 are
   three levels of a **within-program** factor requiring only a BFRT write. This
   collapses three reload boundaries into zero and is the single highest-value design ask
   this memo makes of the P4 authors.
2. **Apply the reload uniformly.** Reload before every arm including `native`, with an
   identical settle time, so "was reloaded" is constant across arms. Log the reload
   timestamp and one `bf_switchd` verification per §17.

### 4.4 Polling schedule: absolute monotonic, and why response-relative leaks D

Schedule: `t_READ(k) = t0 + k·P`, `P = 400 ms`, generated from a monotonic clock, with a
**skip** (not a catch-up) policy if a response is outstanding — and the skip logged.

A response-relative schedule sets `t_READ(k+1) = t_RESP(k) + P'`. Under Defense 3 the
master's observed response time is `a + max(c, D + δ)`, so

```
inter-poll(k+1) = P' + a_k + max(c_k, D + δ)
```

Three failures follow:
1. **The inter-poll interval becomes a direct observable of D.** An adversary reads D off
   the poll cadence without touching the ACK at all — the defense advertises itself.
2. **Feedback confound.** The treatment perturbs the covariate (poll spacing) that drives
   the outcome (CLRT). Arms are then compared at different effective poll rates. F2
   measures that effect at 25.0 ms HL shift, 8.3x the largest D.
3. **Broken independence.** `c_k` enters `t_READ(k+1)`, inducing serial dependence and
   destroying the n_eff ≈ 106 that the absolute schedule delivers.

Empirical check to include in the report: inter-poll sd was **0.028 ms in C3 (absolute)**
versus **23.567 ms in C1 (response-relative)**. Gate every arm on measured inter-poll
sd < 1 ms and reject the arm otherwise.

### 4.5 Capture points

Two capture points are **mandatory**, not optional: master-facing (what the adversary
sees) and **relay-facing (upstream of the hold)**. Without the relay-facing capture the
native `c` is unobservable in defended traces, and the falsification test of §6 cannot be
run at all. Timestamps from a single source or with a measured, reported offset.

---

## 5. Metrics

Notation: `A` = READ→ACK, `C` = ACK→RESPONSE (CLRT), `R` = READ→RESPONSE, `H` = ACK hold
duration (`t_ACK_out − t_ACK_in`), `E = H − D` (deadline error), `δ` = release tail,
`τ` = clamp threshold (pre-registered; propose `τ = 0.20 ms`, ≫ the ~1.72 µs release tail
and ≫ pcap resolution), `ε` = equivalence margin (propose `ε = 0.05 ms`).

### 5.1 Location shift — is the shift exactly D?

* **Estimator:** Hodges-Lehmann `Δ̂ = median{A_def,i − A_nat,j}`, with a distribution-free
  (Moses) CI. Robust to the heavy tail; no normality assumption.
* **H0 to test is `Δ = D`, not `Δ = 0`.** Rejecting `Δ = 0` is trivial (d = 2.6-7.7) and
  proves nothing. Use **TOST equivalence** against `[D−ε, D+ε]`; report the 90% CI on Δ̂.
* **Pass:** the 90% CI lies inside `[D−ε, D+ε]`.
* **Autocorrelation:** A has lag-1 = 0.618. Compute the CI by **moving-block bootstrap**
  (block length ≥ 6, the lag at which the ACF crosses zero), not by an i.i.d. bootstrap.

### 5.2 Spread and shape — the honest negative

* **Estimators:** IQR ratio and MAD ratio, `scale(A_def)/scale(A_nat)`, with moving-block
  bootstrap CIs; plus Ansari-Bradley as a rank check.
* **H0: ratio = 1.** Defense 3 is a pure translation on A, so the **prediction is that
  H0 is not rejected** — native IQR 0.4013 ms, MAD 0.0369 ms, sd 0.3903 ms, all
  unchanged. Report this as a **preserved leak**, not as a pass.
* **The adversary's own test:** two-sample KS / Anderson-Darling on `(A_def − D)` versus
  `A_nat`. On the corpus this is identical by construction (KS = 0.010, p = 1.000). A
  defense-aware adversary subtracts D and recovers the native READ→ACK distribution
  exactly. State it.

### 5.3 The clamped fraction — the primary defense metric

* `p̂ = #{C_out ≤ τ} / n`, **Wilson 95% CI** (not Wald — p is near 0 and near 1 at the
  ends of the grid).
* **Two nulls, both pre-registered:**
  * *Mechanism check:* `H0: p = p_pred(D)` from CAL, exact binomial two-sided. Rejection
    indicates regime drift or a mechanism defect, not a better/worse defense.
  * *Defense claim:* one-sided `H0: p ≤ p0` for a stated operational target `p0`.
* Report `p̂` with CI in the abstract. At D=1 ms the expected result is
  **p̂ = 0.000, CI [0.000, 0.013] at n=300** — the pre-registered negative control.

### 5.4 The adversary-facing quantity — binning-free

For a defense-aware adversary who knows D, the mapping is deterministic:

```
C_out > τ  ->  ĉ = C_out + D          exact recovery
C_out ≤ τ  ->  ĉ ∈ (0, D]             posterior = native CLRT truncated to (0, D]
```

So the sufficient statistic is the **reconstruction rate** `ρ(D) = 1 − p(D)`, and the
residual uncertainty is fully described by the truncated posterior. Report, per D:

| D (ms) | ρ = recon. rate | posterior support width (ms) | posterior IQR (ms) | posterior sd (ms) | added ACK latency | added e2e latency (mean) |
|---|---|---|---|---|---|---|
| 1 | **1.000** | 0.000 | — | — | 1.00 ms | 0.001 ms |
| 2 | 0.384 | 0.979 | 0.140 | 0.242 | 2.00 ms | 0.507 ms |
| 3 | 0.152 | 1.979 | 0.955 | 0.530 | 3.00 ms | 1.302 ms |
| 5 | 0.111 | 3.979 | 0.983 | 0.636 | 5.00 ms | 3.070 ms |
| 7 | 0.040 | 5.979 | 1.069 | 1.345 | 7.00 ms | 4.911 ms |

(projected from CAL/C3 steady; the EVAL table replaces these with measured values and CIs.)

Every column is in milliseconds or a probability. No bin width appears anywhere. This is
the **latency-versus-clamping tradeoff curve** §15 asks for.

Where labels exist (native vs defended is a labelled two-class problem you **do** have),
add a **native-vs-defended detectability** readout: balanced accuracy / AUC of a simple
classifier on `(A, C, R)` with blocked cross-validation (never split within a block),
a **permutation null** (≥ 1000 permutations of the arm label), and a CI. Expect near-1.0
— Defense 3 is trivially detectable — and report that under §16's "do not claim
indistinguishability".

Do **not** claim cross-device anonymity: one relay, no device labels (§15).

### 5.5 Why binned entropy misleads here

Four measured reasons, all from this corpus:

1. **It can increase under a bijection.** At D=0.5 ms the prior study measured
   **ΔH = +0.260 bits** under `y = x − D`, a transform that provably destroys zero
   information. Pure bin-edge crossing.
2. **It is bin-width-dependent by a factor of 7.7.** Native steady CLRT, plug-in entropy:
   4.457 bits @ 0.05 ms bins, 3.985 @ 0.1, 2.870 @ 0.25, 2.316 @ 0.5, 1.686 @ 1.0,
   1.460 @ 2.0, 0.579 @ 5.0. The headline number is a choice, not a measurement.
3. **It is biased, and the bias moves with the treatment.** Miller-Madow bias
   `(K_occ−1)/(2n ln2)` at n=99: +0.051 bits at 1 ms bins (K=8) but +0.291 at 0.05 ms
   (K=41). The defense reduces occupied bins, so it reduces the bias, so part of any
   measured ΔH is a bias artefact, not information destruction.
4. **It conflates moved with destroyed.** Defense 1 leaves total observable entropy
   unchanged (0.819+1.750 → 2.047+0.000); a per-axis entropy table reads as a win.

**Rule:** binned entropy goes in an appendix, with bin width, bin origin, occupied-bin
count, the Miller-Madow correction, and a sensitivity sweep over ≥ 4 bin widths. The
headline is §5.4.

---

## 6. The falsification test

**Claim under test:** the ACK release is *predetermined* — the hold duration depends on D
and on nothing the device does. If that is false, Defense 3 is Defense 1 wearing a
different name.

### 6.1 The measurement

Regress, over successful steady-state defended transactions:

```
H_i = β0 + β1 · c_i + ε_i
```

where `H_i = t_ACK_out − t_ACK_in` (master-facing egress minus relay-facing ingress of the
same ACK) and **`c_i` is the native CLRT measured on the relay-facing link** — the
upstream capture from §4.5. Fit on **all** transactions, then separately on the
`c < D` and `c > D` subsets.

| Result | Meaning |
|---|---|
| **β1 ≈ 0 (CI inside ±ε_β), β0 ≈ D** | **PASS.** Release is predetermined. This is the claim. |
| β1 ≈ 1 on `c < D` | **FAIL.** The response is releasing the ACK → this is Defense 1. |
| 0 < β1 < 1 on `c < D`, β1 ≈ 0 on `c > D` | **FAIL (partial).** Early response is partially unblocking the queue — a queue/blocker interaction, not a deadline. |
| β1 ≈ 0 but β0 ≠ D | Mechanism is predetermined but **mis-calibrated**; report the deadline error separately, do not fail the independence claim. |
| β1 < 0 | Investigate before anything else: implies a shared-cause confound (e.g. ingress load driving both). |

Test `H0: β1 = 0` by **TOST against ±ε_β = 0.01** (1% coupling), reporting the CI, not a
bare p-value. Use HAC (Newey-West) standard errors given the READ→ACK autocorrelation.
Add a partial-correlation check of `H` on `c` controlling for `a`, to exclude `a` as the
real driver.

### 6.2 Power

With native CLRT sd 2.03 ms (steady) and host-pcap timestamp noise ~2 µs,
`se(β1) = σ_meas/(sd(c)·√N)`:

| meas. noise | N=30 | N=100 |
|---|---|---|
| 2 µs | slope 0.01 at **55σ**; slope 1.0 at 5541σ | 0.01 at 101σ; 1.0 at 10116σ |
| 20 µs | 0.01 at 6σ; 1.0 at 554σ | 0.01 at 10σ; 1.0 at 1012σ |

The test is effectively deterministic. **N=30 suffices**; no reason to skip it.

### 6.3 Constructive companion

Run the regression on D=**1 ms** as well as 2 and 3. At D=1 ms **every** response arrives
after the deadline (p_clamp = 0), so β1 = 0 is guaranteed by the arrival order and the
test is uninformative there — it only bites at D=2/3 where clamping actually occurs.
State that. Complement with the §13 Gate-4C forced-missing-response case (ACK must still
release at D), and note it is n=3 (§7).

**Precondition:** without the relay-facing capture point, none of this is measurable.
Treat §4.5 as a hard requirement, not an instrumentation nicety.

---

## 7. Synthetic gate statistics

§13's gates use n=1 (Gate 2), n=5 (Gate 3), and 3×3 (Gate 4). With zero observed
failures, the 95% upper bound on the per-transaction failure probability (rule of three,
exact: `1 − 0.05^(1/N)`) is:

| N consecutive passes | 95% upper bound on failure rate |
|---|---|
| 1 (Gate 2) | **0.950** |
| 3 (Gate 4, per boundary) | **0.632** |
| 5 (Gate 3) | **0.451** |
| 10 | 0.259 |
| 29 | 0.098 |
| 59 | 0.050 |
| 100 | 0.030 |
| 300 | 0.010 |

**What the gates can establish:** existence and wiring. "The mechanism *can* produce
ACK-before-RESPONSE ordering with a correct deadline at least once" (Gate 2); "it does so
repeatably enough that no gross state leak is present across five transactions"
(Gate 3); "each of the three arrival orderings is handled at least once" (Gate 4). That
is a correct and useful debugging function.

**What they cannot establish:** any reliability rate. A Gate-3 pass is statistically
consistent with a **45% failure rate**. Gate 4's 3/3 per boundary is consistent with 63%.
No sentence of the form "the mechanism reliably…", "always…", or "in all cases…" may cite
a synthetic gate.

**Second limit — common-mode.** Synthetic events are generated by the same tooling that
classifies them, so a synthetic pass carries **no** evidence about the physical relay's
ACK stream: keepalives, duplicate ACKs, retransmissions, window updates, and the relay's
actual sequence-number behaviour are all absent. The known ~10 s keepalive hazard is
exactly the class of defect synthetic gates cannot see.

**Recommendations (all cheap):**
* Extend Gate 3 from 5 to **59** transactions (≤ 5% failure rate at 95%) or **300**
  (≤ 1%). Synthetic transactions cost microseconds.
* Keep Gate 4 at 3 reps as a wiring check, but state the 0.632 bound inline in the gate
  report so nobody quotes "3/3" as reliability.
* Report gate outcomes as `k/N passed, 95% UCB on failure = x` — never as a bare "PASS".
* Reliability claims come **only** from the physical campaign: n=300 per arm with zero
  failures supports "≤ 1% failure rate at 95% confidence", which is a publishable
  sentence.

---

## 8. Pre-registration checklist (write before CAL runs)

1. `analysis/defense3_locked_config.json`: D grid, τ, ε, ε_β, `m` (cold prefix),
   exclusion rules, primary/secondary metrics, tests, CAL file SHA-256s. Committed.
2. Randomization seed and the block/arm design table. Committed.
3. Primary endpoint named: **clamp fraction `p(D)` with Wilson 95% CI**, and the
   reconstruction-rate / latency tradeoff table (§5.4). Everything else is secondary.
4. Falsification endpoint named: **β1 with 90% CI and TOST against ±0.01** (§6).
5. Stopping rule: fixed n per arm, no interim looks, no early stopping.
6. Exclusion rules stated in advance (cold prefix, retransmissions, incomplete
   transactions, blocks failing the inter-poll sd < 1 ms gate). Excluded rows kept in the
   CSV with a reason code.
7. Every reported number traceable to `{config hash, seed, arm, block, CAL/EVAL, commit}`.

## 9. Summary of prescriptive asks

| # | Ask | Cost | Consequence if ignored |
|---|---|---|---|
| 1 | Separate CAL (n≥300 native) from EVAL; freeze D before EVAL | ~2 min | D fitted and tested on the same data — fatal to the paper |
| 2 | n = 300 per EVAL arm, not 100 | +8 min total | clamp fraction known only to ±9.4 pp |
| 3 | Never pool cold polls; force them in a separate arm | 1 extra campaign | one observation moves D by 41% |
| 4 | Absolute monotonic schedule, gate on inter-poll sd < 1 ms | free | 25 ms schedule confound, 8.3x the effect |
| 5 | Make D a runtime register, reload uniformly across all arms | P4 design change | reload nested in treatment |
| 6 | Add a relay-facing capture point | 1 mirror port | falsification test (§6) impossible |
| 7 | Headline = clamp fraction + reconstruction rate + latency, in ms/probability | free | binned entropy varies 7.7x with bin width and can *rise* under a bijection |
| 8 | Report `k/N, 95% UCB` for every synthetic gate | free | "5/5 PASS" read as reliability when it bounds failure only at 45% |
