# Panel memo D — Adversarial traffic analysis

**Role:** define the precise CLRT attacker model; distinguish native-trained and defense-aware
attackers; determine what a fixed `D` can and cannot claim.
**Authority:** `meeting_direction.md` §15 (attacker and classifier evaluation), §16 (claim
boundaries). This memo is analysis only — no code was changed and no hardware was touched.
**Primary data:** `evidence/corrected_v2/cwi/out_C{1,2,3,4_*}/native_transactions.csv`
(physical SEL-751, master-side capture, own DNP3 decoder with exact TCP seq/ack pairing).
**Prior work:** Formby et al., *Who's in Control of Your Control System?* (NDSS 2016), repo root.
**Reproduction:** every number below comes from the CSVs named above; the analysis scripts are
inline in the panel transcript and should be re-run as `analysis/analyze_defense3.py` sub-checks
before any of these figures reach a report.

---

## 0. Bottom line

1. Defense 3 is **left-censoring with a known offset**, not obfuscation. Below `D` it destroys the
   CLRT; above `D` it applies `y = c − D`, a bijection that preserves every location-invariant
   statistic exactly (measured sd ratio 1.0000 at D=1). The Formby fingerprint is **truncated,
   not destroyed**: an adversary recovers `P(c<D)` and the exact conditional law of `c | c>D`.
2. The direction's own D grid is mis-centred against the measured device. `D = 1 ms` sits below
   the native minimum (1.0208 ms on C3): **0/100 transactions concealed, ΔH = 0, sd ratio 1.0000,
   zero added end-to-end latency, and 100% exact recovery by an adversary who knows D.** D=1 ms is
   an information no-op and must not be reported as a defended arm without that label.
3. **The largest single result in this dataset is not about the defense.** Three *nominally
   identical* native campaigns of the same relay (C1/C2/C3, all `period_ms=400, idle_s=1`) have
   CLRT medians of 25.25 / 2.31 / 1.40 ms and pairwise AUROC up to **0.985**. The device moves
   further on its own between replicate captures than Defense 3 moves it at D ≤ 3 ms
   (AUROC 0.778 / 0.878 / 0.894). Any concealment number calibrated on C3 alone is fitted to one
   capture session.
4. Defense 3 **relocates the leak into `READ→ACK = a + D`, and relocation is not concealment for
   this feature** — the shift is constant, so the shape of `a` is preserved bit-for-bit and
   `AUROC(a, a+D) = 1.000` for D ≥ 2 ms. The presence of the defense is trivially detectable.
5. Supportable claim: *Defense 3 clamps the observed ACK→RESPONSE interval to the hardware release
   separation for transactions whose native CLRT is below D, and shifts the remainder.* Not
   supportable: any statement that the CLRT is hidden, that the fingerprint is degraded, or that
   defended traffic resembles native traffic.

---

## 1. Attacker model, stated precisely

### 1.1 Vantage

Passive on-path or SPAN observer on the **master-facing** segment, between the Tofino and the
SCADA master — the same vantage Formby assumes (substation aggregation switch, ~130 DNP3 devices,
0.01% link utilisation). The observer is downstream of the defense: it sees released packets, not
the relay's original emission times. It is passive: no injection, no probing, no relay access.

A second, weaker vantage — a tap on the **relay-facing** segment — sees native timing directly and
defeats every construction in this project. Defense 3's threat model must state explicitly that
the adversary is master-side only. That is an assumption, not a result.

### 1.2 Observables

Per Class-0 transaction `READ → pure ACK → RESPONSE`, the observer times three packets and derives:

| symbol | interval | native C3, n=100 |
|---|---|---|
| `a` | READ → pure ACK (TCP-stack latency + path RTT) | median 0.505, sd 0.391, min 0.400, max 2.138 ms |
| `c` = CLRT | pure ACK → RESPONSE (**Formby's feature**) | median 1.401, sd 2.807, min 1.021, p95 6.892, max 21.695 ms |
| `a + c` | READ → RESPONSE (end-to-end envelope) | median 2.507, sd 2.826 ms |

Measured `Spearman ρ(a, c) = −0.0004 (p = 0.997)`: the two intervals are statistically independent
on this device. That matters twice — `a` cannot be used to predict `c`, and conversely inflating
`a` by a constant leaks nothing new about `c`.

Formby selects `c` specifically because both packets travel outstation → master, so `c` is
independent of path RTT and therefore portable across networks. `a` is not: it contains the RTT
and is vantage-dependent. This asymmetry is the only structural advantage Defense 3 has, and it is
an argument about *feature portability*, not about information content.

Secondary observables the evaluation must not forget: frame sizes (unchanged — 66 B ACK, 120 B
response, out of scope this phase), TCP timestamps (relay TSval granularity measured at ~317–400 ms;
`MI(ΔTSval; CLRT) = 0.144 bits`, 6.1% of CLRT entropy — negligible but non-zero), IP ID sequence,
retransmissions and duplicate ACKs, and the inter-READ interval (C3 median 400.0 ms — the master
polls on an absolute schedule, so no CLRT re-exposure through poll spacing; **verify this holds for
every defended arm**, because a response-anchored poller would re-expose `max(c, D+δ)`).

### 1.3 Knowledge — the two §15 cases

**Model A — native-trained attacker.** Has a Formby fingerprint trained on this device before
deployment: a binned CLRT histogram or a (mean, variance) pair per time slice. Does not know a
defense exists. Question §15 asks: *does deployment invalidate the existing model?*
What A recovers under Defense 3: for `c > D`, samples arrive shifted by `−D` and land in the wrong
histogram bins; for `c < D`, samples land in bin 0. A's per-transaction likelihoods are therefore
wrong — but A is not the interesting adversary, because A's failure mode is *detection of change*,
which Formby explicitly treats as an alarm (see §6).

**Model B — defense-aware attacker.** Knows the mechanism, retrains on defended traces, and treats
`D` as an unknown scalar to be estimated. `D` is recoverable several ways, all cheap: (i) the
offset between the observed continuum's lower edge and any native reference; (ii) the inflation of
`READ→ACK` above the plausible TCP-stack range; (iii) the location of the atom relative to the
gap (§6); (iv) reading the switch configuration if the adversary is an insider. **B should be
assumed to know `D` exactly.** What B recovers: `c = CLRT_out + D` exactly for every uncensored
transaction, plus the fact `c ∈ [0, D]` for every censored one.

---

## 2. What a fixed D can and cannot claim

### 2.1 The transform, stated as censoring

`CLRT_out = max(c − D, δ_release)` partitions transactions into two regimes with completely
different security properties:

- **Shift regime (`c > D`)** — `y = c − D` is a bijection. Zero information destroyed. Model B
  inverts it exactly. Even model A, which does *not* know `D`, retains every location-invariant
  statistic: measured `sd(c−D | c>D) = sd(c | c>D)` **identically** (D=1: 2.8071 = 2.8071;
  D=2: 3.8042 = 3.8042; D=3: 4.5998 = 4.5998). Formby's simple (mean, **variance**) feature set is
  half location-invariant, so the variance channel survives a shift untouched.
- **Censoring regime (`c ≤ D`)** — this is the direction's real claim, and it is correct as far as
  it goes: `READ→ACK = a + D` and `ACK→RESPONSE = δ_release` and `READ→RESPONSE = a + D + δ`
  contain no term in `c`. **`c` appears in no first-order inter-packet interval.** This is
  qualitatively stronger than a shift — it is destruction, not relocation.

The residual in the censoring regime is not zero. The adversary still learns the indicator
`1{c < D}`, i.e. interval censoring at `D`. Per transaction that indicator carries
`H(0.61) = 0.965 bits` at D=2 and `H(0.84) = 0.634 bits` at D=3, against a native
`H(c) = 1.750 bits` at 1 ms bins. Across many transactions the *rate* `P(c<D)` is estimated to
arbitrary precision and is itself device-discriminative — it varies from 0% (C1) to 29% (C2) to
61% (C3) on one relay. The honest statement is therefore: **Defense 3 truncates the Formby
fingerprint below `D`; it does not remove it.** The adversary reconstructs the histogram exactly
above `D` and knows the total mass below it.

### 2.2 Quantified on the measured vector — D ∈ {1, 2, 3} ms

C3, n = 100, `δ_release = 1.72 µs` (repo-measured Part 12 deadline-release tail; see caveat in §6):

| D (ms) | censored `c<D` | shifted `c>D` | sd(CLRT_out) | sd ratio | e2e added mean / max (ms) | ACK delay added | AUROC(native vs defended CLRT) | B recovers `c` exactly |
|---|---|---|---|---|---|---|---|---|
| **1** | **0/100** | 100/100 | 2.8071 | **1.0000** | 0.0000 / 0.000 | 1.0 ms, 100/100 | 0.778 | **100/100** |
| **2** | 61/100 | 39/100 | 2.6152 | 0.9316 | 0.4724 / 0.981 | 2.0 ms, 100/100 | 0.878 | 39/100 |
| **3** | 84/100 | 16/100 | 2.3740 | 0.8457 | 1.2477 / 1.981 | 3.0 ms, 100/100 | 0.894 | 16/100 |

Reference points from the same vector: D=7 (≈ p95) → 95/100 censored, 4.816 ms mean added;
D=22 (≈ max) → 100/100, 19.571 ms mean added. These reproduce
`research/case_a_fixed_ack_delay/evidence/D_selection_curve.txt` and
`K1_transform_gate_result.txt` independently.

**D = 1 ms is below the native minimum (1.0208 ms).** Nothing is censored, nothing is destroyed,
no end-to-end latency is added, and a defense-aware adversary recovers 100/100 native CLRTs. Its
only measurable effect is a 1 ms delay on every ACK and a detectable 1 ms shift. It is a valid
*negative control* — an arm that should show zero concealment — and should be reported as such,
never as a defended arm.

**Bounds a censored adversary can place on the native mean** (true `E[c] = 2.4309 ms`):
D=1 → [2.4309, 2.4309] (exact); D=2 → [1.6823, 2.9033], width 1.221 ms; D=3 → [1.1572, 3.6787],
width 2.521 ms. Even at D=3, the native mean is pinned to a ±1.3 ms interval.

### 2.3 The D-calibration problem — the finding that most constrains the claim

C1, C2 and C3 carry identical labels (`period_ms = 400.0, idle_s = 1.0, master_link = 1,
outstation_link = 0`) and are replicate cells of one condition on one relay. They are not
distributionally comparable:

| campaign | n | CLRT median | p95 | max | concealed @ D=2 | @ D=3 | @ D=7 | @ D=22 |
|---|---|---|---|---|---|---|---|---|
| C1 | 30 | 25.252 | 75.20 | 87.74 | **0%** | 3% | 10% | 27% |
| C2 | 100 | 2.309 | 25.77 | 102.81 | 29% | 60% | 81% | 88% |
| C3 | 100 | 1.401 | 6.89 | 21.70 | **61%** | 84% | 95% | 100% |
| pooled (n=230) | 230 | — | 47.06 | 102.81 | **39.1%** | 63.0% | 77.8% | 85.2% |

Pooled, 95% concealment needs `D ≈ 50 ms` (42.1 ms mean added latency) and 100% needs
`D ≈ 103 ms` (94.2 ms mean added). The headline "D=2 → 61/100" is a C3-only number and overstates
pooled concealment by 22 points. Two consequences, both binding on §14 and §15:

- **Calibrate `D` on a campaign that is not an evaluation arm, and calibrate on ≥ 3 replicate
  cells, not one.** Report concealment pooled across replicates with the per-cell spread.
- C1's inter-READ median is 275.3 ms against a configured 400 ms, which is anomalous and
  unexplained. Either C1 is a distinct device state (connection-cold / retry-loaded) and must be
  labelled as such, or it is a capture artifact and must be excluded with a stated reason.
  Silently dropping it because it is inconvenient for the concealment number is not available.
  *(Unverified: I have not established which.)*

---

## 3. Where the leak relocates

Per-observable, C3, n=100. Bold marks the observable that carries `c`.

| observable | native | Defense 1 (hold ACK until RESPONSE) | Defense 2 (hold RESPONSE to `t_ACK+G`) | Defense 3 (hold ACK to `t_ACK+D`) |
|---|---|---|---|---|
| READ→ACK | `a` — med 0.505, sd 0.391 | **`a + c`** — med 2.507, sd 2.826 | `a` — **unchanged**, med 0.505, sd 0.391 | `a + D` — med 2.505 (D=2), sd **0.391** |
| ACK→RESPONSE (CLRT) | **`c`** — med 1.401, sd 2.807 | `δ` — constant | `max(c, G)` — constant iff `G > c_max`; else **`c` unshifted** for the tail | `max(c−D, δ)` — **`c−D`** for the tail, `δ` for `c<D` |
| READ→RESPONSE | `a + c` | **`a + c`** | `a + max(c, G)` | `a + max(c, D+δ)` |

Read across, plainly:

- **Defense 1 leaks `c` wholesale into READ→ACK.** It removes Formby's chosen feature and hands the
  adversary a strictly *more* informative one (`H(a+c) = 2.047` vs `H(c) = 1.750` bits at 1 ms
  bins), because `a` and `c` are independent and `Var(c) ≫ Var(a)` (7.88 vs 0.153 ms²).
- **Defense 2 leaves READ→ACK native and either erases `c` completely (`G > c_max`) or leaks it
  unshifted (`c > G`).** The unshifted tail is the worst case against model A: those samples land
  in the *correct* native histogram bins, so a native-trained classifier scores them normally.
- **Defense 3 splits `c` across two regimes.** Censored transactions genuinely vanish from all
  three intervals; shifted transactions are relocated but perfectly recoverable.

**Defense 2 and Defense 3 at matched threshold conceal the same transactions at the same cost.**
At `G = D` the censored set is identical (both are `{c < threshold}`) and the mean added end-to-end
latency is the same to three decimals (G=2: 0.4713 ms; D=2: 0.4724 ms; G=3: 1.2463; D=3: 1.2477).
The three real differences are:

1. **Clamp value.** Defense 2 pins the clamped CLRT at `G`, a configurable and ICS-plausible value
   (Formby's substation CLRTs are "tens or even hundreds of milliseconds"). Defense 3 pins it at
   `δ_release`, ~µs — 500× below this relay's native minimum and outside the support of Formby's
   entire corpus. **Within the architecture mandated in §6 (one deadline, no response deadline),
   Defense 3's clamp value is not configurable.** That is an architectural constraint the consensus
   should record, not a tuning choice. *(A per-port minimum-inter-packet-gap shaper on the
   master-facing queue could place the clamp at a chosen value without a second deadline — this
   repo has already used a PORT-level shaper for a single global release. Unverified for this
   construction; offered to the panel as a candidate, not a recommendation to build now.)*
2. **Tail treatment.** Defense 3's `c−D` breaks model A's bin assignment; Defense 2's unshifted `c`
   does not. This is Defense 3's only genuine advantage, and it evaporates against model B.
3. **ACK cost.** Defense 3 delays the ACK by `D` for **100/100** transactions including those it
   does not conceal, and inflates READ→ACK detectably (§6). Defense 2 does not touch the ACK.

**End-to-end envelope.** An adversary who only times READ→RESPONSE sees `a + max(c, D+δ)` under
Defense 3 — median 2.711 ms at D=2 against native 2.507 ms, sd 2.638 vs 2.826. The envelope still
carries the entire uncensored tail. There is no defense-side benefit from the envelope; it is
simply a third route to the same tail.

---

## 4. Metrics that survive review

§15 forbids binned entropy as the only result, and it is right to: entropy at 1 ms bins reports
`ΔH = 0.000` at D=1 (correct — an information no-op) but also collapses the shift/censor
distinction that is the whole mechanism. Report the following, each with its null.

**(a) Complete distributions.** ECDF overlays of `a`, `c`, `a+c` for every arm on shared axes,
plus the raw vectors in the evidence tree. Null: the native arm's own ECDF. The censoring atom and
the gap must be visible, not smoothed away — never present the defended CLRT as a KDE.

**(b) Quantiles.** min / p05 / p25 / median / p75 / p90 / p95 / p99 / max / mean / sd per arm, with
non-parametric bootstrap CIs (the existing `native_summary.json` already does 20 000-iteration
percentile bootstrap with a recorded seed — keep that). Null: overlapping CIs against native.

**(c) Concealment and recovery, reported as a pair.** `n_censored/n` (destroyed) and
`n_shifted/n` with "exactly recoverable by an adversary knowing D" stated on the same line. A
concealment figure without its recovery counterpart is misleading, because the two regimes have
opposite security properties. Null: D=1 ms, where recovery is 100/100.

**(d) Correlation / shape invariance.** `sd(CLRT_out)/sd(CLRT_native)` and
`sd(c−D | c>D)` vs `sd(c | c>D)`. Null: ratio = 1.000, which is what D=1 measures. Also report
`ρ(a, c)` per arm to confirm the independence assumption survives the defense.

**(e) Two-sample separability, `AUROC` + `KS`, native vs defended.** Both are single-number
summaries with a meaningful null (0.5 / p > 0.05). Measured: D=1 → 0.778, D=2 → 0.878,
D=3 → 0.894, D=7 → 0.973, D=22 → 1.000; all KS p < 1e-17. **Report against the correct null, which
is not 0.5.** The native-vs-native replicate-cell AUROCs on this device are C1↔C3 0.985,
C1↔C2 0.896, C2↔C3 0.655 — so a defended-vs-native AUROC of 0.878 at D=2 is *within the range the
device produces by itself between capture sessions*. This comparison must appear in the report;
without it the AUROC numbers read as far more meaningful than they are.

**(f) Mutual information — only where labels are real.** `MI(label ; feature)` is defensible for
the labels that actually exist in this repo: campaign identity (C1/C2/C3), idle-gap class
(1/5/15/30 s), and connection state (cold vs steady). It is **not** defensible for device identity,
which we do not have. Report the estimator, the binning, and a permutation null; MI is biased
upward at small n.

**(g) Classifier accuracy / precision / recall / confusion — where justified, and only there.**
I ran two probes to establish whether this dataset supports classifier claims at all.

*Probe 1 (has power, use it).* Formby-style multinomial naive Bayes on 11-bin CLRT histograms of
5-transaction slices, task = C2 vs C3 (same relay, nominally identical configuration), 40 slices,
leave-one-out, Wilson 95% CIs:

| arm | accuracy | 95% CI |
|---|---|---|
| native / native (baseline) | 0.825 | [0.680, 0.913] |
| permutation null | mean 0.486, p95 0.651 | — |
| **model A**, D=1 | 0.700 | [0.546, 0.819] |
| **model A**, D=2 | 0.825 | [0.680, 0.913] |
| **model A**, D=3 | 0.750 | [0.598, 0.858] |
| **model B** (retrained), D=2 | 0.850 | [0.709, 0.929] |
| **model B** (retrained), D=3 | 0.850 | [0.709, 0.929] |

**Every defended arm's CI overlaps the native baseline. At D ≤ 3 ms there is no measured classifier
degradation, for either attacker model, on the one classification task this dataset can support.**
That is the correct headline for §15 as things stand, and it is a negative result.

*Probe 2 (has no power, do not use it).* 4-class idle-gap task (1/5/15/30 s, n=23 each), single
CLRT sample, LOO kernel-density Bayes: native accuracy 0.337 against a permutation null with
p95 = 0.359. The native signal is inside the null, so the task is unlearnable at this n and no
defended comparison against it means anything.

*Trap that probe 2 exposed, and that will bite the final report if unguarded:* at G=22 ms the same
pipeline returns **accuracy 1.000** from a fully clamped, constant feature. A Gaussian KDE fitted
to 23 identical values returns density 2.97e13 and the argmax becomes a tie-breaking artifact. Any
"the defense made classification perfect/impossible" number computed on a degenerate feature is
numerical, not informational. Guard every classifier call with a constant-feature check and a
permutation null.

**(h) Latency-versus-clamping tradeoff.** The tradeoff curve is the paper's actual contribution and
must be plotted with **two** latency axes, because Defense 3 has two distinct costs:
*added ACK latency = `D` for 100% of transactions, unconditionally*, and
*added end-to-end latency = `mean(max(0, D+δ−c))`* (D=2: 0.472 ms mean, 0.981 max; D=3: 1.248 mean,
1.981 max). Reporting only the second understates the cost by 4× at D=2. Plot concealment fraction
(pooled over replicate cells, with per-cell spread) against both, and mark the native minimum
(1.0208 ms) and native max (21.70 ms C3 / 102.81 ms pooled) on the D axis.

---

## 5. The single-device limitation

One physical SEL-751 supports **no cross-device claim of any kind**. Formby's result is a
*between-device* separability claim (200-bin CLRT histograms, FF-ANN and multinomial NB, 93%
average accuracy at 5-minute slices over ~130 DNP3 devices). Nothing in this repo tests it. §15 and
§16 are explicit, and I concur without reservation.

**What IS supportable from the present data:**

1. A mechanism claim — the transform is implemented on Tofino-1 as specified, with measured
   deadline error and release tail.
2. A **within-device distributional transformation** claim — the SEL-751's own CLRT distribution
   under D ∈ {1, 2, 3} ms, reported as §4(a)–(d), with the pooled-replicate concealment figures of
   §2.3 rather than the C3-only ones.
3. A **native-versus-protected detectability** claim (§6), which is a statement *against* the
   defense and must be reported as such.
4. A **single within-device classification** result — probe 1 above, labelled as capture-session
   discrimination, not device fingerprinting, with the finding that no degradation is measurable
   at D ≤ 3 ms.
5. An explicit negative: no anonymity, no cross-device, no cross-configuration claim.

**Concrete multi-device acquisition plan (per §15).** The minimum that would support a
fingerprinting claim:

- **Devices.** ≥ 5 outstations spanning ≥ 3 vendors, all Case A (separate ACK, non-zero CLRT) —
  device count is what buys the claim, and the failure of a defense is usually visible at 5. The
  repo's existing capture corpus already identifies the SEL-751 (10.0.0.1) as separate-ACK and
  AB1400 / ION7550 / 10.0.0.2 as combined-ACK; combined-ACK devices are Case B and must be excluded
  from the CLRT task, not used to pad n.
- **Software-configuration classes.** ≥ 2 per device where the relay configuration can be varied
  read-only. Formby's Appendix A shows software configuration is separable within one hardware
  model; a defense that only hides vendor and not configuration is a weaker claim.
- **Volume.** ≥ 700 CLRT measurements per device per class (Formby's own figure), which at a
  400 ms poll is ~5 minutes per class — cheap. Slice at 5 minutes to match Formby's detection-time
  operating point.
- **Replication.** ≥ 3 replicate cells per (device × class × arm), on **different days**. The
  C1/C2/C3 result in §2.3 shows single-session calibration is not safe on this hardware.
- **Design.** Randomised complete blocks over arms {native, D1 = negative control, D2, D3, D_p95,
  D_max, Defense 2 at matched G}, absolute monotonic polling schedule, arms interleaved within a
  block so device drift is a block effect rather than an arm effect. Never append to an existing
  CSV (§14).
- **Split discipline.** `D` selected on a dedicated calibration campaign; devices split
  device-disjointly into train/test for the classifier so that model B is not evaluated on a device
  it was fitted on.
- **Analysis.** Per-device confusion matrices, macro and per-class precision/recall, permutation
  null over labels, and the accuracy-versus-added-latency curve as the primary figure.
- **Ordering.** Until this exists, the report says "cross-device fingerprinting resistance is not
  evaluated" — not "not degraded", and not silence.

---

## 6. Detectability of the defense

### 6.1 The framing that matters most

Formby's paper is not only an attack. Its stated defensive use is that *"any significant change in a
device's distribution of CLRTs highly suggests either an attacker spoofing the responses with a
different machine, or a change in CPU workload [25] or software configuration, which could be a sign of
a device being compromised with malware."* Deploying Defense 3 therefore does exactly what a Formby-based IDS is
built to alarm on. Model A does not merely fail — model A **fires**. Any claim of the form
"Defense 3 invalidates an existing native-trained model" must state that invalidation and detection
are the same event here.

### 6.2 Reference-based detection (adversary has a native trace of this device)

Two-sample KS, native reference (n=200 bootstrap) against `m` defended transactions, α = 0.05,
2000 reps:

| D | m=5 | m=10 | m=20 | m=50 |
|---|---|---|---|---|
| 1 ms | 0.74 | 0.91 | 1.00 | 1.00 |
| 2 ms | 0.98 | 1.00 | 1.00 | 1.00 |
| 3 ms | 0.99 | 1.00 | 1.00 | 1.00 |

At a 400 ms poll, m=10 is four seconds. Detection is effectively immediate at every D, **including
the D=1 ms arm that conceals nothing** — D=1 buys detectability at zero privacy.

The READ→ACK channel is worse: `AUROC(a, a+D)` = 0.952 at D=1 and **1.000 at D=2 and D=3**, because
`sd(a) = 0.391 ms` and the shift is 2.5–7.7 sd. A single ACK is enough at D ≥ 2 given a native
reference.

### 6.3 Reference-free detection (adversary has no native trace)

The censored transactions produce a point mass at `δ_release` separated from the shifted continuum
by an empty gap:

| D | fraction with CLRT < 10 µs | next-lowest observed CLRT | empty gap |
|---|---|---|---|
| 2 ms | 61% | 0.0429 ms | 0.041 ms |
| 3 ms | 85% | 0.1323 ms | 0.131 ms |

Native C3 support starts at 1.0208 ms with 0/100 samples below it. At D=2, `P(≥1 clamped sample in
m transactions)` = 0.61 (m=1), 0.941 (m=3), 0.991 (m=5) — two seconds of polling.

Whether that atom is *conclusive* depends on a question the panel must answer with a measurement,
not an assumption. Two competing arguments:

- **Against the defense.** Formby's corpus reports CLRTs of "tens or even hundreds of milliseconds";
  this relay's native minimum is 1.0208 ms. A µs-scale CLRT is outside the support of every device
  in that corpus, and the *bimodality* — an atom plus a shifted continuum with a hard gap and
  nothing in between — is not a shape any single processing pipeline produces.
- **For the defense (partially).** A real device that emits its ACK and response back-to-back from
  one interrupt puts them on the wire one serialisation time apart: 6.88 µs on 100 Mbps, 0.69 µs on
  1 Gbps, deterministic to sub-nanosecond. So *sharpness alone is not a signature* — real stacks
  produce sharp back-to-back separations too. The discriminator is the **value relative to the
  device population's support**, plus the mixture structure, not the tightness.

**`δ_release` for this construction is unverified.** The 1.72 µs / 23 ns figure in project memory is
the measured **deadline-release tail of the Part 12 recirculation hold**, not the back-to-back
dequeue separation of two packets leaving one Q_HOLD FIFO on the master-facing port. Those are
different quantities. GATE 2 must measure the ACK→RESPONSE separation in the early-response case
directly, report its median and spread, and state it explicitly, because it is the single number
that determines whether the clamp is detectable from one packet pair. §16's permitted claim —
"clamps the observed CLRT near the hardware release separation" — is a *mechanism* claim; it must
not be restated as a privacy claim.

### 6.4 How to measure detectability without overclaiming

Report a detectability figure explicitly, as a cost of the defense, not a footnote:

1. **AUROC and KS(native, defended)** per arm with bootstrap CIs — already tabulated in §2.2 and
   §6.2. State the null as the native-vs-native replicate-cell range (0.655–0.985, §2.3), not 0.5.
2. **Detector power versus number of observed transactions** for both the reference-based KS test
   and the reference-free atom test, as in §6.2/§6.3, and convert `m` to wall-clock at the
   deployed poll interval.
3. **Measured `δ_release`** with median and spread, alongside the serialisation time of a 66 B frame
   on the relay's own link and on the master-facing link, so a reader can judge plausibility
   themselves.
4. **State the limit.** With one device we can say the clamp value lies outside *this relay's*
   native support (0/100 samples below 1.0208 ms). We cannot say it lies outside the population's
   support — that is an argument from Formby's reported ranges, and must be labelled as such.
5. **Do not claim indistinguishability.** §16 already forbids it; the data above would not support
   it in any case.

---

## 7. Recommendations to the synthesis panel

1. **Keep the D grid, relabel it.** Run D ∈ {1, 2, 3} ms as directed, but report **D = 1 ms as the
   negative control** (0/100 concealed, 100/100 recoverable, ΔH = 0). Add **D ≈ p95** and
   **D ≈ max** arms from the *pooled* calibration campaigns, not from C3, so the curve reaches the
   regime where the defense actually does something. On pooled C1+C2+C3 those are D ≈ 47 ms and
   D ≈ 103 ms — which is itself an important result about the cost of this mechanism on real
   hardware, and should be reported rather than avoided by calibrating on the friendliest campaign.
2. **Calibrate on a campaign that is not an evaluation arm, over ≥ 3 replicate cells.** Report
   concealment pooled with per-cell spread. Never publish a concealment number fitted and tested on
   the same capture session.
3. **Report concealment and exact-recovery as a pair**, always on the same line.
4. **Report both latency costs** — unconditional ACK delay `D` (100% of transactions) and
   conditional end-to-end delay `max(0, D+δ−c)`.
5. **Measure `δ_release` at GATE 2** as a first-class result; it decides §6.
6. **Record as an architectural finding** that under §6's one-deadline constraint the clamp value is
   fixed at the hardware release separation and cannot be moved to a plausible value, whereas
   Defense 2's clamp is configurable at `G`. This is the sharpest structural difference between the
   two mechanisms and belongs in CONSENSUS.md.
7. **Include the native-vs-native replicate-cell comparison in the report.** It is the correct null
   for every separability number and it is uncomfortable — which is why a reviewer will find it if
   we do not.
8. **State in the report that no classifier degradation was measurable at D ≤ 3 ms** on the one
   task this dataset supports (probe 1, §4g), and that no cross-device claim is attempted.

---

## 8. Explicitly unverified in this memo

- `δ_release` for the Q_HOLD FIFO back-to-back release (the 1.72 µs / 23 ns figure is from the
  Part 12 recirculation deadline path, a different mechanism).
- Whether `READ→ACK` (`a`) is device-discriminative across outstation models — untestable with one
  relay; Formby did not use it, precisely because it is RTT-contaminated.
- Whether a µs-scale CLRT is outside the support of the ICS device population — argued from
  Formby's reported "tens to hundreds of ms", not measured here.
- The cause of C1's deviation (median CLRT 25.25 ms, inter-READ 275 ms against a configured 400 ms).
  Must be resolved as either a labelled device state or a documented exclusion.
- Whether the deployed master's polling is anchored absolutely or on response receipt in every
  defended arm; C3 shows absolute (400.0 ms), which must be confirmed per arm.
- Probe 1's task is capture-session discrimination on one device. It is a lower-bound proxy for
  CLRT separability, not a fingerprinting measurement.
