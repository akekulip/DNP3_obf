# Phase 04 — Attacker Evaluation (statistically rigorous)

**Trace-transformation evaluation** — the measured *native* per-transaction features from the six real device PCAPs are transformed by each scenario's model and re-classified. It is **not** a defended-wire capture.

- **Baseline: majority-class = 0.400** (test set; SEL-751 & ION7550 ≈ 40%, AB1400 ≈ 20%). Uniform 3-class chance would be 0.333. Because classes are unequal, **balanced accuracy is the headline metric.**
- **Primary estimator:** capture-level split (train base pcaps, test L pcaps): leakage-free. **Model:** StandardScaler + RandomForest(300 trees), seed 20260716. **Bootstrap:** 2000 resamples. Seed fixed.
- Scenarios: `native` · `ebpf_edt` (prototype: ACK 20 ms / response 40 ms) · `ebpf_edt_aligned` (ablation: ACK = response = 40 ms) · `plus_ackmode` (**counterfactual oracle** — models what would remain if an ideal mechanism removed the ACK-mode distinction; not byte/packet-preserving, **not implemented by `ack_edt.o`**).

## 1. Capture-level split (leakage-free) — random forest per feature family

| family | scenario | accuracy [95% CI] | balanced acc | macro-F1 |
|---|---|---|---:|---:|
| ack_only | native | 0.812 [0.804, 0.819] | 0.759 | 0.761 |
| ack_only | ebpf_edt | 0.800 [0.792, 0.808] | 0.666 | 0.600 |
| ack_only | ebpf_edt_aligned | 0.800 [0.791, 0.807] | 0.666 | 0.600 |
| ack_only | plus_ackmode | 0.400 [0.390, 0.410] | 0.333 | 0.191 |
| timing | native | 0.511 [0.501, 0.521] | 0.482 | 0.473 |
| timing | ebpf_edt | 0.401 [0.392, 0.410] | 0.334 | 0.193 |
| timing | ebpf_edt_aligned | 0.401 [0.391, 0.411] | 0.334 | 0.193 |
| timing | plus_ackmode | 0.400 [0.390, 0.409] | 0.333 | 0.191 |
| size | native | 0.500 [0.490, 0.510] | 0.500 | 0.376 |
| size | ebpf_edt | 0.500 [0.490, 0.510] | 0.500 | 0.376 |
| size | ebpf_edt_aligned | 0.500 [0.490, 0.510] | 0.500 | 0.376 |
| size | plus_ackmode | 0.500 [0.490, 0.510] | 0.500 | 0.376 |
| all | native | 0.889 [0.883, 0.895] | 0.856 | 0.859 |
| all | ebpf_edt | 0.900 [0.894, 0.905] | 0.833 | 0.852 |
| all | ebpf_edt_aligned | 0.900 [0.894, 0.906] | 0.833 | 0.852 |
| all | plus_ackmode | 0.500 [0.490, 0.510] | 0.500 | 0.376 |

## 2. Repeated stratified 5×5 CV (uncertainty band — OPTIMISTIC, within-capture leakage)

| family | scenario | mean acc [95% CI] |
|---|---|---|
| ack_only | native | 0.830 [0.822, 0.840] |
| ack_only | ebpf_edt | 0.791 [0.790, 0.792] |
| ack_only | ebpf_edt_aligned | 0.791 [0.790, 0.792] |
| ack_only | plus_ackmode | 0.417 [0.417, 0.418] |
| timing | native | 0.545 [0.530, 0.558] |
| timing | ebpf_edt | 0.419 [0.418, 0.420] |
| timing | ebpf_edt_aligned | 0.419 [0.418, 0.420] |
| timing | plus_ackmode | 0.417 [0.417, 0.418] |
| size | native | 0.600 [0.591, 0.610] |
| size | ebpf_edt | 0.600 [0.591, 0.610] |
| size | ebpf_edt_aligned | 0.600 [0.591, 0.610] |
| size | plus_ackmode | 0.600 [0.591, 0.610] |
| all | native | 0.907 [0.898, 0.916] |
| all | ebpf_edt | 0.895 [0.887, 0.903] |
| all | ebpf_edt_aligned | 0.895 [0.887, 0.903] |
| all | plus_ackmode | 0.600 [0.591, 0.610] |

_The pooled CV mixes correlated transactions from the same capture into train and test, so it is optimistic; the capture-level split above is the defensible estimate._

## 3. Per-device precision/recall and confusion — `all` features

**native** (balanced acc 0.856, macro-F1 0.859):

| device | precision | recall |
|---|---:|---:|
| AB1400 | 0.739 | 0.691 |
| ION7550 | 0.851 | 0.878 |
| SEL751 | 1.000 | 1.000 |

confusion (rows=true, cols=pred; AB1400, ION7550, SEL751):
```
  AB1400   1382    617      0
 ION7550    486   3512      1
  SEL751      2      0   3997
```

**ebpf_edt** (balanced acc 0.833, macro-F1 0.852):

| device | precision | recall |
|---|---:|---:|
| AB1400 | 1.000 | 0.500 |
| ION7550 | 0.800 | 1.000 |
| SEL751 | 1.000 | 1.000 |

confusion (rows=true, cols=pred; AB1400, ION7550, SEL751):
```
  AB1400    999   1000      0
 ION7550      0   3998      1
  SEL751      0      0   3999
```

**ebpf_edt_aligned** (balanced acc 0.833, macro-F1 0.852):

| device | precision | recall |
|---|---:|---:|
| AB1400 | 1.000 | 0.500 |
| ION7550 | 0.800 | 1.000 |
| SEL751 | 1.000 | 1.000 |

confusion (rows=true, cols=pred; AB1400, ION7550, SEL751):
```
  AB1400    999   1000      0
 ION7550      0   3998      1
  SEL751      0      0   3999
```

## 4. Paired bootstrap vs native — `all` features

| transform | Δ accuracy vs native | 95% CI | significant? |
|---|---:|---|---|
| ebpf_edt | +0.0105 | [+0.0044, +0.0163] | yes |
| ebpf_edt_aligned | +0.0105 | [+0.0045, +0.0163] | yes |
| plus_ackmode | -0.3894 | [-0.4006, -0.3780] | yes |

## 5. Reading (balanced accuracy; baseline 0.333 uniform / majority-class 0.400)

- **Timing channel collapses to baseline.** `timing` balanced accuracy 0.482 → 0.334: request→response pinned to the common target carries no device information, with no re-encoding of mode into timing.
- **ACK-mode channel is NOT closed.** `ack_only` balanced accuracy falls 0.759 → 0.666 (the request→ACK and gap sub-features are normalized) but stays far above baseline — `is_separate` (a separate-mode device still emits a distinct pure-ACK packet) is a categorical leak the mechanism cannot remove.
- **The aligned-target ablation changes nothing** (`ebpf_edt_aligned` = `ebpf_edt` on every metric: `all` balanced 0.833 vs 0.833). So the residual is the categorical ACK-mode and size channels, **not** the choice of timing targets — aligning ACK and response targets neither helps nor hurts.
- **The small raw-accuracy rise is an imbalance artifact.** `all` *raw* accuracy edges up (0.889 → 0.900, paired CI excludes 0) but *balanced* accuracy **falls** 0.856 → 0.833: normalizing the noisy native timing lets the majority classes (SEL/ION) classify a little more cleanly at the minority class's (AB1400) expense. Balanced accuracy is the honest measure and it shows a modest *decrease*, nowhere near baseline.
- **Counterfactual oracle.** `plus_ackmode` (ideal ACK-mode removal — not implemented) drops `ack_only` and `timing` to baseline, but **`all` stays at 0.500, not baseline**, because **response size still leaks**. Do not say the fingerprint 'collapses to the baseline'.

**Result:** egress scheduling removes timing leakage but cannot conceal the transport-structure (ACK-mode) and response-size fingerprints. Full device anonymization is not achieved by timing normalization alone.

_Scope: trace-transformation on the six device PCAPs (SEL-751 separate; AB1400 / ION7550 combined). Loopback/single-kernel provenance for the transformation model; not a rig/defended-wire capture._
