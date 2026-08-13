# Phase 10 — Analysis + figures for the faithful two-pipe BOR + RRC

Data-driven analysis and figures for the faithful two-pipe defense (RRC size/timing parity in
pipe 0 + BOR OPERATE hold with a bounded random jitter codebook in pipe 1). Everything here is
software: pcap analysis, an offline convolution model, and the committed bf-p4c compile matrices.
No hardware was touched and no `.p4` was edited.

**The three evidence tiers are kept strictly separate. Do not blur them.**

- Analysis engine: `defense4/evidence/analysis/phase10_analysis.py`
- Machine output: `defense4/evidence/analysis/phase10_analysis.json`, `clrt_series.csv`
- Figures (scripts + PDF + PNG): `defense4/figures/`

---

## Tier 1 — CLRT parity on physical silicon (the strong result)

Provenance: **physical silicon** — Tofino-1 forwarding between the DNP3 master and the physical
SEL-751, native (D4 hold OFF) vs defended (D4 hold ON). Metrics are per admitted transaction
(20 B READ / 45 B SELECT), paired by TCP-ACK semantics (`analyze_rrc_pcaps.py`), n = 30 per class
per condition. The Case-A CLRT is the pure-ACK → response interval — the quantity the D4 deadline
clamps.

| CLRT (ACK→response) | READ P50 | SELECT P50 | READ−SELECT diff |
|---|---|---|---|
| **native** (no defense) | 2.114 ms | 1.064 ms | **1.051 ms (separable)** |
| **defended** (D4 hold) | 20.003 ms | 20.001 ms | **0.002 ms (merged)** |

Native READ CLRT is dispersed (P5 1.13 ms, P95 8.97 ms, P99 18.25 ms, std 4.19 ms) while native
SELECT is tight (P5 0.95, P95 2.15 ms) — the two request types are separable by their ACK→response
timing. Under the defense both collapse onto ~20 ms with std ≤ 0.015 ms; the READ and SELECT
medians land **0.002 ms apart**. The full-transaction request→response latency is likewise clamped
to the ~22 ms deadline (defended pooled P50 22.64 ms, P95 23.63 ms, P99 23.69 ms, std 0.36 ms), and
the response segmentation is byte-identical for both request types ([28, 21] → 49 B).

**Claim boundary (unchanged):** this is deadline-clamped central-timing parity (ACK→response) plus
identical segmentation for the admitted READ and SELECT profiles on one relay. It is **not**
universal statistical indistinguishability and **not** full READ-vs-SBO transaction equality;
physical OPERATE was not run (SELECT-echo only).

Figures: `fig01_clrt_native_vs_defended` (native vs defended CLRT ECDF), `fig_clrt_silicon`
(READ-vs-SELECT strip — native separable, defended merged; task figure 2), and the copied
`fig_size_silicon` / `fig_timing_silicon`.

---

## Tier 2 — Physical-fingerprint convolution demonstration (mechanism only, synthetic)

Provenance: **synthetic / bootstrapped**. No physical OPERATE exists (H5 BLOCKED), so there is no
silicon operation-time measurement to defend. This tier demonstrates the **convolution mechanism
only** and is explicitly **not** a multi-device silicon fingerprint-defeat claim.

Model: native physical operation time `T_physical` as two device classes from the Formby measured
ranges — vendor-1 ~U[16, 38] ms, vendor-2 ~U[14, 33] ms. The defense convolves each with the
bounded **random** jitter codebook `J ~ U{0, 2, 4, 6, 8, 10, 12} ms` (BOR_RRC_DESIGN §3 /
BOR_CONTROL_PLANE default `--j-set`). **`J` is now random per transaction, not a fixed shift — a
fixed `J` would translate the distribution and change nothing; only a random `J` adds entropy.**

### Before/after two-class classifier (session-separated, chance = 0.50)

Train on one synthetic draw, test on a disjoint draw (4000 per class). Feature = the single timing
value. Bootstrap 95% CI over 1000 test resamples.

| Classifier | native acc | defended acc | drop | toward chance |
|---|---|---|---|---|
| threshold (stump) | 0.614 | 0.559 | 0.055 | 48.6 % |
| logistic | 0.578 | 0.576 | 0.002 | 2.6 % |
| random forest | 0.588 | 0.533 | 0.055 | 62.9 % |

Class-separation Jensen–Shannon divergence drops **0.163 → 0.060 bits** (≈ 63 % reduction) from
native to defended.

**Honest reading — the convolution does not "defeat" the fingerprint.** The two device classes have
different means (27.0 vs 23.5 ms); a random `J` with the same distribution added to both cannot
remove that mean gap, only smear it. The best classifier still sits above chance after the defense
(random forest 0.533, threshold 0.559). We therefore report the **measured reduction** (accuracy
drop up to 5.5 points, JS divergence −63 %) rather than any "defeated" claim. The mechanism reduces
separability; it does not eliminate it for a two-class model. This is an offline convolution
demonstration of one mechanism, not a silicon result.

Figures: `fig03_operation_synth` (two classes, native vs convolved ECDF), `fig04_j_convolution`
(`F_physical * G_delay → F_defended`), `fig05_classifier` (confusion matrices + accuracy bars with
95 % CI and chance line).

### Added latency (silicon RRC hold + model BOR jitter)

Provenance: **silicon** for the RRC hold (measured joint request→response), **model** for the BOR
jitter (the codebook `J`).

- RRC hold (silicon): P50 22.64 ms, P95 23.63 ms, P99 23.69 ms.
- BOR jitter `J` (model): P50 6 ms, P95 12 ms, P99 12 ms, mean 5.99 ms.
- Worst-case added latency (RRC max 23.70 ms + `J` max 12 ms) = **35.70 ms**.
- Master-timeout margin: **1964 ms** against the 2 s DNP3 master response timeout, and **364 ms**
  against the independently evidenced ~400 ms poll gap.

Caveat (audit M5): the 2 s response timeout is a protocol default whose *campaign* provenance is
flagged; the ~400 ms poll interval is independently evidenced and is the tighter operational bound.

Figure: `fig06_added_latency`.

---

## Tier 3 — Compiler resource cost (compiler-only)

Provenance: **compiler-only** — final ingress-stage counts from the committed bf-p4c 9.13.x
`table_summary.log` matrices. A compile is not silicon; this proves placement, not the physical
divergence floor or cross-pipe loopback timing.

| Build | ingress stages | fits (≤ 12) |
|---|---|---|
| RRC kernel (reference) | 12 | yes |
| additive BOR (naive, single pipe) | 14 | **no (+2)** |
| one-pipe faithful (RRC + BOR hold + fold) | 13 | **no (+1)** |
| two-pipe faithful — pipe 0 | 12 | yes |
| two-pipe faithful — pipe 1 | 10 | yes |

The additive single-pipe BOR is +2 over the TF1 limit; even the folded one-pipe faithful build is
+1. The faithful two-pipe split fits (pipe 0 = 12/3 ingress/egress, pipe 1 = 10/0), which is what
makes the faithful first-OPERATE-held design realizable on one Tofino-1.

Figure: `fig07_compiler_resources`.

---

## Figure index (provenance per figure)

| File | Content | Provenance |
|---|---|---|
| `fig01_clrt_native_vs_defended` | CLRT ACK→response ECDF, native vs defended | physical silicon |
| `fig_clrt_silicon` (task fig 2) | READ vs SELECT CLRT strip (separable → merged) | physical silicon |
| `fig_size_silicon` | identical [28,21]→49 B segmentation | physical silicon |
| `fig_timing_silicon` | request→response clamp to the ~22 ms deadline | physical silicon |
| `fig03_operation_synth` | two device classes, native vs convolved | synthetic/bootstrapped |
| `fig04_j_convolution` | `F_physical * G_delay → F_defended` | synthetic/bootstrapped |
| `fig05_classifier` | before/after two-class classifier | synthetic/bootstrapped |
| `fig06_added_latency` | RRC hold + BOR jitter, timeout margin | silicon (hold) + model (J) |
| `fig07_compiler_resources` | ingress stages per build vs TF1 limit | compiler-only |

## Reproduce

```bash
$RESEARCH_PYTHON defense4/evidence/analysis/phase10_analysis.py   # -> JSON + CSV
$RESEARCH_PYTHON defense4/figures/make_phase10_figures.py         # -> 6 new PDFs
# copy silicon figures + rasterize (see the figures dir): pdftoppm -png -r 300 <fig>.pdf <fig>
```
