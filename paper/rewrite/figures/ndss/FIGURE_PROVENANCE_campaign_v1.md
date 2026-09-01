# Figure provenance — campaign_v1 (active)

The one active figure-provenance document. Every figure in the manuscript is listed here with
the inputs it consumed, by repository-relative path and SHA-256, and the hashes of everything
it produced. It supersedes `../FIGURE_PROVENANCE.md` and `../FINAL_FIGURES.md`, which describe
the retired `final_read_sbo` five-figure set and are marked historical.

Regenerate and re-verify with:

```sh
defense4/timing/evidence/campaign_v1/repro/reproduce.sh [OUT_DIR]
```

The last step of that script is the publication gate. It fails if any **authoritative**
artefact differs from a fresh rebuild: the vector PDF, the figure-data CSV, the caption and
note files, the provenance content, or `MANUSCRIPT_VALUES.json`. The 600-dpi PNG is a preview:
its hash is recorded below but not gated, because an Agg raster depends on the FreeType and
libpng bundled with the interpreter build and two environments satisfying the same lock file
can differ by a few hundred pixels while the PDF is byte-identical.

Figures are never hand-edited and no plotting script contains a measured value. Paths recorded
as `pipeline-output/...` are products of that run, identified by their hash rather than by a
location chosen at run time.

## `fig_policy_coverage_cost`

* **Printed size** 7.16 x 4.6 in
* **Source commit** `2a251eca0b197fd74b2d19db832e5b0de9356e5a`
* **Deterministic seed** `20260828`
* **Command** `python make_ndss_figures.py pipeline-output/transactions_canonical.csv pipeline-output/stats.json pipeline-output/leakage.json policy_config.json pipeline-output/figs pipeline-output/sweep_summary.json`
* **Analysis script** `defense4/timing/evidence/campaign_v1/repro/make_ndss_figures.py` `c70ba7178d47eafe…`
* **Style module** `defense4/timing/evidence/campaign_v1/repro/figstyle_ndss.py` `c023b82e910d316f…`

| input | sha256 |
|---|---|
| `pipeline-output/transactions_canonical.csv` | `53252baf38f91e1f…` |
| `defense4/timing/evidence/campaign_v1/repro/policy_config.json` | `d11e81165038a0ee…` |
| `pipeline-output/stats.json` | `d2253be06fa29a0c…` |
| `pipeline-output/sweep_summary.json` | `e4c898866d70bec2…` |

| output | sha256 | gated |
|---|---|---|
| `pipeline-output/fig_policy_coverage_cost.pdf` | `f6732b3b53935e01…` | yes |
| `pipeline-output/fig_policy_coverage_cost_data.csv` | `c208fb12cde1b340…` | yes |
| `pipeline-output/fig_policy_coverage_cost.png` | `6b008f99eda9b3a9…` | no, preview |

**Method.** Panel (a) is an empirical complementary CDF over the Timing OFF read lane (READ and SELECT), 29,040 exchanges; OPERATE is excluded because it is anchored to the request and is not schedulable against D. Panels (b) and (c) are the measured 19-point hardware sweep: each point is one capture under one installed release policy, summarised by the median over its READ transactions, with the full measured range shown in (b). No value is resampled or interpolated. Panel (d) reports quartiles with whiskers over the full support.

**Limitations.** The sweep offsets D_A and D_R are read from the archived sweep_points.csv configuration table; the driver logs record the mode and the J codebook but not the per-point offsets, and no per-point control-plane readback exists, so the configuration provenance for the sweep is partial. The fail-open horizon H is a control-plane quantity computed from the pass budget and reservoir depth, not a value the data plane enforces or that was measured directly. All points come from one relay behind one switch.

## `fig_distributions`

* **Printed size** 7.16 x 4.25 in
* **Source commit** `2a251eca0b197fd74b2d19db832e5b0de9356e5a`
* **Deterministic seed** `20260828`
* **Command** `python make_ndss_figures.py pipeline-output/transactions_canonical.csv pipeline-output/stats.json pipeline-output/leakage.json policy_config.json pipeline-output/figs pipeline-output/sweep_summary.json`
* **Analysis script** `defense4/timing/evidence/campaign_v1/repro/make_ndss_figures.py` `c70ba7178d47eafe…`
* **Style module** `defense4/timing/evidence/campaign_v1/repro/figstyle_ndss.py` `c023b82e910d316f…`

| input | sha256 |
|---|---|
| `pipeline-output/transactions_canonical.csv` | `53252baf38f91e1f…` |

| output | sha256 | gated |
|---|---|---|
| `pipeline-output/fig_distributions.pdf` | `48ccc6b133ae8873…` | yes |
| `pipeline-output/fig_distributions_data.csv` | `68defb9a5a093bc3…` | yes |
| `pipeline-output/fig_distributions.png` | `82c027a20cea42fb…` | no, preview |

**Method.** Empirical distribution functions over every exchange of each class and arm, 26,400 READ and 2,640 each of SELECT and OPERATE per arm. The abscissa is logarithmic and its limits contain the full support of both arms, so the late tail is displayed rather than clipped. Panel (d) shows quartiles with whiskers at the extremes.

**Limitations.** The OPERATE panel is the master-visible ACK-to-echo interval only. The per-transaction hold J, the relay-facing release at T0+J and any physical actuation were not observed. SELECT is the SELECT phase of select-before-operate and is not a complete SBO transaction. One relay, one switch, one campaign.

## `fig_feature_overlap`

* **Printed size** 7.16 x 2.95 in
* **Source commit** `2a251eca0b197fd74b2d19db832e5b0de9356e5a`
* **Deterministic seed** `20260828`
* **Command** `python make_ndss_figures.py pipeline-output/transactions_canonical.csv pipeline-output/stats.json pipeline-output/leakage.json policy_config.json pipeline-output/figs pipeline-output/sweep_summary.json`
* **Analysis script** `defense4/timing/evidence/campaign_v1/repro/make_ndss_figures.py` `c70ba7178d47eafe…`
* **Style module** `defense4/timing/evidence/campaign_v1/repro/figstyle_ndss.py` `c023b82e910d316f…`

| input | sha256 |
|---|---|
| `pipeline-output/transactions_canonical.csv` | `53252baf38f91e1f…` |
| `defense4/timing/evidence/campaign_v1/repro/policy_config.json` | `d11e81165038a0ee…` |

| output | sha256 | gated |
|---|---|---|
| `pipeline-output/fig_feature_overlap.pdf` | `e6dd10b0d6c64b3a…` | yes |
| `pipeline-output/fig_feature_overlap_data.csv` | `21a0c2babe633d1d…` | yes |
| `pipeline-output/fig_feature_overlap.png` | `98965f8887357c07…` | no, preview |

**Method.** Each panel plots the request-to-ACK interval against the post-ACK interval for every transaction class of one arm, on identical logarithmic axes so the two panels are directly comparable. Scatter is a deterministic class-stratified subsample of at most 900 exchanges per class, drawn with a seeded generator so the figure is reproducible; subsampling affects only what is drawn. The large marker is the median and the bars span the 5th to 95th percentile, both computed over the complete 26,400 READ and 2,640 SELECT and OPERATE exchanges per arm. No dimensionality reduction, embedding or clustering algorithm is used anywhere: both axes are measured intervals in milliseconds.

**Limitations.** This is timing-feature overlap among transaction classes on one physical SEL-751A behind one Tofino-1. It is not clustering performance, not device identification, and not evidence that two devices become indistinguishable. The OPERATE ordinate is the master-visible ACK-to-echo interval, a different anchor from the CLRT of the other two classes; the realized per-transaction hold and the relay-facing release were not observed. The subsample changes the visual density only and no reported statistic depends on it.

## `fig_leakage`

* **Printed size** 7.16 x 4.35 in
* **Source commit** `2a251eca0b197fd74b2d19db832e5b0de9356e5a`
* **Deterministic seed** `20260828`
* **Command** `python make_ndss_figures.py pipeline-output/transactions_canonical.csv pipeline-output/stats.json pipeline-output/leakage.json policy_config.json pipeline-output/figs pipeline-output/sweep_summary.json`
* **Analysis script** `defense4/timing/evidence/campaign_v1/repro/make_ndss_figures.py` `c70ba7178d47eafe…`
* **Style module** `defense4/timing/evidence/campaign_v1/repro/figstyle_ndss.py` `c023b82e910d316f…`

| input | sha256 |
|---|---|
| `pipeline-output/transactions_canonical.csv` | `53252baf38f91e1f…` |
| `pipeline-output/leakage.json` | `89119ba60b113ce0…` |

| output | sha256 | gated |
|---|---|---|
| `pipeline-output/fig_leakage.pdf` | `f406288e24922632…` | yes |
| `pipeline-output/fig_leakage_data.csv` | `d7a5074d2de6b599…` | yes |
| `pipeline-output/fig_leakage.png` | `cabb4cda42464901…` | no, preview |

**Method.** Three-class problem over READ, SELECT and OPERATE; chance balanced accuracy is one third. Evaluation is leave-one-grouped-run-out over all 22 runs. Features are the two independent intervals, request-to-ACK and ACK-to-response; the total response time is their sum and carries no independent information, so it is excluded. Mutual information is estimated on the CLRT with a nearest-neighbour estimator, converted from nats to bits, and compared against a null built by permuting class labels within each grouped run, which preserves the per-run class counts. The empirical Monte Carlo p-value uses the (1+r)/(1+n) correction and its resolution is reported alongside it. Classifier spread is the descriptive range of the 22 held-out-run scores. Neither a jackknife interval on the MI estimate nor a bootstrap over the dependent fold scores is reported; both were rejected and the reasons are recorded in leakage.json.

**Limitations.** Results characterise the evaluated fixed Random-Forest attacker and this feature set, and do not generalise to all fingerprinting classifiers. The 22 grouped runs come from one approximately five-hour campaign on one relay behind one switch and are not independent deployments, so the spread shown is within-campaign only. This is transaction-class classification, not device-model identification.

## `fig_stability`

* **Printed size** 3.5 x 3.5 in
* **Source commit** `2a251eca0b197fd74b2d19db832e5b0de9356e5a`
* **Deterministic seed** `20260828`
* **Command** `python make_ndss_figures.py pipeline-output/transactions_canonical.csv pipeline-output/stats.json pipeline-output/leakage.json policy_config.json pipeline-output/figs pipeline-output/sweep_summary.json`
* **Analysis script** `defense4/timing/evidence/campaign_v1/repro/make_ndss_figures.py` `c70ba7178d47eafe…`
* **Style module** `defense4/timing/evidence/campaign_v1/repro/figstyle_ndss.py` `c023b82e910d316f…`

| input | sha256 |
|---|---|
| `pipeline-output/transactions_canonical.csv` | `53252baf38f91e1f…` |
| `defense4/timing/evidence/campaign_v1/repro/policy_config.json` | `d11e81165038a0ee…` |

| output | sha256 | gated |
|---|---|---|
| `pipeline-output/fig_stability.pdf` | `8c39399bcaad5014…` | yes |
| `pipeline-output/fig_stability_data.csv` | `d9205179801567fd…` | yes |
| `pipeline-output/fig_stability.png` | `b3b536ec62ccd82f…` | no, preview |

**Method.** Each marker is the median of one transaction class within one grouped run, and the bar spans that run's interquartile range. Runs are shown in acquisition order so that drift over the campaign would be visible as a trend.

**Limitations.** 22 grouped runs, one approximately five-hour campaign, one SEL-751A, one Tofino-1. This is within-campaign stability only: it is not cross-session, cross-day, longitudinal, or deployment stability, and the runs are not independent replications. Panel (b) uses a magnified ordinate.

## Manifest and values

`FIGURES.sha256` records the full hash of every gated artefact and carries a header saying why
the previews are excluded. `MANUSCRIPT_VALUES.json` is the only file the manuscript quotes
numbers from; the gate regenerates it and fails on any difference.
