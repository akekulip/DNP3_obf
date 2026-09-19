# Figure provenance — the manuscript on campaign_v2

Every figure the manuscript includes, the one generator that produces it, the data it is drawn
from, and the check that fails if the published copy drifts. No figure is edited by hand. Each
data figure carries `.caption.md`, `.method.md`, `.limitations.md`, `_data.csv` and
`.provenance.json` beside it; the provenance sidecar records the SHA-256 of every input.

| manuscript figure | file | generator | data | check |
|---|---|---|---|---|
| `fig:ladder` (Fig. 1) | `figures/fig_ladder` | `pipeline/drawio/build.sh`, then `pipeline/export_schematics.sh` | schematic, no data | `figures/SCHEMATICS.sha256` |
| `fig:observation` (Fig. 2) | `figures/fig_observation` | as above | schematic, no data | as above |
| `fig:design` (Fig. 3) | `figures/fig_design` | `pipeline/drawio/gen_design_drawio.py`, then as above | schematic of the shipped P4 program (`defense4/timing/anchor_fix/src/`) | as above |
| `fig:timeline` (Fig. 4) | `figures/model/fig_m01_release_timeline` | `defense4/timing/audit_current/tools/make_model_figures.py` | `campaign_v2/PROVENANCE_CONSTANTS.json` (D_A 20 ms, CLRT_new 8 ms) and the campaign's Timing OFF READ median from `MANUSCRIPT_VALUES.json`; schematic otherwise | `make_model_figures.py --check` |
| `fig:hist` (Fig. 5) | `figures/clrt/fig_clrt` | `defense4/timing/audit_current/tools/clrt_distribution_and_variance.py` | the 132 campaign_v2 captures, read with `repro/pcap_dnp3.py` in integer nanoseconds; configured value from `repro/policy_config.json` | `clrt_distribution_and_variance.py --check` |
| `fig:policy` (Fig. 6) | `figures/ndss/fig_policy_coverage_cost` | `campaign_v2/repro/reproduce.sh` (step 6, `make_ndss_figures.py`) | canonical table (panels a, c) and the 26-point sweep (panel b, the 8 points at D = 28 ms) | `campaign_v2/repro/publication_gate.py` |
| `fig:leakage` (Fig. 7) | `figures/ndss/fig_leakage` | as above | `leakage.json` (panel a) and `multiobs.json` (panel b) | as above |
| `fig:tail` (Fig. 8) | `figures/tail/fig_release_tail` | `campaign_v2/_bin/make_tail_figure.py` | `sweep/sweep_timing.json` and `sweep_points.csv` (panel a), `derived/transactions.csv` (panel b) | `make_tail_figure.py --check` |

`reproduce.sh` also publishes `fig_distributions`, `fig_feature_overlap` and `fig_stability` into
this directory. The manuscript does not include them; they remain gated so that they cannot drift
while unused.

Every number the text quotes comes from `MANUSCRIPT_VALUES.json` in this directory, which the
publication gate rebuilds and compares, or from the named records listed in
`defense4/timing/CLAIMS_AND_LIMITATIONS.md`.
