# Campaign v2 figure and data audit — 2026-09-25

The long-run figures were rebuilt from the archived captures and corrected for data export,
timing precision, and publication layout. This audit covers **22 grouped runs, 132 captures,
63,360 exchanges, and 5.297 hours**, plus the separate **26-point, 9,360-exchange policy sweep**.
It describes the campaign's 20 ms ACK offset, 8 ms configured interval, and 28 ms release
budget. It does not turn the later seven-stage hardware smoke test, which used a 4 ms
interval, into a long-run evaluation of that optimized implementation.

## Data checks

- All 22 dataset manifests passed: 264 entries and 132 unique capture hashes.
- Every exchange was re-extracted, checked, and compared with the frozen table on identity,
  order, class, and all three intervals. All 63,360 agree at the captures' **1 µs timestamp
  resolution**. The frozen float-based extractor is not exact below that resolution.
- Each arm contains 26,400 READ, 2,640 SELECT, and 2,640 OPERATE exchanges. No observations
  were removed to improve the reported results.
- All 54 sweep-manifest entries passed. Each of the 26 points also passed the archived
  control-plane readback checks for mode, timing parameters, disabled size shaping, and
  request anchoring for D4. Timing addends are independently floored to the switch's 256 ns
  grid, matching the archived installer.
- Sweep and release-tail intervals now subtract integer capture timestamps before converting
  to milliseconds. This removes floating-point epoch-subtraction noise. The sweep values
  change only in their last stored decimal places; the before/after values are retained in
  [result_comparison.json](result_comparison.json).
- Every main-campaign section of `MANUSCRIPT_VALUES.json` is unchanged. Fresh leakage,
  pooled-observation leakage, and replacement analyses exactly match the prior results.
  The read-lane coverage remains **99.9415%**, with **17 of 29,040** native READ/SELECT
  responses exceeding the 28 ms budget.

The machine-readable evidence is in [validation_report.json](validation_report.json),
[sweep_report.json](sweep_report.json), [environment.json](environment.json), and
[result_comparison.json](result_comparison.json). The last file also records hashes of the
rebuilt canonical tables and analysis outputs.

## Final verification

- **154 tests passed**, including raw-timestamp bin recounts, exact empirical curves,
  archived switch readbacks, policy windows, and PDF/PNG layout preservation.
- Campaign publication gate: **0 problems**. CLRT hash manifest: **0 problems**.
  Independent release-tail rebuild comparison: **0 problems**.
- Manuscript build: **PASS**. Writing-gate comparison: **no regression**.
  Local NDSS draft preflight: **PASS**, 13 total pages, 12 counted body pages,
  embedded fonts, and no Type 3 fonts. This remains a draft with an unassigned paper number.
- Actual PNG exports and manuscript figure pages were visually checked for readable axes,
  clipping, and legend/title overlap. Independent review found no remaining layout issues.
- A separate recount from raw integer timestamps matched every exported CLRT and tail
  histogram bin, including the zoom endpoint and overflow categories, with zero mismatches.
- Python syntax checks and `git diff --check` passed. No new dependencies were added.

The command results are retained in [verification.txt](verification.txt). The published
manuscript is `paper/rewrite/main.pdf`; its hash, source digest, and manifest agree.

## Figure corrections

- Replaced stale 4 ms detail windows with windows derived from the active 8 ms policy.
- Corrected request/ACK anchor descriptions. The displayed post-ACK measurement is response
  minus ACK; campaign v2 arms its deadlines from the request.
- Made empirical CDF and strict-exceedance CCDF exports exact, including ties and every
  unique step. The CCDF's zero endpoint remains in the CSV because a log axis cannot show it.
- Included all displayed scatter points and detail-window counts in the figure data.
  Scatter is explicitly a deterministic class-stratified display sample; summary statistics
  use every observation. Full-range axes contain the complete measured support.
- Preserved histogram denominators and made overflow categories explicit. Zoomed views
  disclose their coverage instead of silently excluding the tails.
- Counted histogram ties on the same decimal boundaries that the CSV exports. Previously,
  binary rounding in tail and CLRT zoom edges could put an observation in the adjacent bin.
  Independent raw-timestamp recounts now verify these edges, including the closed final
  CLRT zoom bin. This corrects bin allocation without changing samples or summary statistics.
- Recorded the pooled-classifier input and the tail generator's raw captures/parser in
  figure provenance.
- Moved legends and panel titles outside the data rectangles, kept text at least 8 pt at
  final size, and used column-width vector PDFs with matching PNG previews. A regression
  now catches the PDF/PNG layout-engine reset that moved PNG labels into the legend margin.

The supplied Formby et al. NDSS paper was used as the visual reference: readable axes,
compact panels, restrained styling, and unobstructed data. The five campaign figures are
under `paper/rewrite/figures/ndss/`; the CLRT and release-tail families are under the adjacent
`clrt/` and `tail/` directories. Every published figure includes data and provenance sidecars.

At the campaign policy, the release-tail medians remain 0.101 ms for READ and SELECT and
0.107 ms for OPERATE. The explicit ≥0.129 ms categories contain 112/26,400 READ,
10/2,640 SELECT, and 16/2,640 OPERATE observations. The CLRT detail window contains
24/26,400 Timing OFF and 26,383/26,400 Obfuscated READ observations; its bars keep the
full-arm denominator.

## Reproduction

From the repository root, the complete campaign rebuild is:

```sh
bash defense4/timing/evidence/campaign_v2/repro/reproduce.sh /tmp/cv2_out
```

The CLRT and release-tail families have separate checks, using the same pinned environment:

```sh
defense4/timing/evidence/campaign_v2/repro/.venv/bin/python defense4/timing/audit_current/tools/clrt_distribution_and_variance.py --check
defense4/timing/evidence/campaign_v2/repro/.venv/bin/python defense4/timing/evidence/campaign_v2/_bin/make_tail_figure.py --check
```

The audit used `/tmp/dnp3-figure-audit-20260926` for the complete extraction and statistical
rebuild. After the precision/layout fixes, affected extractors and figure generators were
rerun, followed by the full tests and publication comparison. Expensive, unchanged classifier
analyses were retained from that fresh rebuild.

These checks establish consistency of the archived data, calculations, figures, and
manuscript values. They do not establish generalization beyond the measured relay, switch,
workload, and campaign. Raw captures, the frozen campaign tables, historical campaign v1,
and the deployed P4 implementation were not modified.
