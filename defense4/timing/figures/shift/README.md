# Constant shift versus CLRT normalization — DRAFT figures and their interpretation

Four figures, two corpora, kept separate. **DRAFT** until the manuscript revision that would use
them is authorised, and deliberately not copied into `paper/rewrite/figures/`.

Regenerate with

```sh
../../evidence/campaign_v1/repro/.venv/bin/python \
  ../../audit_current/tools/shift_vs_normalization.py
```

No result value is written into the script: intervals come from the canonical transaction table
and the retired tree's frozen derived CSVs, and both configured targets are read from the
configuration. The read-lane target is `policy_config.json:D_R_ms`, cross-checked against
`scheduled_release_interval_ms`; the control-lane target is `R_ms - A_ms` from
`PROVENANCE_CONSTANTS.json`. An earlier version loaded the policy file and then used a hardcoded
4 ms for both, which happened to be right and would have gone quietly wrong under any policy
change.

Each corpus takes its target from **its own** documented configuration, never from the other's:
the active campaign from `policy_config.json` and `PROVENANCE_CONSTANTS.json`, the retired tree
from its own `CAPTURE_MANIFEST.csv`. They coincide at 4 ms today, which is precisely why they are
kept separate. All of those files are hashed inputs in each figure's provenance sidecar.

**Reproducibility.** The figure-data CSVs and the summary JSON are byte-reproducible wherever
the pinned environment installs; the rendered PDFs are byte-reproducible within a machine but
not guaranteed across machines. See `../../audit_current/REPRODUCIBILITY_SCOPE.md`.

**Manifest.** `FIGURES.sha256` covers the PDFs, the figure-data CSVs and the summary JSON, and is
written by the same run that produces them, so it cannot fall behind. Verify without regenerating:

```sh
../../audit_current/tools/shift_vs_normalization.py --check
```

The provenance sidecars are deliberately excluded: their `source_commit` field changes with every
commit, so hashing them would leave the manifest permanently one commit stale. Each figure ships a vector PDF at 7.16 in, a 600 dpi PNG, its plotted values as
CSV, a caption, a method note, a limitations note, and a provenance sidecar hashing every input.

| figure | corpus | what it shows |
|---|---|---|
| `fig_s1_shift_vs_normalization_campaign_v1` | campaign_v1 | left: full-support ECDF of the observed interval with the measured native, the **analytical** constant-shift reference and the measured defended distributions, plus a zoom on `C`; right: the same measured distributions with their own mean removed |
| `fig_s2_variance_and_target_campaign_v1` | campaign_v1 | (a) variance ratio with a cluster bootstrap over the 22 grouped runs; (b) target-error distribution with a central zoom. Its data CSV is long-form and carries the panel-(a) variance rows **and** the panel-(b) and pooled-OPERATE target-error rows: offsets, spreads, RMSE, tail quantiles, maxima and tolerance coverage, as the caption promises. The pooled OPERATE rows are marked *not plotted*, because this corpus cannot resolve `J` per transaction and so has no panel (c) |
| `fig_s1_shift_vs_normalization_final_read_sbo` | final_read_sbo (retired) | as above, for the retired six-capture dataset |
| `fig_s2_variance_and_target_final_read_sbo` | final_read_sbo (retired) | as above, plus (c) the OPERATE response-to-acknowledgment error per configured `J`, which only this corpus resolves |

---

## What the numbers are

Sample variance throughout, `n − 1` denominator. Variance in ms², deviation in ms.

### Variance ratio, ρ = s²(defended) / s²(native)

| corpus | operation | sd native | sd defended | ρ | 95 % interval | runs |
|---|---|---|---|---|---|---|
| campaign_v1 | READ | 2.6092 ms | 0.6279 ms | 0.0579 | [0.0183, 0.1031] | 22 |
| campaign_v1 | SELECT | 2.2667 ms | 0.0242 ms | 0.000114 | [1.36e−5, 3.38e−4] | 22 |
| final_read_sbo | READ | 1.3549 ms | 0.0222 ms | 0.000268 | none | 1 |
| final_read_sbo | SELECT | 2.5322 ms | 0.0213 ms | 0.0000700 | none | 1 |

The interval is a percentile cluster bootstrap that resamples whole grouped runs, 2,000
replicates, seed 20260907. Runs are the sampling unit, so within-run dependence is preserved and
transactions are not treated as independent. **The retired corpus has one session, so no
interval is reported for it**: a bootstrap over its transactions would assume an independence it
does not have, and the earlier withdrawal of a bootstrap over dependent fold scores
(`CLAIMS_AND_LIMITATIONS.md` L9) is the same mistake. A single point estimate is given instead.

Nothing is clipped at 1, and no interval bound is forced below it. The abscissa is logarithmic
because the two operations' ratios differ by more than two orders of magnitude; the axis says so.

### Target error, `C_obs − C`, over every defended observation

| corpus | operation | n | mean | sd | RMSE | max abs | ≤ 0.05 ms | ≤ 0.5 ms | ≤ 1 ms |
|---|---|---|---|---|---|---|---|---|---|
| campaign_v1 | READ | 26,400 | +0.0124 ms | 0.6279 ms | 0.6280 ms | 53.182 ms | 99.30 % | 99.86 % | 99.91 % |
| campaign_v1 | SELECT | 2,640 | +0.0010 ms | 0.0242 ms | 0.0243 ms | 1.150 ms | 99.62 % | 99.96 % | 99.96 % |
| campaign_v1 | OPERATE, codebook pooled | 2,640 | +0.0003 ms | 0.0335 ms | 0.0335 ms | 1.662 ms | 99.55 % | 99.96 % | 99.96 % |
| final_read_sbo | READ | 599 | +0.0077 ms | 0.0222 ms | 0.0234 ms | 0.098 ms | 89.15 % | 100 % | 100 % |
| final_read_sbo | SELECT | 499 | +0.0078 ms | 0.0213 ms | 0.0226 ms | 0.124 ms | 89.38 % | 100 % | 100 % |
| final_read_sbo | OPERATE, J = 2 ms | 30 | +0.0125 ms | 0.0262 ms | 0.0286 ms | 0.095 ms | 86.67 % | 100 % | 100 % |
| final_read_sbo | OPERATE, J = 6 ms | 30 | +0.0138 ms | 0.0261 ms | 0.0291 ms | 0.080 ms | 83.33 % | 100 % | 100 % |
| final_read_sbo | OPERATE, J = 12 ms | 30 | +0.0117 ms | 0.0280 ms | 0.0299 ms | 0.068 ms | 80.00 % | 100 % | 100 % |

Late and fail-open observations are **included**. That is why READ's RMSE, 0.628 ms, is 26 times
its SELECT counterpart while its mean offset is small: the offset is the systematic part and the
RMSE carries the tail. No conditional on-time analysis is presented; if one is ever wanted it
must be labelled supplementary.

The two corpora differ in a way worth naming: every retired-corpus observation is inside
0.5 ms, with a worst absolute error of 0.098 ms for READ against 53.182 ms for `campaign_v1`,
but the retired corpus is **less** accurate at the tightest tolerance, 89 per cent inside
0.05 ms against 99 per cent. Its 599 READ observations come from one session with no late
arrival in them, whereas `campaign_v1`'s 26,400 span 22 runs and include the fail-open tail. The
two are not comparable as accuracy measurements and are not compared as such; each is reported
against its own provenance.

**Tolerances are fixed independently of these results.** 0.5 ms is half the smallest configured
step in the policy sweep, where `D_R` moves in 1 ms increments, so it is the largest error that
cannot be confused with a neighbouring policy setting. 0.05 ms and 1 ms are reported for context.
The mechanism's own placement floor is the 256 ns deadline quantization grid, recorded in the
figure data.

### Transactions with no valid completed interval

Reported separately, because they have no CLRT to contribute: across all 63,360 `campaign_v1`
exchanges there are **zero** missing responses, zero unpaired requests, zero malformed frames,
zero invalid application rows and zero timeouts, and all 5,280 SELECT and OPERATE exchanges
returned CROB status SUCCESS. The retired corpus likewise has every request answered with both an
acknowledgment and a response. So no observation was dropped for any of these reasons, and the
denominators above are the full samples.

## What the figures establish, and what they do not

**Established.** A constant translation preserves sample variance identically, which is why the
analytical reference in `fig_s1` retains the native shape exactly while merely sliding to `C`.
The measured defended distributions do not look like that: they concentrate at the configured
interval, and the concentration survives removing location, which is what the centered panel
shows. Quantitatively ρ is 0.058 for READ and 0.000114 for SELECT with intervals far below 1, so
the constant-shift prediction ρ = 1 is excluded by a wide margin under these conditions. The
concentration is at the **right** value, not merely a tight one: the mean error is +0.0124 ms for
READ and +0.0010 ms for SELECT against a 4 ms target, with 99.86 % and 99.96 % of observations
inside the independently fixed 0.5 ms tolerance.

Read with the verified mechanism, this is coherent rather than coincidental. Both read-lane
release instants are armed from the single anchor `t_a`, so their difference is the configured
offset and the native interval is absent from it algebraically
(`audit_current/SHIFT_VS_REPLACEMENT.md` §4). The residual tail is the response-availability
boundary in the same section: a response arriving after its deadline is forwarded on arrival
rather than pinned, which produces an upper tail and no lower one, and the data agree — the
smallest defended interval anywhere is 3.922 ms, 78 µs under target, with no left tail.

**Not established, and not claimed.**

* **Not independence from the native interval.** Reduced variance rejects a constant translation
  as the explanation. It does not show the output is independent of the input. That needs paired
  ingress and egress measurement, which this evidence does not contain and which the loaded
  binary cannot provide (`audit_current/INSTRUMENTATION_AUDIT.md`).
* **Not a measured fixed-shift hardware baseline.** The reference is analytical. The loaded
  binary has no shifting mode: its decision table arms only for the dual-deadline mode
  (`SHIFT_VS_REPLACEMENT.md` §1), so no such arm could have been run.
* **Not the elimination of timing leakage.** An attacker retrained on obfuscated traffic recovers
  to 0.651 balanced accuracy from the acknowledgment interval.
* **Not physical operation time.** The OPERATE panel is a master-visible protocol-response
  interval. `audit_current/FORMBY_REVIEW.md` shows the physical-operation-time fingerprint as
  actually reported rests on an application-layer SER timestamp, which this mechanism does not
  touch, and our traffic contains no such timestamp and no unsolicited response.

## The conclusion these figures support

> A constant translation preserves the native CLRT variance. The measured defended distributions
> exhibit reduced variability and concentrate around the configured interval. Together with the
> verified common-anchor scheduling mechanism, these results support CLRT normalization within
> the evaluated operating conditions.

The evaluated operating conditions are: one SEL-751A behind one Tofino-1, master-facing
measurement only, `C` = 4 ms at `D` = 24 ms, 22 grouped runs in one approximately five-hour
campaign for the active corpus and one session for the retired one, with the policy range and
its upper boundary as measured by the 16-point sweep.
