# Correction report — campaign_v1 analysis, figures, reproduction and manuscript

**Branch** `paper/campaign-v1-ndss-corrections-20260828`
**Starting commit** `5a493935ee386e0677505c640c3fd7af82805371`
**Ending commit** see `git log -1`
**Date** 2026-08-31, with a second round after external review the same day
**Pushed** yes. The first six commits were pushed to
`origin/paper/campaign-v1-ndss-corrections-20260828` at `9713e8a` after explicit authorisation;
the review-round commits follow them. Section 7 records what that review found.

No hardware was run, no Tofino program was loaded or changed, no relay was contacted, and no raw
capture or frozen driver log was modified. Every number below is derived from the captures that
already existed in the tree.

---

## 1. Commits

| commit | scope |
|---|---|
| `2ee501f` | evidence and sweep validation |
| `37ee873` | statistical corrections |
| `555dc05` | figure corrections |
| `4a963ca` | manuscript corrections |
| `18c324f` | documentation, build and provenance corrections |
| `9713e8a` | closeout: refreshed provenance, compiled PDF, this report |

plus the review-round commits described in section 7.

Deleted: `paper/rewrite/figures/ndss/fig_budget_cost.pdf` and its provenance, replaced by
`fig_policy_coverage_cost`.

Principal files added: `defense4/timing/evidence/campaign_v1/repro/validate_sweep.py`,
`publication_gate.py`, `uv.lock`; `paper/rewrite/pipeline/ndss_preflight.py`;
`paper/rewrite/ndss/submission.tex`; `paper/rewrite/figures/ndss/MANUSCRIPT_VALUES.json` and
`FIGURE_PROVENANCE_campaign_v1.md`; `defense4/timing/history/CLAIMS_AND_LIMITATIONS_final_read_sbo.md`;
the per-figure PNG, data CSV, caption, method and limitations files.

---

## 2. Scientific corrections, old claim against corrected claim

### 2.1 The read and control lanes were pooled

**Old.** "the budget of 24 ms covers 99.905 % of Timing OFF exchanges, and 30 of 31,680 arrive too
late to be held." The denominator was every Timing OFF exchange, including OPERATE.

**Why it is wrong.** The release budget `D = D_A + D_R` is a property of the ACK-anchored read
path. OPERATE is anchored to the request; its observable is `O = R - A` and `D` is not a
schedulability criterion for it. Pooling the two anchors produces a coverage number for a budget
that never governed part of its own denominator.

**Corrected.** 29 of 29,040 Timing OFF READ and SELECT exchanges exceed 24 ms, that is 0.0999 %
above budget and **99.900 % covered**; 28 are READ and one is SELECT. The single OPERATE exchange
above 24 ms is not a coverage failure. `stats.json` now declares which classes each lane covers,
and a test fails if OPERATE ever re-enters the read-lane denominator.

### 2.2 The mutual-information interval was not defensible

**Old.** A grouped-run jackknife interval was published around the observed MI, and the leakage
figure drew it as an error bar.

**Why it is wrong.** The jackknife pseudo-value construction `n·obs − (n−1)·jk` assumes a smooth
estimator. A nearest-neighbour MI estimator near the zero-information boundary is bounded below
at zero, biased upward on small samples, and not smooth under a leave-one-run-out perturbation.
The published interval excluded its own point estimate **in both arms**, not only the obfuscated
one:

| arm | observed | published jackknife interval |
|---|---|---|
| Timing OFF | 0.38315 bits | [0.34496, 0.37518] |
| Obfuscated | 0.00394 bits | [0.06281, 0.08416] |

**Corrected.** No interval is placed on the estimate. What is published is the observed value, the
within-run permutation null over 1,000 permutations, its 95th and 99th percentiles, and an
empirical Monte Carlo p-value using the `(1+r)/(1+n)` correction with its resolution stated:
Timing OFF 0.383 bits, `p = 0.001` at the resolution floor; Obfuscated 0.004 bits, `p = 0.096`,
inside its null. The jackknife is retained under `rejected_estimators` with its reason and is
never plotted.

### 2.3 The classifier confidence interval was a bootstrap of dependent scores

**Old.** A 95 % confidence interval obtained by bootstrapping the 22 leave-one-run-out fold
scores.

**Why it is wrong.** Every pair of those folds shares 20 of 22 training runs. Resampling
dependent scores does not estimate the sampling distribution of their mean, so the interval was
not a confidence interval.

**Corrected.** The 22 held-out-run scores are reported descriptively (mean, median, range, IQR),
labelled *within-campaign held-out-run variability*, and the figure caption says explicitly that
it is not a confidence interval. Accuracies are scoped to the evaluated fixed Random-Forest
attacker and feature set rather than to fingerprinting classifiers in general.

### 2.4 The sweep's response-time median was a sum of medians

**Old.** `sweep_points.csv` published `rt_med_ms` equal to `ack_med_ms + clrt_med_ms`.

**Why it is wrong.** The sum of two medians is not in general the median of the sum. For `sw_off`
the published value is 2.651 ms while the true median of `t_resp − t_req` is 2.680 ms.

**Corrected.** `rt_med_ms` is now the median of `t_resp − t_req`; the published quantity is
retained as `sum_of_interval_medians_ms` so the difference stays auditable. A test asserts the two
differ measurably somewhere in the sweep, so the correction cannot silently become a no-op.

### 2.5 The sweep's standard deviation used an undocumented convention

**Old.** `clrt_sd_ms` matched none of our recomputations at three decimals.

**Finding.** It was published with the **population** convention (`ddof = 0`), which reproduces
all 19 points exactly. This is a documentation gap, not a data error.

**Corrected.** Both conventions are emitted under explicit names, the published column is verified
against the population value, and the campaign table's sample convention is stated so the two are
never mixed in one reported quantity. No published number changed.

### 2.6 The OPERATE claim exceeded the observation

**Old.** "We therefore claim that the master-visible interval is insensitive to the configured
codebook."

**Why it is wrong.** The campaign records the configured codebook {2, 6, 12} ms but not the
realized per-transaction draw, and the relay-facing release at `T0 + J` is on no captured link.
Insensitivity to a variable that was never observed to vary cannot be concluded.

**Corrected.** "Under the configured {2, 6, 12} ms codebook, the master-visible OPERATE ACK-to-echo
interval remained concentrated near the configured 4 ms policy value." The relay-facing release,
the per-transaction draw, physical actuation and exactly-once delivery are named as unobserved.
Tests fail the build if a per-`J` or relay-facing observation claim reappears in the analysis
source.

### 2.7 The DNP3 integrity explanation was factually wrong

**Old.** Padding "breaks the exchange when the master reassembles the response and checks the
cyclic redundancy check (CRC) that covers every sixteen application bytes."

**Corrected.** A DNP3 link-layer frame carries a declared length and a CRC over each block of the
frame, so bytes inserted at an arbitrary offset change the framing the receiver parses; making
such an insertion valid requires protocol-aware reconstruction of the frame and recomputation of
its link-layer CRC blocks. Separately, the relay that would emit cover traffic cannot be modified.

### 2.8 Smaller claim corrections

* The design figure caption said the scheduler "realizes every deadline". It now realizes an
  armed deadline when the packet arrives within the schedulable window, and otherwise fails open.
* The design text said the adversary learns "the policy and not the physical device" without
  qualification. It now names what remains visible: function codes, direction, the shifted
  acknowledgment latency, and the differing anchors.
* The design text called `D` "both the coverage knob and the delay the framework adds", which
  contradicted its own equation. `D` bounds the added delay; the delay actually added depends on
  how long the outstation took.
* The contribution list contained three fragments and a firstness claim. It is now three verb-led
  contributions with no firstness claim.
* "In-network turning framework" was a typo for timing-obfuscation framework.

---

## 3. Figures

The budget figure pooled the two anchors in its coverage panel and put frame counts and byte
counts on one logarithmic axis. It is replaced by `fig_policy_coverage_cost`, which argues
configurability from the **measured** 19-point hardware sweep rather than from a resampled
distribution, and the zero-added-frame result moves into the evaluation text.

Four published figures, each with a vector PDF, a 600-dpi PNG, its exact figure data as CSV, a
caption, a statistical-method note, a limitations note and a provenance sidecar:

| figure | PDF sha256 (gated) | figure-data sha256 (gated) |
|---|---|---|
| `fig_policy_coverage_cost` | `f6732b3b53935e01…` | `c208fb12cde1b340…` |
| `fig_distributions` | `48ccc6b133ae8873…` | `68defb9a5a093bc3…` |
| `fig_leakage` | `f406288e24922632…` | `d7a5074d2de6b599…` |
| `fig_stability` | `8c39399bcaad5014…` | `d9205179801567fd…` |

Full hashes are in `paper/rewrite/figures/ndss/FIGURES.sha256`, which gates the vector PDF and
the figure data only. Each PNG preview's hash is recorded in its provenance sidecar, marked
non-authoritative; see section 7.3.

Each provenance sidecar records every input by repository-relative path and SHA-256, the analysis
script and style module by path and hash, the source commit, the deterministic seed, the output
hashes, the printed dimensions and the generation command. Paths for pipeline products use a
`pipeline-output/` prefix rather than an absolute directory, so provenance does not depend on
where the run was placed and two runs from different directories agree.

Style gates now fail generation rather than warn: no text below 8 pt at printed size, no Type 3
fonts, opaque white, and class line styles plus arm hatching so every panel reads in greyscale.
Figures were inspected in colour, in greyscale and at printed size. Three defects found and fixed
during that inspection: a control point from a different release mode plotted among the
policy points, a legend covering the response-time series, and READ and SELECT distinguished only
by colour.

---

## 4. Verification

### Reproduction, from a fresh output directory

```
reproduce.sh  ->  exit 0
```

| step | result |
|---|---|
| dataset manifests | 22 verified, 268 entries, 0 problems |
| canonical table vs frozen table | 63,360 rows compared row by row, 0 differences |
| sweep manifest | 42 entries verified |
| sweep | 19 points, 5,860 transactions, 0 problems |
| tests | **121 passed** |
| publication gate | **0 problems**; every authoritative artefact matches what is published |

The gate's scope was corrected after review: see section 7.3. It hash-gates the vector PDFs, the
figure-data CSVs, the caption and note files, the provenance content and `MANUSCRIPT_VALUES.json`.
It does not hash-gate the PNG previews, because those are not byte-reproducible across
interpreter builds.

The gate was also exercised adversarially: perturbing one stored interval by twice its tolerance,
swapping two rows, deleting a row, relabelling a class and relabelling an arm are each detected.

### Dataset counts, reproduced from the raw captures

132 captures; 22 grouped runs; 63,360 DNP3 exchanges; 31,680 per arm; 52,800 READ, 5,280 SELECT,
5,280 OPERATE; 480 exchanges and 440 high-level operations per capture; 1,448 frames and 130,708
captured bytes per capture in both arms; zero malformed, unmatched, duplicated, retransmitted,
out-of-order or wrong-endpoint exchanges; success status on every captured SELECT and OPERATE.
Plus the sweep: 19 points, 5,860 exchanges.

### Values that reproduce unchanged

Timing OFF MI 0.38315 bits; Obfuscated MI 0.00394 bits, inside the permutation null; fixed
CLRT-only Random Forest 0.6515 → 0.3332; fixed ACK+CLRT 0.7328 → 0.3337; adaptive ACK+CLRT
0.6510; obfuscated medians 4.000 ms in all three classes; no master-facing frame or byte increase.

### Values that changed, and why

| quantity | old | corrected | reason |
|---|---|---|---|
| read-path coverage | 30 of 31,680 (99.905 %) | 29 of 29,040 (99.900 %) | OPERATE removed from an ACK-anchored denominator (§2.1) |
| sweep `rt_med_ms` | sum of two medians | median of `t_resp − t_req` | wrong statistic (§2.4) |
| MI uncertainty | jackknife interval | permutation null + empirical p | estimator invalid here (§2.2) |
| classifier interval | bootstrap "95 % CI" | descriptive range over 22 runs | folds are dependent (§2.3) |

### Manuscript

Build PASS with no hard-check failures. `lin_check --compare` against `5a49393`: **no
regression**, with `firstness` and `contribution_grammar` both improving from WARN to PASS and
`readability.outside_band` from 44.6 to 0.0.

`paper/rewrite/main.pdf` sha256 `689f520e9d189d1c3ea540d366a60f5d1e3623cfb4ef6f1af2ee5acb72e88303`
(recorded in `main.pdf.sha256`). 12 pages, US Letter, **10 main-body pages** before References,
which begin on page 11, against a 13-page limit.

NDSS preflight, draft mode: **PASS, 0 blocking issues** — official template hashes, geometry,
page budget, two columns, 10 pt type, 26 embedded fonts with no Type 3, publication block, review
cycle, page numbering matching the official template, anonymity, and black-and-white rendering.
Submission mode correctly **fails** on the unassigned paper number.

### Environment

Python 3.13.12; numpy 2.3.5, scipy 1.16.3, scikit-learn 1.7.2, matplotlib 3.10.7, joblib 1.5.3,
pytest 8.4.2; Tectonic 0.16.9. `uv.lock` is committed and `reproduce.sh` synchronises from it with
`uv sync --frozen --python 3.13`. Seeds: leakage 20260828, RandomForest 0, mutual_info_classif 0.

---

## 5. Unresolved items

| item | status | needs a hardware rerun? |
|---|---|---|
| HotCRP paper number for the DOI | Not assigned. `ndss/submission.tex` leaves it empty; the DOI renders a visible DRAFT marker and `ndss_preflight --submission` fails. The number must not be invented. | No. It is assigned at submission. |
| Sweep configuration provenance | PARTIAL. Per-point `D_A`/`D_R` come from the archived `sweep_points.csv`, cross-checked against the point names; the driver logs record the mode and codebook but not the offsets, and no per-point control-plane readback was archived. | A rerun would be required to archive per-point readbacks. Not required for any claim as stated, because the claim is bounded to the archived configuration. |
| Fail-open horizon `H` = 30.8 ms | Control-plane quantity computed from the pass budget and reservoir depth. The measured saturation near 31.07 ms is consistent with it, but `H` was not measured directly and is not enforced by the data plane. The manuscript reports the observed transition, not a proof the two coincide. | Yes, if a direct measurement of `H` is ever wanted. |
| Realized per-transaction `J`, relay-facing release, exactly-once delivery, physical actuation | Unobserved. `dp68` is internal with no host-capturable tap. Claims are bounded to the master-facing observable. | Yes. Would need a relay-facing tap, which the current topology does not provide. |
| Generalisation across devices, days and deployments | Out of scope of this evidence: one SEL-751A, one Tofino-1, 22 grouped runs in one campaign. | Yes, and a different campaign design. |
| `sentence_health` gate warning | 7 verbless "sentences", all of them bold run-in headers and section headings; `fragments = 0`. A known false positive of the verb detector on run-in headers. | No. |
| Retired `final_read_sbo` evidence | Retained for provenance, labelled historical at the top of each file. The first round missed several active passages that still described it as current; those were found in review and corrected (section 7.5). | No. |

## 6. One change to a checker, disclosed

`lin_check.py`'s contribution-grammar lexicon contained only third-person verb forms
("designs", "implements"), so it could not recognise the bare imperative form that a contribution
headline normally takes ("Design a framework"). The bare stems of the same verbs were added. This
makes the checker recognise a form it already intended to accept; it does not weaken any gate, and
the check moved from WARN to PASS because the headlines genuinely are verb-first.

---

## 7. Second review round

An external review of the pushed branch confirmed the dataset, the numerical results and the
reproduction, and found six defects that the first round missed. All are fixed. The review's
verification of the evidence, the 22 manifests, the row-by-row table agreement, the 19-point
sweep, the manuscript-to-values match and the NDSS draft preflight is consistent with what is
recorded above.

### 7.1 Two figure legends covered data

`fig_leakage` panel (a) used a two-column legend that spanned the panel and completely covered
the panel tag, so the figure printed with (b), (c) and (d) labelled and (a) missing. It is now a
single column, clear of both the tag and the tallest bar.

`fig_policy_coverage_cost` panel (c) used a four-entry legend at upper left that covered the
request-to-acknowledgment curve at $D_A$ = 28 and 30 ms. Those are precisely the two points that
locate the saturation, so the panel hid its own result. The two reference lines are now annotated
on the lines themselves, leaving a two-entry legend that sits in the empty band between the
curves. Both figures were re-inspected at printed size.

### 7.2 One incorrect count and one heading error

The evaluation said "we installed 19 release policies". The sweep is 18 configured policies plus
one control capture with the mechanism disabled, 19 captures in total. Corrected in the method
paragraph and in the corpus paragraph.

The evaluation heading read "RO4a" with no RO4b, and the cost subsection was labelled RO5 while
cost was defined as part of RO4. The objectives are now RO4 (release policy and coverage) and
RO5 (cost and protocol preservation), which map one-to-one onto the two subsections. The gate now
reports all five RO labels as defined and reused; previously RO4 was defined and never reused,
and the gate passed without noticing.

### 7.3 The publication gate failed a correct rebuild

A fresh locked reproduction passed every data check and every test but failed the gate with six
errors that reduced to two PNG mismatches. The PDFs were byte-identical; only a few hundred
pixels of two previews differed. The committed run used Python 3.13.12 and the fresh environment
resolved 3.13.14, because `requires-python` is `==3.13.*`.

Pinning the interpreter would not fix this in general: the Agg raster depends on the FreeType and
libpng bundled with the interpreter build, which the lock file does not describe. The gate was
therefore rescoped rather than tightened. The authoritative artefacts are the vector PDF and the
figure data, both produced entirely by the pinned Python dependencies and byte-reproducible;
`FIGURES.sha256` lists those and carries a header saying so. The PNG remains a published
deliverable and its hash is still recorded in each provenance sidecar, now marked
`"authoritative": false` with the reason. Two tests enforce the split: one asserts the manifest
gates the PDF and the data CSV, another asserts the preview is not in the gated manifest and is
still published.

This means the statement in section 4 of the first version of this report, that a fresh
reproduction necessarily produces "0 problems", was wrong as written. It was true of the
environment the work was done in and not of a fresh one. The gate now behaves as that sentence
claimed.

### 7.4 The classifier and device-fingerprinting wording

Device fingerprinting motivates the work and is the setting the threat model describes, but the
classifier we evaluate separates READ, SELECT and OPERATE on a single outstation. The limitation
was disclosed but the argument did not say plainly what was demonstrated. The threat model now
carries an explicit paragraph separating the two, and the abstract, the RO3 interpretation and
the conclusion state that this is the suppression of a class-conditioned timing feature and not a
demonstration of resistance to device identification. All three also now note that the plaintext
function code already names the operation, so what the mechanism removes is the additional,
device-derived timing signature of an event the function code had already revealed.

"Profiles the device beforehand" is replaced everywhere by "trains on Timing OFF transaction-class
timing before deployment", which is what the fixed attacker actually does.

### 7.5 Documentation that reverted to the retired dataset

`defense4/timing/README.md` opened on campaign_v1 and then, in later sections, described the
retired evidence as current: the arms as running with size shaping active, the raw captures as
`final_read_sbo`, sample counts of 489 and 499, 30 transactions per J condition, the five-figure
workflow and a 102-check test suite. Those sections are now either scoped explicitly to the
retired tree or replaced with the active numbers. The root `README.md` quickstart invoked the
historical reproduction script and the 102-check suite; it now invokes
`evidence/campaign_v1/repro/reproduce.sh`. `paper/rewrite/README.md` described five figures under
`figures/timing/`; the manuscript uses four under `figures/ndss/`, published only by the gate.

### 7.6 CRLF in generated CSVs

The figure-data CSVs were written with CRLF line endings, so `git diff --check` reported every
added line as trailing whitespace. The writer now pins `lineterminator="\n"`, and a test asserts
no generated data CSV contains CRLF.

### 7.7 What the review confirmed

The remote branch and commit, all 22 dataset manifests and their 268 entries, the independent
reconstruction of 63,360 exchanges from 132 captures, row-by-row agreement between the frozen and
regenerated tables, the 19-point sweep with 5,860 exchanges and zero validation errors, the full
test suite, the manuscript-to-`MANUSCRIPT_VALUES.json` match, byte-identical regeneration of all
four vector PDFs, the stored figure and schematic hashes, the NDSS draft preflight, and that
`shape_enable = 0` is supported by the archived `shape_set.py 0` execution, its readback semantics
and the single 49-byte wire responses.
