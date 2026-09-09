# Four post-meeting corrections: notation, drain time, histograms, and D_R

2026-09-09. Branch `paper/clrt-four-corrections-20260909`, cut from
`paper/lin-post-meeting-revision-20260908` at `24c52b4`.

This report covers the four follow-up corrections Dr. Lin asked for after the September meeting:
standardize the CLRT notation, measure the blocker-queue drain time, rebuild the distribution
figure as histograms following Formby, and correct what `D_R` means in the paper. Requirement 2
is delivered as a status with an exact remaining dependency; the other three are complete.

---

## 1. Notation: `CLRT_original` and `CLRT_new`

**Symbols.** The paper now uses exactly two names for the interval between the acknowledgment and
the response, typeset `\mathrm{CLRT}_{\mathrm{original}}` and `\mathrm{CLRT}_{\mathrm{new}}`:

| symbol | endpoints | where defined |
|---|---|---|
| `CLRT_original` | `t_R − t_A`, the interval the outstation itself produces | `04_design.tex`, eq. (1) `eq:clrt-original` |
| `CLRT_new` | `e_R − e_A`, the interval after obfuscation | `04_design.tex`, eq. (3) `eq:clrt-new` |

`CLRT_new` is qualified wherever the distinction matters: **configured `CLRT_new`** for the
policy value the operator installs, **measured `CLRT_new`** for what the master records. The
distinction is introduced at eq. (4) in the Design section and used consistently thereafter.

**Withdrawn.** `CLRT_target` and `C_{\rm target}` no longer appear anywhere in the manuscript or
in any figure generator. No `X`, `Y` or `C` was introduced for these quantities. The word
*target* as a noun for the configured value is gone from the body; it survives only as an
ordinary verb ("the mechanism does not target it").

**OPERATE stays distinct.** The control lane keeps its request-relative quantities `A`, `R` and
`J` and its own subsection (`sec:design:control`). No read-lane symbol was applied to it.

**Timeline symbols aligned.** `fig_m01_release_timeline` previously used lowercase instants
(`t_a`, `e_r`, `m_r`) while the body used uppercase. The figure and its caption now use `m_0`,
`t_0`, `t_A`, `t_R`, `e_A`, `e_R`, `m_A`, `m_R`, matching the body. The response hold is drawn as
`e_R − t_R`, not as a symbol.

**Historical field names preserved, with the mapping.** Nothing in `implementation/`, in the
archived captures, or in any frozen CSV header was renamed. `defense4/timing/NOTATION_MAPPING.md`
was rewritten as the bridge; its §0 records what changed, §2 gives the endpoint definitions, and
§3 gives the field-by-field mapping. The load-bearing entries:

| code / evidence field | paper meaning |
|---|---|
| `D_A_ms` = 20.0 | `D_A`, the ACK hold. Same in both conventions. |
| `D_R_ms` = 4.0 (`policy_config.json`, `sweep/sweep_points.csv`) | **the configured `CLRT_new`** — not `D_R`, not the response hold |
| `scheduled_release_interval_ms` = 4.0 | the same quantity under a second name |
| `release_budget_D_ms` = 24.0 | `D = D_A + CLRT_new` |
| `da_dr` (P4:2369) | `D_A + CLRT_new` in 256 ns ticks |
| `reg_deadline` / `reg_tresp` | `t_A + D_A` / `t_A + D_A + CLRT_new` |
| `clrt_ms` (`derived/transactions.csv`) | measured `m_R − m_A`: `CLRT_original` in the Timing OFF arm, `CLRT_new` in the Obfuscated arm |
| `rt_ms` / `resp_ms` | measured `m_R − m_0`, the request-to-response latency. **Not** `D_R` |

Figure-data rows generated before today carried `CLRT_target` and `D_R_response_hold`; they were
regenerated as `CLRT_new_configured` and `response_hold_eR_minus_tR`, not edited in place.

**Protected text.** `sections/01_introduction.tex` paragraphs 1–3 are Dr. Lin's and were not
touched. `check_lin_intro_verbatim.py` PASSES (123 / 101 / 165 words, word for word). Two edits
were made in the contributions list, which is mine, replacing "the target interval" and "reaches
its target".

---

## 2. Blocker-queue drain time: status and the exact remaining dependency

**Not measured for the evaluated build.** No drain-time result is reported, and none is
fabricated. Full account: `defense4/timing/audit_current/RELEASE_MEASUREMENT_STATUS.md`, rewritten
today.

**Endpoints, verified against the implemented logic** (read 2026-09-09 in
`implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`). The queue labels are the
implementation's own:

* **ACK lane** — `Q_ACK_BLOCK`, qid7, token slot `SLOT_ACK`, tests `reg_deadline`; the held
  acknowledgment waits in qid6.
* **RESPONSE lane** — `Q_RESP_BLOCK`, qid5, token slot `SLOT_RESP`, tests `reg_tresp`; the held
  response waits in qid4.

Both reservoirs hold K = 64 tokens, are seeded from one 2K generator batch (`packet_id` 0–63 ACK,
64–127 RESPONSE, line 851), and share the dp8 loopback under the strict-priority ladder
qid7 > qid6 > qid5 > qid4 (lines 372–384). Expiry is a timestamp-deadline test, not a token
count: `tbl_deadline_expiry` matches `now_word − deadline_word` on the single ternary entry
`32w0x00000000 &&& 32w0x800000FF` (sign bit clear, marker byte cancelled), and `tbl_tresp_expiry`
is symmetric on `reg_tresp`. A token that is not yet due takes `dec_loop(OUT_AB_LOOP)` /
`dec_loop(OUT_RB_LOOP)` and is re-enqueued; a due token takes `dec_o(OUT_AB_DL)` /
`dec_o(OUT_RB_DL)` and is dropped.

Therefore, per lane: **start** = the first pass on which that lane's expiry test fires; **end** =
the last token of that lane's reservoir taking its `_DL` disposition, after which the held packet
below it is served.

**Why the loaded program cannot supply it.** All ten `ts_*_w` timestamp actions
(`ts_ack_arm_w`, `ts_ack_release_w`, `ts_resp_release_w`, `ts_first_block_w`, `ts_last_block_w`,
`ts_block_term_w`, `ts_clone_w`, `ts_read_w`, `ts_resp_bypass_w`, `ts_last_term_w`) appear exactly
once each as a `RegisterAction` declaration and have no execute site; four sit behind the
undefined `D3_SYNTH_EVENTS`. Every declared write takes an ingress timestamp. A control-plane
readback would return initial values. This was checked in the instrumentation audit before any
claim was made; `ts_block_term_w` and `ts_last_term_w` are precisely the two that would give the
end event.

**Existing measurement found and used.** One measurement in the project's history has these
endpoints instrumented on silicon. It belongs to the **predecessor** program, not the campaign
build, and is reported here rather than in the manuscript.

* **Program identity.** `ibspg_hold_response` (IBSPG Part 12), P4 source SHA-256
  `fa073cf691a6beb45fa8ffa61146cf481fc81e42f6cf4640bcb44ae6fe08f947`, BF-SDE 9.13.2, Tofino-1,
  switch `10.10.54.81`, run 2026-07-25. Sources preserved in git history at commit `9adb92e`
  (`research/ibspg_hold_response/IBSPG_HOLD_RESPONSE_RESULT.md` §17 and
  `evidence/part12/rep_campaign_100/campaignA_summary.json`); these paths are not in the pruned
  tree.
* **Blocker population and traffic.** One reservoir, K = 64, Q_BLOCK qid7 (`max_priority` HIGH)
  starving one held response in Q_RESP qid1 (LOW). Synthetic protocol roles, no DNP3 parsing, no
  SEL-751, injector spacing 0.5–2 ms, dp8 `BF_LPBK_MAC_NEAR` at 25G. The acknowledgment was
  forwarded immediately, so this program has one blocker queue, not two.
* **Clock, units, resolution, synchronization, association.** Computed on chip from
  `ig_intr_md.ingress_mac_tstamp` register pairs, nanoseconds, wrapping 32-bit arithmetic; one
  clock, so no cross-device synchronization. Association is by per-repetition register read: one
  held response per repetition, read back and reset between repetitions, 100 unique
  non-duplicated repetition ids. A host PCAP alongside is millisecond-scale corroboration only
  (kernel jitter ≈ 10 µs) and was never used to support the nanosecond figures. Nanosecond
  resolution is not a nanosecond accuracy claim.
* **Results, n = 100, deadline G = 20 ms:**

  | component | endpoints | min | median | mean | sd | max |
  |---|---|---:|---:|---:|---:|---:|
  | c1 | deadline reached → **first** blocker observes expiry | 0 ns | 15 ns | 14.4 ns | 7.16 ns | 26 ns |
  | c2 | first blocker termination → response released | 1,717 ns | 1,720 ns | 1,720.13 ns | 1.14 ns | 1,723 ns |
  | total | deadline reached → response released | 1,720 ns | 1,735 ns | 1,734.53 ns | 7.34 ns | 1,747 ns |

  Across deadlines of {1, 2, 5, 10, 17, 25, 40} ms the total stayed within 1,721–1,744 ns with
  nothing tuned per point.

* **What it does not answer.** c1 is deadline-to-**first**-termination, not deadline-to-empty. The
  remaining tokens drain inside c2 together with the dequeue and the egress path, and c2's
  internal composition is recorded in the source document as `[OPEN]`: no per-token termination
  timestamp, no queue-depth trace. c2 is also ≈4.2× the independently measured ≈408 ns
  single-token dp8 traversal, so it is not one loop. The honest bound is
  `14.4 ns ≤ drain ≤ 1,734.5 ns` on the means, and this evidence cannot place it inside that
  interval. It is single-queue, so it gives no separate ACK-lane and RESPONSE-lane figures.

**Effect on the release schedule, as stated in the paper.** Section V now says that the queue does
not empty at the deadline: each blocker tests the deadline on its own pass, the blockers still
queued when it passes must be served once more before the queue runs dry, and the release
therefore trails the deadline by the time draining takes. Each lane drains its own queue, the
acknowledgment's above the response's in the priority order. Section VI-G says both intervals are
unmeasured on the loaded program.

**Exact remaining dependency.** A new P4 build. The smallest change (option B1 in the status note)
is two execute sites and two 32-bit registers: give `ts_last_term_w` a real execute site on the
`_DL` disposition of each lane, writing `ingress_mac_tstamp`, and difference it against the
already-stored `reg_deadline` / `reg_tresp`. The per-transaction register reset is the part that
needs design work, because the campaign build does not reset per transaction. Both timestamps are
ingress-side, which is correct here — the drain endpoint is a pipeline event, not a wire
departure — so this change does not inherit the ingress/egress objection above. Option B2, an
external two-tap synchronized capture, preserves the binary but observes the wire departure, so
it bounds the drain from above rather than isolating it. **Neither was executed: no new build was
compiled, no binary was loaded, no hardware was contacted.** Any evidence from a new build must be
kept separate from `campaign_v1`, which carries a different binary hash.

**What the CLRT residual is not.** Because both deadlines are armed from the same instant `t_A`,
the measured CLRT carries the *net, signed* difference of the two release delays plus differential
path and capture effects. A histogram of that residual is not a measurement of queue draining, and
the paper does not present it as one.

---

## 3. Histograms following Formby

**Formby's figure, located and inspected.** Formby et al., *Who's in Control of Your Control
System? Device Fingerprinting for Cyber-Physical Systems*, NDSS 2016. The fingerprint is defined
in **Equation 1**: a vector of counts from an equal-width linear-bin histogram of CLRTs over
`[0, H]`, `H` a heuristic threshold, with the final bin catching everything above. The
distribution figure is **Figure 6(b)**, "Estimated PDFs of CLRTs for five sample devices over one
day": five devices overlaid, abscissa "CLRT Measurement [seconds]" from 0 to about 0.28 s,
ordinate "Normalized Frequency of Occurrence", linear axes, no smoothing. Figures 27 and 28 repeat
the construction for software-configuration variants over 0.001–0.009 s. Source inspected:
`~/Zotero/storage/8UIIEM8M/formby2016control_NDSS.pdf`, pages 6 and 15. Recorded in the figure's
method note.

**Bin width, chosen and justified.** The visible spacing in Figure 6(b) is about 5 ms; that is
read off the rendered figure and is **not** a width Formby states, and the method note says so.
Five milliseconds would merge this relay's three Timing OFF modes near 1.2, 2.1 and 4.0 ms into
one bar. The full-range panels therefore use **1 ms** bins — the coarsest width in the 1–2 ms
range the meeting suggested that still separates the three modes. Freedman-Diaconis on the Timing
OFF sample gives 0.1866 ms and is reported rather than followed, since it assumes a roughly
unimodal density.

**The figure.** `paper/rewrite/figures/clrt/fig_clrt_distributions`, one column, four stacked
panels, generated by
`defense4/timing/audit_current/tools/clrt_distribution_and_variance.py`:

* **(a) `CLRT_original` (Timing OFF)** and **(b) `CLRT_new` (Obfuscated)** — full measured range,
  common 1 ms edges from 0 to 84 ms, identical x and y limits, subscripts rendered in the panel
  titles. Tails are plotted, not trimmed: the Timing OFF arm runs to 83.46 ms and the Obfuscated
  arm to 57.2 ms.
* **(c) and (d)** — the same two conditions on **0.005 ms** bins within 0.10 ms of the configured
  `CLRT_new`, labelled "zoom, 0.005 ms bins", sharing one pair of limits with each other.
* Ordinates are logarithmic in all four panels and labelled **"Transactions (%)"**; abscissae are
  labelled **"CLRT (ms)"**. Normalization is stated: each bar is a percentage of *that arm's own*
  transactions, weight 100/n, and in the zoom panels the denominator is still the arm's full
  sample, so the "13.5 % of all transactions" and "99.9 % of all transactions" annotations are
  shares of everything measured in that condition, not of the window.
* Each full-range panel is annotated with **n, mean (ms), sample sd (ms), and sample variance
  (ms², n−1 denominator)**: Timing OFF n 26,400, mean 2.800, sd 2.609, variance 6.808;
  Obfuscated n 26,400, mean 4.012, sd 0.628, variance 0.3943.
* The dashed line is the configured `CLRT_new`, the dotted line the measured mean; the legend
  names both.
* Log-spaced bins, the previous construction, were replaced by linear bins. No smoothing, no
  kernel, no boxplot, and no per-run variance substitute. The zoom width is a deliberate choice
  and is justified in the method note: Freedman-Diaconis on the Obfuscated sample gives 0.0004 ms,
  which puts four hundred bins across the window and renders as a comb one transaction high.

**Separation of classes, settings and datasets.** READ only, from the frozen canonical table
`campaign_v1/derived/transactions.csv`, at the single configured setting in
`repro/policy_config.json`. SELECT and OPERATE are excluded by design and counted in the row
accounting. The 19-capture policy sweep and the retired single-session dataset are not part of
this figure. No exclusions: every READ transaction in the canonical table is plotted.

**Caption.** Rewritten to five lines in the manuscript
(`sections/06_evaluation.tex`, `fig:hist`); the long-form detail lives in the figure's
`.method.md` sidecar.

**Artifacts.** Vector PDF, 300-dpi PNG, `_data.csv`, `.caption.md`, `.method.md`,
`.limitations.md` and `.provenance.json`, all listed in `figures/clrt/FIGURES.sha256`.
`clrt_distribution_and_variance.py --check` reports 0 problems. Rendered and inspected at
manuscript size on page 8 of the built PDF.

---

## 4. `D_R` is the response latency

**Definition by endpoints.** `04_design.tex` eq. (7):

    D_R = m_R − t_R

the **response latency**: from the response's arrival at the switch from the outstation to its
arrival at the master host NIC. The outstation's own emission lies one hop before `t_R` and was
not captured, so `D_R` omits that hop, and the paper says so.

**Three contributions, stated in the paper.** The path latency the response would have incurred
with the mechanism disabled; the time the switch holds it, `e_R − t_R`; and the interval between
the release deadline and the release itself, because the switch stops blocking a queued packet
only once the queue gating it has drained. Section VI-G reports that third term as unmeasured.

**What `D_R` is not.** It is not the configured acknowledgment-to-response gap — that is the
configured `CLRT_new` — and it is not the in-switch response hold. The hold was freed from `D_R`
by writing it from its endpoints, `e_R − t_R`, rather than by inventing a new symbol; eq. (2) now
defines only `D_A`, and eq. (5) reads `e_R − t_R = D_A + CLRT_new − CLRT_original`. Every equation
and the timeline figure were corrected from their event endpoints, not by search-and-replace: eq.
(2), (3), (4), (5), (6), (7) and (8) and Figure 3 were each rewritten against the instants they
relate.

**Measured latency versus the requirement that limits it.** The paper distinguishes the two
explicitly. `D_R` is the measured quantity; the operator's requirement is a bound on it. What the
evaluation reports as the observed cost is the master's **request-to-response latency**
(`m_R − m_0`, the CSV field `rt_ms`), 25.30–25.34 ms across the policy sweep and about 22.66 ms
more for a READ than the device alone; that quantity starts at `m_0`, not at `t_R`, and the figure
axes were relabelled from "response time" to "request-to-response" so the two are not conflated.

**The latency requirement: searched for, not verified.** The search and its sources are recorded
in `defense4/timing/audit_current/RESPONSE_LATENCY_BUDGET.md`, which now carries a notation banner
saying that its `D_R` is the code field, not the paper's. No numeric communications requirement for
a DNP3 poll or a select-before-operate control on a distribution relay could be verified from
primary documentation. The only numeric deadline verified on the evaluated device is the relay's
own **select-to-operate timeout, documented default 1.0 s**: SEL-751A Instruction Manual,
PM751A-01-NB, 20130329 printing, settings table, PDF page 465, setting `STIMEO1` "Select/operate
time-out, seconds". It governs the interval from the relay accepting a SELECT to that selection
lapsing, not the interval from a request to its response. The manual is now cited in the
manuscript at that sentence, and the paper says what the timeout does and does not bound. Timing classes defined for other protocols govern those protocols' own messages and are
not transferred. The meeting's ~100 ms budget and 10 ms margin were examples and appear nowhere in
the manuscript. The configured `CLRT_new` is therefore presented as a deployment choice, with the
tested value (4 ms) and the added latency stated so an operator can check their own requirement
against them.

**`D_A` stays distinct.** The transport bounds `D_A` because the master's retransmission timer runs
on the acknowledgment (RFC 6298, 1 s floor, adaptive); the operation bounds `D_R` because the
answer is what the operation waits for. The paper states the two constraints in one sentence to
keep them apart, and separately notes that neither is the binding limit in practice — the
mechanism's own fail-open horizon `H` = 30.8 ms is.

**Code and evidence names preserved.** `D_R_ms`, `da_dr` and `reg_tresp` keep their names; the
mapping is §3 of `NOTATION_MAPPING.md` and is repeated in the comments at the two sites that read
`D_R_ms` (`make_model_figures.py:figure_release`, `make_ndss_figures.py` panel (b)).

---

## 5. Files changed

**Manuscript** (`paper/rewrite/`)

| file | change |
|---|---|
| `sections/04_design.tex` | model rewritten: `D_A` alone in eq. (2), response hold written as `e_R − t_R`, `CLRT_new` throughout with the configured/measured distinction, new eq. (7) defining `D_R`, the operational constraint restated through `D_R`, transport paragraphs compressed |
| `sections/05_implementation.tex` | new paragraph on post-deadline draining and its effect on the release schedule |
| `sections/06_evaluation.tex` | `CLRT_new` / `CLRT_original` notation, histogram caption rewritten, "The Residual Is Not Attributed" extended to name the drain explicitly |
| `sections/08_conclusion.tex` | "the target" → "the configured value" |
| `sections/01_introduction.tex` | two edits inside the contributions list only; Dr. Lin's paragraphs untouched |
| `figures/clrt/*`, `figures/model/*`, `figures/ndss/*` | regenerated artefacts and sidecars |
| `main.pdf` | rebuilt |

**Evidence and tools** (`defense4/timing/`)

| file | change |
|---|---|
| `NOTATION_MAPPING.md` | rewritten for the new convention, with the change log and the field mapping |
| `audit_current/RELEASE_MEASUREMENT_STATUS.md` | rewritten: verified endpoints, the Part-12 measurement with full metadata, why the loaded program cannot supply it, and the smallest change that would |
| `audit_current/tools/clrt_distribution_and_variance.py` | linear 1 ms bins, 0.005 ms zoom bins, panel titles in the new notation, n added to the annotation, caption shortened, method note records Formby's Figure 6(b) and Equation 1 |
| `audit_current/tools/make_model_figures.py` | uppercase instants, `CLRT_new` bars, response hold drawn as `e_R − t_R`, caption and data-row names updated |
| `evidence/campaign_v1/repro/make_ndss_figures.py` | axis labels and captions in the new notation, "response time" → "request-to-response" |

Nothing under `implementation/` or any `raw_pcaps/` directory was modified.

## 6. Validation

| check | result |
|---|---|
| `paper/rewrite/pipeline/build.sh` | compile rc=0, gate rc=0, **BUILD RESULT: PASS** |
| `pipeline/lin_check.py` (via build.sh) | PASS, no hard-check failures; warnings `sentence_health` (14 pre-existing bold run-in headers) and `acronyms` (DRAFT/ISBN/RFC/RI in boilerplate) |
| `pipeline/check_lin_intro_verbatim.py` | **PASS**, 3 paragraphs word for word (123 / 101 / 165 words) |
| `campaign_v1/repro/reproduce.sh` (clean re-run) | **131 passed**, publication gate **0 problems**, regenerated outputs match every published artefact |
| `clrt_distribution_and_variance.py --check` | 0 problems |
| `make_model_figures.py --check` | 0 problems |
| rendered inspection | pages 4, 5 and 8 of `main.pdf` read at manuscript size: equations (1)–(8), Figure 3's timeline, and the four histogram panels all render with subscripts intact and no clipped labels |
| notation sweep | no `CLRT_target`, no `C_{\rm target}`, no `D_R` used for the hold or the configured gap, in any `.tex` or figure generator |
| page budget | Introduction through Conclusion ends on page 14, unchanged from before these corrections; Ethics and Open Science run to page 15 and References to 16 |

## 7. Unresolved

1. **The drain interval is unmeasured for the evaluated build.** Requirement 2's remaining
   dependency is a new P4 build (§2). Not executed under this handoff.
2. **No response-latency standard could be verified.** The manuscript treats the configured value
   as a deployment choice. If a verifiable requirement is found, §4 of the Design section is the
   place it belongs.
3. **The body is 14 pages** against NDSS's customary 13. Unchanged by these corrections, but still
   open.
4. **Earlier miner findings**: Figures 2 and 4 were fixed after the first commit on this branch
   and are written up in §8. Three near-identical CDF panels in `fig_distributions` remain.
5. **Citation density** is 4.8 per 1000 words against the corpus floor of 9.7. Reported, not
   padded.


---

## 8. Follow-up: Figures 2 and 4

**Figure 2, the clipped label.** "relay-facing" was centred at x = 190 in a 36-unit gap for a
37-unit label, and the outstation box, drawn after it, painted over the final "g". The gap was
widened rather than the label shrunk: the switch box narrowed from 68 to 62 units and moved to
x = 99, which leaves 47 units for "master-facing" and 45 for "relay-facing". Both labels now
clear their neighbouring boxes by about 2 units. Source: `figures/fig_observation.svg`.

**Figure 4, the colour key.** The key read "red: master-facing (observed), green: relay side,
orange: blockers", but green also named the read lane and orange also named the control lane, so
two of the three hues meant two things each, and none of the three survived greyscale. Hue no
longer names a lane: both lane boxes are neutral grey with black headings, and the lanes are
identified by their own headings and their position. Orange is used only for the blocker
machinery, which is labelled in place. The relay-facing arrow changed from dashed green to dashed
grey, matching Figure 2, and the key reduces to the same two entries Figure 2 uses, "observed by
the adversary" (solid) and "not observed (no tap)" (dashed), each redundant in greyscale. Checked
by converting the 600-dpi export to greyscale and reading it. The figure also still carried
`C_target`; it now reads `CLRT_new`, and the four in-box lines were shortened so none touches a
box edge. Source: `figures/fig_design.svg`; the caption in `sections/05_implementation.tex` was
rewritten to describe the key that now exists.

Both were re-exported with `pipeline/export_schematics.sh`; `SCHEMATICS.sha256` verifies and the
mirror under `defense4/timing/figures/schematics/` is byte-identical. `fig_ladder.pdf` also
changed because Inkscape's PDF output is not byte-reproducible; its SVG and PNG are unchanged.
Build PASS, 16 pages, body still ending on page 14.
