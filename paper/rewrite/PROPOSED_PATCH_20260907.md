# Proposed manuscript patch, 2026-09-07 — NOT APPLIED

Twelve changes, each with the exact text to replace and the evidence behind it. **None has been
applied.** No `.tex` file, no figure and no `main.pdf` was touched. Applying this needs
authorization, and after it the build gate must be re-run and `lin_check --compare` must show no
regression.

**A note on matching.** Every quoted "becomes" block is the source text with its line wrapping
normalised to fit this document. Match on the words, not on the line breaks: the `.tex` sources
wrap at column 100 and several quotations here span a break differently. All twelve targets were
verified present, whitespace-insensitively, before this proposal was written.

**Revised 2026-09-07 (second pass).** P5 and P7 are rewritten and three items are added. The
revisions follow from three findings: the loaded binary's timestamp instrumentation is inert, so
no switch-side release measurement exists or can be obtained without a new program
(`INSTRUMENTATION_AUDIT.md`); Formby's physical-operation-time result rests on an
application-layer SER timestamp, not on packet arrivals (`FORMBY_REVIEW.md`); and the
constant-shift comparison now has its own figures (`figures/shift/`).

Two of the nine are corrections of statements that are **not supported** by the evidence (P1,
P2). One is new material answering the question raised in the meeting that the manuscript does
not currently address (P4). The rest sharpen wording or add a bound.

The gate was run on the manuscript as it stands, on a flattened copy, and passes:
`RESULT: PASS (no hard-check failures)`, warnings `sentence_health, acronyms, readability`,
all pre-existing. So the current draft is not broken; these are improvements and two fixes.

---

## P1. The sweep had 16 release policies, not 18 — Evaluation, twice

**Why.** The loaded binary arms a transaction only for the dual-deadline mode. Its decision
table gives `OUT_ARM_FRESH` for `MODE_D4_DUAL` alone (line 2846); `MODE_OFF` and every other
mode fall through to `OUT_ARM_BUSY` (lines 2847, 2849). The two sweep points configured in the
response-only and acknowledgment-only modes therefore measured native timing: 2.108 ms and
2.098 ms released interval with sub-millisecond acknowledgment latency, where 24 ms and 20 ms
holds were configured. Full derivation in `defense4/timing/TIMING_ONLY_RERUN_PLAN.md` §2.

Claim C2 and Figure `fig_policy_coverage_cost` are unaffected: all eight points the text quotes
at fixed `D` = 24 ms are dual-deadline points.

**P1a — `sections/06_evaluation.tex`, Dataset paragraph.**

> To characterize the release policy itself, we collected a separate sweep of 18 configured
> release policies and one control capture on the same testbed, 5{,}860 further exchanges.

becomes

> To characterize the release policy itself, we collected a separate sweep on the same testbed,
> 5{,}860 further exchanges over 19 captures: 16 configured release policies of the
> dual-deadline mode the loaded program realizes, and three captures that measured the
> outstation's native timing.

**P1b — `sections/06_evaluation.tex`, RO4 paragraph.**

> To measure that range on the switch itself, we installed 18 release policies in turn and ran a
> fixed DNP3 workload through each.

becomes

> To measure that range on the switch itself, we installed 16 release policies in turn and ran a
> fixed DNP3 workload through each.

## P2. The loaded program does not realize the other two policies — Implementation

**Why.** Same evidence as P1. The current sentence tells the reader that the response-only and
acknowledgment-only policies appear in the policy evaluation as limits of the dual-deadline
policy. They do not: the two points configured that way produced native timing, because the
build never arms in those modes. As written, the claim is unsupported.

**`sections/05_implementation.tex`, end of the Timing State paragraph.**

> The loaded program realizes the dual-deadline policy; the response-only and
> acknowledgment-only policies of Section~\ref{sec:design} are its limits and appear as such in
> Section~\ref{sec:eval:policy}.

becomes

> The loaded program realizes the dual-deadline policy only. Its arming table admits a
> transaction in that mode alone, so the response-only and acknowledgment-only policies of
> Section~\ref{sec:design} are limits of the design rather than settings of this build: when we
> configured them, the program forwarded both packets unheld and the measured interval was the
> outstation's own. Reaching them would need a different program, which we did not build.

## P3. Say once what the reported interval is measured between — Evaluation

**Why.** The section says every timestamp is taken on the master-facing link, which is right,
but the interval itself is never given its endpoints. Three nearby quantities differ: the
outstation's own interval between its acknowledgment and its response, the switch's two egress
instants, and the two arrival instants at the master. Only the third was measured. Naming all
three "the cross-layer response time" is what made the shift-versus-replacement question hard to
settle. Symbols and observability in `defense4/timing/TIMING_MODEL.md` §2.

**`sections/06_evaluation.tex`, Evaluation Cases paragraph, after the existing final sentence.**

Add:

> Concretely, the interval we report is the time between the arrival of the transport
> acknowledgment and the arrival of the application response, both observed on the master's own
> interface. The switch's internal instants, when the outstation's packets reach it and when it
> releases them, are on links that were not captured, so they are recovered from the program
> rather than measured.

## P4. New: the acknowledgment hold against the timers actually in play — Evaluation, RO5

**Why.** Holding an acknowledgment for 20 ms consumes the master's retransmission and timeout
budget, and the manuscript does not say by how much. It is the question the meeting raised. It
is now measured, and the answer is a wide margin, so the paragraph strengthens the paper rather
than qualifying it. Evidence:
`defense4/timing/TIMEOUT_AND_RETRANSMISSION_AUDIT.md`, and
`defense4/timing/audit_current/outputs/timeout_and_tcp_audit.json`.

**`sections/06_evaluation.tex`, new paragraph in RO5 after the frames-and-bytes sentence.**

> \textbf{Timeout and Retransmission Headroom.} Holding the acknowledgment consumes the master's
> timers, so we measured what it consumed. Across all 132 captures we recovered every
> transport-level event: the request bytes were acknowledged in a separate segment in every one
> of the 63{,}360 exchanges, never piggybacked on the response, and no request was ever sent
> while earlier bytes were still unacknowledged. The longest the master waited for its request to
> be acknowledged was 29.2~ms and the longest it waited for the response was 77.7~ms, against a
> retransmission timeout that no mainstream kernel sets below 200~ms and an application receive
> budget of 3{,}000~ms in our master. Consistently with that, there was no retransmission, no
> reset and no duplicate acknowledgment in either arm, and no application timeout: all 63{,}360
> exchanges completed, and all 5{,}280 SELECT and OPERATE exchanges returned a success status.
> Select validity is the other timer a held control transaction could violate, since the master
> issues its OPERATE only 0.19~ms after the SELECT response reaches it and the mechanism delays
> that response: none of the 2{,}640 obfuscated OPERATE exchanges was refused for a stale select.
> The margins are wide at this operating point rather than universally safe, and they would have
> to be rechecked for a master whose timeout is tens of milliseconds.

## P5. Say what makes it replacement rather than a shift — Evaluation, RO1

**Why.** The paper asserts the interval is "replaced". The basis is two things it does not
state: both release instants are armed from one anchor, so the outstation's own interval drops
out of their difference algebraically; and the empirical discriminator is that the spread
collapses against a constant-shift reference which retains the native spread exactly. That
reference must be labelled analytical, because no reachable mode of the loaded program
implements a shift, so a hardware shift arm could not have been run. Evidence:
`defense4/timing/audit_current/SHIFT_VS_REPLACEMENT.md` and
`defense4/timing/figures/shift/README.md`.

**`sections/06_evaluation.tex`, RO1, after the interquartile-range result.**

> Both release instants are armed from the same anchor, the outstation's acknowledgment, so their
> difference is the configured offset and the outstation's own interval is absent from it
> algebraically rather than merely reduced. A policy that instead delayed each packet by a fixed
> amount would translate the native distribution and leave its variance unchanged, since
> translation does not alter a sample's spread. That is not what we measure. Against an
> analytical constant-shift reference $X_{\rm shift}=X_{\rm native}+[C-\mathrm{median}(X_{\rm
> native})]$, built from the same Timing OFF samples so that it lands on the configured
> interval while retaining the native standard deviation of 2.609~ms for READ and 2.267~ms for
> SELECT, the measured obfuscated standard deviations are 0.628~ms and 0.024~ms. The
> sample-variance ratio $\rho=s^2_{\rm def}/s^2_{\rm nat}$ is 0.058 for READ, with a 95 per
> cent cluster-bootstrap interval over the 22 grouped runs of [0.018, 0.103], and 0.000114 for
> SELECT, interval [1.4$\times10^{-5}$, 3.4$\times10^{-4}$]; a constant translation predicts
> $\rho=1$. The reference is analytical and is computed from the Timing OFF samples: the loaded
> program has no shifting mode, so it is not a measured arm and we do not present it as one.

**Note for the authors.** This wording deliberately does not say the two distributions are
independent, and P6 adds the bound that says why.

## P6. Two bounds to add — Evaluation, Limitations

**Why.** Both are things this evidence cannot exclude, and neither is currently stated.

**`sections/06_evaluation.tex`, What Was Not Observed, appended.**

> The switch's own release instants were likewise not captured, although the program latches
> them in registers that the control plane could read. And because the program suppresses a
> retransmission of the response that matches an already-seen transport position, a
> retransmission by the outstation of a held response would be absorbed inside the switch and
> would not appear in a master-facing capture, so we cannot exclude one.

## P7. Formby: correct the "correlate" claim, and separate three claims — Related Work

**Why.** The abstract-only reading of the first pass has been replaced by a full reading of
Sections IV-A and IV-B, the Figure 14 timing definitions and the page-9 experimental discussion
(`defense4/timing/audit_current/FORMBY_REVIEW.md`). Two findings change what may be said.

Their physical-operation-time fingerprint is computed from a **sequence-of-events-recorder
timestamp inside the application payload**, `m = t2 - t1`. The alternative definition based on
packet arrivals, `m = t3 - t1`, is reported in their own words: *"The unsolicited response
method did not produce any usable results, so the SER method results are described below and
retained as the physical fingerprint."*

So the manuscript's present claim, that on the control path we address "the master-visible
correlate of the physical operation-time feature Formby et al. measured", is **not defensible**.
No correlation was measured; the two quantities are computed from different information, one
from a payload timestamp and the other from packet arrivals; and the arrival-based variant is
the one they report as unusable. Our own traffic settles it further: across all 132 captures
there are zero unsolicited responses and no time-bearing DNP3 object of any kind, so no
physical-event timestamp is present for the mechanism to have affected.

**P7a — `sections/07_related_work.tex`, the "DNP3 timing and security" paragraph.**

> On the control path we address the master-visible correlate of the physical operation-time
> feature Formby et al.\ measured on a physical outstation~\cite{formbyWhosControlYour2016},
> i.e., the OPERATE response-to-ACK interval; unlike their measurement of the device, we report
> only what the master sees and do not observe the relay-facing side or the physical operation
> itself.

becomes

> On the control path we report a different quantity from theirs: the master-visible OPERATE
> response-to-acknowledgment interval, which is a protocol-response timing feature. Formby et
> al.\ estimate physical operation time from a sequence-of-events-recorder timestamp carried in
> the outstation's application payload, and report that the alternative estimate from
> unsolicited-response arrival times produced no usable
> results~\cite{formbyWhosControlYour2016}. A mechanism that moves packets in time and changes
> no byte cannot alter such a payload timestamp, and the traffic we evaluate carries neither
> unsolicited responses nor any time-bearing object. We therefore make no claim about physical
> operation time, and we do not present our control-path result as a correlate of theirs.

**P7b — the first paragraph, unchanged from the first pass.**

> These works define the threat we address; our objective, on the other hand, is to remove the
> timing features they rely on from the master-facing observation.

becomes

> These works define the threat we address; our objective, on the other hand, is to remove the
> timing features they rely on from the master-facing observation. Their target is the device
> type, whereas the classifier we evaluate separates transaction classes on one outstation, so
> we suppress a feature their cross-layer response-time method uses without demonstrating that
> two devices become indistinguishable.

## P8. Figures 1 and 3: the label text still says "echo"

**Why.** The prose was corrected on 2026-09-02; the label text inside the two hand-drawn SVGs
was not. DNP3 has no message called an echo: the first function-129 paired with an OPERATE is a
solicited application response.

**`figures/fig_ladder.svg`** — three strings: `SELECT response (echo)` and
`OPERATE response (echo)` lose the parenthetical; the legend line
`O: master-visible OPERATE ACK-to-echo interval.` becomes
`O: master-visible OPERATE response-to-ACK interval.` The `<desc>` element carries the same
phrase and changes with it.

**`figures/fig_design.svg`** — `ACK at T0 + A, echo at T0 + R` becomes
`ACK at T0 + A, response at T0 + R`; its `<desc>` likewise.

**Then, and this is why it is held rather than applied:** re-export both to PDF and 600 dpi PNG
with `pipeline/export_schematics.sh`, which needs Inkscape 1.x; regenerate
`figures/SCHEMATICS.sha256`; update the hashes in `FIGURE_PROVENANCE.md`; mirror both into
`defense4/timing/figures/schematics/`; recompile `main.pdf` and update `main.pdf.sha256`. That
is a change to the manuscript's figures and to the compiled PDF, so it belongs in an authorized
pass, not in an audit.

## P9. One clause each in the abstract and the conclusion, only if P4 is taken

**Why.** Both summarise the cost. If P4 is added, both should say the cost stayed inside the
timers, otherwise the reader has to reach RO5 to find out. If P4 is not taken, skip P9.

**`sections/00_abstract.tex`.**

> and costs about 21 to 23~ms of added response time per exchange.

becomes

> and costs about 21 to 23~ms of added response time per exchange, which stayed well inside the
> transport and application timers of our master, with no retransmission or timeout in 63{,}360
> exchanges.

**`sections/08_conclusion.tex`.** After "the cost of the exchange stayed fixed", add:

> and the added latency stayed inside the timers the exchange is subject to.

## P10. The policy figure's method note calls all 19 points release policies — published sidecar

**Why.** `paper/rewrite/figures/ndss/fig_policy_coverage_cost.method.md` says "Panels (b) and (c)
are the measured 19-point hardware sweep: each point is one capture under one installed release
policy". Three of the 19 are native controls, and the panels do not plot them: the figure script
filters on `mode == "D4" and not is_control_point`, so panel (b) has 8 points and panel (c) has
9. The note therefore misdescribes both the sweep and the figure's own contents.

**`figures/ndss/fig_policy_coverage_cost.method.md`.**

> Panels (b) and (c) are the measured 19-point hardware sweep: each point is one capture under
> one installed release policy, summarised by the median over its READ transactions, with the
> full measured range shown in (b).

becomes

> Panels (b) and (c) plot the 16 release policies of the 19-capture hardware sweep, 8 of them in
> (b) and 9 in (c); each is one capture under one installed dual-deadline policy, summarised by
> the median over its READ transactions, with the full measured range shown in (b). The sweep's
> other three captures are native controls that establish the unprotected baseline and are not
> plotted.

**Why it is held.** The sidecar is a published artefact whose hash the publication gate compares
against a rebuild. Editing it by hand desynchronises `FIGURES.sha256`; the correct route is to
amend the caption text in `repro/make_ndss_figures.py`, re-run `repro/reproduce.sh`, and let the
gate re-derive both. That is a regeneration of a published figure set and belongs in an
authorized pass.

## P11. New: the constant-shift comparison as figures — Evaluation, RO1

**Why.** P5 states the comparison in prose. Four figures now support it directly, in
`defense4/timing/figures/shift/`, with the two corpora kept separate and every artefact
generated under the same contract as the NDSS figures. Adding one of them would let a reader see
that the defended distribution is not a translated native distribution, rather than take it from
a sentence.

**Recommended.** Add `fig_s1_shift_vs_normalization_campaign_v1` as a figure in RO1, with the
caption already generated at `figures/shift/fig_s1_shift_vs_normalization_campaign_v1.caption.md`,
and cite the variance ratios from P5's text. `fig_s2_variance_and_target_campaign_v1` is the
natural companion if space allows; otherwise its numbers are already in P5 and in the new
paragraph below.

**`sections/06_evaluation.tex`, RO1, following P5's paragraph.**

> Figure~\ref{fig:shift} shows why the distinction matters. The analytical constant-shift
> reference retains the native shape exactly and merely slides it onto the configured interval,
> whereas the measured obfuscated distribution concentrates there; removing each distribution's
> own mean, which alters neither variance nor shape, leaves that difference intact. The
> concentration is also at the correct value rather than merely tight: over every obfuscated
> observation, late and fail-open ones included, the mean error against the configured interval
> is $+0.012$~ms for READ and $+0.001$~ms for SELECT, and 99.86 and 99.96 per cent of
> observations lie within 0.5~ms of it, half the smallest configured step in the policy sweep.
> The residual tail is the response-availability boundary of Section~\ref{sec:design}: a
> response that arrives after its scheduled release is forwarded on arrival rather than held, so
> the error distribution has an upper tail and no lower one, and the smallest obfuscated
> interval we observe is 3.922~ms, 78~$\mu$s below the target.

**Note for the authors.** Adding a figure changes the page budget and the figure numbering. If
only prose is wanted, the paragraph above stands alone without `Figure~\ref{fig:shift}`.

## P12. Withdraw the "switch-side instrumentation" future-work implication — Design or Limitations

**Why.** Nothing in the manuscript currently promises switch-side measurement, so this is a
guard rather than a correction: the rerun plan briefly did, and the claim was wrong. The loaded
program's ten timestamp registers are never written, four of them are not even compiled, and any
write would take an ingress timestamp, so a "release" instant would record a packet re-entering
from the internal loopback rather than departing at dp9 (`INSTRUMENTATION_AUDIT.md`). Obtaining
a real release instant needs a new P4 and a new binary.

**Recommended.** If any future-work sentence is added about measuring the release instant
directly, it must say that it requires a modified program, not a configuration change. No text
is proposed here because none is currently present; this item exists so the claim is not
introduced later by accident.

---

## What is deliberately not proposed

* **No change to any published number.** All 18 interval statistics and both corpus counts
  re-derived exactly (`defense4/timing/audit_current/HISTORICAL_VS_CORRECTED.md` §1). The
  corrections above are to a count of configured policies and to descriptions, not to results.
* **No new figure is imposed.** Six DRAFT figures exist, two in
  `defense4/timing/figures/model/` and four in `defense4/timing/figures/shift/`. `fig_m01` would
  suit Figure 1, `fig_m02` suits P4, and `fig_s1` suits P11. Each addition changes the page
  budget and the figure numbering, so every one is offered and none is assumed.
* **No claim that the mechanism suppresses a physical-operation-time fingerprint.** P7a removes
  the nearest thing the manuscript had to one.
* **No claim about physical operation time.** Nothing here creates a route to one.
* **Nothing about size**, in any form.

## Order of application, once authorized

1. P1a, P1b, P2 — the two unsupported statements, smallest and highest priority.
2. P7a — the Related Work claim that is not defensible.
3. P3, P5, P6, P7b, P12 — wording and bounds, no new results.
4. P4, then P9 — the new paragraph and its two dependent clauses.
5. P11 — the constant-shift paragraph, and the figure if one is wanted.
6. P8 and P10 — last, because they are the only items that regenerate a figure or a published
   sidecar and recompile the PDF. P10 is done by amending the caption in
   `repro/make_ndss_figures.py` and re-running `repro/reproduce.sh`, never by hand-editing the
   sidecar.
7. Re-run `pipeline/build.sh`; require `BUILD RESULT: PASS` and
   `lin_check --compare before.json` showing no regression. If P8, P10 or P11 was applied, also
   re-run `evidence/campaign_v1/repro/reproduce.sh` and require the publication gate to report
   0 problems.
