# Proposed manuscript patch, 2026-09-07 — NOT APPLIED

Nine changes, each with the exact text to replace and the evidence behind it. **None has been
applied.** No `.tex` file, no figure and no `main.pdf` was touched. Applying this needs
authorization, and after it the build gate must be re-run and `lin_check --compare` must show no
regression.

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
collapses against a constant-shift reference which retains the native spread exactly. The
reference is analytical, and should be labelled so, because no reachable mode of the program
implements a shift (P2), so a hardware shift arm was not available.

**`sections/06_evaluation.tex`, RO1, after the interquartile-range result.**

> Both release instants are armed from the same anchor, the outstation's acknowledgment, so their
> difference is the configured offset and the outstation's own interval is absent from it
> algebraically rather than merely reduced. A policy that instead delayed each packet by a fixed
> amount would translate the native distribution and keep its spread: a native distribution
> shifted onto the obfuscated median retains a standard deviation of 2.609~ms for READ and
> 2.267~ms for SELECT, against 0.628~ms and 0.024~ms measured, a variance ratio of 0.058 and
> 0.0001. That reference is analytical, computed from the Timing OFF samples: the loaded program
> has no shifting mode, so it is not a measured arm.

## P6. Two bounds to add — Evaluation, Limitations

**Why.** Both are things this evidence cannot exclude, and neither is currently stated.

**`sections/06_evaluation.tex`, What Was Not Observed, appended.**

> The switch's own release instants were likewise not captured, although the program latches
> them in registers that the control plane could read. And because the program suppresses a
> retransmission of the response that matches an already-seen transport position, a
> retransmission by the outstation of a held response would be absorbed inside the switch and
> would not appear in a master-facing capture, so we cannot exclude one.

## P7. Formby's methods are device typing — Related Work

**Why.** Verified against the primary source's abstract this session, through Semantic Scholar,
paper `3e5a6e6a2779c4ab1f15ff36611ebaa8d54508e8`, NDSS 2016. It states two methods: one that
"measures data response processing times" and one that "uses the physical operation times to
develop a unique signature for each device type". Both features the manuscript attributes are
therefore correct, and the abstract contains no select-before-operate result, so nothing of that
kind is attributed. Only the full text was not read, and this is the one change here that rests
on an abstract rather than a full reading.

What is worth sharpening is that Formby's target is the **device type**, while ours is the
transaction class. The Limitations section already says our result is not device
identification; Related Work should not leave the reader to discover it there.

**`sections/07_related_work.tex`.**

> These works define the threat we address; our objective, on the other hand, is to remove the
> timing features they rely on from the master-facing observation.

becomes

> These works define the threat we address; our objective, on the other hand, is to remove the
> timing features they rely on from the master-facing observation. Their target is the device
> type, whereas the classifier we evaluate separates transaction classes on one outstation, so
> we suppress a feature their methods use without demonstrating that two devices become
> indistinguishable.

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

---

## What is deliberately not proposed

* **No change to any published number.** All 18 interval statistics and both corpus counts
  re-derived exactly (`defense4/timing/audit_current/HISTORICAL_VS_CORRECTED.md` §1). The
  corrections above are to a count of configured policies and to descriptions, not to results.
* **No new figure in the manuscript.** The two new diagrams live in
  `defense4/timing/figures/model/` and are marked DRAFT. `fig_m01` would be a good replacement
  for or companion to Figure 1 and `fig_m02` a good home for P4, but adding a figure changes the
  page budget and the figure numbering, and that is a decision for the authors.
* **No claim about physical operation time.** Nothing here creates a route to one.
* **Nothing about size**, in any form.

## Order of application, once authorized

1. P1a, P1b, P2 — the two unsupported statements, smallest and highest priority.
2. P3, P5, P6 — wording and bounds, no new results.
3. P4, then P9 — the new paragraph and its two dependent clauses.
4. P7 — Related Work.
5. P8 — the SVG labels, the re-export, the hash files and the recompile, last, because it is the
   only step that changes a figure and the compiled PDF.
6. Re-run `pipeline/build.sh`; require `BUILD RESULT: PASS` and
   `lin_check --compare before.json` showing no regression.
