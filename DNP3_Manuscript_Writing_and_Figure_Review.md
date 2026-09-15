# Manuscript writing and figure review

**Review basis:** Dr. Hui Lin's meeting explanations, his supplied introduction, the user's subsequent corrections and clean-figure instruction, and the active manuscript at commit **18a595aff59577f8e9f19de65afeaea11065bd38** in `akekulip/DNP3_obf`.

## Judgment

The paper has adopted much of Lin's requested organization, but it has not consistently adopted his way of building an argument. The first three introduction paragraphs are preserved exactly. Later sections often explain the mechanism clearly, then weaken that explanation with an overly broad conclusion, a defensive aside, repeated qualifications, or an inaccurate link to earlier work.

This needs an argument-and-prose revision, not a synonym pass. Preserve the results and protected introduction; change how the remaining claims are connected and bounded. Keep the technical corrections in the companion repository review alongside this editorial pass.

## The writing standard to apply

Each paragraph should have one identifiable job. State its point, provide the mechanism, example or evidence that supports it, and explain the consequence only when that consequence is established. A paragraph does not need to announce its own job or end with “therefore” to be logical.

Every gap introduced in the motivation should lead to something this paper addresses. Every contribution should lead to a design explanation and an evaluation question. State boundaries where they matter rather than making a broad claim and retracting it several pages later.

Use the existing names consistently. Explain an idea in ordinary language before introducing its equation or P4 representation. Avoid a new symbol when an established endpoint difference or a short phrase already expresses the quantity.

Describe previous work accurately and respectfully. Explain the specific difference in feature, deployment or assumption; do not make a whole class of research look deficient to enlarge this paper's contribution. Do not recast a cited paper's threat model to make the current result look stronger.

These principles transfer Lin's voice. His grammar errors are not a style to imitate, and his protected paragraphs are not permission to repeat broad claims throughout the rest of the paper.

## Section-by-section assessment

### Abstract — narrow the result and give the reader a concrete finding

The problem-to-mechanism progression is clear. The result paragraph is less disciplined: “the device's signature leaves the interval” and the repeated-observation claim go beyond the one-device transaction-class evaluation. A fixed classifier falling to chance does not establish removal of every device fingerprint.

**Revision:** State the specific timing feature, the switch mechanism, the measured concentration/reduction, and the residual information. Keep the evaluation unit clear. Choose a few numbers that establish the main result; do not reproduce the full statistics table. [00_abstract.tex, line 17](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/00_abstract.tex#L17)

### Introduction — keep Lin's three paragraphs; repair the continuation

The first three paragraphs already provide the intended progression: significance, existing approaches, and two setting-specific reasons for this work. They pass the verbatim check and should remain intact.

The continuation should explain how the proposed mechanism addresses those reasons. It currently says the work demonstrates Formby's two features, although the control-response interval here is different from Formby's physical-operation feature. That contradiction forces later sections to undo the introduction's claim.

**Revision:** Describe CLRT replacement and the related control-response case accurately. Keep the contribution list to what the design, implementation and experiment establish. Remove the sentence insisting these are “two case studies ... not two systems”; the structure can establish that without defending the label. [01_introduction.tex, line 49](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/01_introduction.tex#L49)

### Background — explain the exchange; stop restarting the motivation

The packet sequence and source of the ACK-to-response interval are useful. The section then repeats detailed medians and tails that belong in evaluation, rehearses observation limits that reappear in the threat model and limitations, and restores the encryption-visible argument Lin specifically asked the draft to avoid.

The statement that the signature “would remain visible if the payload were encrypted” may be a relevant fact in another paper, but it does not advance the chosen plaintext argument here. Remove that detour unless the paper explicitly studies that setting. [02_background.tex, line 47](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/02_background.tex#L47)

There is also a technical overgeneralization: TCP does not require every request to produce a separate pure ACK before a response. Describe the exchange observed on this relay and the mechanism's eligibility condition. TCP can piggyback acknowledgments. [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4).

**Revision:** Explain READ and SELECT/OPERATE, define the observable interval, and provide just enough switch background for the design. Remove the obsolete `c` alias in the transaction-ladder caption. Move detailed statistics to evaluation and consolidate the measurement boundary in one clear location. [02_background.tex, line 13](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/02_background.tex#L13)

### Threat model — state capabilities and assumptions without arguing with the reader

The one-relay, transaction-class limitation is candid and necessary. The descriptions of the two classifier cases are weakened by claims that retraining asks the wrong question or is stronger than the setting requires. This sounds like an argument chosen after seeing the result.

**Revision:** Define what the observer sees, whether it can train on protected traffic, and the question answered by each evaluation. Give both results their proper scope. Keep the plaintext function-code observation concise: the experiment measures timing leakage, while packet contents already identify operations. Do not repeat the evaluation's numerical results throughout the threat model. [03_threat_model.tex, line 59](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/03_threat_model.tex#L59)

### Design — the strongest structural match, with important corrections

Starting from one transaction and deriving the coupled releases is close to Lin's blueprint. The section's opening spends several sentences explaining what the section will do and that a reader should not need P4 knowledge. The section should demonstrate that clarity directly.

The choosing-the-holds subsection drifts from a simple constraint argument into an assurance about RTO adaptation, a hardware budget calculation, and a long discussion of standards that were not verified. Its technical problems are detailed in the companion review.

**Revision:** Use three clear steps: define the events and interval; explain how coupled deadlines replace it; explain the transport and application constraints on the chosen settings. Keep the response-arrival condition beside the schedule. Distinguish actual departures from scheduled deadlines and count queue-release delay once. State the application requirement as a deployment input until its precise reference is established. [04_design.tex, line 3](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/04_design.tex#L3)

Keep shifting to one short analytical comparison. It should explain why replacement is needed, not become a parallel contribution or a long evaluation thread.

### Implementation — show the four queues before discussing the hardware

The explanation of a held packet being blocked by a higher-priority queue is accessible. However, the current two-lane/four-queue account is inconsistent with the actual four-queue ACK/RESPONSE ladder plus the separate OPERATE pair. The sentence that the deadline decides when the packet leaves also needs to distinguish eligibility from actual service.

**Revision:** Walk through one READ with the four queues, then explain the timestamp check and remaining drain. Add the control extension afterward. Describe unmatched, duplicate and late packets according to actual state transitions. Use the P4 hardware details to explain how the design is realized, not to replace the design explanation. [05_implementation.tex, line 26](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/05_implementation.tex#L26)

### Evaluation — report the answer, then explain it

The question-based subsection order is good. The repeated “Effectiveness in ROx,” “We achieve ROx if,” and “ROx therefore holds” make the prose read like a compliance report. Several paragraphs restate the same concentration result through a histogram, ECDF, quartiles, standard deviation, variance and a shifting counterfactual.

**Revision:** Lead each subsection with the measured answer, present the necessary figure or table, then explain the relevant limit. Keep RO references if useful, but let the scientific question carry the prose. Use one main distribution comparison and the zoom needed to read it. Retain tails; additional full-range or stability evidence can sit in an appendix when it does not answer a new main-paper question. [06_evaluation.tex, line 83](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/06_evaluation.tex#L83)

The paragraph calling 0.082 the “honest figure” and then saying the contribution does not rest on it should be rewritten. Honesty should be evident from accurate reporting. Explain what CLRT suppression achieves and what ACK timing still reveals without arguing that the difficult result is less relevant. [06_evaluation.tex, line 301](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/06_evaluation.tex#L301)

### Related work — generally respectful; sharpen comparisons rather than criticism

The descriptions of complementary defenses are largely constructive. Preserve that tone. Avoid collective claims that all listed defenses assume the same encryption or endpoint cooperation unless each citation supports it. Keep descriptions tied to named works and settings.

The section correctly distinguishes this paper's control-response interval from Formby's physical timing. Bring the introduction and threat model into agreement with that account. Do not make related work carry a correction to an earlier contribution claim. [07_related_work.tex, line 69](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/07_related_work.tex#L69)

### Conclusion — close on the result actually established

The opening again claims identification of which device it is and later says its signature leaves the interval. It also says both deadlines are anchored at the outstation ACK without limiting that description to READ/SELECT; the OPERATE model uses the request.

**Revision:** Summarize the appropriate mechanism by case, then state the demonstrated timing change on one relay and the remaining information. End with the bounded next measurements. Avoid creating a new broader claim in the final paragraph. [08_conclusion.tex, line 4](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/08_conclusion.tex#L4)

### Ethics and Open Science — keep factual statements; remove self-justification

The isolated-testbed description is useful. The paragraph explaining that withholding the adverse classifier result would have been the greater harm is unnecessary and defensive. Report the result where it belongs and keep this section factual.

The single-script/every-figure reproduction claim is stronger than the current tooling: the new histograms and compiled manuscript are outside the five-figure campaign generation path. Correct the actual workflow and the prose together. [09_ethics_openscience.tex, line 14](https://github.com/akekulip/DNP3_obf/blob/18a595aff59577f8e9f19de65afeaea11065bd38/paper/rewrite/sections/09_ethics_openscience.tex#L14)

## Short examples of the intended voice

These are examples for the next revision, not changes already applied to the manuscript or to Lin's protected introduction.

**Model explanation:**

> The switch computes both deadlines when the outstation's acknowledgment arrives. The response deadline is the acknowledgment deadline plus the configured CLRT_new. When the response arrives before its deadline, this schedule removes the original response interval from the scheduled gap. The measured gap also includes the difference between the two packets' release delays.

**Queue explanation:**

> The READ path uses four queues. A blocker queue sits above the held ACK, and a second blocker queue sits above the held response. Each blocker stops circulating after its deadline expires. The corresponding packet becomes eligible for service when its blocker queue empties.

**Result explanation:**

> After obfuscation, 99.86% of READ measurements lie within 0.10 ms of the configured 4 ms interval. Sample variance decreases from 6.808 to 0.394 ms². A small number of observations remain in the tail and contribute to the remaining variance.

**Residual-information explanation:**

> A classifier retrained on CLRT alone remains near three-class chance in this experiment. Adding request-to-ACK timing raises balanced accuracy to 0.651. The result shows that concentrating CLRT leaves information in another observable interval.

## Clean-figure requirements

**The user's latest instruction governs:** remove descriptions, needless captions and redundant labels from inside each graphic. A figure should show its data or mechanism, with only the information needed to read it correctly. Put explanations and interpretation in the paper.

| Figure family | Keep | Remove or relocate |
|---|---|---|
| Main CLRT histograms | Bars, shared axes, `CLRT (ms)`, `Transactions (%)`, short condition/panel identifiers, explicit overflow category | The long mean/SD/variance/count strips; redundant condition-plus-variable titles; explanatory legend entries; mean triangles unless the argument specifically needs them |
| CLRT zoom | Same condition identities, numeric window, necessary target line | Coverage-percentage text inside the plot; repeated definition of the target; interpretation of the peak |
| Full-range companion | Bars and axes showing the complete range | Repeated statistics and a second narrative explanation of the main result |
| Release timeline | Master/switch/outstation rows, necessary event symbols, duration bars, compact panel identifiers | “Late: forwarded on arrival” callout; repeated “deadlines” descriptions; arbitrary numerical precision presented as measurements |
| Queue schematic | Named queues, priority order, packet path and essential port/domain separation | Sentences inside blocks; implementation commentary that belongs in the text |
| Policy sweep | Points/curves, axes and units, necessary series/reference identification | Repeated configuration text in axes, legends and callouts; the misleading universal “fail-open” label; overlapping annotation near the lower axis |
| Feature-overlap plot | Points, axes, class key, inset if it materially reveals the separation | Duplicate long titles or explanatory text; excess visual emphasis on summary symbols if the points answer the question |
| Classifier/stability plots | The comparison, units, class/condition key and necessary uncertainty information | Takeaway sentences, repeated method descriptions and redundant legends |

Prefer one brief external caption explaining what the marks represent and any essential scale or denominator convention. Detailed bin rules, sample statistics and the interpretation belong in methods or results. Do not remove units, hide the overflow meaning, or leave a log scale ambiguous in pursuit of minimalism.

The current histogram calculation is correct, but the statistics strips and enlarged legend make the figure look annotated for a meeting. The policy figure repeats its configuration in several places, and one annotation crowds the lower axis. These need an actual layout pass at final column width, followed by a fresh manuscript build.

## Acceptance criteria for the revision

1. Lin's first three introduction paragraphs remain unchanged.
2. Every later paragraph advances a defined claim or supplies necessary explanation/evidence; repeated roadmap and self-assessment prose is removed.
3. The same contribution and limitation appear consistently in the abstract, continuation of the introduction, design, evaluation and conclusion.
4. Previous work is described accurately; no unsupported Formby attribution or generic dismissal remains.
5. Current notation is used without obsolete aliases; timing boundaries and configured/measured quantities are explicit.
6. Figures contain only essential reading aids. Captions are short, and explanatory paragraphs remain in the manuscript.
7. The compiled PDF contains the revised text and graphics, with readable layout at the intended publication size.
8. Numerical checks continue to pass; remaining build or rendering-gate failures are reported accurately.

This review supplies the direction and examples for a bounded revision. It does not authorize inventing stronger evidence, changing the frozen experiment to match the prose, or rewriting the protected introduction.
