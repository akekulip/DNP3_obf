# Paper Style Card: lin_ndss2020_defrec

Structure and rhetoric only. No content, findings, quotations or paraphrase of the source are
reproduced here.

## Metadata

- Paper ID: `lin_ndss2020_defrec`
- Authors: Lin, H.; Zhuang, J.; Hu, Y.-C.; Zhou, H.
- Venue / year: NDSS 2020
- Corpus role: **primary** — the target venue, and the advisor's own paper
- Length: 18 pages total
- Method type: systems design plus testbed evaluation

## Document shape, by position in the text

| position | section |
|---:|---|
| 1.8% | I. Introduction, containing a subsection *A. Contributions* |
| 10.3% | II. Design Objectives, containing power-grid basics and the threat model |
| 20.7% | III. Design |
| 27.9% | IV. Disruption policy |
| 47.5% | V. Implementation |
| 50.7% | VI. Evaluation, split into security evaluation and performance evaluation |
| 68.1% | VII. Related Work |
| 73.8% | VIII. Conclusion |
| 76.0% | References |
| 89.0% | Appendix A |
| 95.6% | Appendix B |
| 97.2% | Appendix C |

**The body runs to about 76% of the document, the references occupy the next 13%, and three
appendices follow them.** Related Work is second-last and Conclusion is last. Background is not a
standalone section: the domain primer sits inside the objectives section, immediately before the
threat model.

## A. Abstract style

- Length: 223 words.
- Move order: phenomenon and why it matters, the abstraction introduced, the mechanism built on
  it, what the mechanism achieves, implementation platform, evaluation setting, then a single
  quantified headline result.
- Tense: present throughout for the design, present for the reported result.
- Contribution placement: carried by the verbs of the design sentences. There is no "we
  contribute" framing and no enumerated list.

## B. Introduction architecture

- Hook: the phenomenon, stated as an adversary's need, in the first sentence, with a citation.
- Paragraph 1 anchors that phenomenon to one named real-world incident and closes on the
  physical consequence.
- Paragraph 2 argues why a preemptive posture is preferable to a detective one, enumerated as
  *First, … Second, …*.
- Paragraph 3 names the research gap, then enumerates the drawbacks of the existing approach
  family as *First, … Second, … Last, …*.
- Contributions appear as a **named subsection inside the Introduction**, written as prose that
  opens by naming the drawback being overcome and then the proposal. Not bullets, not numbered.
- Inside that subsection, short bold run-in headers label individual points.
- No roadmap paragraph at the end of the Introduction.

## C. Contribution expression

- Voice: "we propose", "we position", "we implement", "we evaluate".
- Claim strength: assertive for what was built, quantified for what was measured.
- Number of contributions: one primary abstraction plus one mechanism built on it, presented as
  a pair rather than as a list of four or five.

## D. Literature

- A standalone Related Work section, placed second-last.
- Positioning inside the Introduction is done by naming an approach family and its drawbacks,
  not by surveying individual papers.

## E. Method and design

- Entry point: the abstraction is named and motivated before any component is described.
- Components are introduced one per labelled block.
- Notation density: light in the design section; the argument is carried in prose with figures.

## F. Evaluation

- Split by question type: a security evaluation and a performance evaluation, in that order.
- Narrative style: result, then the mechanism that produces it, then the implication.
- The headline quantity is expressed as an operational consequence for the adversary rather than
  as a raw statistic.

## G. Language style

- Active voice throughout; "we" is the standard agent.
- Connective-led sentence openings where a real logical relation exists: *Compared to …*,
  *Despite …*, *Although …*, *Instead of …*.
- Enumeration is explicit and finished: *First … Second … Last*.
- Bold run-in headers inside sections.
- Sentence length is moderate and varied; one idea per sentence dominates.

## H. What this paper does not do

- No roadmap paragraph.
- No standalone Background section.
- No bulleted contribution list.
- No hedging stacked on hedging.
- No appendix material inside the body.

## I. Distinctive moves

- The Introduction's gap paragraph enumerates the drawbacks of the incumbent family, and the
  Contributions subsection opens by answering that same enumeration. The two are written as a
  matched pair.
- Supplementary material is pushed past the references into three appendices rather than
  compressed into the body.
- The domain primer is subordinated to the objectives section, so the reader reaches the threat
  model quickly.

## J. Divergences from our manuscript's own style contract

Recorded because the contract, not this paper, governs our manuscript. `DR_LIN_WRITING_GUIDE.md`
bans "significantly" except beside a measured number, and bans "state-of-the-art"; this paper uses
both, the latter when characterising other work. The contract was derived from Dr. Lin's edits to
**our** draft and is the later and more specific authority, so the contract wins and these
divergences are not imported.
