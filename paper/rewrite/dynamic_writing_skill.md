# Dynamic Writing Skill: NDSS 2027, Dr. Lin's register

Generated: 2026-09-16
Primary corpus, two sources:
1. **Dr. Lin's own NDSS paper**, downloaded and read: *DefRec: Establishing Physical Function
   Virtualization to Disrupt Reconnaissance of Power Grids' Cyber-Physical Infrastructures*,
   NDSS 2020, Lin, Zhuang, Hu, Zhou. Saved at `corpus/lin_ndss2020_defrec.pdf`; structure and
   rhetoric extracted to `corpus/lin_ndss2020_style_card.md`. Same venue, same domain, and the
   same problem family: disrupting reconnaissance of power grids.
2. His supplied Introduction (`pipeline/samples/lin_intro.txt`) and the corpus-derived contract
   `pipeline/DR_LIN_WRITING_GUIDE.md`, built from his edits to **this** draft.

Where the two disagree, the contract wins: it is later and specific to this manuscript. The paper
supplies the venue-level shape the contract does not describe.
Secondary corpus available, not required: `2022_NDSS_ditto WAN Traffic Obfuscation at Line Rate.pdf`.
Static base: CS / Engineering.

**Task this skill is built for.** Adapt the manuscript to NDSS 2027 in Dr. Lin's register and fit
the body to the venue's limit. Verified from the NDSS 2027 call for papers: "Technical papers
submitted for NDSS Symposium must not exceed 13 pages, excluding the 'Ethics Considerations'
section, references, or appendices." Open Science is therefore counted. The body is currently 15
pages, so roughly 1,600 words have to go.

---

## PRIORITY RULES

### Priority 1 — HARD PRESERVE (never modify)

* Paragraphs 1 to 3 of `sections/01_introduction.tex`, token for token. `check_lin_intro_verbatim.py`
  enforces this and must pass. Do not fix grammar, tense or facts inside them.
* Every `\cite{}` key, every math environment, every `\ref{}` and `\label{}`.
* Every number. The only source is `figures/ndss/MANUSCRIPT_VALUES.json`; the publication gate
  fails if the manuscript drifts from a rebuild.
* Notation: `D_A` is the ACK hold; `D_R` is the response latency, and the whole
  outstation-to-master journey, which is unmeasured here; the response hold `e_R - t_R` has no
  symbol; the configured gap is the **configured CLRT_new**. `CLRT_target` is withdrawn.
* Arm labels *Timing OFF* and *Obfuscated*. Never `native`, `defended`, `Timing ON`, `baseline`.
* **Every unfavourable measurement stays.** The adaptive adversary's 0.651, the
  request-to-acknowledgment interval rising from 0.380 to 0.662, the tail that misses the budget,
  the PARTIAL configuration provenance, and limitations L1 to L12 in plain text inside the
  Evaluation's Limitations subsection. Shortening must never become suppression.

### Priority 2 — DR. LIN'S REGISTER (the target pattern)

* **One job per sentence, one job per paragraph.** A paragraph moves: topic or problem,
  explanation or evidence, implication, transition.
* **Why before what.**
* Plain words: "use", not "leverage" or "utilize". Repeat the same term for the same thing rather
  than varying it.
* Active voice; "we" is the normal agent.
* No em dashes. No "it is worth noting", "importantly", "notably", "novel", "robust",
  "comprehensive", "state-of-the-art".
* Connectives only where the logical relation is real.
* Calibrated verbs: show, indicate, reduce, pin. Never prove, guarantee, eliminate.
* Structure is fixed and already correct in this draft: Abstract, Introduction, Background and
  Motivation, Threat Model and Objectives, Design, Implementation, Evaluation with Limitations
  inside it, Related Work second-last, Conclusion last.

### Priority 3 — NDSS VENUE FIT

* 13-page body. Ethics Considerations, references and appendices are excluded; Open Science is not.
* Anonymous, two columns, 10 pt, US Letter. `ndss_preflight.py` gates all of this.
* Reviewers read the evaluation for what was measured and where. Keep the observation point in
  every figure sentence.

### Priority 4 — CS / ENGINEERING BASE

Applies only where P2 and P3 are silent: define acronyms at first use, define each symbol once,
prefer the concrete noun over the abstract one, and put the mechanism before its parameters.

### Priority 5 — ALWAYS REMOVE

* Repeated roadmaps and repeated scope statements. Each qualification belongs once, at the claim
  it bounds; general limitations are consolidated in the Limitations subsection.
* Repeated "we do not claim" lists. The design section currently carries three.
* Sentences that restate the previous sentence with different words.
* Clauses that re-derive something the reader was told two paragraphs earlier.
* Hedges stacked on hedges ("may possibly suggest").

---

## WHAT HIS OWN NDSS PAPER CHANGES ABOUT THE PLAN

Reading `DefRec` changes the page problem, because it shows how he solves it at this venue.

**He puts supplementary material in appendices after the references.** DefRec is 18 pages: the
body runs to about 76% of the document, the references take the next 13%, and **three appendices
follow them**. NDSS excludes appendices from the 13-page count, so this is the venue-correct way
to keep material available without spending body pages on it. It is also what the advisor does.

This matters because our repository's own gate forbids a figure after the References heading, and
that rule is stricter than both the venue and his own practice. **This is a decision for you, not
for me:** I am not going to quietly change a gate to let my own edit through. The options are in
the gate question at the end of this file.

**Other structural points his paper settles:**

* Related Work second-last, Conclusion last. Our draft already matches.
* **No standalone Background section.** His domain primer sits inside the objectives section,
  immediately before the threat model, so the reader reaches the threat model early. Our draft
  has a separate 754-word Background plus a 1,116-word Threat Model that repeats some of its
  motivation. Folding the primer into the objectives section is his own shape and would remove
  the duplication the review flagged.
* **Contributions are a named subsection inside the Introduction, in prose**, opening by naming
  the drawback being overcome. Not a bulleted list.
* **No roadmap paragraph.** If ours has one, it goes.
* Enumeration is explicit and finished: *First … Second … Last*.
* Bold run-in headers inside sections, which our draft already uses.

## WHERE THE 1,600 WORDS COME FROM

Measured section lengths, body only:

| block | words | disposition |
|---|---:|---|
| Threat Model and Objectives | 1,116 | compress; the motivation restates Background |
| Design: a timing model | 1,126 | compress; keep the model, cut the re-derivation |
| Design: choosing the holds | 1,010 | compress; three "we do not claim" passages become one |
| Evaluation: RO1 | 1,101 | compress prose, keep every number |
| Evaluation: RO3 | 1,000 | keep; this is where the unfavourable result lives |
| Evaluation: Limitations | 1,008 | keep L1 to L12; tighten the epsilon paragraph only |
| Related Work | 688 | keep; already concise, and the review asked for accuracy here |

**Rule for this pass: compression is sentence-level, not evidence-level.** A cut is legitimate if
the same fact survives in fewer words, or if the sentence repeated something. A cut is illegitimate
if a number, a qualification, or an unfavourable result leaves the paper.

---

## SECTION GUIDANCE

**Abstract.** 252 words now. Problem, mechanism, evaluation, central result, and the bound on it.
Already restructured; leave unless a number changes.

**Introduction.** Paragraphs 1 to 3 are frozen. The continuation carries the framework paragraph
and the bounded contribution list. Do not add implementation detail here.

**Background and Threat Model.** These two currently overlap: both motivate fingerprinting. Say it
once, in Background, and let the Threat Model state visibility, placement, the adversary's access
to plaintext function codes, and the five objectives. Fixed-model and adaptive attacks are
evaluation conditions, not different adversaries.

**Design.** Model, then parameters, then constraints. Keep the coupling equation and the statement
that the three quantities are not separately selectable. Consolidate the scope disclaimers.

**Implementation.** Queue roles and shared state in ordinary networking terms, then how P4 realises
them. Already corrected for the single-slot registers and the late-response queue.

**Evaluation.** Keep the reader's-questions order. Every number stays. Compress the connective
tissue between results, not the results.

**Limitations.** L1 to L12 stay, in plain text. The epsilon paragraph is the one place to tighten:
medians and the four bounds are load-bearing, the full ranges and both standard deviations can go
to the artifact.

**Conclusion.** One or two short paragraphs. Do not restate the introduction or re-list limitations.

---

## CAUTIONS

* The `lin_check.py` gate is fail-closed and must not be edited to accommodate a change. If a
  change trips it, change the prose.
* `check_lin_intro_verbatim.py` must pass after every edit.
* Rebuild and re-run `lin_check --compare` after each section; no hard check may go PASS to FAIL.
* Do not move body text into an appendix to escape the page count. Only genuinely supplementary
  material may move there, and the full-range companion figure is the only candidate.
