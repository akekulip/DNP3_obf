# Dr. Lin writing guide — the one active guide for this manuscript

Consolidates the writing rules the manuscript follows. It replaces `LIN_STYLE_CONTRACT.md`,
`LIN_STYLE_PROFILE.md`, `LIN_VS_PHILIP_DIFF.md`, `PIPELINE_AUDIT_VERDICT.md`,
`WRITING_PIPELINE_AUDIT.md` and `WRITING_PIPELINE_REBUILD_PLAN.md` (archived 2026-08-26, see
`CLEANUP_PLAN.md`). The evidence trail for Dr. Lin's own words stays in
`../LIN_WRITING_GUIDANCE.md` (extracted from the 2026-08-19 meeting) and in
`samples/lin_intro.txt` (his introduction paragraphs, verbatim from the annotated draft).
The style files control style; they never override experimental evidence
(`../../../defense4/timing/CLAIMS_AND_LIMITATIONS.md`).

## 1. What the paper is about, and what it is not

* The framework is the contribution. CLRT normalization (READ and the SELECT phase of SBO) and
  control-path timing (OPERATE) are two case studies that show the framework working. Do not
  write them as two separate systems.
* The application is device fingerprinting. Do not open with anti-reconnaissance in general.
* Industrial control systems are the domain; the power grid and DNP3 are the concrete setting.
* Timing only. Size obfuscation appears as prior-work context in the Introduction and Related
  Work, never as a contribution, a result, or a figure. No padding, splitting, segment-shape,
  dummy-packet, cover-frame, decoy or multi-device claim anywhere.
* No system name. Write "the framework", "the timing-obfuscation framework" or "the in-network
  timing obfuscator". No invented acronym, no `\sysname`.

## 2. Structure

Title, Abstract, Introduction, Background and Motivation, Threat Model and Research Objectives,
Framework Design, Tofino Implementation, Evaluation (with Limitations inside it), Related Work,
Conclusion, References. Design and Implementation stay separate. Related Work is second-last;
Conclusion is last. Use subsections only where they help the reader follow the argument.

Introduction, five paragraphs in this order: (1) device fingerprinting as reconnaissance, why
it matters in ICS, the cyber-physical consequence; (2) traffic obfuscation as the response,
timing and size as the two feature families, delay versus padding/splitting, why Internet
approaches assume encrypted payloads or host-side overhead; (3) why those approaches do not
transfer to legacy ICS traffic; (4) the proposed framework, high level; (5) a short bounded
contribution list. No implementation detail in the Introduction.

Evaluation order: testbed; data and conditions; extraction and exclusions; READ and SELECT CLRT;
distributions and ECDF; timing-feature overlap; master-visible OPERATE timing; timing leakage;
limitations. Reuse the research-objective labels RO1, RO2, RO3 defined in the threat model.

## 3. Paragraph logic (Dr. Lin's method)

* Each sentence has one job. Each paragraph has one job.
* Explain why before what. When stuck, write what was done, but write why first.
* A paragraph moves: topic or problem, explanation or evidence, implication, transition.
* Link sentences with the connective that names the logical relation when the relation is
  real ("Consequently,", "Because …,", "Since …,", "For example,", "Unfortunately,"). Do not add
  a connective for rhythm; "however", "therefore", "moreover", "furthermore" only when the logic
  needs them. The checker does not score connective density.
* Examples serve the argument. Stuxnet and Ukraine 2015 are used once, pointed at
  reconnaissance dwell time, with the E-ISAC/SANS analysis cited; never as decoration.
* Enumerate in balanced, finished form: "(i) …, and (ii) …" or "First, … Second, …".

## 4. Sentence-level rules

* Plain language. "use", not "leverage" or "utilize". Short words. Repeat the same term for
  the same thing; do not vary vocabulary for variety.
* Active voice. "we" is the normal agent of design and evaluation sentences.
* No em dashes. No inflated phrases, no generic AI transitions ("it is worth noting",
  "importantly", "notably"), no "novel", "robust", "comprehensive", "state-of-the-art".
* One idea per sentence; every sentence has a subject and a finite verb (no "By learning …,
  because …" fragments).
* Define every acronym at first use and every symbol once.
* Calibrated claims: "show", "indicate", "reduce", "pin"; never "prove", "guarantee",
  "eliminate fingerprinting". "significantly" only next to a measured number.
* Firstness is not required. The authors' verbatim Introduction (2026-08-26) keeps one
  "to the best of our knowledge … first" sentence; the gate reports it as a warning so it is
  verified against the literature before submission rather than blocked.

## 5. Terminology (fixed)

| write | do not write |
|---|---|
| Timing OFF, Obfuscated (the two arms) | native, defended, Timing ON, baseline (as an arm name) |
| the SELECT phase of SBO (function 3); "SBO" in figure legends means that phase | SBO transaction, complete SBO |
| master-visible OPERATE timing; operation time O = echo − ACK | physical breaker operating time |
| J is the configured codebook value; not observed relay-facing | measured hold, exactly-once delivery |
| timing-feature overlap (Figure 3) | clustering performance, t-SNE, UMAP |
| transaction-class timing leakage / classifier | device identification, device-model separation |
| CLRT (cross-layer response time) = response − ACK, master-facing | ACK-to-response "latency of the relay" without the observation point |
| D_A, D_R (read path, anchored to the relay ACK); A, R, J (control path, anchored to the request) | G; T0 + A for reads |
| size shaping active in both arms; no pure size-free baseline | unmodified native baseline |

## 6. Claim gates (every sentence of results must pass)

* Every number traces to `figures/ndss/MANUSCRIPT_VALUES.json`, regenerated from the raw
  captures by `defense4/timing/evidence/campaign_v1/repro/reproduce.sh`. That file is the only
  source the manuscript quotes from, and the publication gate fails if it drifts from a rebuild.
* Every figure sentence names its figure and reports the observation point.
* The Obfuscated mutual information is quoted as "0.004 bits, inside the permutation null", with
  the empirical p-value where the sentence needs it. (The older rule said "below 0.003 bits" and
  applied to the retired `final_read_sbo` estimate, whose instability at the fourth decimal came
  from a histogram bin edge at exactly 4.000 ms. The campaign_v1 estimate uses a
  nearest-neighbour estimator and does not have that failure mode, so the value is quoted as
  measured.) No uncertainty interval is placed on a mutual-information estimate.
* Classifier accuracy is scoped to the evaluated Random-Forest attacker and feature set, and its
  spread is described as the range over the 22 held-out runs, never as a confidence interval.
* The read lane and the control lane are never pooled: the release budget `D` governs READ and
  the SELECT phase of SBO only, and OPERATE never appears in that coverage denominator.
* The limitations in `CLAIMS_AND_LIMITATIONS.md` L1 to L12 appear in the Evaluation's
  Limitations subsection, in plain text, not in a footnote.
* Configuration provenance is PARTIAL and says so.

## 7. Protected text

Since 2026-08-26 (evening) the whole Introduction is the authors' own text and is kept verbatim;
only citations may be added. The other sections follow its register: connective-led sentences
(Because, Since, Consequently, Therefore, As such, In this way), "we" as the agent, bold run-in
headers, and plain explanatory clauses ("This is because …").

Dr. Lin's opening paragraph and his obfuscation-trend paragraph (red boxes in the annotated
introduction, verbatim in `samples/lin_intro.txt` and quoted in
`reports/PRE_REWRITE_RECONCILIATION.md` R10) keep their sentence roles and logic. Only grammar,
factual correctness, citation correctness, timing-only scope, terminology consistency and the
removal of unsupported claims may change them, and every change is logged in
`reports/LIN_TEXT_CHANGELOG.md` with the original, the revision, the reason and whether it is
editorial or scientific.

## 8. Citation audit

Every externally verifiable claim has a row in `reports/CLAIM_CITATION_MATRIX.md`: section,
claim, key, source, type, exact support, verification status, action. One active bibliography
(`../library.bib`, the Zotero export; only the cited entries were verified, and the export was
not bulk-edited). No undefined keys, no duplicate records cited as two papers, no citation
that does not support its sentence, no citation placed after several unrelated claims.

## 9. Rendering and review gates

`pipeline/build.sh` compiles with tectonic and runs `lin_check.py`. The checker fails on:
forbidden project names, stale arm labels, unsupported firstness, em dashes, unsupported size
claims, missing required sections or wrong order, a figure environment after the bibliography,
a missing Limitations heading, an undefined citation key, and no-main-clause fragments. It
warns on undefined acronyms, density, verbless sentences and marquee-example hygiene. After the
build: `pdfinfo`, `pdffonts`, every page rendered and inspected (title block, abstract,
columns, equations, figures, captions, whitespace, references, nothing after References).
Order for prose: draft in this guide's method, then the `paper-voice` pass, then
`academic-humanizer`, then `lin_check --compare` (no regression), then the build.
