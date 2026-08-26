# Final manuscript audit — 2026-08-26

Covers the manuscript audit, the figure-placement audit, the citation audit and the rendered-page
inspection of `paper/rewrite/main.pdf` as built by `pipeline/build.sh` on this date. Companion
reports: `PRE_REWRITE_KNOWLEDGE.md`, `PRE_REWRITE_RECONCILIATION.md`,
`EVENT_SEMANTICS_TRUTH_TABLE.md`, `LIN_TEXT_CHANGELOG.md`, `CLAIM_CITATION_MATRIX.md`.

## 1. Build

| item | value |
|---|---|
| source | `paper/rewrite/main.tex` + `sections/00…08_*.tex`, `library.bib`, IEEEtran conference class (unchanged template) |
| compiler | tectonic 0.16.9 (`xdvipdfmx`), offline cache; `pipeline/build.sh` |
| result | compile rc 0; gate rc 0; `BUILD RESULT: PASS` |
| pages | 10 (US letter), References end on page 10; no page after References |
| log | no undefined reference, no undefined citation, no multiply-defined label, no missing figure; 4 `Font shape TU/ptm … undefined` info lines from the XeTeX/IEEEtran font setup (body renders in Nimbus Roman No9 L, the Times clone, per `pdffonts`); 9 overfull/underfull boxes, all ≤ 1.5 pt except none (the 41 pt table overflow was fixed) |
| fonts | every font embedded and subset (`pdffonts`: NimbusRomNo9L Type 1C, Computer Modern math Type 1C, Times New Roman TrueType/CID inside the figures); no Type 3, no unembedded font |
| words | 7,568 in the section files |
| final PDF sha256 | in the commit message of the final commit; `paper/rewrite/main.pdf` is byte-identical to `pipeline/build/main.pdf` at build time. Figures 1–3 were redrawn in colour on 2026-08-26 (SVG sources in `paper/rewrite/figures/`, copies in `defense4/timing/figures/schematics/`) |

## 2. Manuscript audit (brief §19 defect list)

| known defect of the earlier PDF | status now |
|---|---|
| placeholder author information | replaced by a visible `[AUTHOR BLOCK PENDING]` marker; metadata not recoverable from the repository (`PRE_REWRITE_RECONCILIATION.md` R9); **unresolved, needs Philip** |
| no abstract | written (`sections/00_abstract.tex`), timing only, bounded |
| incomplete Implementation | written (`sections/05_implementation.tex`), including the combined-program disclosure |
| Evaluation headings without prose | full prose for testbed, data/extraction, RO1, RO2, RO3, Limitations |
| missing Related Work | written, organised by claim, second-last |
| missing Conclusion | written, last |
| result figures after References | none; `figures_after_refs` PASS with the PDF checked |
| figure-only pages | none; every figure page carries body text |
| excessive whitespace | none observed on any page |
| broken `\SysName` | macro removed; no system name anywhere (`forbidden_names` PASS) |
| old timing-and-size title | `Programmable In-Network Timing Obfuscation for DNP3` |
| overclaims about physical operation timing | Figure 7 and RO2 state master-visible timing only; J configured, not observed; breaker motion not measured; exactly-once not established |
| stale terminology | arms `Timing OFF` / `Obfuscated`; `SELECT phase of SBO`; `timing-feature overlap`; `stale_labels` PASS |

Structure (brief §22): Title, Abstract, I Introduction, II Background and Motivation, III Threat
Model and Research Objectives, IV Framework Design, V Tofino Implementation, VI Evaluation
(A Testbed, B Data and Extraction, C RO1, D RO2, E RO3, F Limitations), VII Related Work, VIII
Conclusion, References. Introduction follows the five-paragraph funnel; the two protected
paragraphs keep their sentence roles (`LIN_TEXT_CHANGELOG.md`). Contributions are four verb-first
headlines with the framework leading and the two case studies as its instantiations. No firstness
claim. Equations (1)–(4) match `EVENT_SEMANTICS_TRUTH_TABLE.md`. Every result number matches
`defense4/timing/evidence/final_read_sbo/timing_stats.json` and the derived CSVs regenerated this
session (reproduction report). Limitations L1–L10 of `CLAIMS_AND_LIMITATIONS.md` appear in VI-F in
plain text.

Gate scorecard (latest `pipeline/reports/main_*.txt`): all ten hard checks PASS; warnings:
`sentence_health` (5 verbless "sentences", all bold run-in headers or a section title), none.
Voice fingerprint (`paper-voice/voice_check.py`): no AI-pattern flags; remaining surface
deviations are a low "we" density (10/100 sentences against the corpus floor of 15), fewer hedges
than the corpus, a higher citation density (Related Work), and a Flesch score above the corpus
band (the text is easier to read than the corpus, which the brief's plain-language rule asks for).

## 3. Figure-placement audit

| figure | file | section | page | float | after References? |
|---|---|---|---|---|---|
| Fig. 1 | `figures/fig_ladder.pdf` | II Background | 2 | `figure` | no |
| Fig. 2 | `figures/fig_observation.pdf` | III Threat model | 3 | `figure` | no |
| Fig. 3 | `figures/fig_design.pdf` | IV Design | 4 | `figure` | no |
| Fig. 4 | `figures/timing/fig01_clrt_read_select_before_after.pdf` | VI-C RO1 | 7 | `figure*` | no |
| Fig. 5 | `figures/timing/fig02_clrt_ecdf_before_after.pdf` | VI-C RO1 | 7 | `figure` | no |
| Fig. 6 | `figures/timing/fig03_timing_feature_overlap_before_after.pdf` | VI-C RO1 | 8 | `figure*` | no |
| Fig. 7 | `figures/timing/fig04_sbo_operate_timing_by_j.pdf` | VI-D RO2 | 8 | `figure` | no |
| Fig. 8 | `figures/timing/fig05_timing_leakage_summary.pdf` | VI-E RO3 | 9 | `figure*` | no |

All five timing figures are included at natural size (7.16 in double-column or 3.5 in single
column), 9 pt Times New Roman embedded, opaque white background, legend labels `Timing OFF` /
`Obfuscated` and `READ` / `SBO` only. Manuscript copies are byte-identical to
`defense4/timing/figures/publication/` and their hashes are in `FIGURE_PROVENANCE.md` and
`FINAL_FIGURES.md`. Tables I and II sit in VI-B/VI-C on page 6. No `\FloatBarrier` package was
needed: the section order and the float specifiers place every figure inside VI before VII.

## 4. Citation audit

33 keys cited, all resolving in `library.bib` (`citations` PASS). Per-claim verification in
`CLAIM_CITATION_MATRIX.md`: 31 rows, every row VERIFIED or VERIFIED-RECORD; four entries edited
individually (Minos and Securitas author lists, Securitas title per the USENIX listing, Jeon arXiv
identifier) and one added (Langner 2011); no bulk edit of the Zotero export; duplicate suffixed
records exist in the export but none is cited; `refs.bib` archived. Each Stuxnet/Ukraine
statement carries the source that supports it. No citation is placed after several unrelated
claims (each `\cite` sits on the clause it supports).

## 5. Rendered-page inspection

Every page of the final 10-page build was rendered (`pdftoppm -r 80`) and read.

| page | content | checks |
|---|---|---|
| 1 | title, pending author marker, abstract, index terms, Introduction ¶1–3 | title correct; marker visible; two columns balanced; no clipping |
| 2 | Introduction ¶4–5 and contributions; Fig. 1 ladder; Background start | ladder shows TCP ACK before each response and marks $c$ and $O$ correctly |
| 3 | Fig. 2 observation model; Background end; Threat Model with RO1–RO3 | RO list renders; figure legible |
| 4 | Fig. 3 design; Design with Eqs. (1)–(4) | equations numbered and referenced; schematic text legible at 6–7.5 pt |
| 5 | Design end; Implementation; Evaluation start | run-in headers; "What ran, exactly" disclosure present |
| 6 | Tables I–II; Testbed, Data, RO1 results, Distributions, Overlap text, RO2 start | tables within column width after the footnotesize fix |
| 7 | Fig. 4 (double column), Fig. 5; RO2 and RO3 text | captions complete; legends read `Timing OFF` / `Obfuscated` |
| 8 | Fig. 6 (double column), Fig. 7; RO3 end, Limitations, Related Work start | all seven limitations in body text |
| 9 | Fig. 8 (double column); Related Work; Conclusion start | no whitespace gaps |
| 10 | Conclusion end; References [1]–[33] | no figure after References; no blank page |

No black backgrounds, no transparent-region artifacts, no rasterized text, no unreadably small
text (smallest: 6 pt labels inside the schematics, 8 pt tick labels in the data figures).

## 6. Unresolved items (for Philip)

1. Author block, affiliation, email (`main.tex`).
2. Venue and page limit; the manuscript is 10 pages in the IEEEtran conference template.
3. The Stuxnet sentence of the protected paragraph was split to match the sources
   (`LIN_TEXT_CHANGELOG.md` 1.4); confirm with Dr. Lin.
4. Licence file for the repository.
5. Push: nothing has been pushed; branch `paper/final-timing-rewrite-20260826` is local.
6. `remove-ai-marks` was not run (barred by the brief for this repository); the global
   instruction that requires it is overridden here and noted in `CLAUDE.md`.
