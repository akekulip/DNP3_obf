# journal-adapt revision log — NDSS

Phase 1 built Style Cards for the five Lin-group papers and an aggregate Journal Style Card,
distilled into `dynamic_writing_skill.md`. Phase 2 diagnosed the manuscript against it and revised.

## Diagnosis (before revision)

Mechanical scan of all sections against the corpus red flags:

| pattern | corpus | draft | verdict |
|---|---|---|---|
| `novel` | 0 | 0 | pass |
| `Moreover,` | 0 | 0 | pass |
| em dashes | 0 | 0 | pass |
| `In summary,` / `Overall,` | 0 | 0 | pass |
| roadmap paragraph | 0 | 0 | pass |
| `leverage` / `utilize` | ~0 | 0 | pass (the one hit is the noun "test harness") |
| `outperforms` / `fails to` / `suffers from` | 0 | 0 | pass |
| significance apparatus | 0 | 0 | pass |
| `Finally,` in an enumeration | 0 | 0 | pass |
| `state-of-the-art` / `comprehensive` / `robust` | 0 | 0 | pass |
| bulleted lists outside contributions | 0 | 0 | pass (both lists are contributions and RO labels) |

Positive markers: `Consequently,` 5 (corpus range 4 to 15), `In Figure~N, we show` 8,
`This is because` 3, `can` 20. Structure: RO labels declared once and reused 1:1 in the
Evaluation; Related Work late with five themed bold headers; separate Implementation section.

**Journal match score before: 4.6 / 5.** The draft was already close, because the sections were
written against the DefRec conventions measured earlier in the session.

## Revisions applied

| # | Section | Severity | Problem | Rule applied | Source |
|---|---|---|---|---|---|
| 1 | Evaluation, Testbed | LOW | `i.e.` gloss absent where an abstract noun needed grounding | gloss density | P3 house style |
| 2 | Evaluation, Data | LOW | block ordering asserted without an instance | gloss density | P3 house style |
| 3 | Design, policy family | LOW | the event policy named without an instance | gloss density | P3 house style |

Gloss density moved from 0 `e.g.,` and 5 `i.e.,` to 2 and 6. The corpus runs far denser
(DefRec 39 and 17), but the remaining abstract nouns in this manuscript are already defined
formally in the Design section, so further glossing would restate rather than ground.

**Journal match score after: 4.8 / 5.** Non-regression gate: `lin_check --compare` reports
NO REGRESSION on every hard dimension.

## Not applied, with reasons

- **Remove the Limitations subsection.** The corpus has none and distributes carve-outs instead.
  This project's gate hard-requires the heading and the repository contract requires the
  limitations to appear there. Project rule wins; kept to one paragraph.
- **Add a firstness claim.** Four of five corpus papers make none. The authors' verbatim
  Introduction already carries one; it is theirs and was not touched.
- **Personify the adversary.** A DefRec idiosyncrasy, not a venue requirement. The group habit,
  impersonal and plural, is kept.
- **Drop spread from reported medians.** The corpus reports point values only, but modern NDSS
  review expects variability. Interquartile ranges are reported as plain numbers, with no
  significance-test language, which keeps the voice on-corpus.
- **Rewrite the Introduction.** Protected verbatim; citations only.
