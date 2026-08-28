# Dynamic Writing Skill: NDSS (Lin-group security systems paper)

Generated 2026-08-28. Primary corpus: DefRec (NDSS 2020). Secondary corpus: RAINCOAT (IEEE TSG),
Safety-Critical CPS Attacks (ACM HotSoS), DNP3/Bro IDS (ACM workshop), SDN In-network Honeypot
(arXiv) — all same group. Static base: CS/Engineering. Discipline: ICS and network security,
systems measurement.

## PRIORITY 1 — HARD PRESERVE
Never modify: `\cite{}` keys, math environments, variable names and notation, numerical results,
footnotes, `\ref{}`/`\label{}`, device and tool names. **Section I (Introduction) is authors'
verbatim text; citations only.**

## PRIORITY 2 — TARGET VENUE (NDSS / DefRec)
- Contributions live in a bulleted block inside the Introduction, verb-first bold headlines.
- Declare 2 to 4 labeled objectives early (RO1..RO3) and structure the Evaluation 1:1 against
  them, reusing the labels as bold run-in headings.
- Related Work is late (second to last), five themed bold-headed paragraphs, each closing on a
  mechanism or objective contrast, not a quality judgement.
- A separate Implementation section with per-artifact bold headers.
- Every mechanism gets a short security or trade-off argument; derivations go to an appendix.
- Result paragraphs: `In Figure~N, we show <what is plotted>.` then the number with a bound,
  then a mechanism sentence (`This is because ...`).
- Captions: 9 to 25 words, bold lead noun phrase, descriptive only. Legends inside the axes.
  Single column is the default figure width; full width is the exception.

## PRIORITY 3 — GROUP HOUSE STYLE (all five papers)
- Problem-first abstract, system named by sentence 2 or 3, ~200 words.
- Prior work is credited then bounded: "These approaches are effective against ... However, ..."
  The differentiator is objective or mechanism cost, never a score.
- Threat model states what the adversary can do **and** what it is assumed not to do.
- `Consequently,` is the causal spine (4 to 15 per paper). Hedging rides on the modal `can`.
- First person plural, agentive. Purpose-fronted infinitives: "To X, we Y".
- Sentences average 21 to 26 words; no long ornate sentences.
- Repeat core noun phrases verbatim; one fixed epithet for the artifact; no elegant variation.
- Gloss densely with `e.g.,` and `i.e.,`.
- Numeric bracket citations, stacked not ranged.
- Deployability is the evaluation criterion: practical, little overhead, negligible.

## PRIORITY 4 — STATIC BASE (CS/Engineering)
Applies only where P2 and P3 are silent: define every acronym at first use, active voice,
units on every quantity, no unexplained symbols.

## PRIORITY 5 — ALWAYS REMOVE
`novel` · `Moreover,` · em dashes · `In summary,` / `Overall,` as an opener · roadmap paragraph
(`The rest of this paper is organized as follows`) · `leverage` / `utilize` as verbs ·
`outperforms` / `fails to` / `suffers from` · significance apparatus (p-values, confidence
intervals, error bars, `statistically significant`) · `Finally,` closing an enumeration
(the corpus writes `Last,`) · `state-of-the-art` / `comprehensive` / `robust` as praise ·
bulleted lists outside the contributions block.

## DOCUMENTED DEVIATIONS (deliberate, do not "fix")
1. **Standalone Limitations subsection.** The corpus distributes scope carve-outs and has no
   Limitations section. This project's own gate (`pipeline/lin_check.py`) hard-requires the
   heading, and the repository contract requires the limitations to appear there in plain text.
   The project rule wins; the subsection stays, kept to one tight paragraph.
2. **Spread reported with every median.** The corpus reports point values only. Modern NDSS
   review expects variability, so interquartile ranges and standard deviations are reported as
   plain numbers. No significance-test language is used, which keeps this on-voice.
3. **No firstness claim asserted by us.** Four of five corpus papers make none. The authors'
   verbatim Introduction contains one; it is theirs and is left untouched.
4. **Adversary stays impersonal and plural**, following the group habit rather than DefRec's
   personification.
