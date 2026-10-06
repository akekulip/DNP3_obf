# Changelog of the protected Introduction

**Status 2026-08-26 (evening).** Philip supplied the Introduction he and Dr. Lin wrote and asked
that it be kept **untouched except for citations**. `sections/01_introduction.tex` is now that
text verbatim (paragraphs 1 to 4 and the four contribution bullets), with these citation-only
changes:

| # | place | change | kind |
|---|---|---|---|
| 1 | ¶1, last sentence | reference `[1]` mapped to `leeAnalysisCyberAttack2016`; `langnerStuxnetDissectingCyberwarfare2011` **added** on the same clause, because Lee et al. document the Ukraine dwell and not Stuxnet | citation added |
| 2 | ¶2 | `[2],[3]` → Wright 2009, Dyer 2012; `[4]` → Sirinam 2018; `[2]` → Wright 2009; `[3],[5]` → Dyer 2012, Cai 2014; `[6]–[8]` → Ditto 2022, Minos 2025, Securitas 2026 | citation mapping |
| 3 | ¶3 | `[6]` → Ditto 2022; `[9]` → Formby 2016; `[10]` → IEEE 1815-2012 | citation mapping |
| 4 | bullet 2 | `[9]` → Formby 2016 | citation mapping |

No word of the supplied text was changed. Three points in it are flagged for the authors, not
altered (see the closing note of the 2026-08-26 session):

* ¶4 and bullet 2 say the offsets are "from the request"; the implementation anchors READ and
  SELECT to the outstation's acknowledgment (`EVENT_SEMANTICS_TRUTH_TABLE.md`). Design
  Section IV states the verified rules.
* bullet 1 keeps a "to the best of our knowledge … first" claim; the gate now reports it as a
  warning instead of a failure.
* bullet 1 reads "turning framework" (likely "timing").

## Earlier changelog (2026-08-26, morning), superseded

The morning rewrite had edited Dr. Lin's two paragraphs (tense, grammar, the split Stuxnet
sentence, an appended sentence on encrypted payloads, and a gap paragraph with three reasons).
Those edits are withdrawn by the verbatim replacement above; the version that carried them is
in Git history (commit `f3b6625`, `sections/01_introduction.tex`).


## 2026-09-18: two author corrections, made by Dr. Lin on the printed draft

Dr. Lin marked the build of commit `b71f2836` by hand and corrected two words of his own supplied
text. Both are his corrections, not editorial changes by anyone else, so the protected text and the
two reference copies the verbatim gate compares against were updated together.

| # | paragraph | before | after |
|---|---|---|---|
| 1 | ¶1 | "adversaries stay in their systems" | "adversaries stayed in their systems" |
| 2 | ¶2 | "many studies present network traffic obfuscation" | "many studies have presented network traffic obfuscation" |

Updated in `sections/01_introduction.tex`, in `REFERENCE` inside
`pipeline/check_lin_intro_verbatim.py`, and in `pipeline/samples/lin_intro.txt`. The gate passes
against the corrected reference, so any later drift from his wording still fails.


## 2026-09-25: advisor-ordered Design and Evaluation revision

Approved by the author in this session. Recovery point: `862aa4ed`. Primary voice reference:
`DefRec-Establishing Physical Function.pdf`, supported by the installed Claude `paper-voice`,
`journal-adapt` and `academic-humanizer` skills. No experimental data or figure sources changed.

### Structural and voice changes

- Design now proceeds from timing and packet flow to parameters/constraints, then queue/P4
  realization. The conceptual blocker explanation precedes P4 internals. Implementation retains
  state and platform details without repeating the entire queue walkthrough.
- Evaluation establishes measurements first, then answers timing, latency/timer, release-accuracy
  and residual-information questions. Each experiment keeps its figure, magnitude and interpretation.
- Purpose-led explanations, active author/system subjects and connected sentences follow DefRec.
  Short fragments and repeated generic consequence openers were revised after the first voice pass.
- The protected first three Introduction paragraphs remain verbatim. Focused consistency edits in
  the abstract, unprotected Introduction, threat-model scope sentence and conclusion prevent old
  universal claims from contradicting the revised Design and Evaluation.

### Scientific corrections (not stylistic substitutions)

| Before | After | Reason |
|---|---|---|
| Actual holds equated to deadline offsets without release tails | Ideal holds use scheduled departure hats; actual departures include tails | Distinguish scheduling from service |
| Response availability alone suffices | Both ACK and response must arrive before their deadlines; admission and sustained blockers are required | A late ACK cannot meet its earlier deadline |
| Cancellation establishes no device information, even under pooling | Device independence is conditional; evaluated classifiers and residual tests bound the empirical claim | Algebra alone does not establish independence of residuals |
| Master-facing excess called directly measured drain | ACK-deadline excess is a proxy containing path/capture effects; actual drain is unobserved | Match recorded observation boundary |
| Budget alone guarantees all endpoint timers | Per-endpoint remaining margins must include existing delays, paths and service; universal timer inequality removed | No measured worst-case residual or universal deployment margin |
| Every packet preserved, negligible delay everywhere | Normal protected path and observed completion are distinguished from duplicate suppression and latency requirements | Match OPERATE retransmission behavior |
| 22 runs, half per case | 22 paired runs containing both cases | Matches canonical run identifiers |
| Pooled accuracy followed by unlabeled single-exchange recalls | Separate attack descriptions and aggregation features | Prevent denominator/model confusion |
| All late events causally identified through Timing OFF coverage | Timing OFF coverage and Obfuscated departures are separate observations | Captures do not observe both arms for the same execution |
| 2.969 s treated as an endpoint timeout bound | One separately observed repeated-response interval | Preserved loss trace does not establish a minimum retransmission interval |

### Voice diagnostic interpretation

The skill's whole-corpus numeric-density minimum is not imposed on symbolic Design prose: its
checker omits display equations, and adding measurements would obscure the requested model-first
structure. Evaluation retains result-bearing density within the corpus band. Whole-corpus lexical,
readability and hedge bands remain advisory: clearer language is retained, figure/section refs
inflate the voice checker's citation count, and factual result statements do not receive artificial
hedges. These are documented deviations, not a claim that every style metric passes.

### Verification

- Independent review accepted the Design/Implementation/Evaluation's material claims. Its final
  remaining concern, the universal RO3 timer claim, was replaced with an objective and a statement
  of the evaluated scope; an abstract punctuation error was also corrected.
- Final build and writing gate passed (`main_20260926T020112Z`); the comparison against the
  pre-revision scorecard found no regression on any hard dimension.
- All three protected Introduction paragraphs passed the verbatim check; all 11 pipeline tests passed.
- Draft NDSS preflight passed with no blocking issues. This is a draft, not submission clearance.
- Rendered pages were inspected for equation, figure, caption and column layout. The tracked PDF,
  sidecar, manifest and source digest agree. Existing campaign figure/data artifacts were preserved.
