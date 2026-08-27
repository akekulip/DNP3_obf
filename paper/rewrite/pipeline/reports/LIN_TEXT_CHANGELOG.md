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
in Git history (commit `060c1df`, `sections/01_introduction.tex`).
