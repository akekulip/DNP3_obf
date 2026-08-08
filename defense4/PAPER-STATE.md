# PAPER-STATE — Defense 4 DNP3 timing-obfuscation paper

Venue class: IEEE Transactions / security conference (ICS timing defense). Venue named at drafting.

## Current stage: acceptance gate CLOSED (partial); at Stage F/G (drafting/revision) for the paper

The experimental gate (the completion plan's Phase 6) is closed with a single verdict, re-derived
independently from raw evidence.

## Verdict: TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY

`timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md`. Accepted: the corrected binary's D2/D4 normalize the
SEL-751 CLRT to a fixed 10 ms with 0 bypass across 240 transactions each, reproduced over two
campaigns, quantified (spread 45.6-118x, entropy ≈12→≈2 states), with the lifecycle fix, fail-open,
and rollover proven by counters, and a fail-closed pipeline (78/78). Closed boundary (physically
blocked, not open defects): live controlled negatives, live paired byte identity, cross-device
classification; R11 carried OPEN.

## Stage ledger

- A Ideation / scope — DONE (the completion prompts are the charter).
- B Literature — reused the frozen timing-line references (`defense3/references.bib`).
- C/D Design, experiments, analysis — DONE: fail-closed pipeline; Campaigns A+B; targeted cases;
  reproducible compile; normalization quantification. Losses reported (late tails, D1 weak, blocked negatives).
- E Figures — DONE (ieee-paper-figures): topology, four-queue mechanism, per-mode timing sequence,
  CLRT ECDF, normalization. Reproducible, source-data hashes recorded.
- F/G Drafting/revision — Methods/Results drafted (`paper/METHODS_RESULTS.md`), detailed explainer +
  mechanism diagrams + code walkthrough written, visual PDF report built. Introduction stays
  QUARANTINED; it is rewritten to the bounded PARTIAL claim in the paper-integration pass (not yet done).
- H Review gauntlet — NOT started (paper-self-review / ieee-journal-reviewer).
- I-K Submission/rebuttal/talk — not reached.

## Blocked (needs on-site hardware, documented)

- Phase 2 live negatives: software outstation on switch dp11 + `-DD3_REPLAY_ON_HULK` build + Hulk on
  the DNP3 subnet (`timing/evidence/PHASE2_LIVE_NEGATIVES_BLOCKER.md`). ~15 min on-site to unblock.
- Phase 5 classification: needs a second comparable Case-A device.

## Next actions (when unblocked or resumed)

1. Paper Introduction rewrite to the PARTIAL bounded claim; then Stage H review gauntlet.
2. If hardware provisioned: run the live negatives (outstation ready) and, with a 2nd device, the
   classification study; that could lift the verdict toward full PASS.
