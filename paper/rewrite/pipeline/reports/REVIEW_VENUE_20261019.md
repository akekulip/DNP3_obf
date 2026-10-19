# Adversarial venue review of the NOMAD draft (2026-10-19)

Reviewer: the `ieee-journal-reviewer` agent, reading `pipeline/build/main.pdf` and the claim matrix.
Its verdict for NDSS/CCS/S&P was a reject with resubmission encouraged; for TDSC, a major revision.

## Applied in the text the same day
- **Conclusion:** the offset direction was stated backwards. READ and SELECT are early; OPERATE is
  on target.
- **The fixed attacker on Size:** it falls to chance "in seven of the eight settings"
  (0.41 at D10_J10).
- **CLRT spread:** stated as "within 0.1 ms of D, in two modes about 40 µs apart" rather than "a
  few tens of µs". The D = 10 ms offset is described as possibly reflecting the mode proportions.
- **Window variance:** "three times lower" is now qualified as the median window.
- **READ points:** stated as 23 binary output status points (Group 10 Var 2), distinct from the SEL
  analog example in Table I.
- **Stale blocker tokens:** disclosed, about one per two timed transactions, with delivery
  unaffected.
- **L:** called an estimate; the envelope claim is limited to devices that acknowledge separately.
- **Limitations:**
  - the attackers are metadata-only;
  - device content stays readable;
  - RO1 independence follows from the design and was not tested across devices;
  - piggybacking devices follow the p_b path;
  - the OPERATE hold delays physical execution.
- **Contribution bullet:** now also gives the adaptive 0.69–0.80 when requests are read.
- **Related Work:** traffic normalization, defeating stack fingerprinting, predictive timing
  mitigation and content-based Modbus fingerprinting are cited (`normalization2001`, `smart2000`,
  `askarov2010`, `keliris2016`).
- **Reviewer's errors, checked against the sources:**
  - The 76 ms guarded budget does have a source: `guarded_budget_ns` in
    `release/audit/common_envelope.json`.
  - "At most one recirculation pass" comes from `m10_03/PART2_DESIGN_20261018.md` §1 ("plus at
    most one lap").

## Open: needs Philip and Dr. Lin (not fixable by editing)
1. **C1, the task versus the threat model.** Dr. Lin's protected threat model lets the adversary
   read function codes. Operation labels are then free, so READ/SELECT/OPERATE classification
   measures something the adversary already knows. Meanwhile the title and goal are device
   identification. The fix is to evaluate device identification across at least two outstation
   types, given operation labels, or to reframe the task.
2. **C4, little native timing signal.** The software outstation answers after a fixed 5 ms delay:
   native CLRT-only accuracy is 0.455, and the native SD is 0.06–0.11 ms. A run on the physical
   SEL-751 (spread 2.2–9.4 ms p05–p95), or with heavy-tailed, operation-dependent service delays,
   would test RO1. That needs new hardware runs.
3. **C2, ACK piggybacking.** NOMAD does not synthesize acknowledgments, so separate-ACK and
   piggybacking devices still differ (the ION7550 case in Fig. 4).
4. **Baselines and scale.** A measured constant-delay arm, an ACK-suppression or endpoint
   delayed-ACK baseline, Formby's classifier, and a concurrency experiment. OUT_HELD_REWAIT is about
   3,900 recirculation laps per transaction.
5. **Conformance by an independent tool,** and whether the 1-byte final transport segment or the
   two-byte qualifier is itself a NOMAD signature. The 31 ms ACK is visible.
6. **Strategy 3 generality:** only fixed response shapes are covered. Variable, event,
   multi-fragment and unsolicited responses pass through native.
7. **Advisor-text items:** see `LIN_DRAFT_REVIEW_20261019.md`, plus the reviewer's notes:
   - Stuxnet targeted enrichment centrifuges, not "nuclear power facilities".
   - The SRAM/TCAM sizes look like megabits written as megabytes.
   - The PRT naming and the "two proprietary features" wording should be checked.
   - The 03:62 strategies ("neutralize, mimicry …") are not implemented.
   - The keywords are a single term.
