# Phase 01 — Research Reviewer Worklog (Overclaiming Audit)

**Run reviewed:** `runs/20260716T024101Z_phase_01_real_trace_characterization/`
**Reviewer role:** venue-standard skepticism against Phase 01 claim limits (§10).
**Date:** 2026-07-15. Mode: READ-ONLY (this worklog is the only write).

Artifacts examined: `reports/ack_trace_summary.md`, `reports/data_quality_report.md`,
`reports/statistical_comparison.md`, `profiles/{sel751,ab1400,ion7550}_observed_profile.json`,
`validation/extractor_agreement.md`, `validation/manual_validation_report.md`, plus supporting
`stdout.log`, `manifest.json`, and `tables/transaction_anomalies.csv` for evidence backing.

---

## Verdict

**Hard §10 overclaims found: 0.** All eight claim-limit categories are satisfied with explicit,
correctly-worded caveats. The reports read as if authored directly against §10. Terminology
(no RESPONSE described as an application ACK) and ambiguous-transaction handling are both clean.

Two **minor precision / annotation** items are raised below. Neither is a product-family
overclaim; both concern a single-sample statistic being presented without an `n=1` marker. They
are "should annotate," not "must retract."

---

## §10 checklist — pass evidence

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | Allowed "in the captured <device> traces … X of Y" phrasing; no "always/family/Linux-causes/exact-processing-time/host=wire" | PASS | `ack_trace_summary.md:16` caveat; no `always`/`all devices`/`product family` device-behavior claims found by grep |
| 2 | Every device-behavior report scoped to captured traces of specific devices | PASS | `ack_trace_summary.md:16`; `statistical_comparison.md:32`; profiles carry `label_kind` (see #6). Methodology reports (data_quality, extractor_agreement, manual_validation) make no device-behavior claims, so need no family caveat |
| 3 | No DNP3 RESPONSE called an "application ACK"; CONFIRM not called a TCP ACK | PASS (clean) | grep for "application ack"/"app ack" = 0 hits. Classes are `COMBINED_ACK_RESPONSE` / `SEPARATE_ACK_RESPONSE` / `pure-ACK` — all correctly describe the *TCP* ACK relationship. CONFIRM is not discussed/conflated anywhere |
| 4 | pure-ACK→resp gap not presented as exact device processing time; host≠wire | PASS | `ack_trace_summary.md:16`: "The pure-ACK->response gap is a wire-visible interval, not the device's exact internal processing time. Host-side capture timestamps are not identical to wire timestamps." |
| 5 | OTHER_OR_AMBIGUOUS reported, not silently discarded | PASS | `data_quality_report.md:15` (count=0) and `:23-24` ("retained (not discarded) and enumerated in tables/transaction_anomalies.csv with their ambiguity_reason"). Verified: `transaction_anomalies.csv` has 97 rows with `classification_confidence` + `ambiguity_reason` columns |
| 6 | Profiles labeled "observed descriptive profile (NOT a deployment policy)" | PASS | All three profiles line 4: `"label_kind": "observed descriptive profile (NOT a deployment policy)"` |
| 7 | 22,988 stated as REPRODUCED this run, with isolated-run evidence | PASS | `data_quality_report.md:4-7` ("This isolated run reconstructed 22988 … REPRODUCED"); `ack_trace_summary.md:3` ("re-derived this run; none are carried from prior reports"). Evidence: `stdout.log:3` "reconstructed 22988 transactions"; `manifest.json` lists the six input PCAPs with sha256 |
| 8 | base-vs-L not over-read as temporal stability; effect sizes accompany distances (not p-value-only) | PASS | `statistical_comparison.md:32`: "compare only the captured base vs L traces; they do not imply temporal stability beyond the captured data. Effect sizes accompany the distances; no p-value-only claims are made." Table carries KS + W1 (distances) AND Cliff's δ + Cohen's d (effect sizes); no p-values present at all |

---

## Overclaiming flags

### No hard overclaims.

Every phrasing pattern §10 prohibits ("SEL-751 devices always send separate ACKs", "AB1400
always combines", "Linux causes …", "gap equals exact internal processing time", "host
timestamps equal wire timestamps") is **absent**, and in the two load-bearing cases the report
proactively states the *opposite* caveat (`ack_trace_summary.md:16`).

### Minor precision items (annotate, not retract)

**M1 — ION7550 single separate-ACK transaction (n=1) reported with full distribution stats, no `n=1` marker.**
ION7550 has exactly one `SEPARATE_ACK_RESPONSE` transaction across both captures (`separate%` =
0.025 of 3999 in the L capture).

- File/line: `reports/ack_trace_summary.md:11`
  > `| ION7550 | L | 3999 | 99.975 | 0.025 | 0.0 | 15.984 | 16.587 | 28.754 | 37.000 |`
  The `pure-ACK->resp med (sep) = 28.754` column value is the "median" of a **single** sample.
- File/line: `profiles/ion7550_observed_profile.json:33-46` (`pure_ack_to_resp_ms_separate`)
  > `"n": 1, "mean": 28.753996, "std": 0.0, "cv": 0.0, "p5": 28.753996, … "p99": 28.753996`
  Reporting `std=0.0`, `cv=0.0`, and identical p5…p99 for `n=1` can be misread as unusually
  *stable/deterministic* separate-ACK timing when it is one observation.
- Suggested fix: annotate the value with `(n=1)` in the summary column, and either suppress
  percentile/std/cv fields for `n<` a small threshold in the profile JSON or add an explicit
  `"note": "n=1; percentiles/std/cv are degenerate"`. `statistical_comparison.md:24-25`
  already handles this correctly by emitting `n/a` for the ION7550 pure-ACK KS/W1/effect-size
  rows — apply the same discipline to the summary and profile.

**M2 — Summary ack-mode percentages shown as exact 100.0 / 0.0 while 97 transactions were medium-confidence.**
Not an overclaim (the medium count is disclosed elsewhere), but the two documents are not
cross-linked.

- File/line: `reports/ack_trace_summary.md:9-14` present `combined%`/`separate%` as clean
  100.0 / 0.0 with no confidence footnote.
- Disclosed only at `reports/data_quality_report.md:18`
  > `- high: 22891   medium: 97   low: 0`
- Suggested fix: add a one-line footnote to the summary table pointing to the 97 medium-confidence
  classifications in the data-quality report (classification is cross-validated 60/60 manual and
  23/23 extractor-agreement, so the modes are well-supported — this is a traceability nicety,
  not a correctness issue).

---

## "Safe to state" vs "Must rephrase"

**Safe to state (as written, no change):**
- "In the captured SEL-751 traces, the device emitted a separate ACK for all 4,298 classified
  transactions (100%)." (per-device, scoped, matches `ack_trace_summary.md:13-14` + profile)
- "In the captured AB1400 traces, the device combined the ACK with the response for all 2,398
  classified transactions." (`ack_trace_summary.md:9-10`, profile)
- "In the captured ION7550 traces, 4,797 of 4,798 classified transactions were combined and 1 was
  separate." (`ack_trace_summary.md:11-12`, profile) — provided M1 annotation is applied to the
  single-sample separate-ACK timing.
- The 22,988 reconstruction count as **reproduced this run** (evidence: `stdout.log:3`, manifest).
- The base-vs-L distances **with** their effect sizes, framed as within-capture comparison only.
- The pure-ACK→response interval as a **wire-visible** interval (never as internal processing time).

**Must rephrase / annotate before reuse:**
- Any restatement of the ION7550 separate-ACK timing (28.754 ms, cv=0.0) **must** carry `n=1`;
  do not present it as a stable/representative separate-ACK latency. (M1)
- Do **not** promote any of these device rows to product-family statements
  ("SEL-751 devices always…", "AB1400 always combines…") in downstream phases — the §10 scope
  is the captured unit, not the model line. (Currently respected; flagged as a forward-looking guard.)

---

## Notes on run integrity (non-§10, informational)
- `manifest.json` records `git.dirty_tree: true` with the Phase 01 scripts among `dirty_files`.
  Reproduction provenance is otherwise strong (input sha256s, tool versions, Python 3.8.10,
  tshark 4.4.9, scapy 2.4.3). Worth a clean-tree re-run tag before any external citation, but
  outside the §10 claim-limit scope.
