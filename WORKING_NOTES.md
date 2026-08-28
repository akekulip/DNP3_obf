# WORKING_NOTES.md — final timing-paper repository

Last updated 2026-08-26 (end of the manuscript rewrite session).

## Task

Complete the timing-only IEEE manuscript in Dr. Lin's structure from the verified timing
evidence, on one branch, with every claim bounded by `defense4/timing/CLAIMS_AND_LIMITATIONS.md`.
The experiment is finished; no hardware, size, or push actions.

## Status — manuscript complete to the evidence; branch pushed, draft PR open, not merged

- Branch `paper/final-timing-rewrite-20260826` (from `final/timing-paper-20260824` at `22db6e0`),
  single checkout `/home/philip/Projects/DNP3`. Commits: Phase 0 reports and audit; evidence
  corrections (truth table, manifest D_A/D_R, Obfuscated arm name); figure relabel; manuscript
  and gate; cleanup and archive; final build and audit.
- `paper/rewrite/main.tex` + `sections/00…08` build to a 10-page IEEEtran conference PDF; the
  gate (`pipeline/lin_check.py`, rewritten to the brief's check list) passes; all eight figures
  are in the body before References; every result number traces to `timing_stats.json`.
- Two release rules established from the source and the wire (`pipeline/reports/EVENT_SEMANTICS_TRUTH_TABLE.md`):
  read path anchored to the relay ACK (`t_A + D_A`, `t_A + D_A + D_R`; D_A = 20 ms, D_R = 4 ms;
  CLRT = D_R) and control path anchored to the request (`T0 + A`, `T0 + R`, OPERATE to relay at
  `T0 + J`; echo − ACK = R − A = 4 ms). The earlier Design draft had the read rule wrong.
- Arms are **Timing OFF / Obfuscated** everywhere (figures regenerated with that legend under
  Python 3.8.10 / matplotlib 3.7.5; data CSVs unchanged).
- Stale writing-pipeline documents, the old section drafts, `refs.bib`, the old `main.pdf` and
  the retired checker's demo inputs are in `/home/philip/Projects/DNP3-local-archive-20260826/`
  (hash-verified manifests) and in Git history (`git show e8382d0:<path>`).

## Open decisions (Philip's)

1. Author block supplied (Akekudaga, Lin; University of Rhode Island; uri.edu emails).
2. Venue: NDSS, 13-page limit (confirmed 2026-08-26); the build is 10 pages in the IEEEtran
   conference template, to be moved to the NDSS template at submission.
3. The Introduction is Philip's verbatim text (2026-08-26 evening). Flagged, not changed: "offsets
   from the request" (reads are ACK-anchored), the firstness claim, and "turning framework".
4. `paper/final-timing-rewrite-20260826` is pushed; a draft PR is open and not merged; `main` untouched.
5. No licence file exists.
6. `remove-ai-marks` (the global final-writing step) was not run: the brief for this session
   forbids watermark-removal and detector-evasion tools in this repository.

## Next action

Philip reviews the PDF (`paper/rewrite/main.pdf`) and the open decisions above; then supply the
author block, choose the venue, and decide on the push. Future validation of the evidence, if
ever authorised: a rerun with `shape_enable=0` and a relay-facing tap (`EVIDENCE_AUDIT.md` §9).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-08-27T19:23:24Z -->
### Compaction handoff — 2026-08-27T19:23:24Z
- Git: branch `paper/final-timing-rewrite-20260826`, 0 uncommitted file(s): 
- Last verification run recorded: 2026-08-27T19:23:22Z	S=/tmp/claude-1002/-home-philip-Projects-DNP3/1c321c75-dbad-434e-b965-443eb22f5f3e/scratchpad; cat > $S/campaign_run.py 
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

## 2026-08-27 — v1.0 campaign session s01 collected (READ + SBO, real hardware)

- Root cause of the frozen OPERATE rejections was the driver reusing the DNP3 application sequence
  (SELECT seq=n, OPERATE seq=n) -> NO_SELECT. Fixed: OPERATE seq=n+1 -> SUCCESS. Relay settings
  audit confirms indices {1,3}=RB02/RB04 drive no output (only RB07/index 6 has fanout, to breaker
  close); so operates complete at the protocol layer and move no contact. No relay reconfiguration
  needed for a timing (transaction-class) paper.
- Session s01 = 6 blocks x (400 READ + 40 SBO), interleaved and spaced, shape=0 both arms, master-
  facing capture, balanced randomized order (OFF,D4,D4,OFF,D4,OFF), seeds 10001-10006.
  Result: native READ/SELECT/OPERATE = 2.10 / 1.7 / 2.9 ms (distinct); obfuscated all = 4.000 ms,
  SD ~0.01 ms. 0 dropped/failed transactions. Frozen at
  defense4/timing/evidence/campaign_v1/s01/ (pcaps + jsonl + MANIFEST/sha256/timing summary +
  tools). Untracked, not committed.
- Loaded binary provenance frozen: p4 sha 7ce3..61, tofino.bin 33fa..aa, conf 3d47.., c13c..
- Rig now: unified12 loaded on Tofino (decps@10.10.54.81, gRPC 50052), mcp_fabric still STOPPED,
  Vision holds 192.168.10.1. Restore mcp: sudo setsid nohup bash /home/decps/mcp/p4/launch_mcp_switchd.sh

## Next action
- Collect s02..s06 across >=3 days (same campaign_block.sh, distinct seeds) for the session-disjoint
  split; then wire campaign_v1 into the figures/stats and decide whether the manuscript adopts v1.0
  as its dataset (it currently cites the frozen single-session evidence).

## 2026-08-28 — v1.0 campaign COMPLETE (22 sessions)
- 5h run done. 22 sessions (s01..s22) in defense4/timing/evidence/campaign_v1/. 63,360 txns
  (52,800 READ / 5,280 SELECT / 5,280 OPERATE), 0 anomalies, 132 pcaps + 132 jsonl, 40 MB, all
  sha256-verified. Rollup: DATASET_ROLLUP.json. native READ/SEL/OP = 2.118/2.046/2.942 ms;
  obfuscated all 4.000 ms. Untracked, not committed, nothing pushed.
- Next: decide whether the manuscript adopts campaign_v1 (session-disjoint 4/1/1 split now
  feasible across 22 sessions, though all within one 5h window — not multi-day) and rewire
  figures/stats; then re-run the Lin gate.

## 2026-08-28 — campaign_v1 figure suite generated (ieee-paper-figures)
- derived/transactions.csv: 63,360 per-transaction rows (session, block, arm, class,
  clrt_ms, ack_ms, rt_ms) extracted from the 132 master-facing pcaps.
- Five figures in campaign_v1/figures/ built via defense4/timing/analysis/figstyle.py
  (7.16in / 3.5in exact, 9pt Times embedded subset, opaque white, provenance sidecars):
  c01 cross-session stability, c02 CLRT ECDF, c03 spread collapse (x450-480),
  c04 feature overlap + zoom inset, c05 session-disjoint leakage.
- KEY NEW FINDING: session-disjoint classifier (leave-one-session-out, 22 folds).
  CLRT only -> OFF BA 0.651, Obfuscated BA 0.333 (exact chance), MI 0.266 -> 0.007 bits.
  CLRT+ACK+RT -> OFF 0.746, Obfuscated 0.655. The ACK latency differs by path
  (READ/SELECT ~21.3 ms vs OPERATE ~20.65 ms), so a residual class signal survives.
  Must be disclosed in limitations; visible in c04 inset and c05 second bar pair.
- Figures are NOT yet wired into the manuscript (which still cites the frozen single session).
- Figures cleaned per instruction: NO explanatory text inside figures (legends, axis/tick/
  category labels and (a)(b)(c) tags only); reference lines named in the legend. Rasterised
  scatter now embeds at 600 dpi in the PDF (figstyle.save passes no dpi; raised via rcParams).
- Added fig_c06 (CLRT + ACK anchors) and fig_c07 (OVERHEAD). Overhead result: +21..23 ms
  response time per transaction; ZERO packet/byte overhead (all 132 captures identical:
  1448 frames / 130,708 wire bytes / 153,900 file bytes in BOTH arms); closed-loop sequential
  poll rate ~370 -> ~40 txn/s. Seven evaluation figures generated; recommend showing six
  (drop c03, its fold numbers go in prose).
- fig_c00_parameter_choice added: the offset is a coverage/latency trade-off. D = D_A + D_R
  must exceed the native CLRT tail (switch can only release what it already holds). D=24ms
  covers 99.905% of native transactions; 60ms would buy only +0.082pp for 2.5x the delay, so
  24ms sits at the knee. The uncoverable 0.095% PREDICTS the measured pin-miss (READ 0.091%
  beyond 1ms); native READ CLRT reaches 83.5ms, explaining the 53ms max departure. The tail
  is therefore a designed coverage limit, not a defect.

## 2026-08-28 — parameter sweep (18 points) + Tier-1 figures. 12 figures total.
- SWEEP (defense4/timing/evidence/campaign_v1/sweep/): CLRT == D_R exactly at fixed budget
  D=24 (D_R=2,4,8,12,16,20 -> CLRT 1.999,3.999,8.001,12.001,16.000,20.001) with response time
  constant 25.31-25.33 ms. Cost is set by D, the observable by D_R; they are INDEPENDENT.
- OPERATING ENVELOPE: sweeping D_A at D_R=4, ACK tracks D_A then SATURATES at 31.07 ms and the
  pin breaks (CLRT 5.50 @ D_A=32, 9.51 @ D_A=36, reproduced). Matches the program's fail-open
  horizon H = 30.8 ms (P4 line 1572, BUDGET_DEFAULT=18000). Usable region D_A+D_R < H, and the
  tail needs ~24 ms, so the window is narrow and now measured. Tightest pin is exactly at the
  chosen (20,4): CLRT sd 0.007 ms.
- MODES D1/D2/D3 ARE NOT IN THIS BINARY. Control plane accepts mode=1/2/3 and reads back OK,
  but the unified12 datapath keeps only OFF and D4 (its own source says so, line ~2790).
  Measured: D2 (D_A=0) and D3 (D_R=0) give NATIVE timing (CLRT 2.108/2.098, ACK ~0.55).
  A four-mode comparison would need a different build -> barred by repo rules.
- J has NO master-visible cost and is not recoverable per transaction from a master capture.
- Tier-1 figures: t01 native multi-modality (why it leaks), t02 confusion matrices (what leaks:
  OPERATE recovered at 0.87 via ACK, READ/SELECT stay confused), t03 pin-departure tail.
- Chip restored to the campaign baseline D4 D_A=20 D_R=4 shape=0.
- LEGENDS: all 12 figures now carry their legend OUTSIDE the axes, in a shared band above the
  panels (_bin/figlegend.py top_legend). Removed all 11 in-axes legend calls; canvas heights
  raised (2.35->2.72, 2.5->2.86) so panel area is preserved. Printed widths unchanged
  (515.52 / 371.17 / 252 pt); fonts still embedded subset Times New Roman.
- Sweep extended to the ends of the allowed range at fixed budget D=24: D_R = 1 -> 22 ms gives
  CLRT 0.998 -> 22.001 ms with response time constant 25.307-25.339 ms. 20 sweep points total.
  fig_c08(b) now rings the two endpoints, named in the LEGEND ("D3 and D2 policy limits") so the
  no-text-in-figures rule still holds. Exact limits D_R=0 / D_A=0 are refused by the parameter
  checks, so the sweep approaches but does not reach D3 / D2.
- DRAFT_CONTRIBUTIONS_AND_FRAMING.md written (campaign_v1/): 4 verb-first contributions +
  Design "policy family" paragraphs + Implementation paragraph stating the 12-stage build
  realizes bypass + dual-deadline only, with D2/D3 as parameter limits and D1 not implemented.
  Style-checked: 0 em dashes, 0 stale arm labels, 0 banned words, 0 size claims.
  MULTI-MODE FRAMING RULE: claim a parameterized policy with a measured envelope, NEVER four
  implemented operator-selectable modes (modes 2/3 install and read back but are inert).

## 2026-08-28 — AUDIT PASS (P4 vs claims, figures vs data, DefRec conventions)
DATA: all 22 sessions sha256 OK; 63,360 rows with exact per-arm/class counts; 232 figure data
rows re-derived from raw data with ZERO mismatches.
CAPTION DEFECTS FOUND+FIXED: fig_c03 quoted POOLED IQR while the figure plots the median of
per-session IQRs (OPERATE 2.83 -> 2.750; READ 2.79 -> 2.779; SELECT 2.70 -> 2.690); c06/t02
"about 0.6 ms" -> measured 0.686 ms.
P4 AUDIT (P0, must fix before submission):
 1. "D1/D2/D3 removed from the datapath" is FALSE. Mode branches remain (p4:3122 D1/D3,
    3048+3101 FAIL_OPEN) and the COMPILED DEFAULT IS MODE_D3_ACK (p4:1145, 2380). What confines
    the build is that tbl_decide_fresh has entries only for OFF and D4, so no other mode seeds
    the reservoir. D2/D3 are NOT structurally identical to OFF (they still arm reg_tag and take
    a loopback pass) -> say "indistinguishable in these measurements". CORRECTED in FIGURES.md
    and DRAFT.
 2. shape_enable contradiction: CLAIMS_AND_LIMITATIONS L1 said shaping was active in EVERY
    timing capture - FALSE for campaign_v1. L1 now SCOPED to final_read_sbo, and records that
    campaign_v1 MEETS the clean timing-only requirement L1/EVIDENCE_AUDIT §9 asked for.
 3. "no packet/no byte" is true ONLY for shape_enable=0; with shape=1 one response becomes TWO
    master-facing frames. Qualified in FIGURES.md.
 4. Horizon is counted FROM THE REQUEST (token burst seeded there), so the window is
    t(request->ACK) + D_A + D_R < H. That is why saturation measured 31.07 not 30.8. Corrected.
 5. J is drawn PER PACKET and latched per OPERATE; J-independence rests on control-plane
    assertions (A > J_max + native ACK; R > J_max + native resp), NOT a datapath invariant.
 6. OPERATE T0-anchoring is CONDITIONAL on the SBO hold engaging; with R-A = D_R = 4 ms the CLRT
    cannot separate request- from ACK-anchoring -> the ACK-latency residual is what PROVES
    request anchoring. Reframe the residual as corroborating evidence, not only a leak.
 7. PROVENANCE_CONSTANTS.json "native_arm" -> "timing_off_arm" (forbidden term, machine-readable).
 STILL OPEN: S3 response-retransmission suppression and S4 post-release OPERATE dedup are not in
 CLAIMS_AND_LIMITATIONS; *_TICKS constants hold NANOSECONDS; quote 12 ingress / 6 egress stages;
 -DU_BOR compile flag attested only by prose.
DEFREC CONVENTIONS (measured): captions 9-25 words median 14.5, bold lead noun phrase, DESCRIPTIVE
 not interpretive, only statistic named is the CI, axis template "The x-axis specifies ...; the
 y-axis indicates ...". Result paragraph = "In Figure N, we show X." + number + "This is because".
 Legends INSIDE the axes in a box. Bars hatched AND coloured. Evaluation ~25% of body, 1:1 against
 RO labels; Related Work last-but-one and <5%; NO Limitations section (bounded at point of claim).
APPLIED: all 12 captions rewritten to 12-23 words (median 18); bars now hatched; interpretation
 moved to figures/BODY_PROSE.md in DefRec three-move form.
DEVIATION TO DECIDE: DefRec puts legends INSIDE the axes; ours are OUTSIDE (Philip's instruction
 after real collisions). Keep outside unless he says otherwise.

## 2026-08-28 — MANUSCRIPT UPDATED TO campaign_v1. Build PASS, 12 pages.
Decision taken: campaign_v1 is the manuscript's evidence base (it is the clean timing-only
dataset L1 asked for; shape=0 in both arms).
SECTIONS CHANGED:
 - 00_abstract: 22 sessions / 63,360 txns; CLRT 2.116/2.050/2.937 -> 4.000 ms, IQR 0.006;
   session-disjoint BA 0.651 -> 0.333 (chance), MI 0.266 -> 0.007 bits; +21-23 ms, no packet or
   byte; offsets set cost and observable independently; residual ACK-anchor difference disclosed.
 - 01_introduction: UNTOUCHED (protected, verbatim).
 - 02_background: measured CLRT sentence refreshed to three classes.
 - 04_design: ADDED "A family of release policies" (D2/D3/D4 as parameter cases, D1 event-driven
   and not implemented) and "Choosing the budget" (D is both coverage knob and cost; observer sees
   only D_R; fail-open horizon H bounds from above).
 - 05_implementation: ADDED "Which policies the build realizes" (disposition tables carry entries
   only for bypass + dual-deadline; other modes installable but never arm -> consequence of the
   12-stage fit). Rewrote "What ran, exactly": size datapath DISABLED in both arms for this
   campaign (was: enabled in both) -> the old caveat no longer applies.
 - 06_evaluation: REWRITTEN on campaign_v1. Testbed / Data+Extraction (22 sessions, session-
   disjoint protocol) / RO1 / RO2 / RO3 / Cost / Choosing the Offsets / Limitations. Lin three-move
   result paragraphs ("In Figure N, we show ..." + number + "This is because ...").
 - 08_conclusion: numbers updated; future work now = relay-facing tap + shared anchor.
FIGURES: 11 total = 3 schematics (Figs 1-3) then 8 data plots (Figs 4-11), DefRec ordering
 (all schematics before any data plot). All data figures regenerated at 516 pt = \textwidth and
 typeset as figure*. Captions cut to 12-23 words with bold lead noun phrase. Box-plot medians now
 carry the arm colour so the Obfuscated hairline box is visible.
GATE: build.sh PASS (compile rc=0, gate rc=0). Two gate collisions fixed: "timing on one relay"
 tripped stale_labels; "single 49-byte payload" tripped size_claims -> "one application-layer
 segment". 0 unresolved refs; nothing after References.
PDF: paper/rewrite/main.pdf, 12 pages, sha256 5dd9ea50e8fffbda1ef5f3e6a73765aea4693047a461b3a54c8bbd077870ee9a
 (fresh build lands in pipeline/build/main.pdf; root main.pdf was stale until copied - watch this).
STILL OPEN: S3/S4 reliability changes are now IN the Evaluation limitations but not in
 CLAIMS_AND_LIMITATIONS.md; *_TICKS-means-ns note; archive the -DU_BOR compile invocation.

## 2026-08-28 — figures to NDSS house style; evaluation register corrected
LEGENDS: moved back INSIDE the axes in a drawn box (DefRec convention: every legend inside,
 top-left or top-right, nothing outside). Collision avoided by giving each figure real headroom
 (c01 ylim ->9.2, c05 ->1.28, c06 ->90/200, c07 ->400, c08 ->52) rather than by moving the box out.
 Panel tags flipped to the upper-RIGHT on the five figures whose legend is upper-left, so the
 legend no longer hides "(a)".
WIDTHS: four figures converted to SINGLE COLUMN (252 pt) with panels stacked 2x1 - c00, c05, c07,
 c08 - and their LaTeX floats changed from figure* to figure. Full width (516 pt) kept only for
 the three-panel figures and the RO1/RO2 headline: c01, c02, c06, t02. Now 4 single-column vs
 4 full-width, closer to DefRec where 252 pt is the dominant unit.
REGISTER (Philip: "the paper is not an audit document"): cut 205 words of defensive hedging from
 the Evaluation. Specifically: the "Control point" paragraph reduced to one clause; the RO2 residue
 reframed from a confession into "The anchors are visible in the data" (the 0.686 ms gap is what
 the two anchors PREDICT, so it confirms which rule ran); dropped the aside about the J guarantee
 living in the control plane rather than the datapath; RO3 closes on the outcome ("removed as a
 class signal ... which a common anchor would close"); coverage paragraph ends "The budget
 therefore predicts its own residual."; Limitations cut from five bold paragraphs to ONE tight
 paragraph (the gate still requires the heading).
BUILD: PASS, 12 pages, 0 unresolved refs, 11 figures (3 schematics then 8 data plots).
 main.pdf sha256 3959f66100ef62d7bab84cd581018138255b09e162e5261f7ac3af3da93c8e53

## 2026-08-28 — figure consolidation into 2x2 grids; evaluation reordered
GRIDS (_bin/make_figures3.py): two 2x2 figures replace four separate ones.
 - fig_g1_offsets: (a) native CLRT tail per class, (b) not-coverable vs added latency D with the
   operating point starred, (c) D_A sweep vs the fail-open horizon, (d) fixed budget D=24 with the
   split varied and the policy limits ringed.  Replaces fig_c00 + fig_c08.
 - fig_g2_leakage: (a) balanced accuracy, (b) mutual information, (c)(d) the two confusion
   matrices under the mechanism.  Replaces fig_c05 + fig_t02. Panel tags folded into the
   confusion titles to avoid colliding with them.
PAPER now has 9 figures (was 11): 3 schematics + 6 data. Floats: 2 single-column (c06 intervals,
 c07 cost) + 4 full-width (g1, c02, c01, g2).
REORDER: "Choosing the Offsets" moved from last-before-Limitations to THIRD (after Data and
 Extraction, before RO1). Two reasons: it fixed a hard gate failure (figures_after_refs - the
 offsets float was spilling past References at page 11), and it reads better, since the reader
 now learns why D=24 ms before seeing every result pinned at 4.000 ms.
 Evaluation order: Testbed / Data and Extraction / Choosing the Offsets / RO1 / RO2 / RO3 / Cost /
 Limitations.
BUILD PASS, 12 pages, 0 unresolved refs. main.pdf sha256
 58a77bad49486486a1d2e59834cf107922e9d5b114d9f5ae3b69019629b5c216
IN FLIGHT: journal-adapt Phase 1 corpus analysis (style cards for the four non-DefRec Lin-group
 papers + aggregate journal style card). DefRec already mined; do not redo.

## 2026-08-28 — journal-adapt run fully (Phase 1 + Phase 2)
PHASE 1: style cards built for the four non-DefRec Lin-group papers (RAINCOAT/TSG, CPS-attacks/
 HotSoS, DNP3-Bro/ACM, SDN-honeypot/arXiv) + aggregate journal style card separating GROUP HOUSE
 STYLE (all five) from NDSS-SPECIFIC (DefRec only). Distilled to paper/rewrite/dynamic_writing_skill.md.
 Corpus measurements worth keeping: "novel" 0 occurrences in 42k words; "Moreover" 0; em dashes 0;
 roadmap paragraph 0/5; NO paper has a Limitations section; NO inferential statistics anywhere
 (no p-values/CIs/error bars); hedging rides on the modal "can" (5.6-14.4 per 1k); "Consequently,"
 is the causal spine in all five; enumerations close with "Last," not "Finally,"; citations stacked
 "[1][2]" never ranged; prior work is credited then bounded, never "outperforms/fails to".
PHASE 2 DIAGNOSIS: draft scored 4.6/5 - already clean on 11 of 11 red flags (the single
 leverage/utilize hit was the NOUN "test harness"; both itemize blocks are the contributions and
 RO lists, which are legitimate). Only real gap was gloss density: 0 "e.g.," where the corpus runs
 39. Applied 3 glosses (control point, campaign block order, event policy) -> 2 e.g. / 6 i.e.
 Score after 4.8/5. lin_check --compare: NO REGRESSION on every hard dimension.
DOCUMENTED DEVIATIONS (in dynamic_writing_skill.md, deliberate, do not "fix"): keep the standalone
 Limitations subsection (project gate hard-requires it though the corpus has none); report spread
 with every median (corpus reports point values, but NDSS review now expects variability - no
 significance language used); assert no firstness of our own; adversary stays impersonal.
ARTIFACTS: paper/rewrite/dynamic_writing_skill.md, paper/rewrite/REVISION_LOG_JOURNAL_ADAPT.md.
BUILD PASS, 12 pages, 0 unresolved refs, 9 figures.
 main.pdf sha256 c55ecf85032786e2125c3c8697b6ce54304f080269e298f1adb908feada81c14
