<!-- RESUME:START -->
# RESUME — read this first

**Task:** rebuild the NDSS manuscript on `campaign_v2`. Plan:
`~/.claude/plans/warm-bouncing-waterfall.md`. Running unattended; resume here after any reset.

**Checkpoints 0–4 done. Next is 5, the data figures.**

| # | work | state |
|---|---|---|
| 0 | rescue the three adversarial reviews | **done** `4a782b20` |
| 1 | `campaign_v2`, 22 sessions, 63,360 exchanges, 0 anomalies | **done** (re-run after a capture defect) |
| 2 | sweep, 26 points, shipped policy restored | **done** |
| 3 | `reproduce.sh` end to end + publication gate | **done** — 8/8 steps, 132 tests, gate 0 problems |
| 4 | analysis + `evidence/campaign_v2/FINDINGS.md` | **done** `da61e605` |
| 5 | figures | mechanism `f178ccb9` and timeline `1e36d7a8` done. **To do: `fig_clrt` in Formby's binned style, `fig_release_tail` rebuilt from campaign_v2's sweep, declutter `fig_policy_coverage_cost` and `fig_leakage`, review `fig_ladder` and `fig_observation`** |
| 6 | prose, section by section | not started |
| 7 | repoint `CLAIMS_AND_LIMITATIONS.md` and the writing guide | not started |
| 8 | final verification | not started |

**Decided 2026-09-19: no dither.** The residual stays and is reported. The framework keeps the
property that the released interval *is* the configured value, and the paper states plainly that an
adaptive adversary retains a six-microsecond arrival-phase signature on OPERATE — 0.4452 against a
0.3333 chance level, 0.6500 when it pools twenty exchanges — while the device's own execution time
is gone (READ vs SELECT 0.7847 → 0.5071 against 0.5). The prose is unblocked.

**Next command:**

```bash
# figures, in this order
$RESEARCH_PYTHON defense4/timing/audit_current/tools/clrt_distribution_and_variance.py   # fig_clrt
# fig_release_tail must be rebuilt from evidence/campaign_v2/sweep, NOT the 2026-09-18 tail sweep
```

**Three bugs found and fixed today. Do not reintroduce any of them.**

1. `sweep2_run.sh` fed a `while read` loop from a here-string while the block shelled out to
   `ssh`, which reads stdin. The loop ended after one point and reported COMPLETE.
2. `campaign2_block.sh` and `sweep2_block.sh` killed tcpdump the instant the driver returned, so
   the kernel buffer was never drained. It cost the tail of 55 of 66 Timing OFF captures and none
   of the obfuscated ones — asymmetric between the two arms being compared.
3. Two repro tests asserted campaign_v1's *defect* as expected behaviour (obfuscated MI inside the
   null; the adaptive attacker recovering past 0.55 once the acknowledgment interval is added).

All three reported success while producing wrong data. Every one now has a loud check.

**State of the hardware.** The Tofino runs the corrected request-anchored build
(`anchor_fix_build`, `tofino.bin` sha `22e542f6…`), policy `D_A` 20 ms / `D_R` 8 ms /
`anchor_req` 1, restored and proved by the sweep.
`anchor_fix_build/launch_frozen_restore.sh` puts the frozen build back if ever needed.

**Do not:** modify `defense4/timing/implementation/` or any `raw_pcaps/`; push; rewrite history;
add Claude attribution to commits; run `remove-ai-marks` or any detector-evasion tool here.

**Decisions taken, do not reopen:** the anchor A/B stays out of the paper; all eight figures are
kept and redrawn; figures follow Ditto for mechanism and Formby for distributions; structure and
voice follow DefRec.
<!-- RESUME:END -->

# Working notes

## Status: 2026-09-18, the overnight figure and voice pass is done and unpushed

`main` is the only branch and carries everything. The history rewrite that stripped the
`Co-Authored-By: Claude` trailers was published on 2026-09-16, branch and tags both, and GitHub
lists one contributor. **Nineteen commits since then are local:** `origin/main` is at `f8be278e`
and local `HEAD` is at `932a9317`. Nothing has been pushed, per the standing rule.

The five closed pull requests keep `refs/pull/N/head` refs that still reach two pre-rewrite
commits. Only GitHub Support can purge those; they do not feed the contributors list.

Archives, all verified, in `/home/philip/Archives/`: `DNP3_post_rewrite_20260916/` (current
history plus `commit-map-old-to-new.txt`, the only way to translate a pre-2026-09-16 hash),
`DNP3_pre_rewrite_20260916/` (two bundles: the full backup, and the remote tip one commit further
on that the backup missed), and `DNP3_branch_bundles_20260915/` (the eight branches whose commits
`main` never had, now the sole copy).

## What changed in the 2026-09-15 pass

**Entry points and organisation.** `reproduce.sh` now runs the active campaign and puts the
retired corpus behind `--historical`. `REPOSITORY_MAP.md` names which tree is authoritative for
what. `CLAUDE.md` carries the real four-family figure table; the writing guide's withdrawn
`D_R` / `CLRT_target` notation is corrected.

**New code, none of it in the frozen tree.** `active_control/` holds a timing-only activation path
that can never enable shaping and a delay-admission policy keeping the master, outstation and
application bounds apart with provenance on every input. `active_probe/` holds a corrected
retransmission probe. 49 offline tests across the three.

**Hardware results.** Epsilon measured at **1,705 ns** (ACK) and 1,704 ns (RESP) on an
instrumented build, within 2 % of the inherited `T_TAIL_NS`. Loss-recovery retransmissions are
**delivered, not suppressed**. No detectable perturbation from the instrumentation at n = 200.
All three are reported in the manuscript, scoped to the build and sample that carry them.

## Branch cleanup: state and what is left

`BRANCH_PRUNE_20260915.txt` was recomputed against `main`. **Ten** remote branches are fully
contained in `main` and can be deleted with zero loss; the file records each head so any of them
can be recreated. **Eight** carry commits `main` does not have, and all eight are now bundled to
`/home/philip/Archives/DNP3_branch_bundles_20260915/` (608 MB, `README.md` beside them with the
restore command). `git bundle verify` passes on all eight — it must be run from inside a
repository, not from the archive directory, or it reports a false failure.
`fixed-transcript-experiments` mattered most there: 23 commits with no local branch, so before the
bundle the remote was probably its only copy.

## What the 2026-09-17 review changed

The review is at `DNP3_7388c31_Full_Review_20260917.md`, untracked on purpose: incoming reviews
live beside the repository, and what they find is recorded where the fix is.

**Implementation.** The OPERATE correction candidate was unbuildable as written: every generation
the parser admits is `0xC0`-`0xCF`, so the high bit it proposed to use as a released flag is
already set. Released generations now live in `0xD0`-`0xDF`, the four decode sets stay disjoint,
and the claim that a forwarded repair cannot disturb a later transaction is withdrawn, because the
shared sequence and acknowledgment trackers run before the verdict. Admission is bound to the
deployment: all three constraint checks must be present and passing, and the record must name a
build and a connection that match. The probe cleans up after an install that raises on its way
back and revalidates its own durations. An unverifiable write is reported as possibly applied.

**Evidence.** The canonical validator now checks what the review had to check by hand: the
response's application sequence against the request's, and every CROB status rather than the
first, which is 21,120 statuses over 10,560 control responses. Zero problems over 132 captures.

**Figures.** The leakage figure was unusable at column width and is now two readable panels, with
the confusion matrices in its data file. The policy figure names its series on the marks. Nothing
is below the 8 pt floor. Checked by rendering pages 9, 10 and 11 at printed size.

**Manuscript.** 13 main-body pages against a limit of 13; the venue preflight passes with no
blocking issues. The space came from repeated scope explanations, from narration of our own review
process, and from three floats whose numbers the text already carries. Open Science now precedes
Ethics Considerations. `pipeline/publish_manuscript.py` writes the PDF, its hash and the manifest
together, so they cannot disagree again, and the page-budget rule is stated positively with seven
tests behind it.

**Documents.** 87 prose documents down to 63. `NOTATION_MAPPING.md` held four contradictory
statements about `D_R` at once and five other files repeated the stale one; there is now one
definition. What was removed and where it lives is in `CLAUDE.md`.

## Next actions

1. **Publish.** Nineteen commits are local. `git push origin main` is an ordinary fast-forward;
   nothing here needs a force. It waits on Philip's word.
2. **Read the built PDF at printed size** before circulating it. All eight figures and pages 1,
   3, 5, 8, 10 and 12 were read that way on 2026-09-18; the rest of the prose has not been.
3. The OPERATE spent-marker loss path is specified but not implemented or run. It needs the
   relay-facing link instrumented and a separately authorised hardware session
   (`audit_current/OPERATE_RETRANSMISSION_RISK_20260916.md`).
4. Optional: the duplicate live-window case stays open, and a hardware adapter for the activation
   profile does not exist.

## Overnight pass of 2026-09-18 — what was done, and the four things needing a decision

**The prose now speaks in the introduction's voice on every axis but one.** Measured with
`aivoice` against the five human-written reference papers, the body had been using the copula
(is, are, was, were) at 27.7 per 1000 words, above the human maximum of 21.4 and more than double
the corpus median of 12.8. About seventy of those are gone; the body measures 13.8 in source and
14.4 in the rendered PDF. Every other tier-2 measure is inside the human band. The exception is
mean sentence length at 22.5 against a band of 19.9 to 21.8, and the introduction Philip wrote by
hand measures 24.3, so the two references disagree and the longer reading was kept.

**Six figure defects were found by rendering each figure and reading it, not by trusting the
generator.** Figure 2's read-lane bracket carried a bare italic `c` that appears nowhere else in
the paper or in `NOTATION_MAPPING.md`; it reads CLRT now. Figure 4 drew a master-facing arrow off
the control lane, which holds the outgoing OPERATE and feeds only the relay. Figure 5's overflow
category was a two-pixel sliver whose share is now written beside it. Figure 6's annotation was
cut through by the dashed configured-value line. Figure 7(d)'s legend sat on a 90 ms whisker.
Figure 8(a) abbreviated a condition to "adapt.".

**Four things need Philip's decision, and none of them were decided unilaterally.**

1. **The `natural-voice` academic profile pulls against Philip's own voice on three axes.** Its
   `academic.json` is calibrated on the five Lin-group papers, and on participial clauses,
   transition openers and copula surrogates his 707-word introduction sits far outside that band.
   Those three gaps are small-sample artifacts, not style: his 11.33 copula-surrogate rate is the
   regex counting the *noun* "features" eight times in 707 words. Only the copula gap was real on
   both references, and only the copula gap was acted on.
2. **The introduction Philip pasted contains a firstness claim** ("to the best of our knowledge,
   is the first"). `lin_check`'s `firstness` check blocks it and `CLAUDE.md` says firstness is not
   asserted in this repository. It is not in the compiled draft. Philip decides whether the rule
   stands or the claim goes in.
3. **The two-column architecture SVG cannot be added.** The body is at 13 of 13 pages and the
   drawing overlaps Figure 4, which already shows the pipeline. Adding it costs a page and
   duplicates a figure.
4. **The multi-observation leakage result is computed but not in the paper.**
   `campaign_v1/repro/multiobs_leakage.py` runs as step 5b and publishes `multiobs.json`. Putting
   it in the evaluation needs a paragraph of space that the page budget does not have.

## Standing constraints

Frozen `defense4/timing/implementation/` and every `raw_pcaps/` path are byte-identical to
`8278346` and must stay that way. Dr. Lin's first three Introduction paragraphs are protected by
`check_lin_intro_verbatim.py`. `build.sh` after every manuscript edit; `lin_check --compare` must
show no regression. `configure-all` leaves `shape_enable = 1` — observed five times on hardware on
2026-09-15 — so any run must force it to 0 and read it back.


<!-- AUTO-HANDOFF (PreCompact/auto) 2026-09-17T22:11:13Z -->
### Compaction handoff — 2026-09-17T22:11:13Z
- Git: branch `main`, 3 uncommitted file(s): paper/rewrite/sections/02_background.tex paper/rewrite/sections/06_evaluation.tex paper/rewrite/sections/08_conclusion.tex 
- Last verification run recorded: 2026-09-17T22:11:13Z	cd /home/philip/Projects/DNP3 python3 - <<'PY' import pathlib E = {} # ---- conclusion: one 68-word sentence carrying th
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-09-18T04:14:44Z -->
### Compaction handoff — 2026-09-18T04:14:44Z
- Git: branch `main`, 11 uncommitted file(s): WORKING_NOTES.md paper/rewrite/sections/02_background.tex paper/rewrite/sections/03_threat_model.tex paper/rewrite/sections/04_design.tex paper/rewrite/sections/05_implementation.tex paper/rewrite/sections/06_evaluation.tex paper/rewrite/sections/07_related_work.tex paper/rewrite/sections/08_conclusion.tex paper/rewrite/sections/09_ethics_openscience.tex 2022_NDSS_ditto dnp3_timing_obfuscation_architecture_sbo_twocol.svg 
- Last verification run recorded: 2026-09-18T04:14:29Z	cd /home/philip/Projects/DNP3/paper/rewrite python3 - <<'PY' import pathlib p=pathlib.Path("sections/06_evaluation.tex")
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.
