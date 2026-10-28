# Current execution journal

Earlier diary preserved byte-exactly at Archive/tracked/root/WORKING_NOTES.md and Git anchor63833e020.

## 2026-10-26 — approved repository simplification and stage-cut work

Current target:N<=10/E<=10, behavior preserved, then17models and one fresh2440-exchange matrix. Source promotion
verified byte-exact to c69. Immutable source/compiler comparison bundle copied to results/builds/c69_baseline.
Root navigation now describes only the current task. Paper relocation, current packaging/models and the raw-wire
status checker repair run as separate owned slices; no bulk source archival until their active dependencies detach.
No new hardware traffic. Per-slice results are under results/analysis/.

Repository migration is now complete:212,662 historical files moved by original tracked/local status; every move
verified. Archive inventory records242,403,444,964 logical bytes. All508 adjacent XZ/raw comparisons matched;
70,817,137,063 duplicate raw bytes pruned, with compressed copies and SHA proofs retained. Paper builds alone;
scientific prose/assets unchanged. Current checker derives CROB status from captured bytes and rejects forged claims.

Final comment-clean source97812585…83d887e compiles atN10/E10/T8/p1egress4 (c72_ne_14). Pipe0 physical savings:
12SRAM,7TCAM,4Map RAM,2stateful ALUs,7PHV containers; pipe1 unchanged. Raw state decreases64bits, with no extra
passes. The last cuts fused sequence classification and return-phase dispatch into existing keyed decisions.
Final named c72 package/model gate now being prepared. Lint caught missing visible-CLRT report definitions before
hardware; the checker owner is repairing them. No model or new hardware verdict yet. No commit/push in this task.

User requested pause until tomorrow. c72 smoke02 passed30/30; first attempt failed during SDK startup before
packets. Full17-model gate/hardware/reproduction/commits remain. Owned SDK processes/namespaces are stopped;
hugepages196 returned. Launcher config portability and conservative stdout retention edits need final checks
before smoke03. Read HANDOVER.md for exact resume instructions. No new hardware contact, commit or push.

Pause-time hook audit: remove make_conf.py's unused --offline vendor-check bypass. The only active caller runs
it on the switch and already checks PCI vendor identity. Lock missing/mismatched-vendor refusal and successful
verified generation with regression tests; make no model/hardware launches and keep the broader task paused.
Audit resolved while paused: removed unused make_conf.py --offline option and bypass guidance. Missing or
incorrect switch PCI vendor identity refuses config generation. RED: bypass regression failed; GREEN:30 targeted
hardware/config tests passed, pyflakes clean. No model or hardware launch; broader work remains paused.

## 2026-10-27 — resumed: harness closed, 17-driver model gate PASSED

Harness edits closed test-first (retention stdout rules, private model config): 6/6 mutations caught, suite 177/177,
paper 16/16 (results/analysis/harness_close_red_green.log). Smoke attempt03 PASS 30/30. Gate: 16/17 first pass; abandon
attempt01 FAILED only under ABANDON_T=1, an uncommitted relocation-time coverage change (committed gate and c69 ran T=0).
A/B: c72 T=0 PASS 12/12; c69 T=1 control invalid (historical fixture path). Philip chose original T=0 coverage; abandon
attempt02 PASS 12/12; model_summary --enforce model_gate_passed. T-enabled abandoned-SELECT behavior is UNCHARACTERIZED
(results/analysis/abandon_ab/). Next: hardware per PLAN step 2, approved to proceed by Philip 2026-10-27.
Hardware started. Native READ c72_native_20261027_01 PASS (2 READs OK, IIN 80 00, production unchanged, owner released
safe). Campaign _01 refused at dry-run: persistence --fixtures default separate_ack; lab.json also lacked c69's
--reconnect-policy protected. Both restored test-first (suite 178/178). Campaign rc01_hw_c72_20261027_02: freeze-check
10/10, exact-argv dry-run 10/10, 2,440 exchanges; controller launched. Results: results/hardware/campaigns/.

## 2026-10-28 — evaluation campaign complete

Qualification matrix 9/10 (block 10 loss_full t3 FAIL: relay select-window race, restoration verified). Evaluation
campaign 64/64 blocks, 49,408 exchanges, sufficiency gate PASS; analysis, figures, captions and report under
results/analysis/evaluation/ (REPORT.md). Two independent reviews (code, figures) fixed before delivery. Findings to
decide: first-request loss vs RO3; exploratory SELECT/OPERATE tail residual under Timing+Size. See HANDOVER.md.

## 2026-10-28 — final checks before commit

Third figure review and a numbers audit (both independent): figure and caption defects fixed, REPORT/HANDOVER wording
corrected (CROB count, size-only latency at D5, KS test count, first-request evidence). Figures are byte-stable.
Replay pre-check: the frozen replay.py cannot replay qualification blocks 06-08 (scenario.json, not result.json);
fixing it breaks the bound checker hash, so it was reverted; decision in HANDOVER open item 3. Tests: repository 199,
analysis 32, paper 16.
Shaded std bands removed from the histogram, signature and CDF figures at Philip's request (lines only); spread
stays in the box plots, F7, the bootstrap intervals and T1.
Committed b2634701d (layout, tooling, qualification) and 4e76d9f1f (evaluation), local only. Clean-checkout
reproduction of 4e76d9f1f: compile and model gate reproduced, frozen replay 2,242/2,440 (HANDOVER).
