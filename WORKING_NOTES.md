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
attempt01 FAILED only under ABANDON_T=1, an uncommitted relocation-time coverage change (committed gate and c69 ran
T=0).
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

## 2026-10-28 — figure redesign (P4USE style)

Philip found the grid figures crowded and supplied two reference papers (Archive/papers/). Approved plan: 8 main
figures (fig01-fig08, at most two panels, D as x-axis, D = 5 ms for distributions) and 39 per-D supplementary figures
(S01-S12), P4USE colours, legend below, no bands, captions with one result sentence. New modules fig_style.py,
figs_main.py, figs_supp.py; eval_figures.py is now the driver. Tables, verdicts and REPORT_NUMBERS byte-identical;
figures byte-stable across runs. Tests: repository 199, analysis 35, paper 16.

## 2026-10-28 — handover update and push

An independent review of the redesigned figures fixed the Fig. 7/REPORT pause wording (26.6-26.8 ms after READ,
0.8-1.0 ms after SELECT/OPERATE) and added the joint-feature residual to the Fig. 4 caption; committed 986320d0a.
HANDOVER, PLAN, current.json and these notes updated; Philip asked for main to be pushed to origin.

## 2026-10-28 — audit correction-and-validation pass (plan: ~/.claude/plans/we-were-on-tract-expressive-planet.md)

Philip's order: A/B/C plus read-only D1 now; then the observation path (D2-D3), recovery (E), confirmation (F).
Done so far:
- A1/A1b frozen-tree replay: original stops at 1,934; the adapter accounts for 2,440 with block 10 still FAIL.
- A4 figure-input binding refuses a mismatched classifier artifact.
- A5 coverage report: abandon ran only with ABANDON_T=0.
- A6 tshark decode: 49,408 and 2,440 responses identical in both parsers. tshark cannot reassemble the 63->0
  transport wrap; 384 padded responses go through a control copy.
- D1: no tap or SPAN; dev 10 is very likely Vision enp59s0f1np1 (LLDP cadence); to be confirmed in D3.
Then:
- A2/A3 reassembly v3: 0 differences over 290 connections, with a frozen-v2 control.
- B classifier v2: CLRT unchanged; joint 0.667-0.875 under Timing+Size; ack/rt show no reduction.
- C padding: size-only BA 0.667 under every attainable assignment except a full merge; frames +6.4%.
- Independent code review: 0 critical/high. Its 5 medium findings are fixed (report statuses, summary wording,
  reassembly guard tests, replay audit buckets, wrap-test bytes), plus the cheap low ones.
Tests: repository 202, analysis 75, paper 16. Next: D2 diagnostic mirror build, after Philip confirms.

Philip (2026-10-28, later): proceed with D2, then the gated capture and preservation experiments. 7cec084b4 is not yet
independently inspected by him, so its results are reported, not reviewed.
- Independent-decode wording separates TShark reassembly, failures at 63->0 and content agreement.
- opendnp3 (pydnp3) replay of the exact retained READ wrap responses: 128/128 reassembled, 8,320/8,320 READ delivered,
  renumbered control equal, a bad second segment rejected. SELECT/OPERATE wraps (256) not replayed: the subagent
  stopped on a safety check; reported to Philip, not attempted another way.
- Padding summary: +2.91 B/txn is a workload average; each affected mixed READ +17 B; full merge not proposed.
- E3 recovery as three single-block definitions (recovery_r1/r2/r3) so a failed block cannot leave the others unrun.
  The three-block campaign dir rc01_hw_c72_recovery_20261028_01 is superseded and was never initialised.
Committed 115592bd7. Tests: repository 209, analysis 75 (research Python; overhead_v2 needs scapy 2.7), opendnp3 9.
- D2 c72_diag_mirror committed c78363905: 13 insertions, pipe 0 only, stages as c72; model fidelity on/off/absent
  passes; all 17 c72 drivers identical with sessions absent. Freeze gate refuses it (non-canonical source, no
  model_gate_passed by construction); a narrow diagnostic admission is being built.
- E1 preservation checker committed a7de5b039 (synthetic tests only so far).
- E4: editing model_abandon.py blocked the c72 gate closure; restored byte-for-byte and the T=1 scenario moved to
  model_abandon_t1.py (f2c32cf2a). c72 model T=1 abandoned SELECT 14/14 (attempts 01, 02). The gate's earlier T=1
  attempt model_abandon_c72_01 (no relay SELECT ACK in the stimulus) failed 6/12 and stays recorded.
- D3/E1/E2 registered before traffic: results/analysis/diag_mirror_d3/DESIGN.json (8+8 mirror on/off, 32 E2).
Next: freeze-gate admission + diag definitions, runtime hooks (installer --diag-mirror, Vision mirror capture),
D3 analysis tool; then commit, freeze, dry-run, and run E3 (c72) and D3/E1/E2 (diag build).
- 2026-10-29 E3 done (c72): r1 D20 combined 5/6 SUCCESS (t3 TIMEOUT: OPERATE request itself retransmitted +214 ms),
  r2 D20 size_only 6/6, r3 D5 combined 5/6 (t2 TIMEOUT, single OPERATE copy at 1004.7 ms). Relay retransmits the
  dropped SELECT response at 998-1023 ms in every trial, so OPERATE leaves ~1.0 s after the
  SELECT request (relay timeout not read).
  results/analysis/recovery_e3/SUMMARY.md. TODO after hardware: move scratch e3_extract.py to
  scripts/analysis/recovery_e3.py and regenerate e3_trials.json (must be identical).
- D3 first trial: dev10 -> Vision enp59s0f1np1 (i40e 0000:3b:00.1) CONFIRMED; off-arm copies byte-identical
  (198/198 requests, 389/389 responses). TODO after the diag campaigns: fix copy-direction attribution in
  diag_mirror_capture.py (src == master MAC -> egress, else ingress): a third device (70:49:a2:6b:6c:89) broadcasts
  DHCP Discover on the relay segment and was counted as egress (D3c 200 vs 199). Do not edit scripts/ before then.
- 2026-10-29 d3on done (diag build, 8/8 trials ok, restore ok). Preliminary (pre-fix analysis): D3a 8/8; D3b off arm
  1,173/1,173 copies byte-identical; E1 772/772 responses and 772/772 requests content-identical after removing the
  declared padding, translation 776/776. combined t0: original FIRST REQUEST reached the switch (dev9 RX) but left
  no egress copy (dev64 TX one lower); master retransmitted at 217.7 ms -> loss INSIDE the switch. off t1: handshake
  final ACK also dropped inside the switch. E1's 3 "header differences" in combined t0 pair the original request
  with the relay-side copy of the retransmission (ip.id/TSval) -> fix E1 pairing after the campaigns.
- d3off done (8/8 ok; sessions off -> 0 copies in every trial). D3d (pre-fix tool): delivery and response sizes
  identical on vs off in every arm/class; timed-arm median CLRT (relay ACK -> complete response) differs by -231..+142.5
  us, 4 of 8 timed cells over the REGISTERED 50 us bound -> D3d FAILS as registered. Context: c72 eval D=20 timed arms
  have repetition-median spans of 266-1,085 us over 16 reps (IQR 1.3-1.6 ms), so the bound was tighter than the
  system's own block-to-block variation; no mirror effect detectable, no equivalence claimed. D3d gates mirror TIMING
  use only; E1 (content) and E2 (copy presence/order) stay usable.
- 2026-10-29 Part 1 DONE. E2 complete (32/32); analysis fixed (master-MAC direction, IP-ID pairing, explained missing
  copies, counter narrowing) -> 04e29045d. E4b applied with review M1/M2 tests (563b9efee) and run 6/6 (3bd4baefb).
  results/analysis/validation/REPORT.md answers the four questions; HANDOVER rewritten. Next: tag
  c72-validation-final, then Part 2 (purge + c73 in worktree; inventories in the scratchpad SUMMARY_FOR_PART2.md files).

- Correction 2026-10-29: the connection-start drops are 5 final handshake ACKs (d3on off t1 and size_only t0; E2 t0,
  t17, t27) plus 3 first requests = 8 of 40 mirror-on fresh connections (earlier notes and commit 04e29045d said 4
  and 7: the size_only t0 case was missed because completeness is gated only in the off arm). fig_validation.py
  counts it from the retained captures.
- Part 2: Python purge committed cafc0adcd (scripts/ 32,692 -> 31,087 lines; c72 gate still passes; tests 471/138).
  c73 (optimised P4, variant D2 cumulative) running in the detached worktree scratchpad/c73_wt; merge after its
  17-driver model gate and the comparison with c72.
- 2026-10-29 Part 2 DONE: purge cafc0adcd + review follow-up 3897ea9df; c73 candidate 4ff48b19c (model 17/17,
  identical verdicts; independent P4 review: behaviour-preserving). c72 stays canonical; results/builds/c73/
  canonical_switch.patch switches after Philip approves hardware qualification. Final checks: repository 474, build 48,
  c72 live gate passed. Running: offline investigation of the connection-start drop (E2 mechanism), scratch only.
