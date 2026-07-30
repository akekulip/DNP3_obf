## Status 2026-07-30 (latest) --- 10-point review fully addressed; counter fix re-verified on silicon

The last flagged item is closed. The `BLOCK_ENQ`/`BLOCK_REJECT` counter fix (review item 2) was
**re-run on hardware** (`defense3/evidence/inject/counterfix_20260730T232946Z/`): R1+R2 accepted
token -> `{BLOCK_ENQ:1, BLOCK_TERM_STALE:1}`, `reg_failopen=0xC1`; R1+R2+R3 dropped-fresh token ->
`{BLOCK_REJECT:1}` alone. Drop behaviour unchanged, accounting now correct. `evidence/inject/RESULTS.md`
matrix + counter-fix section updated from "noted" to "verified"; its stale "does NOT demonstrate"
paragraph corrected against the native K-sweep (single token clears reg_tag at K=1 -- the injected
no-clobber was a harness artifact, NOT reservoir dynamics). REPORT.md/.tex 7.8 carry the counter-fix
note. REPORT.pdf rebuilt 36 pp, 0 overfull, 0 missing glyphs. Committed `42855a0`, pushed to
`research/case-a-defense3-fixed-ack-delay` (remote head verified). Switch on `d3_abs.conf`, one
`bf_switchd`, verified. Nothing pending from the review.

Next action: await Philip. All review items (R3 in-switch qualification, BLOCK_ENQ counter, R2 narrowing,
K-sweep reconciliation, R2-note-is-observation, generation-wrap guard, R1 live qualification, three-row
status matrix, defect language, campaign counting 1,920 total / 1,600 defended) are in both report formats.

---

## Status 2026-07-30 --- REPORT.pdf delivered, all 8 figures checked

`defense3/REPORT.pdf` --- 25 pages, single column, typeset from `defense3/REPORT.tex` with
`tectonic`. Not generated from HTML. Funnel structure: setting -> vocabulary -> the leak ->
the three defenses and the arithmetic that selects one -> the mechanism -> the maths ->
implementation and hardware traps -> the state machine -> synthetic gates -> the physical
relay -> the D-sweep and the observer analysis -> claims and limits -> reproduction ->
mistakes -> summary. Zero overfull boxes, zero missing glyphs.

**Eight figures, every one inspected visually and fixed:**
- fig1 D-sweep (2 panels) - moved the release-tail label inside the axes
- fig2 mechanism + hold decomposition - panel (a) fully re-laid out (label collisions),
  panel (b) vertical envelope tightened
- fig3 per-feature separability - bars now start at 0.50 (chance), drift-floor label moved
  below the baseline where there is clear space
- fig4 the four defenses on one time axis (NEW) - ACK and RESPONSE split into two lanes per
  row because under D1/D3 they coincide
- fig5 the transaction state machine (NEW) - rebuilt twice; the first version had four
  separate text collisions and invisible self-loops
- fig6 the trigger chain vs the deadline (NEW) - legend moved, right-edge label was clipped
- fig7 every raw CLRT, native vs defended, 2 panels (NEW, at Philip's request) - panel (b)
  is the "leak is moved, not destroyed" plot: spread leaves the CLRT axis, appears on
  READ->ACK
- fig8 the physical topology (NEW) - relay port corrected to 64 (not 11) from the measured
  topology table

**Figure sizing done properly, not by scaling.** The 3 double-column figures (7.16 in) are
placed at natural size and centred with a symmetric margin bleed; the 5 single-column ones
are REGENERATED at 4.35 in via `D3_FIG_W` with font sizes untouched, into
`figures/out/report/`. So nothing in the PDF is rescaled and a 9 pt label is 9 pt on the
page. Body font dropped 11pt -> 10pt for correct proportion with the figures.

No hardware was touched in this pass. Switch state unchanged from the previous entry.

# WORKING NOTES

## Task
**Case A DEFENSE 3 — predetermined ACK-delay release.** Hold the pure TCP ACK until
`d_ACK = t_ACK + D`, released independent of the RESPONSE. Two queues, one deadline, K=64.

## AUTHORITY
`/home/philip/Projects/DNP3/meeting_direction.md` governs. Read it first, every session.

## Status 2026-07-29 — GATE 3 PASS, GATE 4 CASE C FAIL

Branch `research/case-a-defense3-fixed-ack-delay`.
**Switch RESTORED to Defense 2, verified on all five facts.**

Artifact rebuilt from `c82afcd` on the switch (every prior staged binary deleted first;
source sha256 verified). Gate 2 accepted as PASS 17/17.

- **GATE 3 PASS 5/5.** Five consecutive transactions, no reload and no transaction-state
  reset between them, generations 0xC0→0xC4. Hold spread **86 ns**, drain spread 3 ns,
  release tail spread 4 ns, reservoir standing spread 2 ns, READ→ACK spread 2 ns.
  ★ My FIRST attempt failed on my own clean-state criterion, which demanded a zero
  `reg_deadline`/`reg_ack_rel` the architecture never promised — both are self-clearing by
  generation binding. The rule was replaced with a stricter one that adds a real failure
  mode (a `reg_ack_rel` collision would invert the early/late RESPONSE classification).
- **GATE 4 A PASS 3/3** (RESPONSE 4 872 ns before the deadline) and **B PASS 3/3**
  (RESPONSE 500 128 ns after the ACK committed, `RESP_HOLD_LATE=1`, forwarded once).
- **GATE 4 C FAIL 0/3.** A missing RESPONSE never retires the generation — the only two
  retire paths are the released RESPONSE and the fail-open budget, and the deadline
  pre-empts the budget. Cost measured at **exactly one unprotected transaction**, then
  self-heal.

§18 vocabulary: designed ✅ compiled ✅ loaded ✅ **synthetically validated ✅ (Gate 3 +
Gate 4 A/B)** physically validated ❌ (BLOCKED on Gate 4 C) statistically evaluated ❌.

## Next action

**A decision, not a run.** Three fixes for case C are priced in
`research/case_a_defense3/evidence/defense3/GATE3_PASS_GATE4_CASE_C_FAIL.md` §6;
Option 1 is recommended and needs sign-off. No architecture change has been made.

## Two corrections I made to my own prior work
- The C3 "steady-state" corpus contained a connection-cold poll: D for 100% clamp is 13 ms not 22,
  latency 10.76 ms not 19.57 (`feee51b`).
- The "arm write did not land" diagnosis was wrong; the arm worked and `reg_tag=255` is the correct
  end state after the response path retires the generation (`7ab443a`).

## Discipline that earned its place
Keep the dp8 `$SPEED` guard, the `D + K/rate` correction, the reservoir-standing check and
`ACK_RELEASE_FAILOPEN == 0`. All four caught real faults this session. The analyzer refusing to pass
a zero hold is the single most valuable behaviour in the harness.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-07-29T22:14:22Z -->
### Compaction handoff — 2026-07-29T22:14:22Z
- Git: branch `research/case-a-defense3-fixed-ack-delay`, 0 uncommitted file(s): 
- Last verification run recorded: 2026-07-29T22:11:37Z	timeout 90 scp -o BatchMode=yes research/case_a_defense3/p4/case_a_defense3_fixed_ack_delay.p4 research/case_a_defense3/
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-07-30T08:45:28Z -->
### Compaction handoff — 2026-07-30T08:45:28Z
- Git: branch `research/case-a-defense3-fixed-ack-delay`, 9 uncommitted file(s): defense3/figures/out/fig4_timelines.pdf defense3/figures/out/fig4_timelines.png defense3/figures/out/fig5_statemachine.pdf defense3/figures/out/fig5_statemachine.png defense3/figures/out/fig6_trigger.pdf defense3/figures/out/fig6_trigger.png defense3/figures/src/fig4_timelines.py defense3/figures/src/fig5_statemachine.py defense3/figures/src/fig6_trigger.py 
- Last verification run recorded: 2026-07-30T08:45:24Z	cat > figures/src/fig5_statemachine.py <<'PYEOF' """Figure 5 (single column) — the transaction state machine. One regist
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-07-30T23:32:11Z -->
### Compaction handoff — 2026-07-30T23:32:11Z
- Git: branch `research/case-a-defense3-fixed-ack-delay`, 4 uncommitted file(s): CORRECTIONS_REGISTER.md defense3/evidence/inject/RESULTS.md CORRECTIONS.md defense3/evidence/inject/counterfix_20260730T232946Z/ 
- Last verification run recorded: 2026-07-30T23:29:27Z	cd /home/philip/Projects/DNP3/defense3 scp -q p4/case_a_defense3_repair_candidate.p4 harness/inject_probe.py decps@10.10
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.
