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
