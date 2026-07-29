# WORKING NOTES

## Task
**Case A DEFENSE 3 — predetermined ACK-delay release.** Hold the pure TCP ACK until
`d_ACK = t_ACK + D`, released independent of the RESPONSE. Two queues, one deadline, K=64.

## AUTHORITY
`/home/philip/Projects/DNP3/meeting_direction.md` governs. Read it first, every session.

## Status 2026-07-29 — state saved
Branch `research/case-a-defense3-fixed-ack-delay` @ `7ab443a`, pushed.
**Switch restored to Defense 2, verified on all five facts.**

Panel (7 memos) + CONSENSUS done. Built from the stripped baseline. **Gate 1 PASS** on both SDEs.
**Gate 2 FAIL** with three independent open faults (F01-a/b/c). Gates 3–4 not started.

§18 vocabulary: designed ✅ compiled ✅ loaded ✅ synthetically validated ❌ physically validated ❌
statistically evaluated ❌.

## Next action
Resolve **F01-a** (reservoir never fires), then re-run Gate 2.
Full handoff: `research/case_a_defense3/RESUME_DEFENSE3.md`.
Read `failures/F01_gate2_no_blockers/CORRECTION.md` BEFORE `DIAGNOSIS_PROGRESS.md` — the latter is
superseded and wrong.

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
