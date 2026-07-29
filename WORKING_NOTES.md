# WORKING NOTES

## Task
**Case A DEFENSE 3 — predetermined ACK-delay release.** Hold the pure TCP ACK until
`d_ACK = t_ACK + D`, released independent of the RESPONSE. Two queues, one deadline, K=64.

## AUTHORITY
`/home/philip/Projects/DNP3/meeting_direction.md` governs. Read it first, every session.

## Status 2026-07-29 — GATE 2 PASS

Branch `research/case-a-defense3-fixed-ack-delay` @ `8019c55`.
**Switch RESTORED to Defense 2, verified on all five facts.**

Both blocking checks the updated `meeting_direction.md` imposed are CLOSED, and §13 Gate 2
passes **17/17**:

- **CHECK 1** (inactive-marker safety) found a critical bug the F02 repair itself had
  introduced — `TAG_NO_WRITE` collided with the new `TAG_INACTIVE = 0`, so both
  transaction-retire paths were silent no-ops — plus a clone/`BAD_PORT` miscount that made
  G-10 unsatisfiable and a stale `0xFF` in the analyzer. 790 mutation-checked assertions.
- **CHECK 2** (production blocker-start latency) measured the real trigger chain over 100
  clean trials: **full 64-token reservoir in 1 215 ns**, 329× under the physical ACK floor.
  The ~1 ms was the harness's generator batch span, reproduced to the nanosecond.
- **Gate 2**: `hold = 2 001 505 ns = D + drain 1 692 + tail 27 + detect 23`. The R5 `K/rate`
  bias is now measured directly (1 692 vs 1 711 predicted, 1.1%) rather than inferred from
  the residual it removes.

§18 vocabulary: designed ✅ compiled ✅ loaded ✅ **synthetically validated ✅ (one
transaction)** physically validated ❌ statistically evaluated ❌.

## Next action

**Gate 3 — five transactions.** Full handoff: `research/case_a_defense3/RESUME_DEFENSE3.md`.
Read `evidence/defense3/GATE2_PASS.md` §3 first: three schedules were ruled out by
measurement and the reasons are hardware facts worth not rediscovering.

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
