# WORKING NOTES — post-meeting revision

## Task
Revise the timing paper to Dr. Lin's supplied Introduction and the post-meeting
instructions, then push a reviewable branch. Sources:
`meeting/CLAUDE_Timing_Paper_Revision_and_GitHub_Handoff.md` (the handoff) and
`meeting/DNP3_Post_Meeting_Research_and_Writing_Instructions.md` (the synthesis).

## Working state, established 2026-09-08
- Repo `/home/philip/Projects/DNP3`, origin `https://github.com/akekulip/DNP3_obf.git`.
- `/home/philip/Projects/DNP3-size-probe/paper/rewrite/` named in the handoff DOES NOT EXIST;
  it was a worktree of this repo and was removed. The real entry point is
  `/home/philip/Projects/DNP3/paper/rewrite/main.tex` (verified present).
- Started from `paper/campaign-v1-ndss-corrections-20260828` at `fe42ada`, which is 5 commits
  AHEAD of origin `d895d53` (the five CLRT-figure commits of this session). The handoff's
  `d895d53` is therefore historical, as it says.
- Other worktree `/home/philip/Projects/DNP3-worktrees/...` is detached at `ceb5bea`, clean,
  and an ancestor of HEAD. Nothing unique there.
- Review branch: `paper/lin-post-meeting-revision-20260908`, cut from `fe42ada`.

## The load-bearing finding, before any prose
Dr. Lin's notation INVERTS `D_R`. New convention:
  D_A = e_A - t_A   (ACK hold: native ACK arrival -> ACK release)
  D_R = e_R - t_R   (RESPONSE hold: native RESPONSE arrival -> RESPONSE release)
  CLRT_target       (the configured ACK-to-RESPONSE gap)
The code and the current paper use `D_R` for the configured target gap, with
`da_dr = D_A + D_R`. So the SAME SYMBOL means two different things across the two
conventions. The CLRT figures committed earlier today label the configured target `D_R`,
which is wrong under the new convention and must be changed to CLRT_target.

## Order of work
1. Notation mapping table.            -> NOTATION_MAPPING.md
2. Figures relabelled to it.
3. Dr. Lin's Introduction installed verbatim + framework/contribution continuation.
4. Design rebuilt: model -> design space -> queue realization.
5. Implementation + Evaluation reorganized around the reader's questions.
6. Research tasks A (ACK delay), B (response latency), C (release variability).
7. Writing guide updated; review report; build; push.

## Status
- [x] state established, branch created
