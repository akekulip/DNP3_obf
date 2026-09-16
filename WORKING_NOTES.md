# Working notes

## Status: everything is on `main`, pushed, and the tree is consolidated

`main` is at the tip and pushed to `akekulip/DNP3_obf`, 341 commits, nothing ahead of the remote.
It was fast-forwarded to `paper/clrt-four-corrections-20260909` and verified byte-identical to it,
and the manuscript was rebuilt from it (BUILD PASS, Dr. Lin's introduction verbatim). There is now
**one working tree**: `/home/philip/Projects/DNP3`. Both worktrees under `DNP3-worktrees/` were
removed on 2026-09-15 after checking that each was clean and that its head
(`7414a2f`, `185484d`) is an ancestor of `main`; the directory itself is gone.

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

## Current work: the 2026-09-16 correction pass

Branch `fix/lin-paper-code-review-20260915` off `5ce71ba`. Offline only: no hardware, no switch,
no traffic, no branch deletion, no force push, no merge. The full account is in
`CORRECTION_REPORT_20260916.md`.

Verified at the end of the pass: 178 active offline tests, 131 campaign tests with no failures,
132 captures and 63,360 exchanges with zero validator problems, the publication gate clean, the
protected introduction verbatim, the manuscript building and gating clean, and all four protected
paths byte-identical to `8278346`.

## Next actions

1. **The body is two pages over.** 15 main-body pages against a limit of 13, which is the honest
   count now that the preflight stops charging the excluded Ethics section to the budget. About
   1,600 words have to come out, mostly from Design and Evaluation. This is the one blocker.
2. **Epsilon's build attribution needs the switch.** The patch on disk hashes to `7d175222`, the
   records cite `ac3eb62a`, and settling it needs the loaded-program record or a recompile.
3. **Read the built PDF at printed size** before circulating it.
4. Optional: the duplicate live-window case, a hardware adapter for the activation profile, and a
   measurement of the master's own retransmission timer are all still open.

## Standing constraints

Frozen `defense4/timing/implementation/` and every `raw_pcaps/` path are byte-identical to
`8278346` and must stay that way. Dr. Lin's first three Introduction paragraphs are protected by
`check_lin_intro_verbatim.py`. `build.sh` after every manuscript edit; `lin_check --compare` must
show no regression. `configure-all` leaves `shape_enable = 1` — observed five times on hardware on
2026-09-15 — so any run must force it to 0 and read it back.
