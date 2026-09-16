# Working notes

## Status: one branch, one working tree, and a history without the co-author trailers

`main` carries everything, 888 commits, and it is the only branch. The twenty other GitHub
branches were removed on 2026-09-16 after each was shown to be contained in `main` or bundled to
`/home/philip/Archives/DNP3_branch_bundles_20260915/`. On the same day the history was rewritten
to strip the `Co-Authored-By: Claude` trailers from five commit messages, which changed every hash
from 2026-07-15 onward; `git log --all --format=%B | grep -ci "co-authored-by:.*claude"` returns 0
and every commit is authored by `akekulip`. There is one working tree,
`/home/philip/Projects/DNP3`.

**Publishing has not happened.** The rewritten history is local only, the `origin/main`
remote-tracking ref no longer exists because the rewrite dropped it, and publishing it needs a
lease-checked force update of `main`, which the repository's own rules leave to Philip.

Archives, all verified: `/home/philip/Archives/DNP3_post_rewrite_20260916/` holds the current
history as a bundle together with `commit-map-old-to-new.txt`, the 926-line map that is the only
way to translate a hash written down before the rewrite;
`/home/philip/Archives/DNP3_pre_rewrite_20260916/` holds the history as it stood before, which is
what an undo would clone from; `/home/philip/Archives/DNP3_branch_bundles_20260915/` holds the
eight branches whose commits `main` never had, and since the rewrite pruned them from the
repository those bundles are now the sole copy. The README beside the first of these explains all
three.

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

Offline only: no hardware, no switch, no traffic. The full account is in
`CORRECTION_REPORT_20260916.md`. Verified at the end of the pass: 197 active offline tests, 131
campaign tests with no failures, 132 captures and 63,360 exchanges with zero validator problems,
the publication gate clean, the protected introduction verbatim, the manuscript building and
gating clean, and all four protected paths byte-identical to the frozen tree. After the history
rewrite, `update_hash_references.py --apply` repointed 179 hash references across 53 files and
every gate was re-run against the new hashes.

## Next actions

1. **Publish the rewritten history**, with the lease-checked force update recorded in
   `tools/history_rewrite/README.md`. Anyone with an existing clone has to re-clone.
2. **The body is one page over.** 14 main-body pages against a limit of 13. A compression pass on
   2026-09-16 removed about 150 words without dropping a number or a caveat and cut the spill from
   sixteen column lines to twelve, but the remaining twelve lines will not come out of wording.
   Because the figures reflow into whatever prose frees, roughly 300 more words of source would
   have to go, so the real choice is a content cut or one fewer figure, and that is Philip's call.
   The tallest candidates are `fig_ladder` at 266 pt and `fig_m01_release_timeline` at 288 pt.
3. **Read the built PDF at printed size** before circulating it.
4. The OPERATE spent-marker loss path is specified but not implemented or run: it needs the
   relay-facing link instrumented and a separately authorised hardware session
   (`audit_current/OPERATE_RETRANSMISSION_RISK_20260916.md`).
5. Optional: the duplicate live-window case and a hardware adapter for the activation profile are
   still open.

## Standing constraints

Frozen `defense4/timing/implementation/` and every `raw_pcaps/` path are byte-identical to
`8278346` and must stay that way. Dr. Lin's first three Introduction paragraphs are protected by
`check_lin_intro_verbatim.py`. `build.sh` after every manuscript edit; `lin_check --compare` must
show no regression. `configure-all` leaves `shape_enable = 1` — observed five times on hardware on
2026-09-15 — so any run must force it to 0 and read it back.

