# Working notes

## Status: published, and the 2026-09-17 review is answered

`main` is the only branch and carries everything, 902 commits. The history rewrite that stripped
the `Co-Authored-By: Claude` trailers was published on 2026-09-16, branch and tags both, and
GitHub lists one contributor. **Eleven commits since then are local:** `origin/main` is at
`7388c314` and local `HEAD` is at `5edc4db8`, so the review response has not been pushed.

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

1. **Publish the review response.** Eleven commits are local. `git push origin main` is an
   ordinary fast-forward; nothing here needs a force.
2. **Read the built PDF at printed size** before circulating it. The figures were checked that
   way; the prose has not been.
3. The OPERATE spent-marker loss path is specified but not implemented or run. It needs the
   relay-facing link instrumented and a separately authorised hardware session
   (`audit_current/OPERATE_RETRANSMISSION_RISK_20260916.md`).
4. Optional: the duplicate live-window case stays open, and a hardware adapter for the activation
   profile does not exist.

## Standing constraints

Frozen `defense4/timing/implementation/` and every `raw_pcaps/` path are byte-identical to
`8278346` and must stay that way. Dr. Lin's first three Introduction paragraphs are protected by
`check_lin_intro_verbatim.py`. `build.sh` after every manuscript edit; `lin_check --compare` must
show no regression. `configure-all` leaves `shape_enable = 1` — observed five times on hardware on
2026-09-15 — so any run must force it to 0 and read it back.

