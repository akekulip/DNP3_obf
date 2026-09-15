# Working notes

## Status: the 2026-09-15 correction pass is merged, pushed and verified

Branch **`paper/clrt-four-corrections-20260909`** at `64ab220`, pushed to `akekulip/DNP3_obf`.
Working tree clean. The 13-commit offline pass from `fix/offline-corrections-20260915` is merged
in; that worktree can be removed whenever convenient.

## What changed

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

## Next actions

1. **Nine remote branches can be deleted with zero loss** — every commit is already reachable from
   the current branch. Commands and recorded heads in `BRANCH_PRUNE_20260915.txt`. The risk guard
   blocks remote-branch deletion from the agent, so this one is Philip's.
2. **Read the built PDF at printed size** before circulating it.
3. Optional: tighten the perturbation bound with a paired design; revise the epsilon candidate to
   observe departure, which needs egress instrumentation.

## Standing constraints

Frozen `defense4/timing/implementation/` and every `raw_pcaps/` path are byte-identical to
`18a595a` and must stay that way. Dr. Lin's first three Introduction paragraphs are protected by
`check_lin_intro_verbatim.py`. `build.sh` after every manuscript edit; `lin_check --compare` must
show no regression. `configure-all` leaves `shape_enable = 1` — observed five times on hardware on
2026-09-15 — so any run must force it to 0 and read it back.
