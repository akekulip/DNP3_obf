# RESUME STATE — DNP3 project

**Last updated: 2026-07-30. Branch: `main` @ `ff6e59c`. Working tree clean.**

Read this first, then `CLAUDE.md` for the rules and layout. Authoritative direction is
`meeting_direction.md` (Case A: predetermined ACK-delay release).

---

## Current headline

**Case A Defense 3 (predetermined TCP-ACK delay, Tofino-1, physical SEL-751) is complete
within its stated laboratory and adversary scope.** The three audit-confirmed defects are all
repaired and validated on silicon, the report and all artifacts have been reconciled in a
two-pass documentation freeze, and the whole repository has been consolidated onto a single
`main` branch. Nothing is in progress; the remaining open items are lab-blocked (below).

## Repository / git state

- **Single branch.** GitHub and local both show **only `main`** — all research feature
  branches were audited (every one fully merged, zero unique commits) and deleted. The one
  branch that held unique work (`research/queue-backpressure-release`) had its sole file,
  `research/queue_backpressure_release/PIVOT_TO_ENDPOINT_TIMING.md`, cherry-picked onto `main`
  before deletion, so nothing was lost.
- **In sync:** local `main` = `origin/main` = `ff6e59c` (verified via `ls-remote` and the
  GitHub API). 0 unpushed, 0 behind, working tree clean.
- **Convention (in force):** work on `main`, commit **and** push in the same pass; do not open
  feature branches. Commits in Philip's name only, no Claude attribution.

## Switch state

- **One `bf_switchd`**, restored to the frozen baseline **`d3_abs.conf`** (binds
  `case_a_defense3_fixed_ack_delay`, the original unrepaired Defense 3 program). Verified.
- The repaired **R1+R2+R3** program is `defense3/p4/case_a_defense3_repair_candidate.p4` — it
  was loaded and validated during the repaired campaigns and the injector matrix, then the
  switch was returned to the baseline conf between experiments.
- Hardware/switch changes remain **gated on explicit Philip authorization** (master §10).

## What this session did (all on `main`, pushed)

1. **Re-verified the `BLOCK_ENQ`/`BLOCK_REJECT` counter fix on silicon** — R1+R2 accepted
   token increments `BLOCK_ENQ`; the R3 drop increments only `BLOCK_REJECT`
   (`defense3/evidence/inject/counterfix_20260730T232946Z/`).
2. **Documentation & provenance freeze, pass 1** (`8492fa0`) — nine consistency fixes across
   REPORT.md/.tex, README, the repaired P4, and the resource ledger (loaded-status, §8.6
   repaired fail-open table, 2 675 assertions, two-generation resource table, 36→37 pages / 9
   figures, campaign totals, FINAL-BUILD P4 header, ledger renamed `*_PRE_AUDIT_*`, final-
   status matrix).
3. **Documentation freeze, pass 2** (`23a192b`) — six residual inconsistencies from the
   GitHub-authoritative tree (P4 "nothing loaded" + "one new register" leftovers, stale
   one-loopback-pass commentary, §7.5 duplicate paragraph + campaign scope, Figure 8 caption
   qualified to a master-interface proxy, open-work items 13/8b, README "whole-state
   correctness" → "all known audit defects repaired").
4. **Repository consolidation** (`ff6e59c`) — deleted all stale local and remote branches,
   preserved the pivot note onto `main`, single-branch repo.

REPORT.pdf is 37 pages, 0 overfull boxes. Self-tests pass: `test_tag_domain` 2 675/0,
`analyze_defense3` 17/0, `analyze_gate34` 20/0.

## Open items — all lab-blocked, none in progress

Per REPORT §12 (final-status matrix) and the open-work table:

- **External *wire* adversary** for R1/R3 — no injection vector in the lab (the injectors are
  in-switch stand-ins, not frames from an external host).
- **Defect 2 cross-transaction generation-wrap reach** — model-checked, not physically
  reproduced (needs the wrap coincidence the harness cannot arrange).
- **Acknowledgement-retirement egress sweep (0–1 µs)** — needs master-facing egress order,
  not host-PCAP ingress timestamps.
- **Hardware-timestamped observer capture** — current capture is a host PCAP at the master
  interface (~1 µs), a proxy for a port-9 wire observer.
- **Parser `meta`-uninitialized compiler warning** — present in every build log; still open.

## Key pointers

- `defense3/REPORT.pdf` (and `REPORT.md`/`.tex`) — the full report; start here.
- `defense3/README.md` — directory map + status + campaign totals.
- `defense3/REPAIR_HISTORY.md` — why the repaired P4 is named `..._repair_candidate.p4`.
- `defense3/RESUME_DEFENSE3.md` — Defense-3-specific resume detail.
- `research/case_a_read_anchored_dual_release/RESUME_HERE.md` — the four-queue-oracle /
  `--shaper-sweep` line (the prior contents of this file); still a live thread if resumed.
- `meeting_direction.md` — authoritative direction; `CLAUDE.md` — rules and layout.
