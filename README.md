# DNP3 transaction obfuscation on a Tofino switch

This repository holds the P4 implementation, the hardware and model evidence, and the manuscript for
NOMAD, an in-network defense that hides which DNP3 transaction is in flight by normalizing response
timing and response size on an Intel Tofino-1 switch. Agents start with [CLAUDE.md](CLAUDE.md); the
path-by-path table is [REPOSITORY_MAP.md](REPOSITORY_MAP.md).

## Where things are

- **Manuscript evidence.** The hardware evaluation `eval_m11_09_20261018_02` on candidate m11_09 (four arms:
  no obfuscation, timing, size, timing+size). Every number the paper states traces to a row of
  [CLAIM_EVIDENCE_MATRIX.md](defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/evaluation/CLAIM_EVIDENCE_MATRIX.md).
- **Manuscript.** `paper/rewrite/` (built with `paper/rewrite/pipeline/build.sh`), being rebuilt on Dr. Lin's draft.
- **Current implementation work.** The two-READ candidate `m12p_c25` and its resource-reduced successor
  `m12p_c26`. The code path, from generator to hardware readout, with commands, is in
  [ACTIVE_CODE_MAP.md](defense4/timing/case4_architecture/ACTIVE_CODE_MAP.md). The run's status file is
  [CURRENT.md](defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/CURRENT.md).
- **History.** Earlier campaigns, audits and candidates, and the superseded authorizations, are listed in
  [HISTORY_MAP.md](HISTORY_MAP.md).

## Validation status of the current candidate (2026-10-23)

| tier | m12p_c25 | m12p_c26 |
|---|---|---|
| software endpoints, encoding | passed | unchanged from c25 |
| compile, both SDKs (9.13.1 local, 9.13.2 switch) | passed | passed (pipe-1 egress 7 -> 4 stages; N/E/T 12/12/11) |
| compiled-model gate (v3) | passed | passed (every driver count equal to c25's) |
| hardware padding | byte-exact (campaign 02) | not run (not frozen) |
| hardware timing precision | **FAILED**; cause not located | not run |
| hardware recovery blocks | not run | not run |
| IEEE 1815 conformance | not audited in this run | not audited in this run |

The earlier explanation of the timing failure, a delay that depended on receive-side idleness on the path
into Vision, was withdrawn on 2026-10-22 (commit `4a0b0fc56`): its metric counted the transit it was meant to
explain. The corrected analysis is in
`.../read_complete_01/evidence/timing_reanalysis_20261022/README.md`. No hardware runs were made in the
2026-10-22/23 overnight run.

## Reproduce offline

The candidate (software tests, policy, switch constants, byte-for-byte P4 regeneration, model-gate
recomputation, freeze binding; never touches the switch):

```sh
bash defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01/reproduce.sh
CANDIDATE=c26 bash .../read_complete_01/reproduce.sh     # c25 (default) | c26 | c24 | c12 | c20 | b08
```

A fresh checkout reproduces every step except the freeze binding of compiler artifacts (`compile_*/out/` is
git-ignored by design); `reproduce.sh` then reports that binding as NOT CHECKED. Recompiling with
`defense4/timing/case4_architecture/build.py` restores it. Verified 2026-10-23 on a clean worktree of HEAD: c26 all
steps, c25 all steps with the freeze binding NOT CHECKED.

The paper's figures and tables: `python3 .../seg61_02/analysis/paper_evidence.py --check`. The earlier
timing-only corpus (campaign_v2): `defense4/timing/reproduce.sh`.

## Searching

`.ignore` keeps `rg` and `fd` out of evidence directories, captures, compressed files, compiler output,
`__pycache__`, `paper/`, `history/` and `.scratch_*`. Search them on purpose with `rg --no-ignore PATTERN`
(or `rg -uu`) and `fd --no-ignore`. Candidate builds live under `ctl_timing_01/evidence/`, so they are hidden
by default too. `git grep` does not read `.ignore`. Neither `rg` nor `fd` is installed on this host at present.

## Hardware

Hardware work goes only through the gated machinery listed in ACTIVE_CODE_MAP.md (ownership, preflight,
freeze check, dry run, restoration check) and only under an authorization recorded for that run. Check the
live switch state; a dated report does not tell you what is loaded.

No repository license is present; check redistribution terms before any public release.
