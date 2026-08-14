# Defense 4 — archive (design evolution)

Historical material, preserved for the scientific record. **None of this is the current authority.**
The authoritative implementation and result are in `../README.md` and `../CLAIMS.md`; the clean
handoff is `../defense4_release/`.

These files are the route by which the shipped one-pipe `defense4_rrc_bor_unified12` design was
reached. They are kept because they document the engineering path (and the negative/compile-probe
results are part of the contribution — they show why a design that passes a model can still fail on
silicon), but they must not compete with the final program or the `E_FINAL` evidence.

## `design_evolution/` — superseded programs and their harnesses

| File | What it was |
|---|---|
| `defense4_rrc_bor_compile_probe.p4` | early additive BOR compile probe |
| `defense4_rrc_bor_sr_probe.p4`, `defense4_rrc_bor_stagerecovery_probe.p4`, `defense4_rrc_stagerecovery_probe.p4` | stage-recovery consolidation probes (the additive BOR needed 14→13 ingress stages; still over budget) |
| `probes_snapshot_BC_commit_collapse.p4` | commit-collapse snapshot probe |
| `defense4_twopipe_pipe0_probe.p4`, `defense4_twopipe_pipe1_probe.p4`, `defense4_twopipe_pipe1_faithful_probe.p4` | the two-program / two-pipe BOR path (compile-only) |
| `defense4_bor_twopipe_setup.py`, `bor_twopipe_faithful_emulator.py` | control-plane + emulator for the two-pipe path |

Why they were superseded: the **decision-table flatten** (two mutually-exclusive ternary tables →
one `meta.outcome` → one `tbl_commit`) took RRC from 12→10 ingress stages, so BOR fit in the freed
headroom at **12 stages in a single pass** — the two-pipe split was **not needed**.

## Root historical notes

- `BOR_STAGE_RECOVERY_RESULT.md` — the stage-recovery compile matrix (14→13, one over budget).
- `BOR_TWO_PIPE_FAITHFUL_RESULT.md` — the faithful two-pipe result (first OPERATE genuinely held;
  compile-only, never on silicon).
- `autonomous_overnight.md` — the autonomous-run instruction prompt for the campaign.

## Still in the main tree (not archived, but historical context)

`RRC_BOR_UNIFIED12_FIXED.md` (the six-blocker defect ledger) and `RRC_BOR_UNIFIED12_RESULT.md` (the
decision-table flatten result) remain alongside the program because `../CLAIMS.md` cites them
directly. The `defense4_joint_size_time_kernel.p4` and `defense4_crc_split_kernel.p4` siblings are
alternate/earlier kernels; the shipped program carves size itself (see `../README.md`).

*Everything here also remains in git history. This directory only keeps it out of the active
authority path.*
