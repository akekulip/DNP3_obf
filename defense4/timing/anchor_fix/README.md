# Request-anchored release: the fix for the request-to-acknowledgment leakage — 2026-09-18

The evaluated framework *raises* what a classifier recovers from the master-visible
request-to-acknowledgment interval. Undefended, that interval separates READ, SELECT and OPERATE
at 0.479 balanced accuracy, barely above the 0.333 chance level of three classes. Obfuscated, the
same attacker reaches 0.809. `analysis/anchor_diagnosis/FINDINGS.md` traced it to two causes; this
directory implements and measures the fix for the larger one.

**The cause.** The read lane armed its deadlines at the *relay's own acknowledgment*, so the
master-visible interval was `t_A - T_0 + D_A`: the relay's acknowledgment latency stayed inside
it, and that latency differs between transaction classes. The control lane already armed at the
*request*, so the same latency cancelled there. The asymmetry contributes 0.555 ms of the 0.686 ms
spread between the three class medians.

**The fix.** Widen the override the control lane already uses so a READ or SELECT request writes
`T_0 + D_A` and `T_0 + D_A + D_R` itself. The relay's later acknowledgment then takes
`deadline_arm_once` / `tresp_arm_once`, which are no-ops on an already-armed word. Nothing else
moves: the blocker reservoir is seeded at that same request, the armed word keeps the zero low
byte that the expiry test depends on, and an OFF-mode request still writes the unarmed sentinel.

`anchor_req` is a runtime parameter on the existing `tbl_bor_params` default entry, so one loaded
binary runs both schedules and one session interleaves them. Every block asserts the value back
from the switch before it captures anything.

## What is here

| path | what |
|---|---|
| `src/defense4_rrc_bor_unified12.p4` | the program, copied from the frozen tree and changed in one place |
| `anchor_fix.patch` | that change as a diff against the frozen source |
| `control/` | the control plane, with `--anchor-req` threaded through configure, readback and the printed plan |
| `anchor_fix_control.patch` | that change as a diff against the frozen control plane |
| `compile/` | `bf-p4c` logs and allocator summaries for the frozen program and the candidate, compiled in one session |
| `_bin/anchor_block.sh` | one block: configure, prove the carve off and the anchor set, capture, drive, stop |
| `_bin/run_validation.sh` | the run: 8 rounds x 3 arms, arm order rotated by round |
| `raw_pcaps/` | the captures |
| `analysis/` | canonical table, scoring through the campaign's own evaluator, and the adversarial checks |

**The frozen tree is not modified.** `implementation/` is the record of what `campaign_v1` ran and
stays byte-identical; applying `anchor_fix.patch` to it reproduces `src/` exactly.

## Provenance

| | sha256 |
|---|---|
| frozen `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| candidate `src/defense4_rrc_bor_unified12.p4` | `4bba0949489f2a36fde842335e9256aa0b3fbda107be5998d43ef90c26d8dc56` |
| frozen control plane | `d11af11829e00d0017ebe6acf1ffd1c76b9ccd1a77280147ed1307adcd2df99b` |
| candidate control plane | `9b6dae0132f025a5e801cc0d417003f808f0bb125f9f36b4b5c90bca1e9da7a9` |
| loaded `tofino.bin` | `22e542f64ca2af31c17a613838c7634b25cd8d86d8465b463e34ec1323da1fef` |
| loaded `context.json` | `27db174c91ba24555f151d872ebe0b9a6aee31f67ca2211e40d07547f8a44f58` |

Compiler: `bf-p4c --target tofino --arch tna -g -DU_BOR`, Barefoot SDE 9.13.2, on the switch.

## What the change costs the switch

Both programs were compiled in the same session with the same command, so the columns compare.

| | frozen | with the fix |
|---|---|---|
| ingress stages | 12 | **12** |
| egress stages | 6 | 6 |
| critical path through the dependency graph | 12 | 12 |
| tables allocated | 112 | 113 |
| compiler warnings | 10 | the same 10, textually identical |

The frozen program is already at the 12-stage ingress ceiling, so the one thing that could have
stopped this fix was a stage. It does not cost one. The allocator moves tables between stages 5
and 10 but the depth and the critical path are unchanged.

## The run

Three arms, interleaved, one binary, one session:

- **OFF** — Timing OFF, the undefended baseline.
- **A0** — obfuscated, `anchor_req=0`: the schedule `campaign_v1` evaluated. This is a positive
  control. If it does not reproduce the leakage on today's hardware, nothing else in the
  comparison means anything.
- **A1** — obfuscated, `anchor_req=1`: the request-anchored read lane.

Policy is the campaign's own: `D_A` 20 ms, `D_R` 4 ms, `A` 20 ms, `R` 24 ms, `J` drawn from
{2, 6, 12} ms, size carve off and proved off from a hardware readback in every block. Eight rounds,
24 blocks, 18,914 exchanges, every guard passed.

A second run, `_bin/run_phase_test.sh`, holds the arm and the policy fixed and moves the master's
inter-request spacing across 3, 7, 13 and 20 ms. It exists to test causally whether what survives
the fix is arrival phase rather than device execution time, since the relay does identical work at
every spacing. Eight blocks, 4,000 exchanges.

`FINDINGS.md` records what both runs measured, the negative results included.

## Rollback

The switch is restored to the frozen build by
`/home/decps/Philip_repo/dnp3-defense4/anchor_fix_build/launch_frozen_restore.sh`, which carries
the exact `--conf-file` the switch was running before this work.
