# Canonical final build — silicon validation (2026-07-31)

**Program `case_a_defense3` (R1/R2/R3 unconditional), bf-p4c 9.13.2, Tofino-1.** The
release-hardening changes were validated on silicon; switch restored to the frozen Defense 2
baseline afterward.

## Compile (9.13.2, the deploy compiler)
| build | flags | ingress/12 | crit path | errors | uninitialized_out_param |
|---|---|---|---|---|---|
| core | (none) | 10 | 10 | 0 | **0 (gone)** |
| telemetry | D3_LIVE_FULL_TELEMETRY | 11 | 10 | 0 | **0** |
| synthetic | D3_SYNTH_EVENTS | 11 | 10 | 0 | **0** |
| injector | D3_SYNTH_EVENTS D3_INJECT | 11 | 10 | 0 | **0** |

Matches the report §9.9 final footprint exactly. §5.6 parser fix confirmed on 9.13.2.

## Assembly (artifacts/final/final_core_sde9132.bfa)
`assert_salu_asm.py --require-r2` PASS 0 failures — the R2 note predicate
`equ hi, lo, -phv_hi ; alu_a (cmplo | cmphi)` is present, so the canonical build is the
R1+R2+R3 program at the assembly level (CORRECTIONS.md §6.2).

## Control plane (setup --config on the loaded synthetic build) — n_fail: 0, 43/43 PASS
- **Final-repair arm-guard (§2.2):** present [tbl_resp_authorise, reg_failopen], absent []],
  cf_block_reject_index 17 — refuses to arm a non-final build; passes on the real one.
- **Parameter policy (§3):** D=2 ms admissible (D_max=24.797 ms, H=30.802 ms); tbl_params
  written via the single gated writer and read back (d_ticks=1999872, budget=18000).
- **reg_failopen (§3.4):** clean-start reg_failopen=0; cleanup reg_failopen_after=0; the
  "cleanup: reg_failopen == 0" check PASS.
- Strict priority Q_BLOCK(7) > Q_HOLD(0) PASS; clean-start PASS.

## Restore
Switch returned to Defense 2 (`pktgen_abs.conf`, the frozen silicon-proven baseline),
one bf_switchd — verified.

Evidence: setup_config.log, restore.log in this directory.
