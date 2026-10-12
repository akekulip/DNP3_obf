# t_split_outcomes_01

Isolated T outcome-counter stage experiment from frozen source:

- input: `../combined_nt_diag_01/evidence/full_01/response_only.p4`
- input sha256: `13b21e3c34072b9a113acaf5bda5a1210d9a70cbe787d30fb722ad3c3dcbf5bd`
- generated source: `evidence/full_01/response_only.p4`
- generated source sha256: `b337129ae5fc794a1c899d9b82f2fccb290871a7667c001d1c2f39a73864acc5`

The experiment removes the common late `outcome_count` sink and creates four 25-slot banks:

- `outcomes_token`
- `outcomes_tin`
- `outcomes_held`
- `outcomes_hb`

Control-plane logical value is preserved by summing the same index across banks:

```text
logical_outcome[i] = outcomes_tin[i] + outcomes_token[i] + outcomes_held[i] + outcomes_hb[i]
```

`evidence/full_01/counter_semantics.json` records the action-to-bank map, table-action map, inverse map, and all 25 logical counter meanings.

## Verification

```bash
python3 -m pytest -q defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/t_split_outcomes_01/tests/test_split_outcomes.py
# 5 passed in 0.05s
```

Local compile command:

```bash
/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --target tofino --arch tna -g \
  -o /home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/t_split_outcomes_01/evidence/full_01/compile_local/out \
  /home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/t_split_outcomes_01/evidence/full_01/compile_local/source/response_only.p4
# exit_code: 0, elapsed_seconds 81.43
```

Key compile evidence:

- compile log sha256: `3b7537597819558344ef64c2b01581c597ff292d44d2d2f7bf4d0aaf1648ebd2`
- p1 BFA sha256: `19341716925a51b0c279930fe0ff84de2b46cfd6dc8babf111479d0f8d4f1269`
- p0 BFA sha256: `9ee88cb2341049142eab85bcdb4ee67bd50872c473ddd6e3fbc742858e2a2905`
- compile manifest: `evidence/full_01/compile_local/manifest.json`

T placement from p1 BFA:

- stage 4: `token_verdict_0` with `outcomes_token`
- stage 8: `hb_verdict_0` with `outcomes_hb`
- stage 9: `tin_verdict_0` with `outcomes_tin`
- stage 9: `held_verdict_0` with `outcomes_held`

p1 table summary reports 10 ingress stages and critical path length 10.

A failed intermediate compile is preserved at `evidence/full_01/compile_failed_attempt1_mixed_hb_externs/compile.log`; it caught an HB action mapping bug where some `hb_verdict` actions still referenced `outcomes_held`, violating Tofino's same-indirect-extern requirement within one table.

No model parity or hardware validation was run. Model parity remains required before integration.
