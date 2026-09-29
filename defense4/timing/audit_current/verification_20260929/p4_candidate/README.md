# Offline OPERATE repair candidates

This directory is separate from every measured source and binary. It tests the
source-level OPERATE loss-recovery defect without changing the paper or touching
hardware.

## Measured source

`defense4/timing/latency_search/randomized/defense4_timing_randomized.p4`

- SHA256: `8e6d0ad983acfceadae447aa7b5b4614193604b6cd87b902b1d567eaa5696478`
- Switch compile manifest: `p4c 9.13.2`, exit 0, binary SHA256
  `a8a8cce9030ac5959f290a3db59da8b16fca24915e35221ee104f895060619c8`
- The manifest reports 7 ingress/context stages. The archived table summary has
  multiple allocator attempts; the first attempt says 8, but the final
  `REDO_PHV1` allocation is 7 ingress stages, 0 egress stages, critical path 7.
  The final allocation is the value that matches `context.json`.

## Source-level finding

The measured randomized source drops a matching OPERATE retransmission after the
original was released:

- `BPC_RELEASE` retires the epoch but leaves `reg_bor_gen` in the held domain.
- A later OPERATE with the same application generation reads `V_OP_DUP`.
- `V_OP_DUP` maps to `OUT_OP_DUP`, which commits through `cmt_drop`.

This is a source-level finding. It is not hardware evidence of an induced
relay-facing loss.

## Candidate status

`defense4_timing_randomized_released_domain_candidate.p4` is the retained
experimental candidate. It marks a released generation in a separate `0xD?`
domain and adds an explicit `V_OP_REPAIR -> OUT_OP_REPAIR -> cmt_op_relay`
path. The test binds this path to the register action, release dispatch, verdict
rule, decision-table entry, and commit-table action. The immediate loss-recovery model passes: a same-generation retry after
release is no longer classified as the held duplicate. The supported local build
helper also accepts it within the 7-stage budget:

- Build path: `build_checked_released_domain/`
- Compiler: local SDE 9.13.1, `p4c 9.13.1 (SHA: e558d01)`
- Exit code: 0
- Final table allocation: 7 ingress stages, 0 egress stages, critical path 7,
  78 tables
- `context.json` stage extraction in `manifest.json`: 7 ingress stages,
  0 egress stages
- Retained source-bound context proof: `build_checked_released_domain/context.json.gz`
  with the uncompressed hash in `context.json.sha256`

This candidate is not safe to promote as a replacement yet. The source-driven
model still finds a late-retry limitation: after a later `PREPARE` creates a new
ready epoch, the program clears the released marker, so a stale OPERATE retry
with the same application generation can be held again. Avoid claiming universal
loss recovery from this candidate.

`rejected_clear_on_release_candidate.p4` is rejected. It clears
`reg_bor_gen` on release. That fixes the immediate retry case, but it also lets a
late stale retry look fresh after the next ready epoch. It is retained only as a
negative candidate because it is the smallest source change and shows why the
obvious fix is unsafe.

## Verification commands

Measured source red check:

```bash
P4_SOURCE_UNDER_TEST=defense4/timing/latency_search/randomized/defense4_timing_randomized.p4 \
  python3 -m unittest defense4/timing/audit_current/verification_20260929/p4_candidate/test_operate_repair_candidate.py
```

Rejected clear-on-release candidate red check:

```bash
P4_SOURCE_UNDER_TEST=defense4/timing/audit_current/verification_20260929/p4_candidate/rejected_clear_on_release_candidate.p4 \
  python3 -m unittest defense4/timing/audit_current/verification_20260929/p4_candidate/test_operate_repair_candidate.py
```

Retained released-domain candidate check (default source, with one expected failure documenting the late-retry limit):

```bash
python3 -m unittest defense4/timing/audit_current/verification_20260929/p4_candidate/test_operate_repair_candidate.py
```

Local compile command used for the retained candidate:

```bash
python3 defense4/timing/stage_reduction/build.py \
  defense4/timing/audit_current/verification_20260929/p4_candidate/defense4_timing_randomized_released_domain_candidate.p4 \
  defense4/timing/audit_current/verification_20260929/p4_candidate/build_checked_released_domain \
  --max-ingress 7
```

`SHA256SUMS` records the candidate sources, tests, compact build evidence, retained context, and
table summaries.

## Limits

No candidate here is a replacement for the measured program. No hardware load,
traffic, relay-facing loss injection, or receiver-visible repair validation was
performed. The retained candidate is experimental because the late-retry case
requires more identity than the current one-byte generation marker carries.
