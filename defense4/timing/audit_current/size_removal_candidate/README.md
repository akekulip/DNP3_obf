# Removing the size layer: what it costs the switch, measured — 2026-09-17

The evaluated program carries a size-obfuscation layer that the campaign never used. `shape_enable`
is 0 in every block of `campaign_v1` and the manifests record it, so both arms are timing only.
The machinery is nonetheless compiled in, and the question this answers is what it occupies.

`size_removal.patch` applies to the frozen P4 and produces a candidate with the size layer deleted
and nothing else changed. **The frozen tree is not modified.** The candidate was compiled on the
switch, which is the only place `bf-p4c` exists; it was **not loaded and nothing was run**.

| | sha256 |
|---|---|
| base, `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| candidate after applying the patch | `5d48d18b3f3728186404992647c8ad3e83a982c6474296cdb5469f4fbc2f8ff2` |

Applying the patch to the base reproduces the candidate byte for byte, which is the only check
available offline.

## What the allocator says

Both were compiled in the same session with the same command, so the two columns are comparable:

```
bf-p4c --target tofino --arch tna -g -DU_BOR -o out_<build> <build>.p4
```

Each exits 0 with the same nine warnings.

| | base | candidate | change |
|---|---|---|---|
| ingress stages | 12 | **12** | **none** |
| egress stages | 6 | **0** | all six freed |
| tables allocated | 112 | **97** | 15 fewer |
| critical path through the dependency graph | 12 | 12 | none |

**Removing the size layer frees no ingress stage.** That is the headline, and it is not what one
would guess from the fact that the layer has a table in ingress. The depth is set by the
dependency graph, whose critical path is 12 in both builds.

Tables per ingress stage, base against candidate:

```
stage      0   1   2   3   4   5   6   7   8   9  10  11
base      16  16  16  12  12  11   4   5   3  12   4   1
candidate 16  15  13   6   8  10   4   5   3  12   4   1
```

Everything the removal frees is in stages 1 to 5. **Stages 6 through 11 are identical**, and they
are the control-lane decision chain: `ready_confirm`/`ready_read` at 5, the `ready == epoch`
comparison at 6, `tbl_hold_ok` at 7, `tresp_rmw` at 8, `topj_rmw` at 9, the outcome ladder at 10
and `tbl_commit` at 11. Each step consumes a stage because it reads what the previous stage's
register wrote, and a register access and the comparison of its result cannot share a stage. Six
stages of the twelve carry 29 of the 112 tables; that tail is the pipeline depth, and the size
layer is not in it.

## PHV

The egress is emptied, and the ingress pressure eases without a group being freed:

| MAU group | base | candidate |
|---|---|---|
| B0-15, 8-bit ingress | 16/16 containers, 118 bits used, 150 allocated (117 %) | 16/16, 118 used, **142 allocated (111 %)** |
| H0-15, 16-bit ingress | 16/16, 230 used, 344 allocated (134 %) | 16/16, 230 used, **328 allocated (128 %)** |
| H16-31, 16-bit egress | 9/16 containers, 136 bits | **1/16, 9 bits** |
| W0-15, 32-bit ingress | 16/16, 512 used, 718 allocated | 16/16, 512 used, **742 allocated (145 %)** |
| W16-31, 32-bit egress | 11/16, 352 bits | **0/16, 0 bits** |

The 8-bit ingress group the source calls container-exhausted is still at 16/16 containers, so
removing the size layer does not free a container there; what falls is the overlay pressure on it,
from 150 to 142 bits allocated. The 32-bit ingress group goes the other way, 718 to 742 allocated,
which is the allocator repacking rather than a cost of the removal, and it is recorded here rather
than left out because it is the one number that moved against the change.

## What the patch removes

Only the size layer. Every remaining table, register, queue and deadline is the frozen program's.

* the parser's 49 B eligibility gate, its four exact select entries and its four states
  (`meta.payload49`). The four `(data_offset, total_len)` pairs now fall through to the general
  DNP3 ranges, which send them to the same states;
* `meta.shape_enable`, the sixth parameter of `set_params`, and `meta.do_shape`;
* `tbl_build_do_shape`, the level-1 precompute that existed only to keep the release gateway a
  single-field test;
* the `do_shape` ternary column from `tbl_decide_fresh` and `tbl_decide_deq`, the three entries
  that selected a SHAPE outcome, and the trailing wildcard from the other 36;
* `cmt_shape`, the `RRC_TO_SHAPE` macro, the four `OUT_*_SHAPE` outcome codes, and the multicast
  group `0x2849` they replicated into. `RRC_RESP_FWD` went with them: it was defined and never
  called, since `cmt_shape` used `RRC_TO_SHAPE` directly;
* the whole egress pipeline. The DNP3 CRC-block headers, the block re-parse, the
  replication-id interpreter and the per-window checksum recomputation. The egress held no timing
  logic at all, which is why removing it costs the mechanism nothing.

## What this is not

It is a compile result and nothing more. The candidate has not been loaded, no traffic has crossed
it, and no measurement in the manuscript comes from it. The campaign's numbers come from the
frozen binary, which has the size layer compiled in and switched off, and they stay that way.

A control plane for this candidate would write five parameters to `tbl_params`, not six, and would
have no PRE group to install. The frozen control plane does both and would need a matching change
before this candidate could be configured at all.

## Files

```
size_removal.patch                     applies to the frozen P4; reproduces the candidate exactly
compile_20260917/base.compile.log      bf-p4c on the frozen program, 0 errors
compile_20260917/cand.compile.log      bf-p4c on the candidate, 0 errors
compile_20260917/*_table_summary.log   the allocator's own stage and table assignment
compile_20260917/*_phv_summary.log     the PHV group occupancy the table above is read from
```
