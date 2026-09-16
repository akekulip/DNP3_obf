# Compile result, 2026-09-15: the candidate fits

> **Superseded in part, 2026-09-16.** This records the **v1** candidate: the source and binary
> hashes below are not produced by the patch now in this directory, which is v2. **The resource
> comparison is wrong.** Recompiling both builds on the switch on 2026-09-16 gives, from the
> allocator itself, twelve ingress stages and six egress stages for *both*, with 112 tables for
> the frozen base and 114 for the v2 candidate: the instrumentation adds two tables, not six, and
> neither build uses thirteen ingress stages. **The binary hash below cannot identify a source at
> all**, because `bf-p4c` stamps a random `run_id` into every binary and the same source compiled
> twice produces two different hashes. See `BUILD_ATTRIBUTION_20260916.md`. The closing statement that the candidate has not been loaded and that epsilon
> remains unmeasured was true when written and is no longer: see `run_20260915/` and
> `ATTRIBUTION_AND_DECODE_20260916.md`.

Compiled on the switch with its own SDE, the only place `bf-p4c` exists. Nothing was loaded and
no experiment was run: this establishes that the instrumentation fits, and nothing more.

```
bf-p4c --target tofino --arch tna -g -DU_BOR -o out epsilon_candidate.p4
exit 0 — 0 errors, 9 warnings
```

| | sha256 |
|---|---|
| base `defense4_rrc_bor_unified12.p4` (verified on the switch) | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| candidate source after the patch | `ac3eb62a1be7e0b38d9c36185034b2e0e48a78a7d0e825b2a5df1283cbe33c60` |
| candidate `tofino.bin` | `1d5470a678c6df4eb881d208ec58ae484079bff5e8b7fe247335c39123c8fb1f` |
| frozen `tofino.bin`, for contrast | `33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa` |

## The first attempt failed, and the failure was informative

Three registers on the existing expiry table was rejected outright:

> `error: overlap. Both Register Ingress.reg_ep_valid and Ingress.reg_ep_expiry_first require
> the meter address hardware, and cannot be on the same table Ingress.tbl_deadline_expiry.`

**A table may access only one register.** That is a hardware rule, not a style preference, and it
is worth recording because it constrains any future instrumentation of this program.

The redesign drops the separate validity flag and gives each remaining register its own table.
Validity is derived instead: a slot is valid when both words are non-zero, since the registers are
cleared to 0 and `ingress_mac_tstamp` is never 0 in practice. A zero word therefore reads as *not
measured*, which is the property the plan required, without a third register.

## Resources

| | frozen | candidate |
|---|---|---|
| ingress stages | 13 | **13** |
| ingress tables | 176 | 182 |

It fits in the same stages. The plan's expected failure, that a program already filling the
pipeline would have no room, did not occur; six small tables were absorbed.

## The registers are live, which the inert ones are not

The compiler's unused-instance warnings name `ts_first_block_w`, `ts_ack_arm_w`,
`ts_block_term_w`, `ts_ack_release_w`, `ctr_fresh` and `ctr_deq`. **Neither
`ep_expiry_first_w` nor `ep_block_last_w` appears**, so unlike the four registers already in the
program these are genuinely executed. The frozen build's own `compile_v2.log` carries the same
four warnings, which independently confirms the inertness recorded in the instrumentation audit.

## What this does and does not establish

**Established:** the instrumentation compiles for Tofino, fits the existing stage budget, and its
register actions are reachable.

**Not established:** that it measures anything. It has not been loaded, no traffic has run through
it, and epsilon remains unmeasured. A successful compile also says nothing about whether the
instrumentation perturbs the timing it is meant to observe, which is a question only a loaded run
with a comparison against the frozen build can answer.

The procedure, required evidence and failure criteria for that run are in
`../EPSILON_MEASUREMENT_PLAN.md`. Loading the candidate remains a separately authorised step.
