# Where the twelve ingress stages go, and which of them could be recovered — 2026-09-17

Twelve ingress stages is the whole pipeline. Nothing else can be put on this chip beside the
mechanism, so the question is which stages are load-bearing and which are an artefact of how the
program is written. This reads the answer out of `bf-p4c`'s own dependency analysis for the
size-free candidate, not out of the source.

The compiler prints its critical paths. **There are 39 of them and every one is twelve stages
long, ending at `tbl_commit`.** They fall into two families.

## The two chains

Both lanes are twelve deep, and they have the same shape: a register access, then a table whose
only job is to test what that register just returned, repeated.

| stage | READ lane (19 of the 39 paths) | CONTROL lane (20 of the 39) |
|---|---|---|
| 2 | `exp_ack_w.execute` | |
| 3 | `tbl_resp_authorise` | `epoch_prepare/retire/read.execute` |
| 4 | `tag_arm.execute` | test `hdr.ib.gen == epoch_stored` |
| 5 | `tbl_state_decode` | `ready_confirm/read.execute` |
| 6 | `dl_val = dl_cand_op` | test `ready_stored == epoch_stored` |
| 7 | `tresp_rmw.execute` | `tbl_hold_ok` |
| 8 | `tbl_tresp_expiry` | `topj_rmw.execute` |
| 9 | test `dl_pre == UNARMED_WORD` | `tbl_topj_expiry` |
| 10 | `tbl_decide_fresh` | test `expired_topj` |
| 11 | `tbl_commit` | `tbl_commit` |

**Neither lane is the problem on its own.** Removing the control lane would not get below twelve,
because the read lane has its own twelve-stage path. Any depth reduction has to shorten both.

## The pattern that costs the stages

Eleven of the boundaries are one of two kinds:

* **A register access followed by a table that tests its result.** Six occurrences. The SALU
  returns a value into metadata, and the next stage compares that metadata against something. The
  comparison cannot share the stage that produced its input.
* **A decision table followed by the table that acts on its verdict.** Two occurrences, at the
  outcome ladder and at `tbl_commit`.

The first kind is where the recoverable stages are, because a Tofino SALU can compute a comparison
itself and return a predicate rather than a value. Three cases are especially clear.

### 1. The three expiry tables are one-bit tests of the preceding SALU

`tbl_deadline_expiry`, `tbl_tresp_expiry` and `tbl_topj_expiry` are the same table three times:

```p4
table tbl_topj_expiry {
    key = { meta.age_topj : ternary; }
    const entries = { (32w0x00000000 &&& 32w0x800000FF) : mark_expired_topj(); }
    size = 2;
}
```

Two entries, testing the sign bit of an age the SALU immediately before it computed. `topj_rmw`
already evaluates `rv = meta.now_word - v`; the sign of that subtraction is the whole answer, and
a table consumes a stage to look at one bit of it.

### 2. `ready_read` is a pure read whose result is compared one stage later

```p4
RegisterAction<...>(reg_bor_ready) ready_read = {
    void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
};
```

The next stage computes `ready_stored == epoch_stored`. `epoch_stored` is available from stage 3,
so the comparison's second operand exists before the register is even read. An SALU that returned
the comparison instead of the value would remove the stage that follows it.

### 3. `epoch_read` already performs the comparison it is followed by

```p4
void apply(inout bit<8> v, out bit<8> rv) {
    rv = v;
    if (meta.tok_spent == 8w1 && hdr.ib.gen == v) { v = EPOCH_NONE; }
}
```

It evaluates `hdr.ib.gen == v` internally, returns the epoch instead, and the next stage
recomputes exactly that comparison as `hdr.ib.gen == meta.epoch_stored`.

## What is not worth merging

**`tbl_commit` must stay one terminal table.** It is const-mapped in the P4 so that every `OUT_*`
value has exactly one action known at compile time, and its default is a fail-open forward. An
earlier revision was a control-plane-managed table whose default was `cmt_drop()`, which dropped
every packet if the setup had not run. Folding commit into the decision sites would scatter it
across more than thirty places and give that property up to save one stage. It is the wrong
trade.

**`tbl_hold_ok` → `topj_rmw` is the mechanism.** The hold must be armed before its age can be
taken. That boundary is the thing the paper measures.

## What this is worth: four compiles, and the answer is no

The claim above was that folding an expiry predicate into its SALU would remove a stage. It does.
It was also written before any of it was built, and building it changed the conclusion, so the
paragraph that estimated "nine to ten stages" is withdrawn and replaced by what compiled.

Four variants of the `topj` expiry were compiled on the switch, each identical to the size-free
candidate except for that one register and its table.

| variant | what it does | result |
|---|---|---|
| 1 | SALU returns `(age & 0x800000FF) == 0`, the exact test the table performed | **rejected**: "You can only have more than one binary operator in a statement if the outer one is \|" |
| 2 | SALU returns `v <= now_word`, dropping the armed check | compiles, **11 stages** |
| 3 | adds the armed check back inside the same action | **rejected**: "needs 3 comparisons but the device only has 2 comparison units" |
| 4 | splits the write guard into its own action, as `reg_bor_epoch` already does, freeing a comparison unit | compiles, **11 stages**, 98 tables |

So the resource question is answered: **the fold removes a stage, 12 to 11, and the critical path
falls with it.** Variant 4 costs one extra table for one fewer stage.

## And the answer to whether it may be used is no

**None of the variants that compile is correct**, which is why this is recorded rather than
proposed.

The table being replaced tests `(now - deadline) & 0x800000FF == 0`. That is deliberately
*modular*: the sign bit of a 32-bit subtraction, which is wrap-safe. Variants 2 and 4 replace it
with `deadline <= now`, a direct comparison, which is not. The clock is the low 32 bits of the
nanosecond timestamp, so it **wraps every 4.295 seconds**, and a hold is 20 to 24 ms:

```
deadline 0xFFF00001 armed just before a wrap, tested at now = 0x00100001, 2.10 ms later
   the table's test : expired   (correct)
   the folded test  : not expired
```

About **0.56 %** of holds straddle a wrap, one in a hundred and eighty, and on each of those the
folded version would miss a deadline that is due. That is not a corner case worth accepting in a
release mechanism.

The wrap-safe test needs a subtraction and then a comparison of its sign. One SALU statement
cannot express both, which is exactly what variant 1's rejection says, and the two comparison
units the device has are not the constraint that blocks it. So the stage is recoverable only by
changing how a deadline is encoded, so that "armed and due" becomes a single wrap-safe
comparison. That is a design change to the timing mechanism, not a rewrite of one register action,
and nothing here has been done to it.

## What this establishes, exactly

* Both lanes are twelve stages deep independently; shortening one does not shorten the pipeline.
* The depth is spent on a repeated pattern, a register access followed by a table that tests its
  result, and that pattern is where any saving has to come from.
* One such fold does save a stage, measured, twice.
* No version of that fold preserves the mechanism's semantics, and the obstacle is the modular
  clock rather than the compiler.

`tbl_commit` and `tbl_hold_ok -> topj_rmw` remain excluded for the reasons given above.

## Evidence

```
compile_20260917/candidate_table_dependency_summary.log   the 39 critical paths
compile_20260917/probe_compile.log                        variants 1 and 2
compile_20260917/probe_table_summary.log                  variant 2: 11 stages
compile_20260917/probe3_compile.log                       variant 3, the comparison-unit limit
compile_20260917/probe4_compile.log                       variant 4
compile_20260917/probe4_table_summary.log                 variant 4: 11 stages, 98 tables
probe4_topj_predicate_fold.p4                             the variant-4 source, kept for reference
```

None of the probes was loaded, and no probe is a proposal.
