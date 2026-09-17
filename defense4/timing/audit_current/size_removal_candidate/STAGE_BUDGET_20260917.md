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

## What this would be worth, and what it would cost

Folding the three expiry predicates into their SALUs is the one change that helps both lanes,
because both have an expiry table on their critical path. On its own it is worth about one stage,
not three: `tbl_tresp_expiry` and `tbl_deadline_expiry` already share stage 8. Getting further
means also removing the read lane's `exp_ack → tbl_resp_authorise` and `tag_arm →
tbl_state_decode` boundaries, and those are harder, because both tables key on several fields
rather than on one register's result.

A plausible ceiling is **nine to ten stages rather than twelve**, freeing two or three for
something else on the chip.

**None of this is verified.** It is read from the dependency log and from the SALU sources, and
the TNA predicate facility has its own constraints on how many comparisons one SALU can express
and on whether the result can drive a gateway in the same stage. The only way to know is to build
one fold and compile it. Nothing here should be quoted as a result until that is done.

## Evidence

`compile_20260917/candidate_table_dependency_summary.log` carries the 39 critical paths and the
per-stage dependency matrix; the legend for the dependency letters is at the end of that file.
`candidate_table_summary.log` carries the stage assignment the table above is read from.
