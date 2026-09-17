# A lost OPERATE cannot be repaired by its own retransmission

> **A correction now exists, 2026-09-17.** It is built, compiled, loaded and measured in
> `../operate_repair_candidate/`: released generations move to `0xD0..0xDF`, a repair is
> relayed instead of dropped, the encoding is verified exhaustively over all 528 cases, and
> it costs four tables and no additional ingress stage. Sixty READ polls through each build
> give a CLRT median of 3.9995 ms frozen against 4.0000 ms corrected, so the timing is
> unchanged. **The repair path itself is still untested**, because inducing a loss needs the
> relay-facing link instrumented and it is not. The frozen program, which is what the
> manuscript evaluates, still has the defect described below.


Identified by the 2026-09-16 review and confirmed here by reading the frozen program. This is
source-level reasoning about `defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`.
**It has not been reproduced on hardware, and no capture in this repository exercises it.** No P4
source was changed: the evaluated program is the record of what ran.

## The state transitions

Three facts from the frozen source, each quoted by location rather than paraphrased:

* `gen_arm` (line 1774) writes the OPERATE's generation into `reg_bor_gen` when the register is
  inactive.
* `gen_clear` (line 1780) is executed on exactly one path, `BPC_PREPARE` (line 3202), which is the
  SELECT phase. The program's own comment at that point states that **release does not clear the
  generation**: it keeps the just-released value deliberately, as a spent marker.
* A later OPERATE whose generation equals the stored one is classified `V_OP_DUP` (line 3225) and
  committed to `cmt_drop()` through `OUT_OP_DUP` (lines 794 and 2340). The source labels this
  "exactly-once".

So the marker survives the command's release and is cleared only by the next SELECT.

## The failure sequence

1. A SELECT completes and the switch arms the transaction.
2. The switch holds the OPERATE and releases it toward the relay.
3. **That released packet is lost on the relay-facing link.** The relay never receives those TCP
   bytes and therefore cannot acknowledge them.
4. The master's transport retransmits the OPERATE: same sequence range, same application control
   byte, so the same generation.
5. The stored spent marker classifies it `V_OP_DUP`, and it is dropped. So is every later copy,
   until a new SELECT clears the marker.

The retransmission in step 4 is the packet that would repair the loss, and it is the one the
switch discards. Forwarding a packet out of the switch is not delivery to the relay, and a
mechanism cannot treat its own earlier forward as proof that the bytes arrived.

## Why the existing evidence does not cover it

The 2026-09-15 duplicate diagnostic drops an **outstation RESPONSE on the master side**. This case
loses a **master OPERATE on the relay side**: a different packet, a different direction, and a
different link, which is not instrumented.

The separation-of-timescales argument in `duplicate_test_20260915/LIVE_WINDOW_20260916.md` does
not apply either. That argument bounds how long a transaction stays live against how soon a copy
can arrive. The spent marker is not bounded by the live window at all: it persists after release
and until the next SELECT, so a retransmission arriving long after every hold has ended still
meets it.

## What must not be claimed

* Not general loss recovery, and not "delivery preservation" for the control path.
* Not exactly-once execution. The source comment uses that phrase for this mechanism; the
  repository's claim boundaries already state that exactly-once is neither provided nor claimed,
  and this is a further reason. Dropping a retransmission is not exactly-once; it is a lost
  command that the transport is prevented from repairing.
* Nothing about the campaign changes. The campaign exchanged 5,280 OPERATEs with zero
  retransmissions and every control operation returning success, so this path was never entered
  there. That is the normal case working, not evidence that the failure case is handled.

## What a correction would have to do

Not implemented here, and out of scope for the evaluated build:

* Distinguish a duplicate arriving while the original is still **held** from a retransmission
  arriving after the original has been **forwarded**. Only the first is a duplicate of something
  the switch still controls.
* Allow the transport to repair a missing sequence range without replaying the command as new
  application bytes. TCP itself separates newly delivered bytes from a repeated range; a
  data-plane rule keyed on an application generation does not.
* Bound the marker's lifetime by something other than the arrival of the next SELECT.

A focused test would need the relay-facing link instrumented and a controlled loss injected on it
after release, which is a separately authorised hardware session and a different instrumentation
build from the one this repository has.

---

# A correction candidate, and the test that would settle it

Neither is implemented. The evaluated P4 is unchanged and stays that way. This records what a
future implementation would have to do, at the level of the state it already keeps, so that the
work is specified rather than left as "fix the duplicate rule".

## The distinction the current rule cannot make

`V_OP_DUP` fires on one condition: the arriving OPERATE's generation equals the stored one. That
condition is true in two situations that need opposite treatment.

| situation | what the switch still controls | correct action |
|---|---|---|
| a copy arrives while the original is **held** in qid2, before `BPC_RELEASE` | the original: it has not left the switch | drop the copy. Releasing both would put the command on the relay-facing link twice |
| a copy arrives **after** `BPC_RELEASE` has forwarded the original | nothing: the bytes are gone, and their delivery is unknown | forward the copy. It is the transport repairing a loss the switch cannot see |

The program already distinguishes these two phases: `BPC_RELEASE` is a distinct pass code, and it
is the point at which the comment says the generation is deliberately kept. So the information
needed is present; what is missing is that the duplicate rule does not consult it.

## The candidate

An earlier version of this section proposed reserving the stored byte's high bit as a released
flag, on the reading that the generation occupied only the low nibble. **That was wrong and must
not be implemented.** The parser assigns `meta.gen_in = hdr.dnp3_app.app_control` at line 1462 and
the arming branch admits only `(app_control & 0xF0) == 0xC0`, so every generation that can be
written is in `0xC0..0xCF` and already has bit `0x80` set. A released flag in that bit would make
every held generation read as released. Masking down to the low nibble instead is no better:
application sequence zero would become `0x00` and collide with `GEN_INACTIVE`, which is the
sentinel the fresh-arm test depends on.

What the mechanism needs is three states for each of the sixteen application sequence values, and
the byte has room for them in a different place:

| state | stored value | written by |
|---|---|---|
| inactive | `0x00` | `gen_clear` on `BPC_PREPARE`, as now |
| held | `0xC0 \| s` | `gen_arm` on `BPC_OPERATE`, as now |
| released | `0xD0 \| s` | a new write on `BPC_RELEASE`, where today the value is left alone |

The verdict then reads the stored byte rather than a flag. The program compares through the SALU's
difference, so the three outcomes stay disjoint arithmetically: an arriving `0xCn` against an
inactive `0x00` gives `0xCn`, which is the fresh set; against a held `0xCn` gives `0x00`, the
duplicate; against a held `0xCm` gives `0x01..0x0F`, the busy set; and against a released `0xDm`
gives `0xE1..0xFF`, with the exact match at `0xF0`. That last range is the new one, and it is
disjoint from all three existing sets. `V_OP_REPAIR` is the `0xF0` case and forwards; the rest of
`0xE1..0xFF` is a different sequence arriving after a release, which is the busy case and fails
open as it does today.

**Every reader of the register has to be audited, not only the verdict.** `tbl_txn_active` matches
`cur_gen` against `0xC0 &&& 0xF0`, so today a released-but-uncleared transaction still matches it
and a released one under this encoding would not. That is the intended meaning, because no hold is
live after release, but whatever depends on the current behaviour has to be found first. The same
applies to the comment block at lines 504 to 511, which documents the disjointness of the decode
sets and would no longer be complete.

This keeps the property the spent marker was introduced for, which is that a duplicate cannot arm
a second deadline or release the command twice, while letting the transport repair a loss after
the command has left.

**What is not established.** The earlier claim here that a forwarded repair cannot perturb a later
transaction was asserted, not shown, and the program contradicts the easy version of it: the
shared sequence and acknowledgment trackers `exp_seq_w` and `exp_ack_w` execute at lines 3070 and
3074, well before the OPERATE verdict is computed at line 3225, so a repair that arrives while a
later transaction is live has already touched shared state by the time anything decides to forward
or drop it. A repair is also indistinguishable at the register from a spurious retransmission,
and forwarding one during a later transaction writes that transaction's expected relay sequence
from the wrong packet. The candidate therefore has to specify what happens in that overlap before
it is worth building, and the specification is not finished here.

**What it does not give.** Exactly-once execution. If the original did reach the relay and the
copy is a spurious retransmission, forwarding it delivers the command's bytes twice to the relay's
TCP, which will discard them as an already-received sequence range. That is TCP's job and not the
switch's, and it is the reason the switch must not try to be the arbiter: it cannot see what the
relay received.

## The acceptance cases a correction has to satisfy

One isolated SELECT and OPERATE is not enough to accept this change, because the failure the
encoding introduces is an overlap failure. A correction is acceptable only when all of the
following are settled, offline in simulation first and on hardware afterwards:

1. **Duplicate while held.** A second copy arriving before `BPC_RELEASE` is dropped, arms no
   second deadline, and the command reaches the relay exactly once.
2. **Repair after release.** A copy arriving after `BPC_RELEASE`, with no intervening SELECT, is
   forwarded.
3. **Repair during a later transaction.** A copy arriving after a new SELECT has armed a new
   generation must not alter the live transaction's deadline, and the behaviour of `exp_seq_w`
   and `exp_ack_w` on that packet has to be defined rather than inherited. This is the case the
   earlier version of this document wrongly assumed away.
4. **Sequence wrap.** Sixteen intervening control operations return the same application
   sequence; the marker must not make a genuinely new OPERATE read as a repair.
5. **Lost SELECT.** The marker is cleared only by the next `BPC_PREPARE`, so the specification has
   to say what a released marker means when the SELECT that would clear it never arrives.

## The test

One SELECT, one OPERATE, no other traffic, with the relay-facing link instrumented, which the
current testbed does not do.

1. Configure through `active_control/`, with shaping forced to 0 and read back, and record the
   loaded build's normalised hash.
2. Capture on **both** links at nanosecond resolution. The relay-facing capture is the point of
   the test: without it, forwarding cannot be distinguished from delivery.
3. Drive one SELECT and one OPERATE to an isolated point through the guarded driver.
4. After the switch releases the OPERATE toward the relay, drop that released packet on the
   relay-facing link only, scoped to the probe's own 4-tuple.
5. Let the master's transport retransmit the OPERATE.

**The outcome is binary.** If the retransmission reaches the relay, the repair path works. If it
is dropped inside the switch, `OUT_OP_DUP` has discarded a packet TCP needed, which is the defect.

**What would make the run invalid:** shaping enabled; the drop rule matching anything but the
probe's connection; the relay-facing link not captured, which reduces the test to the one already
run; or any control point that is not isolated.

This needs a separately authorised hardware session and an instrumentation build that does not yet
exist. Until it runs, the manuscript claims no loss recovery on the control path, and the
repository's claim boundaries say exactly-once is neither provided nor claimed.
