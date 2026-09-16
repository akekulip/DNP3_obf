# A lost OPERATE cannot be repaired by its own retransmission

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

Split the stored marker's meaning into held and released, rather than adding new state:

* `reg_bor_gen` already holds one byte. Reserve its high bit as a **released** flag, set on the
  `BPC_RELEASE` pass, in the same action that currently keeps the generation. The generation
  occupies the low nibble already, so the encoding has room, and the one-register, one-access
  rule is preserved because `BPC_RELEASE` is a different packet from the retransmission.
* Classify on both: generation match **and** released clear stays `V_OP_DUP` and drops;
  generation match **and** released set becomes a new verdict, `V_OP_REPAIR`, whose outcome
  forwards rather than drops.
* `gen_clear` on the next `BPC_PREPARE` clears the flag with the generation, as now.

This keeps the property the spent marker was introduced for, which is that a duplicate cannot arm
a second deadline or release the command twice, while letting the transport repair a loss after
the command has left. It changes no timing path: a forwarded repair takes the ordinary forwarding
outcome and is not held, so it cannot perturb the release schedule of a later transaction.

**What it does not give.** Exactly-once execution. If the original did reach the relay and the
copy is a spurious retransmission, forwarding it delivers the command's bytes twice to the relay's
TCP, which will discard them as an already-received sequence range. That is TCP's job and not the
switch's, and it is the reason the switch must not try to be the arbiter: it cannot see what the
relay received.

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
