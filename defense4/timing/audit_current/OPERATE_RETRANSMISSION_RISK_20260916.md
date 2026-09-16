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
