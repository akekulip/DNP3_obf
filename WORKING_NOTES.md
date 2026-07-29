# WORKING NOTES

## Task
Case A READ-anchored dual release on Tofino-1: release the pure TCP ACK at `t_READ + A` and the
DNP3 RESPONSE at `t_READ + R`, both switch-chosen, so the relay's native timing is an input to
neither deadline.

## Status 2026-07-29 ~02:00 — STATE SAVED, picking up tomorrow
Branch `research/case-a-read-anchored-dual-release` @ `416f70a`, pushed, tree clean.
**Switch verified on the proven Defense 2 program, one bf_switchd.**

Design corrected and Phase 0 complete. The mechanism FITS (skeleton 9/12 ingress, ~1 stage of
margin after deferred Phase-4 work). Four-queue `max_priority` configures and reads back on
silicon. But **no dequeue-ORDER conclusion exists yet** — two pilots both failed for harness
reasons, never for a scheduling reason, and both defects are now fixed and verified.

## Next action
Read Philip's comments on the last exchange first — he said he is picking up from those and they
may redirect. Otherwise: run the restricted five-setting dp8 port-shaper sweep.
Full handoff: `research/case_a_read_anchored_dual_release/RESUME_HERE.md`.

## Key decisions on record
- Fixed-D ACK hold: BUILD IT but re-centre D — my first "don't build" verdict was WRONG (graded
  against the wrong objective). D must exceed the native CLRT, not sit at its centre.
- The timing leak is RELOCATED, not destroyed, by every defense so far. Anchor on `t_READ`.
- Oracle is fully on-chip — no host, no capture, no capabilities. Hulk/dp11 path dropped (link
  dark) but retained as superseded evidence.
- Release gate must be a dp8 PORT-level shaper (dp8 owns the queues; dp11 is post-scheduler).
  Never sequential queue-enable writes — enable-write skew would masquerade as scheduling.
