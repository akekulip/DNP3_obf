# WORKING NOTES

**Task (2026-08-03): §5.8 hold-continuity K-sweep on silicon — COMPLETE.**

Philip authorized the hardware run. 96 in-chip Gate-2 trials (final synthetic build,
K 1..64 × D 2/8/16 ms × 3 reps, budget scaled so only coverage binds; K=64 pin relaxed
by name, recorded in every manifest). **Measured continuity floor K = 44 at every D**
(D-independent as modeled; the ~16 estimate falsified — this build's loop RTT is
(1036, 1176] ns, not Part-12's 408 ns). Release-bias = K/rate confirmed at K 44/48/64.
Deployed K = 64 keeps a measured 1.45× margin. Switch RESTORED to Defense 2 + verified.

Deliverables: evidence + RESULTS.md at `defense3/evidence/ksweep_hold/20260803T175912Z/`;
runner `run/ksweep_hold.sh` (+`_refine.sh`); analyzer `analysis/analyze_ksweep_hold.py`;
fig14 (measured, IEEE single-column) + fig13 corrected to floor 44; RESUME_STATE updated;
memory note `ksweep-hold-continuity-floor.md`; MEMORY.md index compacted (blurbs archived
into topic files).

**Next action:** none pending — commit/push is the last step of this task. Open items
remain per RESUME_STATE (§10.B: hardware-timestamped capture, egress sweep; Case C
physical repro).
