# m12 gating-risk probe — classify_rev at a 282-byte image COMPILES (2026-10-19)

The integrated READ+SBO size candidate must generalize the reverse-ACK withhold window
`classify_rev` (key `m.r` ternary x `tcp.window` range) from the 61-byte image (124 entries) to an
image that accommodates the 247-byte full READ. The 2-D (ACK-offset vs window) comparison cannot
collapse to one range, so the table grows ~2 entries per image byte. This was the single hardest
unknown gating the whole candidate.

**Result:** `make_classify_rev_probe.py --image 282` regenerates classify_rev to 566 entries on an
otherwise-unchanged m11_09 and compiles under SDE 9.13.1 with **exit_code 0**, resources
**egress 12 / ingress 11 stages** (`probe/evidence/classify_rev282_manifest.json`). bf-p4c's first
placement round reported 16 egress stages, then re-placed within the 12-stage egress budget
(`classify_rev` final at stage 10, 6 TCAMs). The per-byte withhold construction therefore scales to a
282-byte image without a new match primitive.

Caveat: this probe keeps the OLD read/ctl padding in place and only enlarges classify_rev. The
integrated candidate removes the old READ re-encode + SBO fixed-61 (freeing stages) and adds the new
variable padding + the rest of the mapper image-length generalization; final placement is determined by
the integrated compile (M4/M6), not by this probe. What this probe establishes: the withhold-window
size is not the blocker.
