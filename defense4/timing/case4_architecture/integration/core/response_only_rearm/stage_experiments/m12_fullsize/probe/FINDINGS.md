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

# m12 gating-risk probe 2 — adding 220 bytes in one egress pass COMPILES (2026-10-19)

The software append-padder reaches a shared target ≥266 B by adding ~220 B to a 49-B READ (and ~232 B
of framing to a 37-B SBO). The existing E adds only 12–24 B via small PHV headers and uses no
recirculation, so the concern was that large byte injection needs added traversals.

**Result:** `make_addbytes_probe.py --bytes 220` adds six 40-B constant headers to the READ eligible
path and emits them; it compiles under SDE 9.13.1 with **exit_code 0**, resources **egress 12 /
ingress 11** (`probe/evidence/addbytes220_manifest.json`). bf-p4c materializes ~220 added egress bytes
in one pass. Caveat: the probe adds a constant blob with no CRC/TCP-checksum handling; the real padder
must carry valid DNP3 link-frame CRCs and a TCP checksum over the added bytes (the deparser checksum
branch must sum them). That is correctness work, not a placement blocker.

**Combined:** both placement unknowns for the integrated candidate — the reverse-withhold window at a
282-byte image and ~220-byte egress injection — compile within the 12-stage egress budget. The
integrated READ+SBO candidate is placement-feasible; the remaining work is correct implementation
(valid CRCs, TCP checksum over the additions, N lane, model gates).

# Review corrections (2026-10-20)
- **#5 add-bytes probe emits 240 B, not 220.** `make_addbytes_probe.py` rounds the request up to six
  40-byte headers (240 B) while bumping IP length by the requested 220. It is explicitly a **placement**
  probe, so the "large constant injection places in one egress pass" result stands; it does NOT establish
  byte-exact encoding or checksums. The byte-exact encoding is validated by the integrated candidate and
  `model_packets`, not by this probe.
- **#2 intermediate generator output is now flagged non-runnable.** `make_m12.py` writes
  `runnable/full_target: false` with an `intermediate_note` whenever the mapper and the size-path
  transforms (`read_pad`, `sbo_frame`, `n_lane`) do not all agree, so a mapper-only build (image 269 while
  the encoders still emit 61) is never mistaken for a working candidate.
- **#3/#4 verifier holes closed** in `full_read_01/verify_demo.py` with `tests/test_verify_demo.py`: a
  disabled padder (size == native when a target is reachable) now FAILS via `size_verdict`, and corrupted
  synthetic padding in ANY scan now FAILS (the value check moved into the per-scan loop).
- **#1 full-READ append-order** is addressed by the replacement design below (full parse so the appended
  frame emits AFTER the native payload; a partial parse would place padding inside the native frame).
