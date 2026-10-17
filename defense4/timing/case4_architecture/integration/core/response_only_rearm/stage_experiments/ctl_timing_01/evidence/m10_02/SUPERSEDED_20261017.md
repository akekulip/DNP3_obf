# m10_02 is superseded by m10_03 (2026-10-17)

m10_02 (source `23a808c2…`) compiled on both SDKs at N12/E12/T11 with the mirror guard passing, but **failed the
compiled-model suite**: `model_smoke_m10_02_01` 17/19, and every other driver exited 1 (`model_summary_v3` blocked).
- The SELECT response reached the master unpadded.
- The first divergence from m9_01 is N's loop pass of an ACK, whose origin header was emitted shifted by 16 bits.
- The bisect (`../m10_bisect_01/README.md`) traces it to the new 16-bit metadata field `m.rst_laps` and its parser
  assignments. m10's table and restart actions alone pass 30/30.

No hardware ran on m10_02. Its sealed-profile entries are withdrawn; m10_03 replaces them. All of its evidence is
kept unchanged.
