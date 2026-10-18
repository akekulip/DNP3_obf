# Campaign fit estimate (2026-10-18, before start)

154 hardware blocks within 24 h need an average below 9.35 min per block, before controller processing.

Estimate from retained runner durations (`rearm_01/hw/run_block.log`, START/END pairs):

| part | blocks | basis | estimate |
|---|---|---|---|
| recovery | 5 | m10_03 Step 4 blocks: 5.2, 3.1, 10.4, 4.0, 5.1 min | 28 min |
| reference | 1 | a complete four-arm repeated-SBO block | ~7 min |
| pilot | 4 | the same | ~28 min |
| feasibility | 16 | combined arm only, short workloads | ~56 min |
| main | 128 | complete four-arm repeated-SBO blocks (m9 ackdiag, m4/m5 characterization): 6.7–7.0 min | ~883 min |
| **total** | **154** | | **~1,000 min (~16.7 h), about 6.5 min per block** |

Shorter retained blocks (2.8–4.3 min) were runs that ended early and are not used as the basis. The evaluation
envelope adds tens of ms per exchange, which is small next to the per-arm cold bring-up time that dominates a block.
This is an estimate, not a guarantee. The 24 h limit stands, and any block not reached is reported as unexecuted.
