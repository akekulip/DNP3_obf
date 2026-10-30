# c72 baselines before the connection-start fix (2026-10-30)

Evidence: the c72 build (source SHA-256 `97812585…`) and, for the connection starts, the `c72_diag_mirror` diagnostic
build. Designs registered before traffic: `DESIGN.json` here and `../diag_mirror_d3/DESIGN_e2_combined.json`. Each
campaign was one block with its own freeze, a dry-run of the exact command, and verified restoration. Counts come from
`scripts/analysis/confirmation_summary.py` (`c72_sc20_summary.json`, `c72_sc5_summary.json`,
`../diag_mirror_d3/c72_e2_combined_starts.json`).

## Strict workload (timing and padding on)

Campaigns `rc01_hw_c72_sc20_20261030_01` (D = 20 ms) and `rc01_hw_c72_sc5_20261030_01` (D = 5 ms). Each has 4 cold
trials of 32 strict cycles (mixed READ → SELECT → OPERATE → integrity READ), so 128 exchanges per trial.

| Check | D = 20 ms | D = 5 ms |
|---|---|---|
| Trials passing the strict gate and the recorded verdict | 4/4 | 4/4 |
| Transaction order equal to the strict cycle × 32 | 4/4 | 4/4 |
| Response sizes equal to the class images (141, 60, 60, 158 octets) | 512/512 | 512/512 |
| SELECT/OPERATE with CROB SUCCESS on points 1 and 3 | 256/256 | 256/256 |
| Master TCP retransmissions | 1 (t3: the first request, resent after 212.5 ms) | 0 |

CLRT (relay ACK to complete response at the master) under the response-ready ACK contract, by class:

| Class | D = 20 ms median [p5, p95] (µs) | D = 5 ms median [p5, p95] (µs) |
|---|---|---|
| READ mixed | 20,005 [18,420, 21,597] | 4,930 [3,879, 6,857] |
| SELECT | 20,078.5 [18,695, 21,452] | 5,007 [3,599, 6,455] |
| OPERATE | 20,043 [18,420, 21,677] | 4,919.5 [3,385, 6,700] |
| READ integrity | 19,943.5 [18,408, 21,398] | 4,973 [3,631, 6,726] |

Each class has 128 exchanges per D. The superseded precision criterion is not used; these are measured values.

## Connection starts with timing and padding on (diagnostic build)

Campaign `rc01_hw_c72diag_e2c_20261030_01`: 32 fresh connections, combined arm, D = 20 ms, mirror sessions on. The
mirror capture is complete in 32/32 trials.

- **5 of 32** connections lost one of the master's first two frames after the relay's SYN-ACK inside the switch:
  - the final handshake ACK in 3 (t17, t18, t19);
  - the first request in 2 (t0, t30), retransmitted by the master after 207.6 and 216.7 ms.
- In every case the frame has no egress copy toward the relay, and dev9 RX − dev64 TX = 1.
- The off-arm baseline from 2026-10-29 gave the same count, 5 of 32 (`../diag_mirror_d3/SUMMARY.md`).

Counts are bounded diagnostics, not rates. The mirror is used for packet presence only.
