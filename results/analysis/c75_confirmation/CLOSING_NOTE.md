# c75 stopped; c72 restored as the build (2026-10-30)

Philip stopped the c75 SEL-751 confirmation after three of its eight blocks and restored c72 as the build:
`p4/response_only.p4` and the observation binding equal the `c72-validation-final` state, and `current_build.json`
names c72 with its recorded `model_gate_passed`. Git
history and every result are kept. c75 is **not hardware-qualified**: it was the source selected for testing
(`434c7cf72`), and five blocks never ran.

**Answer from the blocks that ran:** on the exact c75 binary, both READ workloads and SBO completed correctly with
timing and padding, as on c72. In the 32 combined-arm connection starts, c75 lost no first request (c72: 2). It also
showed none of c74's extra relay ACK, because it does not forward the late handshake ACK. These are bounded counts
from one arm, not rates.

## What ran on c75

c75 is c72 plus request retries only (`results/builds/c75/README.md`). The exact binary is source `5ca9168d…`, with
pinned `p0/tofino.bin` `3e11043a…` and `p1/tofino.bin` `f52aaedd…`. Every block ran with a fresh freeze and a dry run of
the exact command, and every one restored the switch.

| Block | c72 | c75 |
|---|---|---|
| Strict workload D = 20 ms: trials / order / class sizes / CROB / retransmissions | 4/4, 4/4, 512/512, 256/256, 1 | 4/4, 4/4, 512/512, 256/256, 0 |
| Strict workload D = 5 ms: same | 4/4, 4/4, 512/512, 256/256, 0 | 4/4, 4/4, 512/512, 256/256, 0 |
| Connection starts, combined arm, 32 fresh connections (c75_diag_mirror): first requests lost inside the switch / retransmitted by the master | 2 / 2 | 0 / 0 |
| Same starts: handshake ACKs suppressed as obsolete (intentional, recorded) / valid ACKs lost / unexplained missing copies | 3 / 0 / 0 | 7 / 0 / 0 |
| Same starts: extra relay ACK before the first response (c74: 4 of 32, its late-ACK reply) / mirror capture complete | 0 / 32 | 0 / 32 |

Median CLRT per class is 19.96–20.22 ms at D = 20 ms and 4.89–5.01 ms at D = 5 ms. Both fall within c72's spread.

**Not run** (stopped by Philip): E2 off-arm starts, recovery r1–r3 and E4b.

## Status of the open items

- **Wrap replay: BLOCKED.**
  - The safety check stopped the offline SelectAndOperate replay on 2026-10-28 and 2026-10-29 (`6d61fc9e4`).
  - Separately, the opendnp3 master writes the SELECT CROB header with qualifier 0x28, where the recorded SEL-751
    traffic uses 0x17. The existing tool (`scripts/analysis/opendnp3_wrap_check.py`) requires the live request to equal
    the recorded one, so it would fail on every SELECT/OPERATE.
  - The original 63→0 bytes of the 256 SELECT/OPERATE wrap responses therefore have no independent reassembly.
    TShark agreed only on renumbered copies (`results/analysis/independent_decode/SUMMARY.md`). opendnp3 reassembled
    all 128 READ wraps (`results/analysis/opendnp3_wrap/SUMMARY.md`).
- **Window updates and keepalives:** suppressed while a READ is outstanding, on c72, c74 and c75 alike. This is
  documented, unqualified behaviour (`results/analysis/ack_behaviour/summary.json`). The supported master sent none in
  498 retained trials (`hardware_master_ack_scan.json`).
- **E3 difference** (c74 13/18 against c72 16/18): unresolved (`results/analysis/recovery_e3/COMPARE_c72_c74.md`).

## Evidence and reproduction

- **Campaigns:** `results/hardware/campaigns/rc01_hw_c75_{sc20,sc5}_20261030_01` and `rc01_hw_c75diag_e2c_20261030_01`.
  Per-trial records are in `results/hardware/blocks/`.
- **Counts:** `results/analysis/c75_confirmation/c75_sc20_summary.json`, `c75_sc5_summary.json` and
  `c75_e2_combined_starts.json`.
- **Procedure:** `D=20261030 bash results/analysis/c75_confirmation/procedure/c75_prepare.sh`, then `c75_run.sh`, then
  `c75_analyze.sh`. All three run from the repository root, and each block runs only once.
