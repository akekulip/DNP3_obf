# ACK-delay localization: predefined, bounded plan (written 2026-10-17, before any m9d run)

## Question

In m9_01 qualification, two repeated-SBO blocks each had one exchange where the master saw the outstation's ACK
about 1.1 ms late, while the response kept close to its own deadline (b1 SELECT 127, b3 READ 117;
`m9_01/COMPLETION_REPORT_20261017.md`).

Is that delay already present when the packets leave the switch's queues, or is it added afterwards?

## Instrument (m9d_01, a diagnostic build, never a candidate)

`generate.transform_e_diag`: m9 plus one E register. N and T are byte-identical to m9.
- **What is recorded:** for every master-bound TCP packet that is not dropped, E stores the egress parser's
  `global_tstamp[31:0]` (ns), indexed by the master-visible `tcp.ack[13:0]`. `lo` holds the pure ACK and `hi` the
  response.
- **Where that point is:** the egress parser runs when the packet leaves the traffic manager toward the master port,
  after T's recirculating holds and the final TM queue. That is the latest point this pipeline can observe.
- **What remains unobserved:** E's egress processing and the deparser (a fixed pipeline latency); the MAC, serdes
  and cable; and Vision's NIC, interrupt moderation and kernel, up to the capture timestamp.
- **How it is read:** at each trial's after-snapshot, before teardown (`snapshot_counters.read_egress_diag`).

## Runs (exactly six, one attempt each, in this order; no run is added or repeated)

| # | run id | build | workload |
|---|---|---|---|
| 1 | ctl_m9_ackdiag_ctrl_b1_01 | m9_01 (control) | repeated-SBO, separate ACK, 4 arms, arm order of qualification b1 |
| 2 | ctl_m9d_ackdiag_b1_01 | m9d_01 | the same |
| 3 | ctl_m9_ackdiag_ctrl_b2_01 | m9_01 | qualification b2's arm order |
| 4 | ctl_m9d_ackdiag_b2_01 | m9d_01 | the same |
| 5 | ctl_m9_ackdiag_ctrl_b3_01 | m9_01 | qualification b3's arm order |
| 6 | ctl_m9d_ackdiag_b3_01 | m9d_01 | the same |

Each block runs the same template, endpoint, shaping, pacing, 65 READs + 64 SBO cycles per arm, gap and timing
parameters as the qualification blocks. They differ only in purpose: `timing_precision_characterization`, so every
arm runs even after a miss. The checks before and after each block are the usual ones:
- `freeze_gate.py check` before every block, via `run_block_frozen.sh`;
- `restore_verify` after every block;
- stop all hardware on an unverified restore.

## Definitions and outcome rules (fixed now)

- **Tail exchange.** One whose master-observed CLRT is off by more than 100 µs from 950 µs. Each tail is also
  classified by signature: is the master-visible ACK latency more than 500 µs above that kind's block median, and is
  the round trip within 300 µs of its median?
- **Instrumentation effect.**
  - Compare m9d with control, per kind and arm: median CLRT, nearest-rank p99 absolute error, and the number of
    tail exchanges.
  - A median shift above 10 µs, or a precision objective that passes on one build and fails on the other, is
    reported as a possible instrumentation effect.
  - Tail counts are reported, not tested; they are too few.
- **Correlation.** For every m9d exchange, the entry at index `ack & 0x3fff` gives `switch_clrt = hi − lo` (mod
  2^32). Two rules:
  - each master-visible ACK and response in the capture must have its entry, or the exchange is reported
    unmatched;
  - `host_clrt − switch_clrt` is reported for all matched exchanges: median, p99, max.
- **Localization of each m9d tail exchange.**
  - **Downstream of the egress parser:** `switch_clrt` is within ±100 µs of 950 while the host's CLRT is not.
  - **At or before the egress parser:** `switch_clrt` is itself off by more than 100 µs. The switch emitted the ACK
    late relative to the response.
  - **Unmatched:** otherwise.
- **If no tail occurs in the three m9d blocks**, the result is "not reproduced". The ACK delay remains unlocalized,
  nothing is claimed fixed, and no further run is made under this plan.
