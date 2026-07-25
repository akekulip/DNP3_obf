# Stage A — native timing characterization (directive §5)

120 read-only Class-0 polls of the physical SEL-751 (`192.168.10.1` → `192.168.10.7`, link addr 0),
captured full-frame on Vision eno1. Read-only: Class-0 READ only, no control/write.

- transactions: 120 (119 clean, 1 flagged ambiguous — correctly excluded)
- **native CLRT: median 2.034 ms, p99 11.423 ms, sd 10.33 ms** (sd inflated by a single ~112 ms tail
  sample; the device's real distribution has a heavy tail), 107 distinct values over 119 transactions
- separate-ACK device confirmed; `data_offset=8`
- independent tshark cross-check median 2.038 ms — **agrees within 3.8 µs**
- leakage: 4.44 bits @50 µs, 2.32 bits @1 ms (native)

**Final G selection:** G must exceed the native p99 (11.42 ms). **Final G = 25 ms** (clears p99 with
margin; matches the SEL-751 corpus CLRT p99). The G-sweep {5,10,17,20,25,40} ms spans below-p99
(5,10 — deliberate low-G-guard demonstrations) through above-p99 (17,20,25,40 — protection applied).

Artifacts: `native120.pcap`, `native.{transactions.csv,summary.json,validation.json}`.
