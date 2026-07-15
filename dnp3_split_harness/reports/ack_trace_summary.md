# DNP3 ACK / Response Trace Characterization

Per-transaction reconstruction of six real-device DNP3-over-TCP captures (port 20000). A transaction is anchored at each payload-bearing DNP3 REQUEST (master -> outstation) and matched to the first reverse-direction TCP packet and the first payload-bearing DNP3 RESPONSE.

Terminology: **pure TCP ACK** = zero-payload TCP acknowledgement; **ACK-bearing DNP3 RESPONSE** = a DNP3 response packet that also acknowledges (piggyback). The DNP3 response is never called an "application ACK"; "DNP3 application CONFIRM" is reserved for an actual DNP3 CONFIRM function code (none observed here).

## Top-level summary (per pcap, per outstation IP)

| pcap | outstation IP | role | txns | combined% | separate% | other% | ack->resp med (ms) | ack->resp p95 | ack->resp max | resp sizes |
|---|---|---|---|---|---|---|---|---|---|---|
| AB1400.pcap | 10.0.0.12 | device | 399 | 100.0 | 0.0 | 0.0 | 0.00 | 0.00 | 0.00 | 37:200, 54:199 |
| AB1400.pcap | 10.0.0.2 | reference | 399 | 99.75 | 0.25 | 0.0 | 0.00 | 0.00 | 14.47 | 37:200, 54:199 |
| AB1400L.pcap | 10.0.0.12 | device | 1999 | 100.0 | 0.0 | 0.0 | 0.00 | 0.00 | 0.00 | 37:1000, 54:999 |
| AB1400L.pcap | 10.0.0.2 | reference | 1999 | 99.95 | 0.05 | 0.0 | 0.00 | 0.00 | 13.26 | 37:1000, 54:999 |
| ION7550.pcap | 10.0.0.11 | device | 799 | 100.0 | 0.0 | 0.0 | 0.00 | 0.00 | 0.00 | 37:400, 61:399 |
| ION7550.pcap | 10.0.0.2 | reference | 799 | 99.87 | 0.13 | 0.0 | 0.00 | 0.00 | 13.84 | 37:400, 61:399 |
| ION7550L.pcap | 10.0.0.11 | device | 3999 | 99.97 | 0.03 | 0.0 | 0.00 | 0.00 | 28.75 | 37:2000, 61:1999 |
| ION7550L.pcap | 10.0.0.2 | reference | 3999 | 99.97 | 0.03 | 0.0 | 0.00 | 0.00 | 13.15 | 37:2000, 61:1999 |
| SEL751.pcap | 10.0.0.1 | device | 299 | 0.0 | 100.0 | 0.0 | 12.90 | 16.55 | 165.98 | 37:200, 54:99 |
| SEL751.pcap | 10.0.0.2 | reference | 299 | 99.67 | 0.33 | 0.0 | 0.00 | 0.00 | 11.79 | 37:200, 54:99 |
| SEL751L.pcap | 10.0.0.1 | device | 3999 | 0.0 | 100.0 | 0.0 | 12.18 | 17.18 | 160.71 | 37:2000, 54:1999 |
| SEL751L.pcap | 10.0.0.2 | reference | 3999 | 99.97 | 0.03 | 0.0 | 0.00 | 0.00 | 15.42 | 37:2000, 54:1999 |

## Per-device detail

### AB1400.pcap  |  outstation 10.0.0.12 (device-specific)

- Transactions: **399**  (combined 399 / 100.0%, separate 0 / 0.0%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 0
- request->ACK (ms): median 16.62, p95 17.70, max 95.29, mean 16.89, n 399
- request->response (ms): median 16.62, p95 17.70, max 95.29, mean 16.89, n 399
- ACK->response gap (ms): median 0.00, p95 0.00, max 0.00, mean 0.00, n 399
- Request sizes (bytes): 22:199, 35:200
- Response sizes (bytes): 37:200, 54:199
- Request DNP3 funcs: 1:199, 5:200
- Response DNP3 funcs: 129:399
- Retransmissions: 0, duplicate ACKs: 0, resets: 1, out-of-order: 0

### AB1400.pcap  |  outstation 10.0.0.2 (reference)

- Transactions: **399**  (combined 398 / 99.75%, separate 1 / 0.25%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 1
- request->ACK (ms): median 16.58, p95 18.30, max 21.59, mean 16.69, n 399
- request->response (ms): median 16.58, p95 18.30, max 21.59, mean 16.73, n 399
- ACK->response gap (ms): median 0.00, p95 0.00, max 14.47, mean 0.04, n 399
- Request sizes (bytes): 22:199, 35:200
- Response sizes (bytes): 37:200, 54:199
- Request DNP3 funcs: 1:199, 5:200
- Response DNP3 funcs: 129:399
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

### AB1400L.pcap  |  outstation 10.0.0.12 (device-specific)

- Transactions: **1999**  (combined 1999 / 100.0%, separate 0 / 0.0%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 0
- request->ACK (ms): median 16.25, p95 17.34, max 52.49, mean 16.27, n 1999
- request->response (ms): median 16.25, p95 17.34, max 52.49, mean 16.27, n 1999
- ACK->response gap (ms): median 0.00, p95 0.00, max 0.00, mean 0.00, n 1999
- Request sizes (bytes): 22:999, 35:1000
- Response sizes (bytes): 37:1000, 54:999
- Request DNP3 funcs: 1:999, 5:1000
- Response DNP3 funcs: 129:1999
- Retransmissions: 0, duplicate ACKs: 0, resets: 1, out-of-order: 0

### AB1400L.pcap  |  outstation 10.0.0.2 (reference)

- Transactions: **1999**  (combined 1998 / 99.95%, separate 1 / 0.05%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 1
- request->ACK (ms): median 16.23, p95 18.14, max 52.89, mean 16.38, n 1999
- request->response (ms): median 16.23, p95 18.14, max 52.89, mean 16.39, n 1999
- ACK->response gap (ms): median 0.00, p95 0.00, max 13.26, mean 0.01, n 1999
- Request sizes (bytes): 22:999, 35:1000
- Response sizes (bytes): 37:1000, 54:999
- Request DNP3 funcs: 1:999, 5:1000
- Response DNP3 funcs: 129:1999
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

### ION7550.pcap  |  outstation 10.0.0.11 (device-specific)

- Transactions: **799**  (combined 799 / 100.0%, separate 0 / 0.0%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 0
- request->ACK (ms): median 16.06, p95 19.19, max 21.49, mean 16.47, n 799
- request->response (ms): median 16.06, p95 19.19, max 21.49, mean 16.47, n 799
- ACK->response gap (ms): median 0.00, p95 0.00, max 0.00, mean 0.00, n 799
- Request sizes (bytes): 22:399, 35:400
- Response sizes (bytes): 37:400, 61:399
- Request DNP3 funcs: 1:399, 5:400
- Response DNP3 funcs: 129:799
- Retransmissions: 49, duplicate ACKs: 49, resets: 1, out-of-order: 0

### ION7550.pcap  |  outstation 10.0.0.2 (reference)

- Transactions: **799**  (combined 798 / 99.87%, separate 1 / 0.13%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 1
- request->ACK (ms): median 16.12, p95 32.29, max 40.30, mean 17.39, n 799
- request->response (ms): median 16.13, p95 32.29, max 40.30, mean 17.41, n 799
- ACK->response gap (ms): median 0.00, p95 0.00, max 13.84, mean 0.02, n 799
- Request sizes (bytes): 22:399, 35:400
- Response sizes (bytes): 37:400, 61:399
- Request DNP3 funcs: 1:399, 5:400
- Response DNP3 funcs: 129:799
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

### ION7550L.pcap  |  outstation 10.0.0.11 (device-specific)

- Transactions: **3999**  (combined 3998 / 99.97%, separate 1 / 0.03%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 1
- request->ACK (ms): median 15.98, p95 16.59, max 97.99, mean 16.12, n 3999
- request->response (ms): median 15.98, p95 16.59, max 97.99, mean 16.13, n 3999
- ACK->response gap (ms): median 0.00, p95 0.00, max 28.75, mean 0.01, n 3999
- Request sizes (bytes): 22:1999, 35:2000
- Response sizes (bytes): 37:2000, 61:1999
- Request DNP3 funcs: 1:1999, 5:2000
- Response DNP3 funcs: 129:3999
- Retransmissions: 44, duplicate ACKs: 44, resets: 1, out-of-order: 0

### ION7550L.pcap  |  outstation 10.0.0.2 (reference)

- Transactions: **3999**  (combined 3998 / 99.97%, separate 1 / 0.03%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 1
- request->ACK (ms): median 16.26, p95 17.52, max 120.30, mean 16.51, n 3999
- request->response (ms): median 16.26, p95 17.52, max 120.30, mean 16.52, n 3999
- ACK->response gap (ms): median 0.00, p95 0.00, max 13.15, mean 0.00, n 3999
- Request sizes (bytes): 22:1999, 35:2000
- Response sizes (bytes): 37:2000, 61:1999
- Request DNP3 funcs: 1:1999, 5:2000
- Response DNP3 funcs: 129:3999
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

### SEL751.pcap  |  outstation 10.0.0.1 (device-specific)

- Transactions: **299**  (combined 0 / 0.0%, separate 299 / 100.0%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 299
- request->ACK (ms): median 3.69, p95 5.09, max 12.65, mean 4.01, n 299
- request->response (ms): median 16.98, p95 21.55, max 170.80, mean 18.57, n 299
- ACK->response gap (ms): median 12.90, p95 16.55, max 165.98, mean 14.56, n 299
- Request sizes (bytes): 22:99, 35:200
- Response sizes (bytes): 37:200, 54:99
- Request DNP3 funcs: 1:99, 5:200
- Response DNP3 funcs: 129:299
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

### SEL751.pcap  |  outstation 10.0.0.2 (reference)

- Transactions: **299**  (combined 298 / 99.67%, separate 1 / 0.33%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 1
- request->ACK (ms): median 16.38, p95 22.35, max 171.15, mean 18.40, n 299
- request->response (ms): median 16.38, p95 22.35, max 171.15, mean 18.44, n 299
- ACK->response gap (ms): median 0.00, p95 0.00, max 11.79, mean 0.04, n 299
- Request sizes (bytes): 22:99, 35:200
- Response sizes (bytes): 37:200, 54:99
- Request DNP3 funcs: 1:99, 5:200
- Response DNP3 funcs: 129:299
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

### SEL751L.pcap  |  outstation 10.0.0.1 (device-specific)

- Transactions: **3999**  (combined 0 / 0.0%, separate 3999 / 100.0%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 3999
- request->ACK (ms): median 3.67, p95 5.04, max 17.13, mean 3.95, n 3999
- request->response (ms): median 16.10, p95 21.05, max 164.32, mean 17.31, n 3999
- ACK->response gap (ms): median 12.18, p95 17.18, max 160.71, mean 13.37, n 3999
- Request sizes (bytes): 22:1999, 35:2000
- Response sizes (bytes): 37:2000, 54:1999
- Request DNP3 funcs: 1:1999, 5:2000
- Response DNP3 funcs: 129:3999
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

### SEL751L.pcap  |  outstation 10.0.0.2 (reference)

- Transactions: **3999**  (combined 3998 / 99.97%, separate 1 / 0.03%, other 0 / 0.0%)
- Pure-TCP-ACK-first count: 1
- request->ACK (ms): median 16.42, p95 21.60, max 163.47, mean 17.48, n 3999
- request->response (ms): median 16.42, p95 21.60, max 163.47, mean 17.48, n 3999
- ACK->response gap (ms): median 0.00, p95 0.00, max 15.42, mean 0.00, n 3999
- Request sizes (bytes): 22:1999, 35:2000
- Response sizes (bytes): 37:2000, 54:1999
- Request DNP3 funcs: 1:1999, 5:2000
- Response DNP3 funcs: 129:3999
- Retransmissions: 0, duplicate ACKs: 0, resets: 0, out-of-order: 0

## Measured validation of the expected pattern

Expectation under test: *SEL-751 traces should mostly show SEPARATE_ACK_RESPONSE; AB1400 and ION7550 mostly COMBINED_ACK_RESPONSE.* Measured (device-specific outstation, base+L aggregated):

| device | outstation IP | txns | combined% | separate% | other% | verdict |
|---|---|---|---|---|---|---|
| SEL-751 | 10.0.0.1 | 4298 | 0.0 | 100.0 | 0.0 | mostly SEPARATE |
| AB1400 | 10.0.0.12 | 2398 | 100.0 | 0.0 | 0.0 | mostly COMBINED |
| ION7550 | 10.0.0.11 | 4798 | 99.98 | 0.02 | 0.0 | mostly COMBINED |

