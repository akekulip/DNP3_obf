# Rejected Size-Normalization Options

This log is append-only. Rejection means an option cannot satisfy the declared passive TCP-aware observer; it may still be useful for a narrower experiment.

## 2026-08-14 — Rejected before design selection

| Option | Decision | Reason |
| --- | --- | --- |
| `[49] -> [28,21]` and other resegmentation | Reject as total-length hiding | TCP reassembly still yields exactly 49 response bytes. |
| IP fragmentation | Reject | Fragment totals and reassembly expose the original IP payload length. |
| Ethernet padding | Reject | Bytes outside the IP total length are recognizable link padding. |
| TCP options | Reject | Options do not conceal application byte count. |
| Invalid-checksum or out-of-window segments | Reject | A protocol-aware observer can discard them. |
| Recognizable retransmissions | Reject | Sequence numbers identify duplicate bytes. |
| Cover traffic on another port or flow | Reject | The observer can filter it from the protected flow. |
| Cleartext DNP3 padding | Reject | DNP3 structure, length, function, or padding boundary remains parseable. |
| Ordinary encrypted tunnel without fixed inner records | Reject as sufficient mechanism | Ciphertext length continues to correlate with plaintext length. |
