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

## 2026-08-14 — Rejected or demoted at S2

| Option | Decision | Reason |
| --- | --- | --- |
| Dual TCP proxies with fixed AEAD records | Reject as primary | The proxies replace the original master-relay TCP connection, so master-visible acknowledgments no longer traverse the existing RRC path. |
| Standard tunnel carrying fixed records | Demote to fallback | The fixed-record shim, not the tunnel, supplies normalization; tools are absent and tunnel handshakes/rekeys add visible control events. |
| Existing NIC/ASIC crypto offload | Reject as unavailable | ESP, TLS, and MACsec offloads are fixed off on the audited interfaces, and no reviewed P4 cryptographic implementation exists. |
| Adaptive cell-layer retransmission or public NACK | Reject | Loss-dependent recovery changes public count/timing and creates an occupancy oracle. |
| Variable overflow spill or escape packet | Reject | It reveals an exact length or bucket and can expose native clear traffic. |
| Fail-open native DNP3 bypass | Reject | One clear frame immediately defeats the protected-link claim. |
