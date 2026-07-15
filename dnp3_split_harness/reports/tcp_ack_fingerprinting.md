# TCP ACK Fingerprinting Results

Live results from the Vision↔Hulk rig. Phase 9: inter-layer response
fingerprinting of the Hulk outstation from the large-read capture.

## Setup
- **Capture:** `captures/baseline/large_read.pcap` (Vision `10.10.54.19` master →
  Hulk `10.10.54.158` slave, one large Class 0 read).
- **Tool:** `analysis_tools/analyze_tcp_ack_behavior.py`.

## Per-device summary (`reports/tcp_ack_summary.csv`)
| device | pcap | total_requests | pure_ack | piggyback_ack | pure_ack_ratio | mean_ack_delay_ms | mean_response_delay_ms | tcp_option_signature |
|---|---|---|---|---|---|---|---|---|
| 10.10.54.158 (Hulk) | large_read.pcap | 9 | 1 | 9 | 0.111 | 0.239 | 1.014 | `NOP-NOP-Timestamp` |

## Interpretation
- **Piggyback-dominant.** 9/9 requests got the application response with the ACK
  piggybacked; only 1 standalone pure ACK was seen (ratio 0.11). The Hulk outstation
  answers immediately rather than ACKing first and replying later.
- **Very low latency:** mean request→ACK ≈ **0.24 ms**, mean request→response ≈ **1.01 ms** —
  consistent with two directly-switched Dell R440s on the 1G management LAN (no WAN).
- **TCP option signature `NOP-NOP-Timestamp`** on the steady-state data segments — the Linux
  6.8 / i40e stack fingerprint (TCP timestamps enabled, NOP-padded). Window scaling / MSS /
  SACK appear on the SYN, not on these mid-stream data packets.
- This is the host's TCP/IP response fingerprint; it is distinct from the DNP3 application
  behavior and would differ for a real field RTU (different OS/stack, TTL, window, options).

## Notes
- `reports/tcp_ack_details.csv` has the per-request rows (TTL, IP ID, window, PSH, delays).
- Capturing the same exchange from a different device/stack would let this be used as a
  device-distinguishing fingerprint (the original motivation for the analyzer).
