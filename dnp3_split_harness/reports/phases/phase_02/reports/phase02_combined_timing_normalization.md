# Phase 02 — Combined-Response Timing Normalization (loopback measurement)

_Run `20260716T111608Z_phase_02_combined_timing_normalization`. Mechanism: existing `timing_policy` native/fixed/bounded via `split_server`. **Loopback, application-level** measurement — not a sniffer PCAP. PCAP wire timing and ACK-mode-after-normalization are unavailable on this host (dumpcap not group-executable; no rig) and remain the open items._

## Per-config summary (big Class-0 READ = 2407 B)

| config | n txns | byte-identical | bypassed | deadline miss | READ client-visible med (ms) | CI |
|---|---:|---:|---:|---:|---:|---|
| native/full | 150 | 100.0% | 0 | 0 | 0.60 | [0.59, 0.61] |
| fixed25/full | 150 | 100.0% | 0 | 0 | 25.31 | [25.28, 25.32] |
| bounded20-30/full | 150 | 100.0% | 0 | 0 | 23.30 | [23.30, 23.31] |
| native/crc-split | 150 | 100.0% | 0 | 0 | 0.78 | [0.78, 0.79] |
| fixed25/crc-split | 150 | 100.0% | 0 | 0 | 25.31 | [25.29, 25.31] |
| bounded20-30/crc-split | 150 | 100.0% | 0 | 0 | 23.28 | [23.21, 23.33] |
| fixed300-rto105/full (bypass) | 150 | 100.0% | 150 | 0 | 0.64 | [0.63, 0.65] |

## Decorrelation of visible time (client-observed)
Correlation of the visible request→response time with response size and with the native response-ready delay, per config. Normalization should DROP the size/native correlation vs native mode.

| config | n | corr(visible, resp size) | corr(visible, native-ready) |
|---|---:|---:|---:|
| native/full | 150 | -0.550 | 0.681 |
| fixed25/full | 150 | 0.178 | -0.183 |
| bounded20-30/full | 150 | -0.173 | 0.031 |
| native/crc-split | 150 | 0.284 | 0.072 |
| fixed25/crc-split | 150 | 0.217 | -0.214 |
| bounded20-30/crc-split | 150 | -0.151 | 0.042 |
| fixed300-rto105/full (bypass) | 150 | -0.293 | 0.830 |

> Loopback/application-level results. Byte identity and the mechanism are verified here; whether a normalized target induces a *separate* pure ACK, and the exact wire timing, require packet capture or the rig — the Phase 02 open items.

