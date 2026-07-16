# Phase 02 — Combined-Response Timing Normalization (loopback measurement)

_Run `20260716T123500Z_phase_02_combined_timing_normalization`. Mechanism: existing `timing_policy` native/fixed/bounded via `split_server`. **Loopback, application-level** measurement — not a sniffer PCAP. PCAP wire timing and ACK-mode-after-normalization are unavailable on this host (dumpcap not group-executable; no rig) and remain the open items._

## Per-config summary (big Class-0 READ = 2407 B)

| config | n txns | byte-identical | bypassed | deadline miss | READ client-visible med (ms) | CI |
|---|---:|---:|---:|---:|---:|---|
| native/full | 250 | 100.0% | 0 | 0 | 0.60 | [0.59, 0.61] |
| fixed25/full | 250 | 100.0% | 0 | 0 | 25.31 | [25.31, 25.31] |
| bounded20-30/full | 250 | 100.0% | 0 | 0 | 25.12 | [24.06, 26.27] |
| native/crc-split | 250 | 100.0% | 0 | 0 | 0.74 | [0.73, 0.75] |
| fixed25/crc-split | 250 | 100.0% | 0 | 0 | 25.29 | [25.23, 25.31] |
| bounded20-30/crc-split | 250 | 100.0% | 0 | 0 | 25.62 | [24.08, 26.60] |
| fixed300-rto105/full (bypass) | 250 | 100.0% | 250 | 0 | 0.64 | [0.63, 0.65] |

## Decorrelation of visible time (client-observed)
Correlation of the visible request→response time with response size and with the native response-ready delay, per config. Normalization should DROP the size/native correlation vs native mode.

| config | n | corr(visible, resp size) | corr(visible, native-ready) |
|---|---:|---:|---:|
| native/full | 250 | -0.352 | 0.685 |
| fixed25/full | 250 | 0.156 | -0.176 |
| bounded20-30/full | 250 | 0.019 | 0.009 |
| native/crc-split | 250 | 0.348 | 0.752 |
| fixed25/crc-split | 250 | 0.110 | 0.138 |
| bounded20-30/crc-split | 250 | 0.036 | -0.055 |
| fixed300-rto105/full (bypass) | 250 | -0.206 | 0.836 |

> Loopback/application-level results. Byte identity and the mechanism are verified here; whether a normalized target induces a *separate* pure ACK, and the exact wire timing, require packet capture or the rig — the Phase 02 open items.

