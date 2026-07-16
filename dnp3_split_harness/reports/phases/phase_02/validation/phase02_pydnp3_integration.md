# Phase 02 — Real pydnp3 Master Integration (loopback)

A real OpenDNP3/pydnp3 master (`run_master --action scan-all-classes`) drives the timing-enabled `split_server` for each config and completes a genuine DNP3 integrity poll. This validates DNP3 **task** correctness (OnTaskComplete + database decode), not just byte identity. Loopback, not a wire PCAP.

**6/6 configs PASS** (master exits clean, task completes, database decoded, byte-preservation PASS, zero deadline-miss/bypass).

| config | task complete | db decoded | held to target | byte-preserve | ddl-miss | bypass | responses |
|---|:--:|:--:|:--:|:--:|---:|---:|---:|
| native/full | True | True | True | True | 0 | 0 | 5 |
| fixed25/full | True | True | True | True | 0 | 0 | 5 |
| bounded20-30/full | True | True | True | True | 0 | 0 | 5 |
| native/crc-split | True | True | True | True | 0 | 0 | 4 |
| fixed25/crc-split | True | True | True | True | 0 | 0 | 4 |
| bounded20-30/crc-split | True | True | True | True | 0 | 0 | 4 |

> Loopback DNP3 task correctness. Wire timing and ACK-mode-after-normalization still require a PCAP (rig).

