# Phase 01 — Extractor Agreement (tshark vs Scapy)

Canonical extractor: **tshark** (feeds the downstream reports). Scapy is an INDEPENDENT re-implementation used only to validate agreement on a fixture. Neither extractor is retired in Phase 01.

Fixture composition: **10 combined, 10 separate, 3 anomalous** (total 23). Timestamp/delay tolerance: 0.01 ms.

Full-agreement transactions: **23/23**.

## Result

The two extractors agree on frame selection, ACK mode, timestamps, and sizes for every fixture transaction. tshark remains the canonical extractor with an independent Scapy cross-check.

