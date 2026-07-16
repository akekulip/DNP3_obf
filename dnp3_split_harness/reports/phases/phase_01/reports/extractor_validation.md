# Phase 01 — Extractor Validation

Two independent checks that the canonical **tshark** extractor is trustworthy for the
Phase 01 characterization. Raw artifacts are in this run's `validation/`.

## 1. tshark vs Scapy agreement (§5)

- Canonical extractor: **tshark** (it feeds the downstream tables/reports). **Scapy** is an
  independent re-implementation used only to cross-check. Neither extractor is retired.
- Fixture: **10 combined + 10 separate + 3 anomalous = 23 transactions**, drawn from the raw
  captures. Timestamp/delay tolerance 0.01 ms.
- **Result: 23/23 fixture transactions agree** on frame selection (request / pure-ACK /
  response frames), ACK mode, request/response timestamps, and request/response sizes.
- Detail: `validation/extractor_agreement.csv`, `validation/extractor_agreement.md`.

Because the extractors agree on the fixture, the tshark reconstruction is used for all
Phase 01 numbers; the Scapy path remains available as a cross-check for future disputes.

## 2. Transaction re-verification (§6)

- **Method (stated honestly): automated, frame-targeted re-extraction and cross-derivation**
  — an independent second tshark read of each sampled transaction's request / pure-ACK /
  response frames, then re-derivation of the ACK mode and a TCP sequence/acknowledgement
  relationship check. This is **not** human visual inspection.
- Sample: **20 transactions per device (60 total)**, deterministic seed `20250716`
  (numpy `default_rng`); every `OTHER_OR_AMBIGUOUS` transaction is added in full (0 this run).
- Checks per transaction: re-read sizes and timestamps match the recorded values; the ACKing
  packet's `tcp.ack` equals `req_seq + req_tcp_len` (it acknowledges the request bytes); and
  the re-derived ACK-mode classification matches the automated one.
- **Result: 60/60 sampled transactions re-verified.**
- Detail: `validation/manual_validation_sample.csv`, `validation/manual_validation_report.md`.

> Limitation: the re-verification is automated (a second extraction path), not a human
> eyeballing packets in Wireshark. It confirms internal consistency and the sequence/ack
> relationship; it is labeled as automated so it is not mistaken for manual inspection.
