# Phase 03A — AI-assisted packet analysis (SUPPLEMENTARY evidence, NOT the human gate)

```
verification_type: AI-assisted packet analysis
reviewer: ChatGPT
human_gate_credit: false
```

**This is not a human packet inspection and does not satisfy the Phase 03A human gate.** The
per-frame assessments below were produced with AI assistance, not by a person opening the PCAPs
and independently reading the frames. They are recorded as supplementary evidence only. The human
worksheet (`phase03_human_packet_validation.csv`) remains **0 of 13** until a person personally
inspects the frames and signs.

## AI-assisted per-frame assessment (all 13 worksheet cases; all agree with the software)

| Case | Request | Pure ACK | First payload response | AI-assisted result |
|---|---|---|---|---|
| Native non-first 1 | 10 | none | 11 | Combined, full |
| Native non-first 2 | 12 | none | 13 | Combined, full |
| Native first request | 6 | 7 | 8 | Separate, full |
| Fixed 25 ms | 10 | none | 11 | Combined, full |
| Bounded 20–30 ms | 10 | none | 11 | Combined, full |
| CRC-split | 14 | none | 15 | Combined, multi-segment |
| Delay 37 ms | 10 | 11 | 12 | Separate, full |
| Delay 38 ms | 52 | 53 | 54 | Separate, full |
| Delay 39 ms, separate | 10 | 11 | 12 | Separate, full |
| Delay 39 ms, combined | 19 | none | 20 | Combined, full |
| Delay 40 ms | 10 | 11 | 12 | Separate, full |
| QUICKACK at 25 ms | 10 | 11 | 12 | Separate, full |
| NODELAY off at 25 ms | 10 | none | 11 | Combined, full |

For the CRC-split case: request frame 14, expected server ACK = request sequence + 18 bytes, first
response payload frame 15, **no standalone ACK before it**, frame 15 carries the ACK, additional
response segments at frames 16, 18, 19, 21, … (frame 39 is a later segment, not the first
payload). → **COMBINED, MULTI_SEGMENT.** The software agrees (ack_mode COMBINED, response_delivery
MULTI_SEGMENT, first_payload_frame 15).

The AI-assisted refined-sweep cross-check (0/80 → 1/80 → 6/80 → 15/80 → 38/80 → 80/80) matches the
report's graded 35–40 ms transition.

## Human governance decision (separate from the analysis above)

The project PI (Philip Akekudaga) issued the Phase 03A **CONDITIONAL PASS** governance decision and
the required changes (crc-split ack_mode/response_delivery decomposition; three wording
corrections; recording of verdicts). Those decisions are the PI's own. What is **not** yet done is
the PI's **personal packet inspection** of the 13 worksheet rows — the AI-assisted assessment above
does not stand in for it.

## What still satisfies the gate

A human must open each PCAP in `pcaps/` and fill the worksheet's `reviewer`, `date`,
`reviewer_ack_mode`, `agreement` columns from their own reading of the frames. Only then does the
human gate move from 0/13 toward 13/13 and Phase 03A become eligible for final PASS.
