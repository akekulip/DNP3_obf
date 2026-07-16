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

## AI-assisted per-frame assessment (6 representative cases, all agree with the software)

- **native_full**: non-first request frame 10 → payload-bearing response frame 11 directly; no
  standalone ACK. → COMBINED.
- **fixed25_full**: request frame 10 → response frame 11 after ~25 ms. → COMBINED.
- **bounded20-30_full**: request frame 10 → response frame 11 within the bounded delay. → COMBINED.
- **delay_040ms**: request frame 10 → zero-payload ACK frame 11 → response frame 12 ~40 ms later.
  → SEPARATE.
- **sock_quickack_on_delay025ms**: QUICKACK → standalone ACK frame 11 even at 25 ms. → SEPARATE.
- **sock_nodelay_off_delay025ms**: 25 ms response remains combined; disabling Nagle unchanged.
  → COMBINED.

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
