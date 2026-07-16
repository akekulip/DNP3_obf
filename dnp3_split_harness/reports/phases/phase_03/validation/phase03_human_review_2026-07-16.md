# Phase 03A — Human Review Record (reviewer: akekulip, 2026-07-16)

This file preserves the human reviewer's verdict verbatim. It is the authoritative record of the
independent human packet inspection. The reviewer's per-case verdicts (below) were transcribed
into `phase03_human_packet_validation.csv` for the six transactions the reviewer explicitly
checked; the remaining rows are left blank pending inspection.

---

## Verdict

Phase 03A receives a **CONDITIONAL PASS**. Do not begin Phase 04 yet.

The reviewer independently checked representative packet sequences and confirmed the findings:

- **native_full**: non-first request at frame 10 is followed directly by a payload-bearing
  response at frame 11. No standalone ACK appears. → COMBINED.
- **fixed25_full**: request frame 10 is followed directly by response frame 11 after about 25 ms.
  → COMBINED.
- **bounded20-30_full**: request frame 10 is followed directly by response frame 11 within the
  selected bounded delay. → COMBINED.
- **delay_040ms**: request frame 10 is followed by a zero-payload ACK at frame 11 and the response
  at frame 12 about 40 ms later. → SEPARATE.
- **sock_quickack_on_delay025ms**: QUICKACK produces a standalone ACK at frame 11 even at 25 ms.
  → SEPARATE.
- **sock_nodelay_off_delay025ms**: the 25 ms response remains combined, supporting the conclusion
  that disabling Nagle did not change ACK separation in this setup. → COMBINED.

The refined 35–40 ms sweep matches the report (0/80 → 1/80 → 6/80 → 15/80 → 38/80 → 80/80), a
graded transition, not a universal hard threshold. Scope correctly limited to gambit loopback,
Linux 5.15.0-139, and the tested socket configuration.

## Required changes issued by the reviewer (all addressed in this update)

1. **CRC-split classification** must separate two properties — `ack_mode` (COMBINED / SEPARATE,
   decided by a standalone pure ACK before the first payload-bearing segment) and
   `response_delivery` (FULL / MULTI_SEGMENT / AMBIGUOUS). A multi-segment response must not make
   the ACK mode unknowable. → Implemented in `phase01_reconstruct.py`; crc-split non-first is
   ack_mode COMBINED 100/100, delivery FULL 50 + MULTI_SEGMENT 50 (`tables/phase03_crc_split_decomposition.csv`).
2. **Wording corrections** (post-handshake quick-ACK phrasing; replay-client-exchange vs
   DNP3-task-completion; response-size claim narrowed to the tested anchors) → applied in
   `phase_03_ack_separation.md`.
3. **Complete and sign the 13-row worksheet** → the six reviewer-verified cases above are recorded
   in the worksheet with provenance; the remaining seven rows await inspection.

## Approval status (reviewer)

| Component | Decision |
|---|---|
| Capture pipeline | PASS |
| Combined/separate classification | PASS |
| Refined 35–40 ms transition | PASS |
| QUICKACK/NODELAY anchor experiments | PASS |
| Byte preservation and connection stability | PASS |
| Scope and claim discipline | PASS (with the wording changes above) |
| CRC-split ACK reconstruction | CONDITIONAL → addressed in this update |
| Human packet validation | NOT COMPLETE (6 of 13 rows verified) |
| Phase 04 authorization | NOT APPROVED |

**Final: Phase 03A CONDITIONAL PASS.** Phase 04 (mechanism-feasibility analysis for delaying
existing ACK and response packets) may begin only after the worksheet is completed and signed and
the human classifications agree.
