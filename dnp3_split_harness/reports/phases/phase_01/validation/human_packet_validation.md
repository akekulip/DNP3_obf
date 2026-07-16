# Phase 01 — Human Packet Validation (protocol + worksheet)

**Status: PENDING HUMAN REVIEW.** This sheet was *prepared* by `phase01_human_validation_prep.py` — it selects the transactions and pre-reads their packet fields. The **verdict columns are intentionally blank**. A human must open each transaction in Wireshark (or inspect the packet fields directly) and complete `reviewer`, `date`, `reviewer_ack_mode`, `agreement`, and `notes` in `human_packet_validation.csv`. No software wrote any human verdict.

This is distinct from the **AUTOMATED FRAME-TARGETED RE-EXTRACTION VALIDATION** (`manual_validation_report.md`, 60/60), which is an independent second tshark read — not human inspection.

## Transactions to review (75 total)
- deterministic-sample: 60
- lone-ion7550-separate: 1
- reset: 4
- retransmission: 10

## Procedure (per transaction)
1. Open the `capture` in Wireshark; go to `req_frame`, `pure_ack_frame` (if any), `resp_frame`.
2. Confirm the request payload length, response payload length, and request TCP sequence number against the sheet.
3. Confirm the ACKing packet's acknowledgement number equals `expected_ack` (= req_seq + req_payload_len): for a SEPARATE transaction the pure TCP ACK, for a COMBINED transaction the DNP3 response.
4. Decide the ACK mode yourself (COMBINED_ACK_RESPONSE / SEPARATE_ACK_RESPONSE / OTHER_OR_AMBIGUOUS) and record it in `reviewer_ack_mode`.
5. Set `agreement` = yes/no vs `software_ack_mode`; add `notes` for any anomaly (retransmission, duplicate ACK, reset, delayed response).
6. Fill `reviewer` and `date`.

## Completion criterion
Phase 01 human validation is complete only when every row has a human `reviewer_ack_mode` and `agreement`. Until then the Phase 01 gate records human validation as INCOMPLETE.

