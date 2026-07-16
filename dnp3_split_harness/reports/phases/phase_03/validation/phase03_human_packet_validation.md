# Phase 03A — Human Packet Validation (reviewer worksheet)

This is a **gate item**. The Phase 03A software classified every transaction (COMBINED /
SEPARATE / OTHER) with the Phase 01-validated extractor, but the gate requires a **human** to
open the packets and independently confirm the ACK mode. An AI cannot supply the reviewer
verdict — the `reviewer_ack_mode` / `agreement` columns must be filled by a person reading the
PCAPs.

**Status (2026-07-16): human gate = 0 of 13.** No row has been personally inspected by a human yet;
the `reviewer` / `reviewer_ack_mode` / `agreement` columns are all blank. An earlier AI-assisted
assessment of six representative cases exists as **supplementary evidence only** in
`phase03_ai_assisted_packet_analysis_2026-07-16.md` (`verification_type: AI-assisted packet
analysis`, `reviewer: ChatGPT`, `human_gate_credit: false`) — it does **not** count toward this
gate and must not be entered in the `reviewer` column. A person must open each PCAP and fill the
columns from their own reading of the frames.

## Files

- `phase03_human_packet_validation.csv` — 13 pre-selected transactions spanning every category
  (native combined, first-in-connection quickack artifact, fixed25 / bounded20-30 normalization,
  crc-split OTHER, the 37–39 ms transition region, full 40 ms separation, and two RQ3 socket-option
  cases: TCP_QUICKACK forcing SEPARATE at 25 ms and TCP_NODELAY-off staying COMBINED at 25 ms).
- `pcaps/` — the exact capture files the worksheet points into, copied from the (git-ignored)
  run directories so the review is self-contained. Frame numbers in the CSV are absolute frame
  numbers in these PCAPs.

## Columns

`software_*` columns are what the extractor recorded and must not be edited. The reviewer fills:

- `reviewer` / `date` — who validated and when.
- `reviewer_ack_mode` — COMBINED_ACK_RESPONSE, SEPARATE_ACK_RESPONSE, or OTHER_OR_AMBIGUOUS,
  decided by reading the frames (not by trusting `software_ack_mode`).
- `agreement` — `agree` or `disagree` versus `software_ack_mode`.
- `notes` — anything unexpected.

## How to validate one row (Wireshark or tshark)

1. Open `pcaps/<capture_pcap>`; go to `req_frame`.
2. Confirm it is the DNP3 request (client→outstation, `req_seq`, length `req_tcp_len`).
3. The server's ACK number for that request should be `software_expected_server_ack`
   (= `req_seq` + `req_tcp_len`).
4. Decide the ACK mode from the frames between the request and the response:
   - **SEPARATE**: a standalone pure TCP ACK (no payload) at `pure_ack_frame` carrying that ACK
     number, *before* the DNP3 response at `resp_frame`.
   - **COMBINED**: no standalone pure ACK; the DNP3 response packet at `resp_frame` itself
     carries the ACK (`pure_ack_frame` is blank).
   - **OTHER**: chunked / reordered / ambiguous (the crc-split case, where the response arrives
     in multiple segments).
5. Record `reviewer_ack_mode` and `agreement`.

## What the software claims (for the reviewer to confirm or refute)

- Non-first requests under native, fixed25, and bounded20-30 (all app-write delays < ~36 ms) are
  **COMBINED** — normalization did not create a separate ACK.
- The **first request of every TCP connection** carries a prompt pure ACK regardless of delay
  (a post-handshake quickack artifact), which is why it classifies SEPARATE; it is excluded from
  the timing-relevant metric.
- Non-first requests become **SEPARATE** as the app-write delay crosses ~36–40 ms, reaching 100%
  at 40 ms. In the separated regime the pure ACK is emitted **promptly** (~0.01 ms after the
  request) and the response follows at the app-write delay.
- crc-split chunked responses classify as **OTHER** (multiple response segments), not a timing
  effect.

Until this worksheet is completed and signed, Phase 03A is **CONDITIONAL PASS** and
`next_phase_allowed = false`.

_Scope: measured on the gambit loopback interface, Linux kernel 5.15.0-139-generic, in the tested
socket and application configuration. Do not generalize to other kernels, the Vision/Hulk rig,
OpenDNP3 generally, or the physical SEL-751 / AB1400 / ION7550 devices._
