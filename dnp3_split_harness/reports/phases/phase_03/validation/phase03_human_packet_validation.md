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
  (native combined, first-in-connection quick-ACK case, fixed25 / bounded20-30 normalization, the
  **crc-split multi-segment** case, the 37–39 ms transition region, full 40 ms separation, and two
  RQ3 socket-option cases: TCP_QUICKACK forcing SEPARATE at 25 ms and TCP_NODELAY-off staying
  COMBINED at 25 ms).
- `pcaps/` — the exact capture files the worksheet points into, copied from the (git-ignored)
  run directories so the review is self-contained. Frame numbers in the CSV are absolute frame
  numbers in these PCAPs.

## Two orthogonal properties (this is the key change)

ACK mode and response segmentation are **independent**. A multi-segment (crc-split) response is
**not** automatically OTHER — it still has a definable ACK mode. The worksheet therefore records
each separately:

- `software_ack_mode` — COMBINED_ACK_RESPONSE / SEPARATE_ACK_RESPONSE / UNDETERMINED.
- `software_response_delivery` — FULL / MULTI_SEGMENT / AMBIGUOUS.

## Columns

`software_*`, `req_*`, `first_payload_frame`, `final_payload_frame`, `payload_segments`, and
`pure_ack_frame` are extractor output — do not edit them. The reviewer fills:

- `reviewer` / `date` — who validated and when.
- `reviewer_ack_mode` — COMBINED_ACK_RESPONSE / SEPARATE_ACK_RESPONSE / UNDETERMINED, from reading
  the frames (not by trusting `software_ack_mode`).
- `reviewer_response_delivery` — FULL / MULTI_SEGMENT / AMBIGUOUS.
- `ack_mode_agreement` / `delivery_agreement` — `agree` or `disagree` versus the software columns.
- `notes` — anything unexpected. **Record disagreements; never edit the software column to force agreement.**

## How to validate one row (Wireshark or tshark)

1. Open `pcaps/<capture_pcap>`; go to `req_frame`. Confirm it is the DNP3 request
   (client→outstation, `req_seq`, length `req_tcp_len`); the server's ACK for it should be
   `software_expected_server_ack` (= `req_seq` + `req_tcp_len`).
2. Find `first_payload_frame` — the **first** payload-bearing reverse segment (a server→client
   packet with TCP payload). This is the ACK-mode anchor.
3. **ACK mode** = is there a standalone pure TCP ACK (no payload) *before* `first_payload_frame`?
   - **SEPARATE**: yes — a pure ACK at `pure_ack_frame` precedes the first payload segment.
   - **COMBINED**: no — the first payload segment itself carries the ACK (`pure_ack_frame` blank).
   Decide this **independently of segment count** — do NOT choose OTHER merely because the response
   spans multiple segments.
4. **Response delivery** = FULL if the response is a single payload segment; MULTI_SEGMENT if it
   spans several (`first_payload_frame` … `final_payload_frame`, `payload_segments` > 1); AMBIGUOUS
   only if there is no clean payload / a reset / reordering that prevents a determination.
5. Record `reviewer_ack_mode`, `reviewer_response_delivery`, and both agreement columns.

## What the software claims (for the reviewer to confirm or refute)

- Non-first requests under native, fixed25, and bounded20-30 (all app-write delays < ~36 ms) are
  **COMBINED / FULL** — normalization did not create a separate ACK.
- The **first request of every TCP connection** carries a prompt pure ACK regardless of delay
  (behavior consistent with a post-handshake quick-ACK state), so it is SEPARATE / FULL; it is
  excluded from the timing-relevant metric.
- Non-first requests become **SEPARATE** as the app-write delay crosses ~36–40 ms (pure ACK at
  `pure_ack_frame`, then the response at the app-write delay).
- The **crc-split** case is **COMBINED / MULTI_SEGMENT**: no pure ACK precedes the first payload
  segment (`first_payload_frame`), and the response arrives in several segments — the segmentation
  does not change the ACK mode.

Until this worksheet is completed and signed, Phase 03A is **CONDITIONAL PASS** and
`next_phase_allowed = false`.

_Scope: measured on the gambit loopback interface, Linux kernel 5.15.0-139-generic, in the tested
socket and application configuration. Do not generalize to other kernels, the Vision/Hulk rig,
OpenDNP3 generally, or the physical SEL-751 / AB1400 / ION7550 devices._
