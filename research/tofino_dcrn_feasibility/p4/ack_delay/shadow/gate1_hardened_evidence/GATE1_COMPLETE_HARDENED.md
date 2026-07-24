# Phase-1 GATE-1 — COMPLETE on silicon (parser-hardened dp9/dp11, 2026-07-24)

The DNP3 shadow classifier passes the **complete** GATE-1 on Tofino-1, both directions, after the parser
hardening that fixed the link-only-frame drop. Frozen `dnp3_shadow.p4` was never modified; all work is in
the variant `dnp3_shadow_parser_hardened_dp9_dp11.p4`.

## Validated topology (measured, final)
- **Vision = master = dev_port 9 = direction 0** (`PORT_MASTER=9w9`)
- **Hulk = outstation = dev_port 11 = direction 1** (`PORT_OUTSTATION=9w11`)
- ingress dp9 → dir 0 → egress dp11; ingress dp11 → dir 1 → egress dp9.

## The defect and the fix
- **Defect (found on the first dir-0 silicon run):** the frozen parser dropped valid DNP3 **link-only**
  control frames (link-length 5, 10-byte payload). After `dnp3_dl` consumed the payload, the parser
  unconditionally extracted `dnp3_tp` past end-of-packet → reject → drop. Full root cause:
  `PARSER_HARDENING_ROOTCAUSE_20260724.md`.
- **Fix (variant only):** (A) `parse_dnp3_dl` descends to transport/app only when `start==0x0564` AND
  `length >= 10` (full app header present); link-only/short frames pass through to `accept`. (B) the MAU
  classifies a valid `0x0564` link-only frame as `LINK_OTHER`, never `MALFORMED`.
- Compiles on bf-p4c 9.13.1 (local) and 9.13.2 (switch), 0 errors; stage/resource layout unchanged vs
  frozen (adds one parser length-select + one MAU gateway).

## Silicon revalidation — 3 reps, ALL PASS (exact)

| rep | hulk_cap (exp 606) | vision_cap (exp 605) | verify |
|---|---|---|---|
| 1 | 606 | 605 | **PASS** |
| 2 | 606 | 605 | **PASS** |
| 3 | 606 | 605 | **PASS** |

All 12 verify checks OK on every rep: `dir0/dir1_count_identity`, `dir0/dir1_byte_identity`,
`dir0/dir1_tcp_seq_ack_identity`, `reads_classified_300`, `responses_classified_300`, `pure_acks_ge_600`,
`no_malformed`, `silicon_matches_refmodel`, `no_loss_or_reorder`.

Switch class counters (rep1): `DNP3_READ=300, DNP3_RESP=300, PURE_ACK=605, TCP_FIN=2, LINK_OTHER=2,
MALFORMED=0, NON_DNP3=4(background)`. The **2 LINK_OTHER** are the two formerly-dropped link-only frames
(one per direction) — now forwarded and classified, not dropped, not malformed.

## GATE-1 acceptance — met
- Input/accounting: Vision 606, Hulk 605, all 1211 frames accounted for; switch RX = injected counts.
- Classification: 300 DNP3_READ (dir0), 300 DNP3_RESP (dir1), 605 PURE_ACK, FIN handled, **0 MALFORMED**;
  link-only frames = valid pass-through (LINK_OTHER).
- Forwarding: all 606 (Vision→Hulk) and 605 (Hulk→Vision) forwarded; exact count/order/length identity;
  byte-for-byte identity; **zero loss, zero duplication, zero corruption, zero parser drops**.
- Links: dp9/dp11 stable 5 min, 0 flaps, 0 errors (`link_stability_hardened.log`).
- Reproducibility: 3 independent reps, all pass.

**Phase-1 GATE-1: COMPLETE (silicon, bidirectional).** The defect was exposed only after the master-side
(dir-0) silicon path became available (dp8 was blocked until the lane-15/0 fault was isolated and the
role remapped to dp9/dp11). Frozen baseline preserved.

Evidence: `rep1..3/` (captures + counters), `link_stability_hardened.log`, root-cause + this report.
