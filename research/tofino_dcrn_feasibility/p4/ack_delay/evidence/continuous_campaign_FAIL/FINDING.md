# Continuous-traffic campaign — caught a hardware REGRESSION in the hardened build (2026-07-20)

Hardened dcrn_ackA.p4 sha `6e1b659b` (commit d380d1a), 120 sequential Class-0 txns on ONE connection,
shuffled readiness, no cold reload, single-host Hulk loopback rig (Tofino-1 9.13.2).

## Result: transport PASS, DEFENSE FAIL
- **Transport / integrity PASS:** 120/120 txns byte-identical (client mism=0), 0 retransmits, 0 resets,
  no app-layer degradation (head10 9.7 ms ~ tail10 10.6 ms). The lifecycle/occupancy fixes did NOT
  cause accumulation or transport breakage.
- **DEFENSE FAIL — the ACK is NOT held.** Wire per-txn: the outstation's pure ACK appears TWICE on the
  tap (hairpinned straight through, immediate) — it is forwarded, not recirculated/held. CLRT tracks
  readiness (median 10.3 ms, min 2.2, max 20.3) instead of collapsing to the ~0.03 ms guard. Egress
  evstat all zero (evstat_ack[0]=evstat_ack[1]=evstat_resp[0]=evstat_resp[1]=0): no ACK_HELD/RELEASED.

So the hardened FIX 1 exact-qualification rejects the pure ACK on silicon (qual==0), even though the
off-switch unit tests pass. The C3-pass baseline `c9f4c109` (tag ack-delay-caseA-c3-pass), which used
BROAD matching (armed && payload==0), held the ACK correctly — so the regression is in the ADDED
conditions: `flags_ok ((flags&0x17)==0x10)` and/or `amatch (reg_expected_ack == tcp.ack_no)`.

## Secondary finding
The earlier WIP moved evstat to the EGRESS control (`pipe.DcrnEgress.evstat_*`) as the stage-headroom
lever. That silently broke the committed reader `ackA_read.py` (reads `pipe.DcrnIngress.evstat_*` ->
KeyError) and FIX 4's reg_held_count was replaced by flow_has_held_ack, so the reader is stale for
this build and must be updated (evstat in egress; occupancy = flow_has_held_ack).

## Most-likely cause + debug plan (off-switch first)
Hypothesis: `amatch` fails — reg_expected_ack (stored at arm on the dp8/dir0 loop pass) != the ACK's
ack_no at match time. flow_id is IDENTICAL on the arm pass and the ACK pass (verified by reasoning),
and exp_ack = req_seq + 22 should equal the ACK's ack (req_seq + 22), so the value or its
cross-pass visibility is the suspect. flags_ok is the cheaper second suspect.
Debug:
1. Off-switch: line-by-line compare the hardened pure-ACK hold path vs the c9f4c109 path; re-audit the
   exp_addend/exp_ack lowering and the expack_set/expack_match SALU bodies for a value/visibility bug.
2. Gated probe window: bind the client to a FIXED source port, compute flow_id, run ONE txn, read
   reg_armed + reg_expected_ack for that flow_id DURING the readiness window and compare exp_ack to the
   request's seq+22 from the pcap. This pins armed-fired vs exp_ack-wrong vs flags_ok.
The C3-pass baseline c9f4c109 remains the known-good deployable version.
