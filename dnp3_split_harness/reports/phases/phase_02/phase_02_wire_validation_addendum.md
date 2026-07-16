# Phase 02 — Wire-Validation Addendum

Phase 02 closed as **CONDITIONAL PASS**, with two open conditions requiring a packet sniffer:
PCAP-verified wire timing and ACK-mode-after-normalization. Phase 03A was authorized to close
them, and — capture now being unblocked (`philip` in the `wireshark` group; captures run under
`sg wireshark`, not sudo) — **both conditions are now satisfied by measurement.**

## Measured result (from Phase 03A fresh loopback PCAPs)

Source: `reports/phases/phase_03/` (matrix run `20260716T134719Z_phase_03a_wire_matrix`,
875 transactions; 100 non-first per config). Full detail in
`reports/phases/phase_03/phase_03_ack_separation.md`.

| Config (full delivery) | non-first SEPARATE | ACK mode | median request→response | retrans / dupACK / reset | byte-identical |
|---|---|---|---|---|---|
| native | 0 / 100 (W95 [0.000, 0.037]) | COMBINED | ~0.6 ms | 0 / 0 / 0 | yes |
| fixed 25 ms | 0 / 100 (W95 [0.000, 0.037]) | COMBINED | ~25.3 ms | 0 / 0 / 0 | yes |
| bounded 20–30 ms | 0 / 100 (W95 [0.000, 0.037]) | COMBINED | ~23.0 ms | 0 / 0 / 0 | yes |

The normalized targets (fixed 25 ms, bounded 20–30 ms) sit **below** the ~36–40 ms ACK-separation
transition characterized in Phase 03A, so they **preserve the native COMBINED ACK mode**: the
DNP3 response still carries the ACK, no separate pure ACK is introduced, wire timing is captured
from the PCAP, and there are **zero** retransmissions, duplicate ACKs, or resets. Byte-identity
holds on the wire (875/875).

_Scope: measured on the gambit loopback interface, Linux kernel 5.15.0-139-generic, in the tested
socket and application configuration. Not generalized to the rig, physical NICs, other kernels, or
the real devices._

## Does the Phase 02 final status change from CONDITIONAL PASS to PASS?

**Recommended: yes — the technical PASS condition is met.** The condition stated in the original
addendum ("the Phase 03A wire matrix shows, from PCAP evidence, that fixed and bounded
normalization preserve the intended ACK behavior, with wire timing captured and
retransmissions/resets reported") is now satisfied by measurement above.

The **formal flip to PASS is deferred to the same human packet-inspection gate** the project
applies to Phase 01 and Phase 03A (`reports/phases/phase_03/validation/phase03_human_packet_validation.csv`).

**Documented governance policy (consistent for all phases):** a phase reaches *final PASS* only
after its governing human packet-inspection gate is personally signed by a human. That gate is
currently **0 of 13** (an earlier AI-assisted assessment is supplementary only and carries
`human_gate_credit: false`). Phase 02's wire conditions are met by measurement and PASS is
*warranted on the machine evidence*, but under this single consistent policy Phase 02 stays
**CONDITIONAL PASS** until the Phase 03A worksheet — which provides the independent human
confirmation of the very ACK-mode measurement Phase 02 depends on — is signed. `next_phase_allowed`
remains false.

## Remaining (non-blocking for Phase 02) generalization

Rig / physical-device capture and a socket-option factorial would extend these results beyond the
loopback configuration; these belong to later phases (RQ3 / Phase 06+), not to the Phase 02 PASS
condition.
