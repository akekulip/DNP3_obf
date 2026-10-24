# Current status — physical SEL-751 qualification (2026-10-24, in progress)

Authority: repository-root Claude_dd7741152_Verified_Assessment_and_Overnight_Command.md and Philip's subsequent
packetization corrections. Execution plan/ledger: OVERNIGHT_PLAN_20261024.md. History: STATUS.md;
full record: COMPLETION_RECORD.md. Work on main; no push.

## Demonstrated current tier

The repaired software master accepted a fresh native physical-relay block through production Tofino passthrough:
`evidence/relay_native_capture_20261024/relay_native_20261024_02/`.
Campaign `evidence/hw_campaigns/sel751_native_20261024_02` completed rc0; independent restoration passed;
recorded ownership is inactive, unsafe_restoration=false. This is NATIVE acceptance, not padded silicon qualification.

| Exchange | Request bytes | Native response bytes | Master outcome | Selected encoded response (offline) |
|---|---:|---:|---|---|
| mixed READ |25|91|OK|141, link frames[50,91]|
| integrity READ |27|134|OK|158, link frames[24,134]|
| SELECT |45|49|OK, both guarded points SUCCESS|60, link frames[28,32]|
| OPERATE |45|49|OK, both guarded points SUCCESS|60, link frames[28,32]|

All responses were observed as one TCP payload each. Historical sbo_j2's28+21 was the old switch PRE carve, not
proof of native relay packetization. No split-input reassembly/holding is needed for this observed profile.
The capture is one master-NIC observation under hash-bound verified forwarding-only production state;
pre-switch ingress packetization is inferred from that path, not independently TAP-observed.

Current connection has IPv4 IHL5, TCP SYN40 bytes / SYNACK44 bytes, and timestamp-bearing DATA/ACK32-byte
TCP headers. The old clean TCP20 candidate/model assumptions do not qualify this connection. Host global TCP
settings remain unchanged. Actual IP/MAC/address/dev identity is .1/1/dev9 to .7:20000/0/dev64;
master MAC3c:fd:fe:cc:5d:c0, relay MAC00:30:a7:02:4c:a2.

## Completion matrix

| Deliverable | State |
|---|---|
| Master complete-response validation | Independently reviewed and committed f60a3ae21;104tests+135subtests pass; prefix-only acceptance repaired |
| Native baseline READ/SBO | Physical02 block PASS; all4 planned exchanges; full capture and independent restoration retained |
| READ construction | Preserve c30 source b006752 and its original READ model evidence;91→141 and134→158 targets fixed |
| Actual SBO encoding | Whole49→60/15+17app offline reference and generated-byte tests pass; ASIC/model qualification pending |
| Integrated candidate | c48 compiles within every limit and passes artifact review. Model smoke passes handshake and padded mixed READ, then drops SELECT; no successor loaded on hardware |
| Exact model gate | Corrected c30 control_timing04 passes415/415; successor requires14 existing drivers+relay_sbo+fin_busy on one sealed bundle |
| FIN race | OPEN: c29 fin_busy01 reproduces half-close retry_epoch invalidation, stale retries and missing FIN; successor repair unqualified |
| Relay padded/four-arm/recovery/timing/J | NOT RUN; requires current timestamp-capable image, placement, review and complete model gate |
| Reproduction | Active reproduce.sh recognizes c30_sdk9132 and exact flags/hash; selected integrated candidate pending |

## Active work

- P4/resource lane: c47 source `2191c15b94f4f83fcd78650b0bdc8f66f3029eda66253d8df85abfb48e1711fe`
  compiles successfully on pinned SDK9.13.2. Raw contexts confirm N/E/T stages0–10 and pipe1 egress0–3;
  independent review verifies parser deposit bounds, mirror guards and all ten artifact/source pins.
  The first smoke observes one SYN with an extra16-byte internal header before the exact Ethernet frame.
  E's missing provenance parsing on dev64 caused the leak; c48 repairs this path. Failed attempts remain retained.
  No stage-limit, checksum, traversal or packet assertion waiver.
- c48 adds only relay port64 to E provenance parsing, preserving OPEN processing before stripping the internal header.
  Source `902a84bf1714d15788b707b7c23b86c4abe8f66a4ba8395d1d52f0377a2eae66` compiles in96.862s;
  physical indices, PHV summaries and table placement match c47. All ten pins and mirror guards verify independently.
  Smoke01 passes15checks through SYN/SYNACK, READ91→141 and mapped ACK, then SELECT_request produces no departure.
  The reproduced SELECT drop is under investigation; the complete16-driver gate remains blocked.
- Model lane: all14 gates retargeted and reviewed for actual45/49→60, physical IP/MAC and TS options; runtime execution pending. Strengthen actual-SBO one-commit/growth/retransmission and partial-ACK observations.
  Keep old fixtures only as offline historical regressions. Gate fails closed for missing relay/FIN evidence.
- Campaign lane: explicit sel751 profile, permitted privileged Python application with explicit --apply,
  persistent+independent NIC/firewall restoration and frozen helper closure committed d3d2fe634;1543tests+5export checks pass. Physical four-arm/recovery await the image gate.
- Integrator: source/artifact identity, serialize model/testbed, review, docs, active reproduce and milestone commits.

## Boundaries and corrected claims

158 is the floor of the preserved-tail prefix construction, not a global minimum: software reserialization can
reach144–154 and157 on the retained integrity response. Keep141/158; no new target selection.
Native samples and software/model encoding do not establish physical padding or same-packet original preservation.
The c30 213/415 timing failure used a stale247-byte software vector; corrected134-byte vector passes415/415 on the
same sealed bundle. This does not qualify actual two-CROB SBO. The specific c29 FIN race remains open despite old
close tests and eventual retransmission. Every planned connection must be present in the recovery verdict.
No software outstations/proxies, Vision reboot, kernel/firmware change, keep-alive masking, relaxed100us threshold,
D/J or attacker campaign, manual ownership edits, weakened restoration, IEEE audit or paper work.
