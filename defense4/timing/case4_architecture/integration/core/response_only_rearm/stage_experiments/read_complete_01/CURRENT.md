# Current status — Claude handover (2026-10-24)

Authority: repository-root Claude_dd7741152_Verified_Assessment_and_Overnight_Command.md and Philip's subsequent
packetization corrections. Execution plan/ledger: OVERNIGHT_PLAN_20261024.md. History: STATUS.md;
full record: COMPLETION_RECORD.md. Continuation: repository-root plan.md and CLAUDE_HANDOVER_20261024.md.
Philip requested handover and commit/push; implementation and runtime execution are stopped at verified c50.

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
| Actual SBO encoding | c49 relay_sbo1085/1085 across3 connections, including complete application, one+11 commit, partial/full ACKs, replay and timing; final-image/physical qualification pending |
| Integrated candidate | c50 compiled/reviewed within every limit; exact fin_busy193/193 across3 connections. No successor loaded on hardware |
| Exact model gate | BLOCKED: c50 has fin_busy only; all16 required on final repaired source. c49 SBO pass cannot substitute |
| FIN race | OPEN for physical recovery: c50 repairs exact busy FIN race in model193/193. Separate half-closed qualified RST defect remains unimplemented |
| Relay padded/four-arm/recovery/timing/J | NOT RUN; requires current timestamp-capable image, placement, review and complete model gate |
| Reproduction | Active reproduce.sh recognizes c30/c48/c49/c50 exact metadata; default remains historical c30. Final candidate/full gate/readout pending |

## Handover state and retained milestones

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
  Installed-row diagnostics localized this SELECT drop to constant-key offsets; c49 repairs it.
- c49 repairs the installed constant-key encoding by merging repeated w0 slices into equivalent whole-word
  predicates. Source `995386583fc373e9a770b22e50194b49c246afc0e1c5789ccd099d9ae0b31bc2` compiles in96.674s;
  physical stage limits and resource use remain unchanged. All86 static tables pass the offset-layout audit.
  Diagnostic01 passes30/30, including READ141 and SELECT/OPERATE60, independent application/framing checks and ACKs.
  Dedicated relay_sbo passes1085/1085 across3 connections; fin_busy01/02 fail62/70 and remain retained.
- c50 source `1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b` adds3 guarded FIN retry rows.
  Compile95.989s, all ten pins, stages/resources/mirror/static-offset review pass. Exact fin_busy193/193 completes all3
  connections.143 offline tests and10 legacy identities pass. Normal traversal unchanged; the proven collision adds
  one bounded recovery retry lap.
- Model lane: actual-SBO assertions are exercised on c49; c50 final gate remains blocked with15 drivers unexecuted.
  c51 half-closed RST admission and its model_packets regression are proposals only: no edits/tests/source/build exist.
  Keep old fixtures only as offline historical regressions. Gate fails closed for missing relay/FIN evidence.
- Campaign lane: explicit sel751 profile, permitted privileged Python application with explicit --apply,
  persistent+independent NIC/firewall restoration and frozen helper closure committed d3d2fe634;1543tests+5export checks pass. Physical four-arm/recovery await the image gate.
- Integrator: all agents stopped; source/artifacts/logs and handover notes retained for commit/push. Continue from
  root plan.md: reproduce qualified half-closed RST, implement/review c51, run all16 gates, then physical smoke/reference/recovery.

## Boundaries and corrected claims

158 is the floor of the preserved-tail prefix construction, not a global minimum: software reserialization can
reach144–154 and157 on the retained integrity response. Keep141/158; no new target selection.
Native samples and software/model encoding do not establish physical padding or same-packet original preservation.
The c30 213/415 timing failure used a stale247-byte software vector; corrected134-byte vector passes415/415 on the
same sealed bundle. This does not qualify actual two-CROB SBO. The specific c29 FIN race remains open despite old
close tests and eventual retransmission. Every planned connection must be present in the recovery verdict.
No software outstations/proxies, Vision reboot, kernel/firmware change, keep-alive masking, relaxed100us threshold,
D/J or attacker campaign, manual ownership edits, weakened restoration, IEEE audit or paper work.
