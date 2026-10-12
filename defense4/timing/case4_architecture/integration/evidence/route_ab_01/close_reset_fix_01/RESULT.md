# Close path and RESET-event wire type fixed (2026-10-11)

Fixes the two N defects localized in `close_defect_01` and the RESET-envelope defect that silicon confirmed
(`p2_production_01/p_unshaped`: port 180 `$OctetsReceived` minus `$OctetsReceivedinGoodFrames` = 80 B, one
76-byte RESET event + FCS, counted received-not-good). All changes are at the generators; the generated
`n_response_only.p4` is make_n.py's exact output.

## Changes

| where | what |
|---|---|
| make_n.py edit 10 | `close_forward` sets `tm.bypass_egress=1w0`: the single-pass phase-7 close departure no longer inherits `snapshot()`'s recirculation bypass, so an outstation FIN/RST crosses E and is translated |
| make_n.py edit 11 | `seq_fin` (sequence code 5) for (client_diff, server_diff) = (1,0), (1,1), (0,1): one FIN sequence byte per side. (0,1) was added beyond the approved (1,0)/(1,1) because the outstation-first vector needs it (the master's ACK of an outstation-first FIN) |
| make_n.py edit 12 | `first_event` row `(kind 3, seq 5, phase 7) -> forward_original`; code 5 matches nothing else, so it is inert outside phase 7 (tested) |
| make_n.py edit 13 | `emit_reset` kind 4 -> 13: RESET events carry 0x0d01 / 0x0d02 at wire bytes 12-13 |
| read_queue_timing.p4 | `KIND_RESET = 13`; `parse_tev` uses the constant (was the literal 4). Operate slices regenerated |
| compose.py | `check_reset_kind`: refuses a build whose N RESET kind differs from T's or is < 6 |
| port_map.py | the loop-port EtherType rule (>= 0x0600, not MAC control / slow protocols / VLAN tags / LLDP / EAPOL / PTP / CFM) |
| queue_sim.py, model_drive_t_queue.py, model_drive_t_response_join.py | RESET kind from T's constant / 13 |
| legacy profile | unchanged (connection/binding 85/85, native_binding.p4 byte-identical) |

## Wire bytes 12-13 on every front-panel loop port (hardware map, model, reflected frames)

| port | role | values seen (green) | before |
|---|---|---|---|
| 48 | N ACK lap: master's Ethernet frame | 0x0800 | same |
| 180 | T_IN events READ / ACK / RESPONSE / OPERATE / RESET | 0x0900, 0x0a00, 0x0b00, 0x0c00, **0x0d01 / 0x0d02** | **0x0401** (802.3 length) |
| 181 | OPERATE ladder: direct blocker and held OPERATE (Ethernet header kept) | 0x4455 (endpoint dst-MAC octets 5-6), 0x0800 | same |
| 182 | READ ladder: held ACK / response | 0x4455 | same |

Not in the model: generator-seeded blockers on 181/182 (no packet generator in these drivers). Their bytes 12-13 are
generator-buffer bytes 4-5, set by the bring-up (hw/t_config.py, Agent 2, f4272787a). Held frames carry the endpoint
destination MAC's octets 5-6, so they are data dependent; they lap on this testbed.

## Red -> green (model; `red/` = sbo_admission_01 builds, commit 8efae4002; `green/` = this build)

| scenario | red | green |
|---|---|---|
| CLOSE=client (prod case) | 21/24: server FIN 975 (native) not 1017, final ACK dropped | 24/24 |
| CLOSE=client_sepack (outstation ACKs the client FIN separately) | 23/26: server FIN, final ACK (the separate ACK itself already passed: kind-10 forward_original) | 26/26 |
| CLOSE=server (outstation closes first) | 24/25: master's ACK of the outstation FIN (0,1) dropped | 25/25 |
| CLOSE=rst (outstation RST in phase 7) | 20/22: RST left in native coordinates | 22/22 |
| composite, hardware map (loop-port EtherType check) | 60/61: 0x0401 on 180 | 61/61 |
| CLOSE=client, hardware map | 21/25 (incl. 0x0401) | 25/25 |
| CLOSE=server, hardware map | not run | 26/26 (0x0d02 on 180) |
| composite default / shared / sbo_toff milestone | (70 / 57 / 18 before) | 70/70, 57/57, 18/18 |

Kept: command-bearing FIN/RST rejection (`fin_operate_retransmission_not_delivered`, test_sbo_admission 9/9) and
exactly-once delivery (`OPERATE_reached_outstation_exactly_once`).

Source-level: `tests/test_close_path.py` 9 tests; teeth (in memory): reverting edits 10-12 fails the 4 close tests,
reverting edit 13 fails the 3 wire-type tests. Suites: response_only 80, read+harness 214, binding 85,
protocol cp 11, hw 73.

## Builds (all exit 0)

| build | p0 ingress / egress | p1 ingress / egress |
|---|---|---|
| hw_compile_local (9.13.1) | 12 / 11, critical path 11 | 11 / 0, critical path 9 |
| hw_compile_switch_9132 (9.13.2) | 12 / 11, critical path 11 | 11 / 0, critical path 9 |
| default_compile_local, shared_default_compile_local | 12 / 11 | 11 / 0 |

PHV identical to sbo_admission_01 on both compilers: p0 ingress 127 containers / 2,832 bits, egress 118 / 2,535;
p1 ingress 50 / 1,542, egress 21 / 369 (p0 normal 8-bit 56/64, 16-bit 74/96, 32-bit 64/64).

**Hardware-map 9.13.2 (load this):** bfrt.json `7c7e7f3bbe1220b6abcc7cbc1fdc9cc18d7854428447529f79b6c4ed7808d2e3`,
p0/tofino.bin `e15b6177ddc87ee6e2132bdd5a5e8c720ae4e8850c3b1df2c9a2eaff0bccbe6a`,
p1/tofino.bin `7ab242e86b9a30d66b468e6f01e7d4c5142d07b76d17bad26c336b6ff9e302a0`.
Sources: hw `98a0df642380...`, default `b3dfda122bb9...`, shared `be05b6975...`.

## Not verifiable off-silicon

- Whether the MAC now passes the RESET event: the model does not filter. Silicon check: port 180
  `$OctetsReceived - $OctetsReceivedinGoodFrames` delta 0 across a close (and `$FramesReceivedwithLengthError` +0).
- The clean close on the wire: server FIN at the padded frontier, the master's final ACK reaching the outstation,
  no outstation FIN retransmissions; wire_check on the new capture.
- Generator-blocker bytes 12-13 (bring-up buffer, not in the model) and the data-dependent held-frame MAC octets.
- N has no re-arm: one close per connection, a cold bring-up per connection (unchanged).
