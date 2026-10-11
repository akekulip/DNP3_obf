# Keep the Ethernet header on the OPERATE blocker; audit of every MAC-loopback frame (2026-10-11)

Proven necessary by the first combined silicon run (`evidence/combined_silicon_01`): with the hardware port
map the OPERATE path and the clean ACK-commit path cross front-panel ports in MAC loopback (48/180/181/182),
and the switch MAC drops frames whose bytes 12-13 are not a valid ethertype. On the bound connection all ten
READs released by fallback (OUT_ACK_FALLBACK/OUT_RESP_FALLBACK = 10, not commit) and the OPERATE was lost.

## The fix (step 1)

`read/read_queue_timing.p4` `hold_operate`: removed `hdr.eth.setInvalid()`. The direct OPERATE blocker now
keeps the original's Ethernet header, so wire offset 12-13 is the original's ethertype octets, as on every
held frame. The parser accepts role 13 and ignores what follows the ladder (`read_queue_timing.p4:131`), the
blocker only holds qid3, and the real OPERATE is released from the mirror clone (`admit_operate_held`), which
already kept the header. The mirror copies the pristine received packet, so this does not change the clone.
Slices regenerated (`make_operate_slice.py`, `--capture-hb`). Stages and PHV unchanged (below).

## Offset 12-13 audit, every frame egressing on a MAC-loopback port

The frame on the wire begins with its internal header (ladder for T, tev envelope for N), so the MAC reads
offset 12-13 counted from there. Measured through the interpreter (T: queue_sim; N: the real-capture replay).

| port | frame | what is at wire offset 12-13 | value | verdict |
|---|---|---|---|---|
| 48 (lap) | master's Ethernet frame, unchanged (`normalize_ack`) | the real ethertype (no prefix) | 0x0800 | OK |
| 180 (T_IN) | READ / ACK / RESPONSE / OPERATE event (`emit_tev`) | tev.kind, tev.stage | 0x0900 / 0x0a00 / 0x0b00 / 0x0c00 | OK (all >= 0x09xx) |
| 180 (T_IN) | RESET event (`emit_reset`) | tev.kind=4, direction | 0x0401 / 0x0402 | **RISK (< 0x0600)** |
| 182 (HELD) | held ACK / held RESPONSE (`hold_ack`, `admit_response`, rewait) | ladder(8) then eth.dst octets 5-6 | eth.dst[4:6] | data-dependent |
| 182 (HELD) | generator ACK / RESPONSE blocker (`seed_ack_blocker`, `seed_resp_blocker`, keep_blocking) | ladder(8) then generator buffer bytes 4-5 | 0x0000 | **RISK (< 0x0600)** |
| 181 (HB) | held OPERATE (`admit_operate_held`, rewait) | ladder(8) then eth.dst octets 5-6 | eth.dst[4:6] | data-dependent |
| 181 (HB) | direct OPERATE blocker (`hold_operate`) | **before:** ladder(8) then IP header -> IP identification; **after this fix:** ladder(8) then eth.dst octets 5-6 | before: IP id (arbitrary); after: eth.dst[4:6] | **was RISK, FIXED** |
| 181 (HB) | generator OPERATE blocker (`seed_op_blocker`, keep_blocking) | ladder(8) then generator buffer bytes 4-5 | 0x0000 | **RISK (< 0x0600)** |

Recorded before/after for the direct OPERATE blocker on 181, from the reflected frame sample (role byte 13):
before (`loopback_ports_01/model_hw_02`) `0d...45 00 00 4b 00 01 ...` — byte 8 = 0x45 (IP), offset 12-13 =
0x0001 (IP id); after (`model_hw_operate`) `0d 00000100 03a980 00 11 22 33 44 55 ...` — byte 8 = 0x00
(eth.dst), offset 12-13 = 0x4455 (ethertype octets).

### Items still at risk (reported, not applied — per the task: report and propose, do not silently rewrite)

1. **Generator-seeded blockers (ACK/RESP/OP), offset 12-13 = 0x0000.** This is the cause of the silicon
   fallback-only releases: the blockers that signal "child seen" to commit are dropped by the MAC, so every
   held frame re-waits to its fallback deadline (silicon OUT_HELD_REWAIT 149,833, OUT_*_FALLBACK = 10). The
   frame is `ladder(8) + generator buffer`, so offset 12-13 is generator buffer bytes 4-5, which the control
   plane sets to zero. **Smallest fix: set those two buffer bytes to an ethertype >= 0x0600** (e.g. 0x0800) in
   the generator buffer content. Control-plane only, no P4 change: `hw/t_config.py` `pktgen_ops` builds the
   buffer as `bytes(TOKEN_LEN)`; set buffer[4:6] = b'\x08\x00'. T reads nothing from the buffer (batch_id is
   read from the 6-byte timer header before it is invalidated; the ladder fields are written by the action),
   so the bytes are inert to the logic. Not applied here: `hw/t_config.py` belongs to the hardware-installer
   workstream, and the model drivers that configure the generator must set the same bytes. This must be fixed
   before the next combined run commits rather than falls back.
2. **RESET event on 180, offset 12-13 = 0x04xx.** Reached only on a qualified close (RST/FIN) through the
   timing path; not exercised in `combined_silicon_01`. The value is tev.kind=4 (`KIND_RESET`), required by
   T's `parse_tev` and apply logic and by N's `emit_reset`/`read_terminal_t` event values. **Smallest fix:
   give the RESET its kind byte a value >= 6** (every other kind is already 9-12), coordinated across N's
   generator (the event constants in `connection/binding/generate.py`) and T (`KIND_RESET` and the
   `parse_tev` entry). Not applied: it spans N and T and the task scoped the applied change to the OPERATE
   blocker. If the next OFF/ON run closes connections through the timing path, the close event would be lost
   without this.
3. **Held frames (ACK/RESP/OP) and the fixed direct OPERATE blocker, offset 12-13 = eth.dst octets 5-6.**
   Data-dependent on the real endpoint MAC. On this testbed they lapped (silicon OUT_HELD_REWAIT 149,833), so
   octet 5 of the destination MAC is >= 0x06 there. If an endpoint's MAC had octet 5 < 0x06 these would drop.
   No change proposed; noted so the dependency is on record.

## Builds (C + this fix; exit 0 on all four)

Sources: hardware map `5d7127d7d252…`, default `b85843162b16…`, shared `19152b0571536…`.

| build | p0 ingress / egress | p1 ingress / egress | bfrt.json | p0/tofino.bin | p1/tofino.bin |
|---|---|---|---|---|---|
| `hw_compile_local` (9.13.1) | 12 / 11, crit 11 | 11 / 0, crit 9 | `fc3e09d4951dc7` | `7d19578061c7a4` | `76cfe5ebdd5994` |
| `hw_compile_switch_9132` (9.13.2) | 12 / 11, crit 11 | 11 / 0, crit 9 | `8459a74d1b108a4e3076fe9d4189fdef6f470a2c8e2e5f3f35d9d3e9b0aa2ff7` | `634e14ede24bd2` | `314680f335e25e` |
| `default_compile_local` (9.13.1) | 12 / 11 | 11 / 0 | `3e9d36d106a4a9` | `91a1dac5960933` | `e531fae30bce8b` |
| `shared_default_compile_local` (9.13.1) | 12 / 11 | 11 / 0 | `f54f6f670a6142` | `8817f7336970be` | `32bffef36fe4ee` |

**9.13.2 hardware-map hashes in full (this is the build to load next):** bfrt.json
`8459a74d1b108a4e3076fe9d4189fdef6f470a2c8e2e5f3f35d9d3e9b0aa2ff7`, p0/tofino.bin from the manifest, p1/tofino.bin
from the manifest (`hw_compile_switch_9132/manifest.json`).

**PHV, identical on both compilers and identical to the C-only build** (the fix adds no PHV: the Ethernet
header was already allocated for the held frames). Containers / bits:

| pipe and gress | value |
|---|---|
| p0 ingress | 127 / 2,832 |
| p0 egress | 118 / 2,535 |
| p1 ingress | 50 / 1,542 |
| p1 egress | 21 / 369 |

Pipe 0 normal containers 8-bit 56/64, 16-bit 74/96, 32-bit 64/64 (full). Stages and critical path unchanged
from C-only (`ts_profile_01`).

## Model (functional only; reflectors stand in for MAC loopback and do not filter on bytes 12-13)

| run | result |
|---|---|
| `model_default` (default ports) | 70/70 |
| `model_shared` (`SHARED_PORT=1`) | 57/57 |
| `model_hw_operate` (hardware map; SELECT then OPERATE) | 60/60 |
| `model_real_hw` (hardware map; real timestamped profile, 3 READs) | 36/36 |

`model_hw_operate` is the OPERATE scenario on the hardware map. It shows the OPERATE releases
(`T_released_the_OPERATE_once_after_holding`, OUT_OP_RELEASE = 1), that the OPERATE ladder port 181 carried
frames (`every_front_panel_loop_port_carried_frames`, 32 frames on 181), and two new cases that pin the fix:
`operate_blocker_on_181_keeps_eth_no_ip_after_ladder` (no role 13/16 frame has the IP header after its ladder)
and `operate_blocker_on_181_has_ethertype_at_offset_12_13` (the direct blocker sample is
`0d0000010003a980001122334455`, offset 12-13 = 0x4455). On the unfixed build the same sample was
`0d...4500...0001` (IP id). The model cannot reproduce the MAC drop; these cases assert the frame SHAPE the
MAC needs. Unit test `D_SeparateGates::test_operate_blocker_keeps_the_ethernet_header_so_offset_12_13_is_the_ethertype`
pins the same at source level.

The generator-blocker and RESET risks above are MAC-only effects; the model reflector does not filter, so the
model cannot show them and they remain open for the coordinator.
