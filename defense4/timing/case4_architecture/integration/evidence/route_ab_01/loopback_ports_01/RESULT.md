# Looping ports as build parameters; the hardware port map (2026-10-11)

**Why.** On the switch only pipe-local 68 recirculates (dev 68 and 196; `evidence/recirc_ports_01/STATUS.md`).
The composite's other four looping ports must be front-panel ports in MAC loopback.

| role | default (model) | hardware map | pipe |
|---|---|---|---|
| `N_ACK_RETURN` (N's ACK lap; E's reverse-map pass) | 70 | 48 | 0 |
| `T_IN` = N's `READ_HANDOFF_PORT` | 197 | 180 | 1 |
| `HB_RETURN` (OPERATE ladder) | 198 | 181 | 1 |
| `HELD_RETURN` (ACK / response ladder) | 199 | 182 | 1 |
| `RELAY_PORT` (T's outstation-side release) | 64 | 9 | 0 |
| `RETURN_PORT` 68, `PKTGEN_RETURN` 196 | fixed | fixed | 0, 1 |

**Build.** `compose.py out.p4 --relay-port=9 --n-ack-return=48 --t-in=180 --hb-return=181 --held-return=182`,
source sha256 `44eebdcf74ba…`. With no flag the output is `90eab15b4028…`, the same bytes as
`shared_port_01/source_distinct`; with `--relay-port=9` alone it is `8fc7486d0061…`, the same bytes as
`shared_port_01/source_shared`. Seven lines differ between the default and the hardware source: N's two
declarations, E's dispatch, T's four declarations. Every other use of a port is by constant name, and
`tests/test_port_map.py` asserts that no other 9-bit literal exists in the composed program.

| build | exit | p0 ingress / egress stages | p1 ingress / egress | bfrt.json | p0/tofino.bin | p1/tofino.bin |
|---|---|---|---|---|---|---|
| `shared_compile_local` (9.13.1) | 0 | 12 / 11, critical path 11 | 11 / 0, critical path 9 | `6c5fa933f619…` | `19badb93f9b2…` | `1ecb4824401e…` |
| `shared_compile_switch_9132` (9.13.2) | 0 | 12 / 11, critical path 11 | 11 / 0, critical path 9 | `d1ac5cf67103…` | `4a322a755dbb…` | `bb58c2cbb8b7…` |

`table_summary.log` is identical to `shared_port_01/shared_compile_*` on both pipes and both compilers, and
`pa.results.log` differs only in its timestamp and run id. So placement and PHV are those of that build: pipe 0
uses 193 of 224 containers (8-bit 55/64, 16-bit 74/96, 32-bit 64/64), 1,954 ingress and 1,683 egress bits;
pipe 1 uses 42 containers, 870 ingress and 13 egress bits. `bfrt.json` on 9.13.1 is byte-identical to the
shared-port build's: the port numbers are not part of the runtime interface.

**Model.** Functional only; not hardware, not timing.

| run | build | result |
|---|---|---|
| `model_hw_01` | hardware map, `$LOOPBACK_MODE = BF_LPBK_MAC_NEAR` on 48, 180, 181, 182 | 14/57. The model transmits on a port in MAC loopback instead of looping it (`Tx Pkt to port 48`), so nothing returned. A fact about the model, not the program. |
| `model_hw_02` | hardware map, `-P "9 48 180 181 182"`, the driver reflects each frame on those four ports back into the same port | **58/58**: the 57 shared-port checks plus one that all four ports carried frames (9, 11, 29 and 173 frames). |
| `model_default_distinct_01` | `shared_port_01/distinct_compile_local` (default ports) | 70/70 |
| `model_default_shared_01` | `shared_port_01/shared_compile_local`, `SHARED_PORT=1` | 57/57 |

## Frames on the front-panel loop ports: size and first bytes

Sizes are without the 4-byte FCS; the wire minimum is 60 + 4. `model_hw_02` recorded the shortest frame the
model sent on each port (`cases.json`, `meta.loopback_frames`); the model has no MAC and pads nothing.

| port | frame | first bytes | size | shortest on the model |
|---|---|---|---|---|
| 48 | the master's own frame, unchanged (`n_response_only.p4:102` `normalize_ack`; E rewrites ACK and window only) | a valid Ethernet header | as received | 60 |
| 180 | N's 16-byte event envelope + the original (`n_response_only.p4:318,321`; T's `tev_t`, `read_queue_timing.p4:46`) | epoch, work generation, t0, kind, stage | original + 16 | 76 |
| 182 | held ACK / response: 8-byte ladder + the original (`read_queue_timing.p4:482,489`, rewait `:639,673`) | role 14/15, child, generation, budget, then the original's Ethernet header | original + 8 | 68 |
| 182, 181 | generated blocker: ladder replaces the 6-byte timer header (`:537,544,551`; `keep_blocking` `:570`) | role 11/12/13, child, generation, budget, then the generator buffer | buffer + 8 | not generated in this run |
| 181 | direct OPERATE blocker: ladder + the original WITHOUT its Ethernet header (`:505-506`) | role 13, …, then the IP header | original - 6 | 83 |
| 181 | held OPERATE: ladder + the clone's original (`:526`, rewait `:691`) | role 16, …, then the Ethernet header | original + 8 | 97 |

**No internal frame is under 64 bytes on the wire on the switch**, on two conditions that hold today:

1. An endpoint frame received from a real link is at least 60 bytes. Then port 48 carries >= 60, port 180
   >= 76, held frames >= 68. The direct OPERATE blocker is the original minus 6; an OPERATE is 89 bytes in
   the document vector, so 83.
2. The generator buffer is at least 52 bytes. A generated packet is the 6-byte header plus `pkt_len` buffer
   bytes (SDE `tna_pktgen/test.py:443`, `exp_size = generated_pkt_len + 6 + 4`), so a blocker is `pkt_len + 8`.
   `hw/t_config.py:24` sets `TOKEN_LEN = 60`, giving 68. **A `TOKEN_LEN` below 52 would make every blocker a
   runt on 181 and 182.** Nothing in the build enforces this; it is a bring-up parameter.

Nothing was padded and no fix is needed for size. What a Tofino MAC does with a runt is therefore not
exercised and was not measured.

**Frames that do not start with an Ethernet header: UNVERIFIED on silicon.** The only loopback measurement so
far is one 60-byte frame with a valid header and type 0x88b5 (`recirc_ports_01`). Every frame on 180, 181 and
182 starts with an internal header, so the MAC sees these bytes in the type/length position (offset 12-13):

- 180: `tev.kind`, `tev.stage` = 0x0900..0x0c02 or 0x0400..0x0402. The reset values are below 0x0600, which
  802.3 reads as a length that does not match the frame.
- 182 and held OPERATE on 181: octets 5 and 6 of the original's destination MAC (an endpoint constant).
- generated blockers: two buffer bytes (zero today).
- direct OPERATE blocker on 181: **the IP identification field**, any 16-bit value, different per packet.

A MAC that drops on a length mismatch, or that consumes type 0x8808 (MAC control), would lose some of these.
Whether this MAC does either is not known here. Smallest check before the first run: with the three ports in
loopback, send one frame of each row above through the pipe and compare `$PORT_STAT` receive-good against
transmit, including a direct OPERATE blocker with IP id 0x8808 and a reset event. Smallest fix if the IP-id
case fails: delete `hdr.eth.setInvalid();` in `hold_operate` (`read_queue_timing.p4:506`), so the blocker keeps
the original's Ethernet header and offset 12-13 becomes the same endpoint constant as the held frames. The
parser already ends at the ladder for role 13, so nothing else changes. Not applied.

**Deployment requirements that follow from using front-panel ports.**

- 48, 180, 181 and 182 must be in MAC loopback before any row is installed, and read back: loopback is
  volatile. A frame arriving from a cable on 48 would be taken as the master's packet after its lap (forward
  provenance); on 180 a frame whose bytes 12-15 look like an event is admitted as one. T's "every other
  pipe-1 ingress is dropped" (3c6138aaa) still holds for every port except these three and 196.
- T's strict-priority queues (qid 2-7) must be configured on 181 and 182, not 198 and 199.
- The ports' MTU must allow the original + 16 bytes.
- A lap now crosses a 25G MAC twice instead of the internal recirculation path, so the blocker lap time and
  the release tail measured on the earlier build (about 1.7 us) do not carry over and must be measured again.
