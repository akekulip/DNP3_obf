# PORTS_PROPOSAL (not applied): device-port table for integration/read/ports.p4 and N, from the model (model_28/run9)

`integration/read/ports.p4` itself is NOT edited. Device port = pipe*128 + pipe-local port. All numbers below are model results (SDE 9.13.1
tofino-model, chip type TofinoB0, 4 pipes); gate G-PORTS must confirm them on the switch before any use.

## What the model says about each pipe-local port (probe `xpipe_probe.p4`, section (e) of `run9/cases.json`)
| local port | pipe 0 | pipe 1 | pipe 2 | pipe 3 |
|---|---|---|---|---|
| 1 (front, enabled via $PORT) | leaves (9, 64 tested) | leaves (129) | leaves (257) | leaves (385) |
| 64-67 | leave the chip (veth), `$PORT` add ok | recirculate to ingress, `$PORT` add refused | 64 dropped, 65-67 leave, `$PORT` add refused | recirculate, `$PORT` add refused |
| 68-71 | recirculate to the SAME port's ingress; `$PORT` add refused (INVALID_ARGUMENT, nothing to add) | same | same | same |
| 72 and above | the model refuses to start: `Invalid port 72 in PortToVeth mapping` | | | |
"Recirculate" = egress to that device port (with or without egress bypass) re-enters ingress of the same pipe with `ingress_port` = that device port,
prefix intact. Only local 68-71 behave identically in all four pipes; 64-67 differ by pipe and must not be used as private hops.

## The READ handoff mismatch (finding 3 of STEP3_DESIGN)
* N sends the tev to `READ_HANDOFF_PORT = 66` = pipe 0 local 66. On the model that port LEAVES the chip (frame appears on veth133); it never reaches any ingress.
* T listens on `T_IN = 69` = pipe 0 local 69. That port recirculates into pipe 0's own ingress, which is N's pipe, not T's.
So the two numbers cannot meet in any pipe: not a typo to fix by renumbering inside pipe 0, the handoff must cross pipes.

## Proposed table (pipes per STEP3_DESIGN 2.1: N pipe 0, M pipe 1, T pipe 2)
| constant | value | pipe, local | verified on model |
|---|---|---|---|
| front master / relay (existing) | 9, 64 | 0, 9 / 0, 64 | yes (leave) |
| N `RETURN_PORT` | 68 | 0, 68 | yes (recirculates; model_23) |
| N to T: N `READ_HANDOFF_PORT` = T `T_IN` | **325** | 2, 69 | yes: pipe 0 ingress -> port 325 -> pipe 2 ingress, prefix preserved (case f) |
| T `HELD_RETURN` | **327** | 2, 71 | recirculates (sweep) |
| T `HB_RETURN` (replaces testbed loopback 10) | **326** | 2, 70 | recirculates (sweep) |
| T `HB_PKTGEN` | pktgen of pipe 2 (dev 324, local 68) | 2, 68 | generator runs (case d) but see quirk |
| N to M (E1) | **196** | 1, 68 | yes (cases a, b) |
| T to M (E4) | **197** | 1, 69 | recirculates (sweep); distinct from 196 so M tells the source by ingress port |
| M to E, toward relay / master | 64 / 9 with egress bypass off | 0 | yes (cases a, b, f, g) |
| E to N confirm (e2e mirror) | mirror session -> 68 | 0, 68 | yes (case c: clone returns to ingress 68 with prefix) |
`FORWARD_PORT` (9) and `RELAY_PORT` (64) stay egress targets in pipe 0.

## Rules this implies for `tests/test_read_ports.py`
1. Replace "every value must be <= 71" by "device port = pipe*128 + local, local <= 71, local 68-71 for every private hop"; add a pipe tag per constant.
2. No local number may serve two ingress roles in the SAME pipe; the same local number in different pipes (68 in pipe 0 and pipe 1) is fine and verified.
3. Do not use local 64-67 of pipes 1-3 or 64 of pipe 2 as private hops (model behavior differs by pipe).

## Generator quirk that matters for T's heartbeat
On the model, packet-generator packets arrive with `ig_intr_md.ingress_port == 0` (not 68) and a 6-byte `pktgen_timer_header_t` in front (first byte 000pp0aa:
pipe, app). A parser or table keyed on ingress port 68 never sees them. T must recognise generator packets by the timer header (the SDE `tna_pktgen` example uses a
parser value set), not by port. Whether silicon reports 68 is unverified (G-PORTS).
