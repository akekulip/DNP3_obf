#ifndef CASE4_READ_PORTS_P4
#define CASE4_READ_PORTS_P4
// Single source of every private port and role of the READ timing program (read_timing.p4).
// Include after <tna.p4> (PortId_t). tests/test_read_ports.py parses this file.
// Device port = pipe * 128 + pipe-local port (9 bits). Pipes per STEP3_DESIGN 2.1: N pipe 0, M pipe 1, T pipe 2.
// Source: integration/evidence/model_28 (PORTS_PROPOSAL.md, RESULT.md), local Tofino-1 model only; gate G-PORTS
// must confirm every number on the switch before use. Facts the numbers rest on:
//   * local 68-71 recirculate to the SAME port's ingress in every pipe; `$PORT` add is refused for them;
//   * local 64-67 behave differently per pipe (leave in pipe 0, recirculate or drop elsewhere): never a private hop;
//   * local >= 72 aborts the model start; a pipe-0 port never reaches another pipe's ingress, so N's tev must go
//     to a device port of T's pipe: 325 = pipe 2 local 69.
// Tags: ingress = a frame enters a pipe on this port; egress = a forwarding target; peer = owned by another role
// (listed so every private number lives in one file; T does not use it).
// The packet generator is not a port: on the model its packets arrive with ingress_port 0 behind a 6-byte timer
// header (pipe, app), so T recognises them by that header (PKTGEN_PIPE below), not by number.
const PortId_t T_IN         = 9w325; // ingress pipe 2 local 69: N-to-T handoff (N's READ_HANDOFF_PORT must equal this)
const PortId_t HB_RETURN    = 9w326; // ingress pipe 2 local 70: heartbeat service return
const PortId_t HELD_RETURN  = 9w327; // ingress pipe 2 local 71: private held-original recirculation
const PortId_t FORWARD_PORT = 9w9;   // egress pipe 0 local 9: master side (cross-pipe, egress pipe not bypassed)
const PortId_t RELAY_PORT   = 9w64;  // egress pipe 0 local 64: outstation relay (cross-pipe, egress pipe not bypassed)
const PortId_t N_RETURN     = 9w68;  // peer pipe 0 local 68: N's own recirculation
const PortId_t N_TO_M       = 9w196; // peer pipe 1 local 68: N to M (E1)
const PortId_t T_TO_M       = 9w197; // peer pipe 1 local 69: T to M (E4), distinct from N_TO_M so M tells the source
const bit<2> PKTGEN_PIPE = 2;        // pipe whose packet generator drives T's heartbeat (device port 324, local 68)
#endif
