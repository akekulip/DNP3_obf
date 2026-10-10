#ifndef CASE4_READ_PORTS_P4
#define CASE4_READ_PORTS_P4
// Single source of every private port and role of the READ timing program (T). Include after <tna.p4>.
// tests/test_read_ports.py parses this file.
// Device port = pipe * 128 + pipe-local port (9 bits).
//
// TWO-PIPE LAYOUT (2026-10-10). The switch has two physical pipes: loading Switch(p0,p1,p2,p3) failed with
// "Pipeline p2 cannot be assigned to device 0 pipe 2, only 2 pipe(s) available", and BFRT $PORT shows
// 68-71 and 196-199 present, 324-327 absent. So N + E are pipe 0 and T is pipe 1; M is retired. The
// earlier layout (N pipe 0, M pipe 1, T pipe 2: T_IN 325, M's N_TO_M 196 / T_TO_M 197) cannot load on this
// chip; its M constants are removed so no stale M route can land on T's input (197 is T_IN now).
// Pipe-local 68-71 are dedicated recirculation ports, each independent (confirmed on the switch).
// Tags: ingress = a frame enters a pipe on this port; egress = a forwarding target; peer = owned by another role.
//
// The packet generator is not a port role here: T recognises generated tokens by their timer header on the
// default parser path. UNVERIFIED ON SILICON and a pre-hardware blocker: with app_cfg.pipe_local_source_port
// = 68 (required on this switch, Defense 2), generated tokens may arrive on local 68 = PKTGEN_RETURN, where
// T's parser expects a mirror clone (it selects parse_clone by port). See TIMING_QUEUE_MIGRATION_STATUS.md.
const PortId_t PKTGEN_RETURN = 9w196; // ingress pipe 1 local 68: mirror-clone recirculation into T ($mirror.cfg)
const PortId_t T_IN          = 9w197; // ingress pipe 1 local 69: N-to-T handoff (N's READ_HANDOFF_PORT must equal this)
const PortId_t HB_RETURN     = 9w198; // ingress pipe 1 local 70: heartbeat / OPERATE-ladder service return
const PortId_t HELD_RETURN   = 9w199; // ingress pipe 1 local 71: private held-original recirculation
const PortId_t FORWARD_PORT  = 9w9;   // egress pipe 0 local 9: master side (cross-pipe, egress pipe not bypassed)
const PortId_t RELAY_PORT    = 9w64;  // egress pipe 0 local 64: outstation relay (cross-pipe, egress pipe not bypassed)
const PortId_t N_RETURN      = 9w68;  // peer pipe 0 local 68: N's own recirculation
const bit<2> PKTGEN_PIPE = 1;         // pipe whose packet generator drives T (T's pipe)
#endif
