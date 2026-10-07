#ifndef CASE4_READ_PORTS_P4
#define CASE4_READ_PORTS_P4
// Single source of every private port and role of the READ timing program (read_timing.p4).
// Include after <tna.p4> (PortId_t). tests/test_read_ports.py parses this file: every
// constant needs an "// ingress" or "// egress" tag, every value must be <= 71 (Tofino-1
// pipe-local ports are 0..71), and no number may serve two ingress roles.
// PROVISIONAL until gate G-PORTS (STEP2_DESIGN.md 0, 3): which ports are loopback-capable
// on the target pipe is not read from any configuration in this repository.
// The frozen probe's FORWARD_PORT 72 and heartbeat return 73 are above 71 and are replaced
// here by HB_RETURN (a testbed loopback) and FORWARD_PORT (master side, an egress target).
// HB_PKTGEN is local 68, the same number as the native binding RETURN_PORT 68; that is only
// legal if N and T sit in different pipes (STEP2_DESIGN.md 1.1), which G-XPIPE must prove.
const PortId_t HB_PKTGEN    = 9w68; // ingress heartbeat packet-generator source
const PortId_t ACK_INPUT    = 9w69; // ingress pure-ACK fixture input
const PortId_t TYPED_INPUT  = 9w70; // ingress typed producer seam (response, unsent operate)
const PortId_t HELD_RETURN  = 9w71; // ingress private held-original recirculation
const PortId_t HB_RETURN    = 9w10; // ingress heartbeat service return (testbed loopback)
const PortId_t FORWARD_PORT = 9w9;  // egress forwarding target (master side), controller-mapped later
#endif
