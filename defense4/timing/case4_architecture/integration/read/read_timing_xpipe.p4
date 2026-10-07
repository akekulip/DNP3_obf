// Four-pipe model wrapper for read_timing.p4 (NEVER DEPLOY): pipe 2 is the unmodified READ timing role T; pipes 0, 1
// and 3 are stubs. Pipe 0 stands in for N: a frame entering front port 9 is sent to T's handoff port (device 325 =
// pipe 2 local 69, ports.p4 T_IN) with the egress pipe bypassed. T's own forwarding targets (ports 9 and 64) are pipe 0
// front ports reached through pipe 0's empty egress. This only exercises the cross-pipe hop and T; it is not N or M.
#include <core.p4>
#include <tna.p4>
#define READ_TIMING_NO_MAIN
#include "read_timing.p4"

struct stub_h { }
struct stub_m { }
parser StubParser(packet_in pkt, out stub_h hdr, out stub_m md, out ingress_intrinsic_metadata_t ig_intr_md) {
    state start { pkt.extract(ig_intr_md); pkt.advance(PORT_METADATA_SIZE); transition accept; }
}
control StubToT(inout stub_h hdr, inout stub_m md, in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    apply {
        if (ig_intr_md.ingress_port == FORWARD_PORT) { ig_tm_md.ucast_egress_port = T_IN; ig_tm_md.bypass_egress = 1; }
        else { ig_dprsr_md.drop_ctl = 1; }
    }
}
control StubDrop(inout stub_h hdr, inout stub_m md, in ingress_intrinsic_metadata_t ig_intr_md,
                 in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                 inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                 inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    apply { ig_dprsr_md.drop_ctl = 1; }
}
control StubDeparser(packet_out pkt, inout stub_h hdr, in stub_m md,
                     in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) { apply { } }

Pipeline(StubParser(), StubToT(), StubDeparser(), EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) p0;
Pipeline(StubParser(), StubDrop(), StubDeparser(), EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) p1;
Pipeline(IngressParser(), Ingress(), IngressDeparser(), EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) p2;
Pipeline(StubParser(), StubDrop(), StubDeparser(), EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) p3;
Switch(p0, p1, p2, p3) main;
