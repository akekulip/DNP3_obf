/*
 * Gate S6 / H0 diagnostic — localize the reinject failure.
 *
 * For the test EtherType (0x88b6):
 *   - ingress on dp9 (Vision)  -> egress dp9   (loopback; proves dp9 egress + Vision round-trip)
 *   - ingress on ANY other port (CPU-injected) -> stamp the ingress_port into the
 *     dst MAC low byte, then egress dp9. Vision (promiscuous) reads the low byte to
 *     learn exactly which ingress port CPU-TX frames carry (and whether they enter
 *     the pipeline at all).
 * Everything else is dropped. No loop: dp9 egress goes to Vision, not back in.
 */
#include <core.p4>
#include <tna.p4>

const bit<9> VISION_PORT = 9;
const bit<16> TEST_ETYPE = 0x88b6;

header ethernet_h { bit<48> dst_addr; bit<48> src_addr; bit<16> ether_type; }
struct headers_t { ethernet_h ethernet; }
struct metadata_t { }

parser IngressParser(packet_in pkt, out headers_t hdr, out metadata_t md,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

control Ingress(inout headers_t hdr, inout metadata_t md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    action to_vision() { ig_tm_md.ucast_egress_port = VISION_PORT; }
    action to_vision_stamped() {
        hdr.ethernet.dst_addr[7:0] = ig_intr_md.ingress_port[7:0];  // stamp ingress port
        ig_tm_md.ucast_egress_port = VISION_PORT;
    }
    action drop() { ig_dprsr_md.drop_ctl = 1; }
    apply {
        if (hdr.ethernet.ether_type == TEST_ETYPE) {
            if (ig_intr_md.ingress_port == VISION_PORT) {
                to_vision();            // loopback
            } else {
                to_vision_stamped();    // CPU-injected: stamp port + send to Vision
            }
        } else {
            drop();
        }
    }
}

control IngressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t md,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr.ethernet); }
}

parser EgressParser(packet_in pkt, out headers_t hdr, out metadata_t md,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); transition accept; }
}
control Egress(inout headers_t hdr, inout metadata_t md,
               in egress_intrinsic_metadata_t eg_intr_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) { apply { } }
control EgressDeparser(packet_out pkt, inout headers_t hdr, in metadata_t md,
                       in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) { apply { } }

Pipeline(IngressParser(), Ingress(), IngressDeparser(),
         EgressParser(), Egress(), EgressDeparser()) pipe;
Switch(pipe) main;
