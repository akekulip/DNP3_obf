/* Experiment only: which of two egress priorities does BMv2 serve first, and how does set_queue_rate pace a port?
 * Port 0 -> egress port 2 (the loopback), ethertype 0x1234 at priority 0, anything else at priority 1.
 * Port 3 (the other end of the loopback) -> port 1. */
#include <core.p4>
#include <v1model.p4>
header eth_t { bit<48> dst; bit<48> src; bit<16> etype; }
struct headers_t { eth_t eth; }
struct meta_t { }
parser P(packet_in pkt, out headers_t h, inout meta_t m, inout standard_metadata_t sm) { state start { pkt.extract(h.eth); transition accept; } }
control VC(inout headers_t h, inout meta_t m) { apply { } }
control Ing(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    apply {
        if (sm.ingress_port == 0) { sm.egress_spec = 2; sm.priority = (h.eth.etype == 0x1234) ? (bit<3>)0 : (bit<3>)1; }
        else if (sm.ingress_port == 3) { sm.egress_spec = 1; }
        else { mark_to_drop(sm); }
    }
}
control Egr(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) { apply { } }
control CC(inout headers_t h, inout meta_t m) { apply { } }
control Dep(packet_out pkt, in headers_t h) { apply { pkt.emit(h.eth); } }
V1Switch(P(), VC(), Ing(), Egr(), CC(), Dep()) main;
