/* BMv2 step 1: a plain L2 forwarder. No DNP3 awareness. Establishes that master -> switch -> outstation works. */
#include <core.p4>
#include <v1model.p4>

header eth_t { bit<48> dst; bit<48> src; bit<16> etype; }
struct headers_t { eth_t eth; }
struct meta_t { }

parser P(packet_in pkt, out headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    state start { pkt.extract(h.eth); transition accept; }
}
control VC(inout headers_t h, inout meta_t m) { apply { } }
control Ing(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    action fwd(bit<9> port) { sm.egress_spec = port; }
    action drop() { mark_to_drop(sm); }
    table dmac {
        key = { h.eth.dst : exact; }
        actions = { fwd; drop; }
        default_action = drop();
        size = 16;
    }
    apply { dmac.apply(); }
}
control Egr(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) { apply { } }
control CC(inout headers_t h, inout meta_t m) { apply { } }
control Dep(packet_out pkt, in headers_t h) { apply { pkt.emit(h.eth); } }
V1Switch(P(), VC(), Ing(), Egr(), CC(), Dep()) main;
