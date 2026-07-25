/* SALU capability probe B — the aggressive form P1 wants:
 *   ONE 32-bit register, ONE RegisterAction, ONE call site, which
 *     (1) OUTPUTS an expression of the register and a PHV  (rv = now_word - v)
 *     (2) has TWO write branches, the second predicated on a
 *         memory-vs-PHV equality  (v == meta.exp_word)
 * If this compiles, the packed-state variant can collapse the three serial
 * state registers into one MAU stage. */
#include <core.p4>
#include <tna.p4>

header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }
struct headers_t { ethernet_h eth; ibspg_h ib; }

struct ig_meta_t {
    bit<32> now_word;
    bit<32> exp_word;
    bit<32> st_val;
    bit<32> ack_val;
    bit<8>  st_we;
    bit<32> age;
    bit<8>  expired;
}

parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.now_word = 32w0; meta.exp_word = 32w0; meta.st_val = 32w0;
        meta.ack_val = 32w0;  meta.st_we = 8w0;     meta.age = 32w0;
        meta.expired = 8w0;
        transition parse_eth;
    }
    state parse_eth {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etype) { 0x88C0: parse_ib; 0x88C1: parse_ib; default: accept; }
    }
    state parse_ib { pkt.extract(hdr.ib); transition accept; }
}

control Ingress(inout headers_t hdr, inout ig_meta_t meta,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    Register<bit<32>, bit<1>>(1, 0) reg_state;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_state) state_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;                      /* (1) output expression */
            if (meta.st_we == 8w1)       { v = meta.st_val;  }
            else if (v == meta.exp_word) { v = meta.ack_val; }   /* (2) mem-vs-PHV */
        }
    };

    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_decode {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = { (32w0 &&& 32w0x800000FF) : mark_expired(); }
        size = 4;
    }

    apply {
        if (hdr.ib.isValid()) {
            meta.now_word = ig_intr_md.ingress_mac_tstamp[31:0] & 32w0xFFFFFF00;
            meta.exp_word = (bit<32>)hdr.ib.gen;
            meta.st_val   = (bit<32>)hdr.ib.gen;
            meta.ack_val  = hdr.ib.seq;
            if (hdr.ib.role == 8w6) { meta.st_we = 8w1; }
            meta.age = state_rmw.execute(0);
            tbl_decode.apply();
            if (meta.expired == 8w1) { ig_dprsr_md.drop_ctl = 3w1; }
            else { ig_tm_md.ucast_egress_port = 9w9; }
        } else {
            ig_dprsr_md.drop_ctl = 3w1;
        }
    }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_meta_t meta,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr.eth); pkt.emit(hdr.ib); }
}

struct eg_meta_t { }
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t meta,
                out egress_intrinsic_metadata_t eg_intr_md) {
    state start { pkt.extract(eg_intr_md); transition accept; }
}
control Egress(inout headers_t hdr, inout eg_meta_t meta,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) { apply { } }
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t meta,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) { apply { } }

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
