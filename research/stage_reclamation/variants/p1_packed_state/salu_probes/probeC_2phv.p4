/* SALU capability probe C — the 2-PHV-input forms the fallback design needs.
 * Probe B established the hard limit: a Tofino SALU takes at most 2 PHV inputs.
 * Each RegisterAction here uses EXACTLY 2:
 *   reg_tag:      output = (PHV - memory);  write predicated on a PHV-vs-const sentinel
 *   reg_deadline: output = (PHV - memory);  write predicated on a PHV-vs-const sentinel
 * If both compile, the age subtraction and the tag comparison both move INTO the
 * SALU, removing one MAU level each. */
#include <core.p4>
#include <tna.p4>

header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ibspg_h    { bit<8> role; bit<8> slot; bit<8> gen; bit<32> seq; }
struct headers_t { ethernet_h eth; ibspg_h ib; }

struct ig_meta_t {
    bit<32> now_word;
    bit<32> dl_val;
    bit<32> age;
    bit<8>  exp_tag;
    bit<8>  tag_val;
    bit<8>  tag_diff;
    bit<8>  expired;
}

parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.now_word = 32w0; meta.dl_val = 32w0xFFFFFFFF; meta.age = 32w0;
        meta.exp_tag = 8w0;   meta.tag_val = 8w0xFF;       meta.tag_diff = 8w0;
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

    /* 2 PHV inputs: meta.exp_tag (output operand), meta.tag_val (write + condition) */
    Register<bit<8>, bit<1>>(1, 0) reg_tag;
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) tag_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.exp_tag - v;
            if (meta.tag_val != 8w0xFF) { v = meta.tag_val; }
        }
    };

    /* 2 PHV inputs: meta.now_word (output operand), meta.dl_val (write + condition) */
    Register<bit<32>, bit<1>>(1, 0) reg_deadline;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_deadline) deadline_rmw = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = meta.now_word - v;
            if (meta.dl_val != 32w0xFFFFFFFF) { v = meta.dl_val; }
        }
    };

    action set_arm()  { meta.dl_val = 32w0; }
    action set_none() { meta.dl_val = 32w0xFFFFFFFF; }
    table tbl_decode_tag {
        key = { meta.tag_diff : ternary; hdr.ib.role : exact; }
        actions = { set_arm; set_none; }
        const default_action = set_none();
        const entries = { (8w0 &&& 8w0xFF, 8w7) : set_arm(); }
        size = 8;
    }

    action mark_expired()     { meta.expired = 8w1; }
    action mark_not_expired() { meta.expired = 8w0; }
    table tbl_deadline_expiry {
        key = { meta.age : ternary; }
        actions = { mark_expired; mark_not_expired; }
        const default_action = mark_not_expired();
        const entries = { (32w0 &&& 32w0x800000FF) : mark_expired(); }
        size = 4;
    }

    apply {
        if (hdr.ib.isValid()) {
            meta.exp_tag  = hdr.ib.gen;
            meta.now_word = ig_intr_md.ingress_mac_tstamp[31:0] & 32w0xFFFFFF00;
            if (hdr.ib.role == 8w6) { meta.tag_val = hdr.ib.gen; }
            meta.tag_diff = tag_rmw.execute(0);
            tbl_decode_tag.apply();
            meta.age = deadline_rmw.execute(0);
            tbl_deadline_expiry.apply();
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
