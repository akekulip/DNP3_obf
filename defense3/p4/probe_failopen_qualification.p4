/* Compile-only probe for the Defense 3 defect-2 repair (generation-qualified fail-open).
 * Reproduces, in the smallest possible program, the two walls that block it:
 *   -DPROBE_THREE_OPERANDS  a merged arm needing three PHV operands
 *   -DPROBE_FIFTH_ACTION    keeping the arms separate, i.e. a fifth RegisterAction
 *   (no flag)               the four-action baseline, which must compile
 */
#include <core.p4>
#include <tna.p4>
header eth_h { bit<48> dst; bit<48> src; bit<16> etype; }
struct hdrs_t { eth_h eth; }
struct meta_t { bit<8> gen_in; bit<8> tag_val; bit<8> tag_alt; bit<8> diff; }

parser IgParser(packet_in pkt, out hdrs_t hdr, out meta_t meta,
                out ingress_intrinsic_metadata_t ig_md) {
    state start { pkt.extract(ig_md); pkt.advance(PORT_METADATA_SIZE);
                  meta.gen_in = 8w0; meta.tag_val = 8w0; meta.tag_alt = 8w0;
                  meta.diff = 8w0; transition parse_eth; }
    state parse_eth { pkt.extract(hdr.eth); transition accept; }
}
control Ingress(inout hdrs_t hdr, inout meta_t meta,
                in ingress_intrinsic_metadata_t ig_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm) {
    Register<bit<8>, bit<1>>(1, 0) reg_tag;

#ifdef PROBE_THREE_OPERANDS
    /* WALL 1: compare against one PHV operand and write a SECOND, while still
     * returning a difference computed from a THIRD. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) a_merged = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (v == meta.tag_val) { v = meta.tag_alt; } } };
#else
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) a_arm = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (v == 8w0) { v = meta.gen_in; } } };
#endif
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) a_rmw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (meta.tag_val != 8w1) { v = meta.tag_val; } } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) a_mark = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v; if ((int<8>)v < 8s0) { v = v + meta.tag_val; } } };
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) a_retire = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v; if ((int<8>)v < 8s0) { v = 8w0; } } };
#ifdef PROBE_FIFTH_ACTION
    /* WALL 2: keep the arms separate -> a FIFTH RegisterAction on one Register. */
    RegisterAction<bit<8>, bit<1>, bit<8>>(reg_tag) a_failopen = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = meta.gen_in - v;
            if (v == meta.gen_in) { v = 8w0; } } };
#endif
    apply {
        if (hdr.eth.etype == 16w0x0801) {
#ifdef PROBE_THREE_OPERANDS
            meta.diff = a_merged.execute(0);
#else
            meta.diff = a_arm.execute(0);
#endif
        } else if (hdr.eth.etype == 16w0x0802) { meta.diff = a_rmw.execute(0); }
        else if (hdr.eth.etype == 16w0x0803) { meta.diff = a_mark.execute(0); }
        else if (hdr.eth.etype == 16w0x0804) { meta.diff = a_retire.execute(0); }
#ifdef PROBE_FIFTH_ACTION
        else if (hdr.eth.etype == 16w0x0805) { meta.diff = a_failopen.execute(0); }
#endif
        ig_tm.ucast_egress_port = 9w1;
        ig_dprsr.drop_ctl = (bit<3>)meta.diff[0:0];
    }
}
control IgDeparser(packet_out pkt, inout hdrs_t hdr, in meta_t meta,
                   in ingress_intrinsic_metadata_for_deparser_t d) { apply { pkt.emit(hdr); } }
parser EgParser(packet_in pkt, out hdrs_t hdr, out meta_t meta,
                out egress_intrinsic_metadata_t eg) {
    state start { pkt.extract(eg); transition accept; } }
control Egress(inout hdrs_t h, inout meta_t m, in egress_intrinsic_metadata_t e,
               in egress_intrinsic_metadata_from_parser_t ep,
               inout egress_intrinsic_metadata_for_deparser_t ed,
               inout egress_intrinsic_metadata_for_output_port_t eo) { apply { } }
control EgDeparser(packet_out pkt, inout hdrs_t h, in meta_t m,
                   in egress_intrinsic_metadata_for_deparser_t d) { apply { pkt.emit(h); } }
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
