/* ACK-mode normalizer for Intel Tofino-1 (TNA) — standalone compile probe.
 *
 * Collapses the Case-A/Case-B ACK-mode fingerprint: suppress the OUTSTATION's standalone pure ACK
 * (payload-less, ACK-only, not SYN/FIN/RST) so a separate-ACK device (SEL-751) emits ONE observable
 * packet per response — the DNP3 RESPONSE, which re-ACKs — matching a combined-ACK device (ION7550).
 * Packet-bounded (no reassembly). Safe for the DNP3 request->ACK->response pattern within the CLRT
 * budget; a fully robust version needs light per-flow "response pending" state (see oracle_ackmode.py).
 */
#include <core.p4>
#include <tna.p4>

const bit<16> OUTSTATION_PORT = 20000;

header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ipv4_h { bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> total_len;
  bit<16> id; bit<3> flags; bit<13> frag_off; bit<8> ttl; bit<8> protocol;
  bit<16> hdr_csum; bit<32> src; bit<32> dst; }
header tcp_h { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack;
  bit<4> data_offset; bit<4> res; bit<8> flags; bit<16> window;
  bit<16> checksum; bit<16> urgent; }

struct headers_t { ethernet_h eth; ipv4_h ipv4; tcp_h tcp; }
struct ig_meta_t { bit<1> is_tcp; bit<16> tlen; bit<16> exp; }

parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t md,
                out ingress_intrinsic_metadata_t ig_md) {
    state start { pkt.extract(ig_md); pkt.advance(PORT_METADATA_SIZE); md = {0,0,0}; transition pe; }
    state pe { pkt.extract(hdr.eth);
        transition select(hdr.eth.etype){0x0800: pi; default: accept;} }
    state pi { pkt.extract(hdr.ipv4); md.tlen = hdr.ipv4.total_len;
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl, hdr.ipv4.flags, hdr.ipv4.frag_off){
            (6,5,0b010,0): pt; (6,5,0b000,0): pt; default: accept; } }
    state pt { pkt.extract(hdr.tcp); md.is_tcp = 1; transition accept; }
}

control Ingress(inout headers_t hdr, inout ig_meta_t md,
                in ingress_intrinsic_metadata_t ig_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm) {
    Counter<bit<64>, bit<2>>(4, CounterType_t.PACKETS) ctr;  /* 0 fwd 1 ack_suppressed 2 non_tcp */

    action set_exp(bit<16> v) { md.exp = v; }
    table t_exp {                                   /* header-only length per data_offset (payload==0 test) */
        key = { hdr.tcp.data_offset : exact; }
        actions = { set_exp; }
        const default_action = set_exp(0);
        const entries = { 5:set_exp(40); 6:set_exp(44); 7:set_exp(48); 8:set_exp(52);
                          9:set_exp(56); 10:set_exp(60); 11:set_exp(64); }
        size = 8;
    }
    apply {
        ig_tm.ucast_egress_port = (ig_md.ingress_port ^ 9w1);   /* pass-through */
        if (md.is_tcp == 1) {
            t_exp.apply();
            bit<1> from_out = 0; if (hdr.tcp.sport == OUTSTATION_PORT) { from_out = 1; }
            bit<1> no_payload = 0; if (md.tlen == md.exp) { no_payload = 1; }
            /* pure ACK: ACK set, no SYN/FIN/RST (mask 0x07), zero payload */
            bit<1> ack_only = 0; if ((hdr.tcp.flags & 0x10) != 0 && (hdr.tcp.flags & 0x07) == 0) { ack_only = 1; }
            if (from_out == 1 && no_payload == 1 && ack_only == 1) {
                ig_dprsr.drop_ctl = 1;              /* suppress the standalone ACK */
                ctr.count(1);
            } else { ctr.count(0); }
        } else { ctr.count(2); }
    }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_meta_t md,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr) {
    apply { pkt.emit(hdr.eth); pkt.emit(hdr.ipv4); pkt.emit(hdr.tcp); }
}

struct eg_meta_t {}
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t md,
                out egress_intrinsic_metadata_t eg_md){ state start { pkt.extract(eg_md); transition accept; } }
control Egress(inout headers_t hdr, inout eg_meta_t md, in egress_intrinsic_metadata_t eg_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport){ apply {} }
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t md,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr){ apply { pkt.emit(hdr); } }
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
