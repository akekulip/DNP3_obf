/* Size Probe 1 — standalone Tofino-1 (TNA) compile probe for equal-length DNP3
 * READ-range normalization. Fixed-layout: TCP (no options) carrying a DNP3 READ
 * request with a single object header, qualifier 0x00 (8-bit start/stop).
 *
 * Mechanism: match a configured (group,var,qual) -> expand the stop byte to a
 * public superset (same width, frame length unchanged), recompute the DNP3 data-
 * block CRC with the native Tofino CRCPolynomial hash extern (candidate #1; the
 * key compile question), and recompute the TCP checksum. Fail open otherwise.
 *
 * DNP3 CRC-16: poly 0x3D65, init 0x0000, input+output reflected, xor-out 0xFFFF.
 */
#include <core.p4>
#include <tna.p4>

header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ipv4_h { bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> total_len;
  bit<16> id; bit<3> flags; bit<13> frag_off; bit<8> ttl; bit<8> protocol;
  bit<16> hdr_csum; bit<32> src; bit<32> dst; }
header tcp_h { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack;
  bit<4> data_offset; bit<4> res; bit<8> flags; bit<16> window;
  bit<16> checksum; bit<16> urgent; }
/* DNP3 link header (10 B incl. link CRC) */
header dnp3_link_h { bit<16> start; bit<8> len; bit<8> ctrl;
  bit<16> dst; bit<16> src; bit<16> lcrc; }
/* one CRC block: transport+app+object (8 B data) + block CRC (2 B) */
header dnp3_blk_h {
  bit<8> transport; bit<8> app_ctrl; bit<8> func;
  bit<8> group; bit<8> var; bit<8> qual; bit<8> rstart; bit<8> rstop;
  bit<16> bcrc;
}

struct headers_t { ethernet_h eth; ipv4_h ipv4; tcp_h tcp;
  dnp3_link_h dl; dnp3_blk_h db; }
struct ig_meta_t { bit<8> pub_stop; bit<1> eligible; bit<16> tcp_plen; }

parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t md,
                out ingress_intrinsic_metadata_t ig_md) {
    state start { pkt.extract(ig_md); pkt.advance(PORT_METADATA_SIZE);
        md = {0,0,0}; transition pe; }
    state pe { pkt.extract(hdr.eth);
        transition select(hdr.eth.etype){0x0800: pi; default: accept;} }
    state pi { pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl, hdr.ipv4.flags, hdr.ipv4.frag_off){
            (6,5,0b010,0): pt; (6,5,0b000,0): pt; default: accept; } }
    state pt { pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset){ 5: pdl; default: accept; } }
    state pdl { pkt.extract(hdr.dl);
        transition select(hdr.dl.start){ 0x0564: pdb; default: accept; } }
    state pdb { pkt.extract(hdr.db); transition accept; }
}

control Ingress(inout headers_t hdr, inout ig_meta_t md,
                in ingress_intrinsic_metadata_t ig_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm) {
    Counter<bit<64>, bit<2>>(4, CounterType_t.PACKETS) ctr;  /* 0 fwd 1 expanded 2 failopen */
    /* DNP3 CRC-16 via the native CRCPolynomial hash extern (candidate #1). The
     * Hash extern runs in the MAU, not the deparser. */
    CRCPolynomial<bit<16>>(16w0x3D65, true, false, false, 16w0x0000, 16w0xFFFF) dnp3_poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, dnp3_poly) dnp3_crc;

    action set_policy(bit<8> pub) { md.pub_stop = pub; md.eligible = 1; }
    action nop() {}
    /* configured (group,var,qual) -> public stop, with a RANGE match on the current
     * stop so we only ever EXPAND (rstop <= pub_stop): a request already reading past
     * the public range does not match and fails open. This keeps the "never shrink"
     * bound in TCAM instead of a variable-vs-variable gateway. qual 0x00 only here. */
    table t_policy {
        key = { hdr.db.group : exact; hdr.db.var : exact; hdr.db.qual : exact;
                hdr.db.rstop : range; }
        actions = { set_policy; nop; }
        const default_action = nop();
        const entries = {
            (30, 1, 0x00, 0..15) : set_policy(15);
            (1,  2, 0x00, 0..31) : set_policy(31);
        }
        size = 8;
    }
    apply {
        ig_tm.ucast_egress_port = ig_md.ingress_port;   /* pass-through / loopback */
        bool is_read = hdr.db.isValid() && hdr.db.func == 0x01;
        bit<2> outc = 0;
        if (is_read) {
            t_policy.apply();               /* range-matched: eligible only if rstop <= pub_stop */
            if (md.eligible == 1) {
                hdr.db.rstop = md.pub_stop;
                /* recompute the DNP3 block CRC over the 8 data bytes with the new stop.
                 * DNP3 appends the block CRC LOW-OCTET-FIRST; a bit<16> header field serializes
                 * MSB-first, so BYTE-SWAP the hash result before storing (H2). */
                bit<16> v = dnp3_crc.get({ hdr.db.transport, hdr.db.app_ctrl, hdr.db.func,
                    hdr.db.group, hdr.db.var, hdr.db.qual, hdr.db.rstart, hdr.db.rstop });
                hdr.db.bcrc = v[7:0] ++ v[15:8];
                md.tcp_plen = 40;               /* TCP segment length for the pseudo-header (H1) */
                outc = 1;
            } else { outc = 2; }
        }
        ctr.count(outc);
    }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_meta_t md,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr) {
    Checksum() ipv4_csum;
    Checksum() tcp_csum;
    apply {
        hdr.ipv4.hdr_csum = ipv4_csum.update({hdr.ipv4.version, hdr.ipv4.ihl,
            hdr.ipv4.diffserv, hdr.ipv4.total_len, hdr.ipv4.id, hdr.ipv4.flags,
            hdr.ipv4.frag_off, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src, hdr.ipv4.dst});
        /* TCP checksum recompute ONLY when we actually rewrote the request (H3): a fail-open or
         * non-DNP3 or multi-block packet has residual beyond the parsed prefix that Checksum()
         * cannot cover, so its original (valid) checksum must pass through untouched.
         * Pseudo-header now includes the 16-bit TCP length md.tcp_plen (H1). */
        if (md.eligible == 1) {
            hdr.tcp.checksum = tcp_csum.update({ hdr.ipv4.src, hdr.ipv4.dst, 8w0, hdr.ipv4.protocol,
                md.tcp_plen,
                hdr.tcp.sport, hdr.tcp.dport, hdr.tcp.seq, hdr.tcp.ack,
                hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgent,
                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.lcrc,
                hdr.db.transport, hdr.db.app_ctrl, hdr.db.func, hdr.db.group, hdr.db.var,
                hdr.db.qual, hdr.db.rstart, hdr.db.rstop, hdr.db.bcrc });
        }
        pkt.emit(hdr.eth); pkt.emit(hdr.ipv4); pkt.emit(hdr.tcp);
        pkt.emit(hdr.dl); pkt.emit(hdr.db);
    }
}

struct eg_meta_t {}
parser EgParser(packet_in pkt, out headers_t hdr, out eg_meta_t md,
                out egress_intrinsic_metadata_t eg_md){
    state start { pkt.extract(eg_md); transition accept; } }
control Egress(inout headers_t hdr, inout eg_meta_t md,
               in egress_intrinsic_metadata_t eg_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport){ apply {} }
control EgDeparser(packet_out pkt, inout headers_t hdr, in eg_meta_t md,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr){
    apply { pkt.emit(hdr); } }
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
