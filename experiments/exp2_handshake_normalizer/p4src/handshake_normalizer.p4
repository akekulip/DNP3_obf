/* Standalone TCP handshake-header normalizer for Intel Tofino-1 (TNA).
 * Experiment 2B. Implements the reviewed Experiment 2A design.
 * Standalone: no Defense 4 import. Packet-bounded, stateless.
 *
 * Option region decomposed into non-overlapping sequential 4-byte pieces:
 *   o0 = first option (MSS, k0/l0/mss); e1..e5 = successive 4-byte extras,
 *   extracted cumulatively by data_offset (6..11). Normalization keeps o0
 *   (canonical MSS) and invalidates the extras, shrinking data_offset to 6.
 * Supported data_offset 5..11; anything else / IP options / non-atomic frag /
 * SYN payload / MSS-not-first / MD5/AO/unknown 2nd option -> FAIL OPEN.
 */
#include <core.p4>
#include <tna.p4>

const bit<16> PUBLIC_MSS = 1460;
const bit<16> PUBLIC_WINDOW = 16w8192;   /* canonical handshake window (all devices identical) */
const bit<8>  OPT_EOL=0; const bit<8> OPT_NOP=1; const bit<8> OPT_MSS=2;
const bit<8>  OPT_WS=3;  const bit<8> OPT_SACKOK=4; const bit<8> OPT_TS=8;

header ethernet_h { bit<48> dst; bit<48> src; bit<16> etype; }
header ipv4_h { bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> total_len;
  bit<16> id; bit<3> flags; bit<13> frag_off; bit<8> ttl; bit<8> protocol;
  bit<16> hdr_csum; bit<32> src; bit<32> dst; }
header tcp_h { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack;
  bit<4> data_offset; bit<4> res; bit<8> flags; bit<16> window;
  bit<16> checksum; bit<16> urgent; }
header opt0_h { bit<8> k0; bit<8> l0; bit<16> mss; }  /* first option (MSS) */
header ext_h  { bit<8> k; bit<24> r; }                /* a 4-byte extra */
header norm_h { bit<8> v; }                           /* marker (not emitted) */

struct headers_t {
    ethernet_h eth; ipv4_h ipv4; tcp_h tcp;
    opt0_h o0; ext_h e1; ext_h e2; ext_h e3; ext_h e4; ext_h e5;
    norm_h norm;
}
struct ig_meta_t {
    bit<16> orig_mss; bit<8> k0; bit<8> l0; bit<8> k1;
    bit<1> has_opts; bit<1> is_tcp; bit<16> outmss; bit<1> eligible;
    bit<16> tcp_pseudo_len; bit<1> pl; bit<16> tlen; bit<16> exp; bit<1> clampf;
}

parser IgParser(packet_in pkt, out headers_t hdr, out ig_meta_t md,
                out ingress_intrinsic_metadata_t ig_md) {
    state start { pkt.extract(ig_md); pkt.advance(PORT_METADATA_SIZE);
        md = {0,0,0,0,0,0,0,0,0,0,0,0,0}; transition pe; }
    state pe { pkt.extract(hdr.eth);
        transition select(hdr.eth.etype){0x0800: pi; default: accept;} }
    state pi { pkt.extract(hdr.ipv4); md.tlen = hdr.ipv4.total_len;
        /* TCP only for UNfragmented datagrams: ihl==5 (no IP options), offset 0,
         * and MF clear. A first fragment (MF=1, offset 0) must NOT be normalized
         * (its options may span fragments) -> fall through, forward, L3 only. */
        transition select(hdr.ipv4.protocol, hdr.ipv4.ihl, hdr.ipv4.flags, hdr.ipv4.frag_off){
            (6, 5, 0b010, 0): pt;   /* DF set, not fragmented */
            (6, 5, 0b000, 0): pt;   /* no DF, not fragmented */
            default: accept; } }
    state pt { pkt.extract(hdr.tcp); md.is_tcp=1;
        transition select(hdr.tcp.data_offset){
            6: po; 7: po; 8: po; 9: po; 10: po; 11: po; default: accept; } }
    state po { pkt.extract(hdr.o0); md.has_opts=1;
        md.k0=hdr.o0.k0; md.l0=hdr.o0.l0; md.orig_mss=hdr.o0.mss;
        transition select(hdr.tcp.data_offset){ 6: accept; default: pe1; } }
    state pe1 { pkt.extract(hdr.e1); md.k1=hdr.e1.k;
        transition select(hdr.tcp.data_offset){ 7: accept; default: pe2; } }
    state pe2 { pkt.extract(hdr.e2);
        transition select(hdr.tcp.data_offset){ 8: accept; default: pe3; } }
    state pe3 { pkt.extract(hdr.e3);
        transition select(hdr.tcp.data_offset){ 9: accept; default: pe4; } }
    state pe4 { pkt.extract(hdr.e4);
        transition select(hdr.tcp.data_offset){ 10: accept; default: pe5; } }
    state pe5 { pkt.extract(hdr.e5); transition accept; }
}

control Ingress(inout headers_t hdr, inout ig_meta_t md,
                in ingress_intrinsic_metadata_t ig_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm) {
    Counter<bit<64>, bit<4>>(16, CounterType_t.PACKETS) ctr;
    /* TCP-normalization OUTCOME per packet, mutually exclusive, counted ONCE
     * (bf-p4c turns each inline count() into an implicit table; multiple
     * non-exclusive count() sites sharing one Counter is rejected, and at scale
     * ICEs the backend):
     *  0 fwd_other/established_noopt  1 norm_syn  2 norm_syn_clamp
     *  3 synack_normalize  4 synack_normalize_clamp  5 synack_nonminimal_bypass
     *  6 syn_failopen  7 established_leak  9 security_opt_bypass
     * 10 syn_payload_bypass  11 tcp_unsupported_do (data_offset 12-15: TCP
     *    fail-open, header+payload byte-identical, counted explicitly).
     * Indices 1-4 are the only TCP-transforming outcomes; 5,6,7,9,10,11 are
     * TCP_NORM_FAIL_OPEN (TCP header untouched); 0 is plain forward. */
    Counter<bit<64>, bit<1>>(2, CounterType_t.PACKETS) ctr_l3;
    /* Independent L3-normalization record (applied to every IPv4 packet,
     * including TCP fail-open ones): 0 = ttl-only, 1 = ttl + atomic IP-ID zeroed.
     * This is L3_NORM_APPLIED, recorded separately from the TCP outcome so a
     * fail-open packet is never mislabelled "entirely unchanged". */
    action canon() {
        hdr.o0.k0 = OPT_MSS; hdr.o0.l0 = 4; hdr.o0.mss = md.outmss;
        hdr.e1.setInvalid(); hdr.e2.setInvalid(); hdr.e3.setInvalid();
        hdr.e4.setInvalid(); hdr.e5.setInvalid();
        hdr.tcp.data_offset = 6;
        hdr.tcp.window = PUBLIC_WINDOW;   /* canonicalize the handshake window (device residual) */
        hdr.ipv4.total_len = 44;
        hdr.norm.setValid(); hdr.norm.v = 1;
        md.tcp_pseudo_len = 24;
    }
    action nop() {}
    table t_norm {
        key = { md.eligible : exact; }
        actions = { canon; nop; }
        const default_action = nop();
        const entries = { 1 : canon(); }
        size = 2;
    }
    /* expected no-payload total_len per data_offset, as constants (no arithmetic
     * on the deparsed data_offset field, which the backend cannot lower) */
    action set_exp(bit<16> v) { md.exp = v; }
    table t_exp {
        key = { hdr.tcp.data_offset : exact; }
        actions = { set_exp; }
        const default_action = set_exp(0);
        const entries = { 5:set_exp(40); 6:set_exp(44); 7:set_exp(48); 8:set_exp(52);
                          9:set_exp(56); 10:set_exp(60); 11:set_exp(64); }
        size = 8;
    }
    /* MSS clamp uses a range match (a wide > in a gateway is not lowerable):
     * flag MSS > 1460 so it can be capped to the public MSS, never raised. */
    action set_clamp() { md.clampf = 1; }
    table t_clamp {
        key = { md.orig_mss : range; }
        actions = { set_clamp; nop; }
        const default_action = nop();
        const entries = { 1461 .. 65535 : set_clamp(); }
        size = 2;
    }
    apply {
        bool k1_safe = (md.k1==OPT_NOP || md.k1==OPT_EOL || md.k1==OPT_SACKOK
                        || md.k1==OPT_TS || md.k1==OPT_WS);
        ig_tm.ucast_egress_port = (ig_md.ingress_port ^ 9w1);
        bool ipv4 = hdr.ipv4.isValid();
        bool tcp  = (md.is_tcp==1);
        bool syn    = tcp && (hdr.tcp.flags & 0x02)!=0 && (hdr.tcp.flags & 0x10)==0;
        bool synack = tcp && (hdr.tcp.flags & 0x02)!=0 && (hdr.tcp.flags & 0x10)!=0;
        /* payload-presence computed in an ALU (ihl is always 5 here -> 20-byte IPv4),
         * NOT inside a gateway: total_len vs 20 + 4*data_offset. Embedding this
         * arithmetic in an if-condition exceeds the gateway PHV-input limit and, at
         * full nesting, ICEs bf-p4c 9.13.1 -- so it is reduced to a single bit. */
        t_exp.apply();                              /* md.exp = header-only length */
        t_clamp.apply();                            /* md.clampf = (orig_mss > 1460) */
        md.pl = 1;                                  /* payload present unless total_len */
        if (md.tlen == md.exp) { md.pl = 0; }       /* == expected header-only length */
        md.outmss = md.orig_mss;                    /* clamp: never raise, cap at public */
        if (md.clampf == 1) { md.outmss = PUBLIC_MSS; }
        /* Precompute every deep predicate as a 1-bit flag, each in its own simple
         * gateway. Nested if/else makes each leaf gateway carry the whole path
         * predicate; with wide fields (orig_mss, k0/l0) at depth that exceeds the
         * gateway PHV-input limit and ICEs. Testing only 1-bit flags keeps every
         * gateway tiny. */
        bit<1> mssff = 0; if (md.k0==OPT_MSS && md.l0==4) { mssff = 1; }
        bit<1> clamp = md.clampf;
        bit<1> do6 = 0;   if (hdr.tcp.data_offset == 6)   { do6 = 1; }
        bit<1> k1ok = 0;  if (k1_safe)                    { k1ok = 1; }
        /* data_offset 12-15: options not extracted by the parser (fall-through to
         * accept), so the TCP header + payload are byte-identical. Route to an
         * explicit unsupported outcome; never normalize. 4-bit compare, cheap. */
        bit<1> do_hi = 0; if (tcp && hdr.tcp.data_offset > 11) { do_hi = 1; }
        md.eligible = 0;
        bit<4> outc = 0;                                 /* fwd_other / established_noopt */
        if (do_hi == 1) { outc = 11; }                   /* tcp_unsupported_do (12-15) */
        else if (syn) {
            if (md.pl == 1) { outc = 10; }               /* syn_payload_bypass */
            else if (md.has_opts==0) { outc = 6; }       /* syn_failopen (no options) */
            else if (mssff==0) { outc = 6; }             /* MSS not first */
            else if (do6==0 && k1ok==0) { outc = 9; }    /* security_opt_bypass */
            else { md.eligible=1; outc = 1;              /* norm_syn */
                   if (clamp==1) { outc = 2; } }         /* norm_syn_clamp */
        } else if (synack) {
            /* Symmetric with the SYN path: strip the SYN-ACK options too. Safe because the
             * master's SYN was already stripped, so both ends consistently negotiate no
             * options (no window-scale desync). Only MSS-first with a safe 2nd option is
             * touched; MD5/AO/unknown 2nd option fails open. */
            if (md.has_opts==0) { outc = 5; }            /* no options -> nothing to canonicalize */
            else if (mssff==0) { outc = 5; }             /* MSS not first -> bypass */
            else if (do6==0 && k1ok==0) { outc = 5; }    /* unsafe 2nd option (MD5/AO) -> bypass */
            else { md.eligible=1; outc = 3;              /* synack_normalize (aggressive) */
                   if (clamp==1) { outc = 4; } }         /* synack_normalize_clamp */
        } else if (tcp && md.has_opts==1) { outc = 7; }  /* established_leak */
        ctr.count(outc);                                 /* single TCP-outcome count */
        t_norm.apply();                                  /* fires only for eligible==1 */
        /* L3 normalization: independent of the TCP decision, applied to every
         * IPv4 packet (fail-open packets included). Recorded separately. */
        bool atomic = (hdr.ipv4.flags==3w0b010 && hdr.ipv4.frag_off==0);
        if (ipv4) {
            hdr.ipv4.ttl = 64;
            bit<1> l3i = 0;
            if (atomic) { hdr.ipv4.id = 0; l3i = 1; }
            ctr_l3.count(l3i);                           /* L3_NORM_APPLIED, one count */
        }
    }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_meta_t md,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr) {
    Checksum() ipv4_csum; Checksum() tcp_csum;
    apply {
        hdr.ipv4.hdr_csum = ipv4_csum.update({hdr.ipv4.version, hdr.ipv4.ihl,
            hdr.ipv4.diffserv, hdr.ipv4.total_len, hdr.ipv4.id, hdr.ipv4.flags,
            hdr.ipv4.frag_off, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src,
            hdr.ipv4.dst});
        if (hdr.norm.isValid()) {
            hdr.tcp.checksum = tcp_csum.update({hdr.ipv4.src, hdr.ipv4.dst, 8w0,
                hdr.ipv4.protocol, md.tcp_pseudo_len, hdr.tcp.sport, hdr.tcp.dport,
                hdr.tcp.seq, hdr.tcp.ack, hdr.tcp.data_offset, hdr.tcp.res,
                hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgent,
                hdr.o0.k0, hdr.o0.l0, hdr.o0.mss});
        }
        pkt.emit(hdr.eth); pkt.emit(hdr.ipv4); pkt.emit(hdr.tcp);
        pkt.emit(hdr.o0); pkt.emit(hdr.e1); pkt.emit(hdr.e2);
        pkt.emit(hdr.e3); pkt.emit(hdr.e4); pkt.emit(hdr.e5);
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
Pipeline(IgParser(), Ingress(), IgDeparser(),
         EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
