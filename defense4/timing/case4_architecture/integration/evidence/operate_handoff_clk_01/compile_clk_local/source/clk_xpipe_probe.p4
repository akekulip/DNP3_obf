/* T2-CLK-XPIPE probe (STEP2_DESIGN.md 1.2 and 5.1). NEVER DEPLOY. Synthetic non-DNP3 frames only.
 *
 * Question: N stamps t0q from global_tstamp in pipe 0; T compares it with its own global_tstamp in pipe 2
 * (read_queue_timing.p4 `md.now`). Is that one time base, so that T.now - N.t0q is only the N->T transit?
 *
 * Frame: Ethernet(type 0x88b6) + stamp header: path id, hop count, then eight {ingress_port16, global_tstamp48}
 * slots. Every ingress pass, in every pipe, writes slot[hop] and increments hop, then forwards by
 * (ingress_port, path, hop) with egress bypassed. The driver programs the paths (one hop each, same-pipe and
 * cross-pipe in both directions, plus N's real pass count: front port, three recirculations, then T_IN).
 * Identical logic per pipe, so a difference between two slots is the difference between two pipes' reads of
 * global_tstamp for one packet. Model execution says nothing about silicon timing. */
#include <core.p4>
#include <tna.p4>

const bit<16> STAMP_TYPE = 0x88b6;

header eth_h { bit<48> dst; bit<48> src; bit<16> type; }
header st_h {
  bit<8> path; bit<8> hop; bit<16> reserved;
  bit<16> p0; bit<48> t0; bit<16> p1; bit<48> t1; bit<16> p2; bit<48> t2; bit<16> p3; bit<48> t3;
  bit<16> p4; bit<48> t4; bit<16> p5; bit<48> t5; bit<16> p6; bit<48> t6; bit<16> p7; bit<48> t7;
}
struct headers_t { eth_h eth; st_h st; }
struct meta_t { bit<8> unused; }

parser IgParser(packet_in pkt, out headers_t hdr, out meta_t m, out ingress_intrinsic_metadata_t ig) {
  state start { pkt.extract(ig); pkt.advance(PORT_METADATA_SIZE); m.unused = 0; transition eth; }
  state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { STAMP_TYPE: st; default: accept; } }
  state st { pkt.extract(hdr.st); transition accept; }
}

control Ingress(inout headers_t hdr, inout meta_t m, in ingress_intrinsic_metadata_t ig,
                in ingress_intrinsic_metadata_from_parser_t p, inout ingress_intrinsic_metadata_for_deparser_t md,
                inout ingress_intrinsic_metadata_for_tm_t tm) {
  action deny() { md.drop_ctl = 3w1; }
  action go(PortId_t port) { tm.ucast_egress_port = port; tm.bypass_egress = 1w1; }
  // Keyed on the hop BEFORE this pass's stamp increments it.
  table fwd { key = { ig.ingress_port : exact; hdr.st.path : exact; hdr.st.hop : exact; }
              actions = { go; deny; } size = 64; default_action = deny(); }
  action s0() { hdr.st.p0 = (bit<16>)ig.ingress_port; hdr.st.t0 = p.global_tstamp; hdr.st.hop = 1; }
  action s1() { hdr.st.p1 = (bit<16>)ig.ingress_port; hdr.st.t1 = p.global_tstamp; hdr.st.hop = 2; }
  action s2() { hdr.st.p2 = (bit<16>)ig.ingress_port; hdr.st.t2 = p.global_tstamp; hdr.st.hop = 3; }
  action s3() { hdr.st.p3 = (bit<16>)ig.ingress_port; hdr.st.t3 = p.global_tstamp; hdr.st.hop = 4; }
  action s4() { hdr.st.p4 = (bit<16>)ig.ingress_port; hdr.st.t4 = p.global_tstamp; hdr.st.hop = 5; }
  action s5() { hdr.st.p5 = (bit<16>)ig.ingress_port; hdr.st.t5 = p.global_tstamp; hdr.st.hop = 6; }
  action s6() { hdr.st.p6 = (bit<16>)ig.ingress_port; hdr.st.t6 = p.global_tstamp; hdr.st.hop = 7; }
  action s7() { hdr.st.p7 = (bit<16>)ig.ingress_port; hdr.st.t7 = p.global_tstamp; hdr.st.hop = 8; }
  table stamp { key = { hdr.st.hop : exact; } actions = { s0; s1; s2; s3; s4; s5; s6; s7; NoAction; } size = 8;
                const default_action = NoAction();
                const entries = { 0: s0(); 1: s1(); 2: s2(); 3: s3(); 4: s4(); 5: s5(); 6: s6(); 7: s7(); } }
  apply {
    if (hdr.st.isValid()) { fwd.apply(); stamp.apply(); } else { deny(); }
  }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in ingress_intrinsic_metadata_for_deparser_t md) {
  apply { pkt.emit(hdr); }
}

parser EgParser(packet_in pkt, out headers_t hdr, out meta_t m, out egress_intrinsic_metadata_t eg) {
  state start { pkt.extract(eg); m.unused = 0; transition accept; }
}
control Egress(inout headers_t hdr, inout meta_t m, in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t p, inout egress_intrinsic_metadata_for_deparser_t md,
               inout egress_intrinsic_metadata_for_output_port_t port) { apply { } }
control EgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {
  apply { }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p0;
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p1;
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p2;
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p3;
Switch(p0, p1, p2, p3) main;
