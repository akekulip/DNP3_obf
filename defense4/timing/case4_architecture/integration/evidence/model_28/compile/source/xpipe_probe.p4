/* G-XPIPE probe (ticket S3-0). NEVER DEPLOY. Non-DNP3 synthetic frames only.
 * Frame: Ethernet(type 0x88b5) + 16-byte private prefix (epoch, generation, expected, event, reserved) + payload.
 * Every pipe runs the same logic through its own Pipeline instance (Switch(p0,p1,p2,p3) = pipes 0..3):
 *   - counts every ingress arrival per pipe-local port (arr_ig), every egress traversal per local port (arr_eg),
 *     every e2e-mirror copy seen in egress (arr_mir), and every pktgen-timer packet seen in ingress (pgen_arr);
 *   - latches the last prefix it saw (seen_*), so a hop that corrupts or drops the prefix is visible without a wire tap;
 *   - fwd(ingress_port): go_bypass(port)  -> straight to the port's pipe, egress bypassed (cross-pipe loopback hop)
 *                        go_egress(port,sid,mir) -> through the egress pipe of the egress port, optional e2e mirror clone.
 * No DNP3 semantics, no authority state. */
#include <core.p4>
#include <tna.p4>

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_E2E = 2;
const bit<16> PROBE_TYPE = 0x88b5;
const bit<8> PT_NORMAL = 1;
const bit<8> PT_MIRROR = 2;

header eth_h  { bit<48> dst; bit<48> src; bit<16> type; }
header pfx_h  { bit<32> epoch; bit<32> gen; bit<32> expected; bit<16> event; bit<16> reserved; }
header look_h { bit<96> a; bit<16> t1; bit<32> b; bit<16> t2; }
header bridge_h { bit<8> pkt_type; bit<8> do_mir; bit<16> sid; }
header mirror_h { bit<8> pkt_type; }

struct headers_t { bridge_h bridge; pktgen_timer_header_t timer; eth_h eth; pfx_h pfx; }
struct meta_t { bit<8> pkt_type; bit<16> sid; bit<8> do_mir; }

parser IgParser(packet_in pkt, out headers_t hdr, out meta_t m, out ingress_intrinsic_metadata_t ig) {
  state start { pkt.extract(ig); pkt.advance(PORT_METADATA_SIZE); m.pkt_type = 0; m.sid = 0; m.do_mir = 0;
    transition select(ig.ingress_port[6:0]) { 7w68: look; default: eth; } }
  state look { transition select(pkt.lookahead<look_h>().t1) { PROBE_TYPE: eth; default: pgen; } }
  state pgen { pkt.extract(hdr.timer); transition eth; }
  state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { PROBE_TYPE: pfx; default: accept; } }
  state pfx { pkt.extract(hdr.pfx); transition accept; }
}

control Ingress(inout headers_t hdr, inout meta_t m, in ingress_intrinsic_metadata_t ig,
                in ingress_intrinsic_metadata_from_parser_t p, inout ingress_intrinsic_metadata_for_deparser_t md,
                inout ingress_intrinsic_metadata_for_tm_t tm) {
  Register<bit<32>, bit<7>>(128, 0) arr_ig;
  RegisterAction<bit<32>, bit<7>, bit<32>>(arr_ig) count_ig = { void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; } };
  Register<bit<32>, bit<1>>(1, 0) pgen_arr;
  RegisterAction<bit<32>, bit<1>, bit<32>>(pgen_arr) count_pg = { void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; } };
  Register<bit<32>, bit<1>>(1, 0) seen_epoch;
  Register<bit<32>, bit<1>>(1, 0) seen_gen;
  Register<bit<32>, bit<1>>(1, 0) seen_expected;
  Register<bit<32>, bit<1>>(1, 0) seen_event;   /* event16 ++ reserved16 */
  RegisterAction<bit<32>, bit<1>, bit<32>>(seen_epoch) put_epoch = { void apply(inout bit<32> v, out bit<32> r) { v = hdr.pfx.epoch; r = v; } };
  RegisterAction<bit<32>, bit<1>, bit<32>>(seen_gen) put_gen = { void apply(inout bit<32> v, out bit<32> r) { v = hdr.pfx.gen; r = v; } };
  RegisterAction<bit<32>, bit<1>, bit<32>>(seen_expected) put_expected = { void apply(inout bit<32> v, out bit<32> r) { v = hdr.pfx.expected; r = v; } };
  RegisterAction<bit<32>, bit<1>, bit<32>>(seen_event) put_event = { void apply(inout bit<32> v, out bit<32> r) { v = hdr.pfx.event ++ hdr.pfx.reserved; r = v; } };
  action deny() { md.drop_ctl = 3w1; }
  action go_bypass(PortId_t port) { tm.ucast_egress_port = port; tm.bypass_egress = 1w1; }
  action go_egress(PortId_t port, bit<8> do_mir, bit<16> sid) {
    tm.ucast_egress_port = port; tm.bypass_egress = 1w0;
    hdr.bridge.setValid(); hdr.bridge.pkt_type = PT_NORMAL; hdr.bridge.do_mir = do_mir; hdr.bridge.sid = sid; }
  table fwd { key = { ig.ingress_port : exact; } actions = { go_bypass; go_egress; deny; } size = 512; default_action = deny(); }
  apply {
    count_ig.execute(ig.ingress_port[6:0]);
    if (hdr.timer.isValid()) { count_pg.execute(0); }
    if (hdr.pfx.isValid()) { put_epoch.execute(0); put_gen.execute(0); put_expected.execute(0); put_event.execute(0); }
    fwd.apply();
  }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in ingress_intrinsic_metadata_for_deparser_t md) {
  apply { pkt.emit(hdr.bridge); pkt.emit(hdr.eth); pkt.emit(hdr.pfx); }
}

parser EgParser(packet_in pkt, out headers_t hdr, out meta_t m, out egress_intrinsic_metadata_t eg) {
  state start { pkt.extract(eg); m.pkt_type = 0; m.sid = 0; m.do_mir = 0; transition meta; }
  state meta { transition select(pkt.lookahead<mirror_h>().pkt_type) { PT_MIRROR: mirror_md; PT_NORMAL: bridged; default: accept; } }
  state bridged { pkt.extract(hdr.bridge); m.pkt_type = PT_NORMAL; m.do_mir = hdr.bridge.do_mir; m.sid = hdr.bridge.sid; transition eth; }
  state mirror_md { mirror_h mm; pkt.extract(mm); m.pkt_type = PT_MIRROR; transition eth; }
  state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { PROBE_TYPE: pfx; default: accept; } }
  state pfx { pkt.extract(hdr.pfx); transition accept; }
}

control Egress(inout headers_t hdr, inout meta_t m, in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t p, inout egress_intrinsic_metadata_for_deparser_t md,
               inout egress_intrinsic_metadata_for_output_port_t port) {
  Register<bit<32>, bit<7>>(128, 0) arr_eg;
  RegisterAction<bit<32>, bit<7>, bit<32>>(arr_eg) count_eg = { void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; } };
  Register<bit<32>, bit<7>>(128, 0) arr_mir;
  RegisterAction<bit<32>, bit<7>, bit<32>>(arr_mir) count_mir = { void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; } };
  apply {
    if (m.pkt_type == PT_NORMAL) {
      count_eg.execute(eg.egress_port[6:0]);
      if (m.do_mir == 8w1) { md.mirror_type = MIRROR_E2E; }
    } else if (m.pkt_type == PT_MIRROR) {
      count_mir.execute(eg.egress_port[6:0]);
    }
  }
}

control EgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {
  Mirror() mirror;
  apply {
    if (md.mirror_type == MIRROR_E2E) { mirror.emit<mirror_h>(m.sid, { PT_MIRROR }); }
    pkt.emit(hdr.eth); pkt.emit(hdr.pfx);
  }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p0;
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p1;
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p2;
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) p3;
Switch(p0, p1, p2, p3) main;
