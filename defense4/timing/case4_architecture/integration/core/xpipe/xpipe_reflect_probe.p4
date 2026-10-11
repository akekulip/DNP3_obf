/* G-VEPA reflection probe. NEVER DEPLOY. Non-DNP3 synthetic frames only.
 * Derived from xpipe_probe.p4 (same frame format, same per-port counters, same "NEVER DEPLOY"
 * discipline) with exactly one addition: a destination-MAC-keyed table, checked before the
 * original port-only table, that can reflect a frame back out its OWN ingress port instead of
 * routing it elsewhere.
 *
 * Purpose: case4_response_path.p4's Ingress.forwarding table (and every other Ingress forwarding
 * table in this codebase) keys only on ig.ingress_port, so it can never express "same port in,
 * same port out" -- any two hosts sharing one physical port (e.g. two Linux macvlan interfaces in
 * VEPA mode on one NIC) would, under that table alone, both match the single ig.ingress_port=9 row
 * and get sent toward whatever port that row names (today, the relay's port), never back to each
 * other. This probe tests, with inert synthetic frames only, whether a P4 table that also keys on
 * destination MAC can reflect frames between two specific addresses back out the port they arrived
 * on -- the mechanism the real forwarding rule would need if VEPA same-port reflection is to work.
 *
 * fwd_mac(ig.ingress_port, hdr.eth.dst): go_reflect(port) -> same semantics as xpipe_probe's
 *   go_egress, but intended for a destination that shares the arrival port. Checked FIRST; on a
 *   miss, falls back to the original fwd table unchanged (so any entry not specifically listed
 *   here gets exactly xpipe_probe's original behavior -- the "preserve existing forwarding"
 *   requirement, modeled here as "preserve the original probe's forwarding table untouched").
 * No DNP3 semantics, no authority state, model-only until a hardware gate explicitly approves it. */
#include <core.p4>
#include <tna.p4>

typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_E2E = 2;
const bit<16> PROBE_TYPE = 0x88b5;
const bit<8> PT_NORMAL = 1;
const bit<8> PT_MIRROR = 2;

header eth_h  { bit<48> dst; bit<48> src; bit<16> type; }
header pfx_h  { bit<32> epoch; bit<32> gen; bit<32> expected; bit<16> event; bit<16> reserved; }
header bridge_h { bit<8> pkt_type; bit<8> do_mir; bit<16> sid; }
header mirror_h { bit<8> pkt_type; }

struct headers_t { bridge_h bridge; pktgen_timer_header_t timer; eth_h eth; pfx_h pfx; }
struct meta_t { bit<8> pkt_type; MirrorId_t sid; bit<8> do_mir; }

parser IgParser(packet_in pkt, out headers_t hdr, out meta_t m, out ingress_intrinsic_metadata_t ig) {
  state start { pkt.extract(ig); pkt.advance(PORT_METADATA_SIZE); m.pkt_type = 0; m.sid = 0; m.do_mir = 0;
    transition select(pkt.lookahead<bit<8>>()) { 8w0x00: pgen; 8w0x08: pgen; 8w0x10: pgen; 8w0x18: pgen; default: eth; } }
  state pgen { pkt.extract(hdr.timer); transition eth; }
  state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { PROBE_TYPE: pfx; default: accept; } }
  state pfx { pkt.extract(hdr.pfx); transition accept; }
}

control Ingress(inout headers_t hdr, inout meta_t m, in ingress_intrinsic_metadata_t ig,
                in ingress_intrinsic_metadata_from_parser_t p, inout ingress_intrinsic_metadata_for_deparser_t md,
                inout ingress_intrinsic_metadata_for_tm_t tm) {
  /* Same observability counters as xpipe_probe.p4: per-port ingress/egress arrival counts let the
     negative-control test (drop the flow, confirm counters stop moving, restore, confirm they
     resume) correlate captures with real ASIC state, not just application-level success. */
  Register<bit<32>, bit<7>>(128, 0) arr_ig;
  RegisterAction<bit<32>, bit<7>, bit<32>>(arr_ig) count_ig = { void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; } };
  Register<bit<32>, bit<1>>(1, 0) seen_epoch;
  Register<bit<32>, bit<1>>(1, 0) seen_gen;
  RegisterAction<bit<32>, bit<1>, bit<32>>(seen_epoch) put_epoch = { void apply(inout bit<32> v, out bit<32> r) { v = hdr.pfx.epoch; r = v; } };
  RegisterAction<bit<32>, bit<1>, bit<32>>(seen_gen) put_gen = { void apply(inout bit<32> v, out bit<32> r) { v = hdr.pfx.gen; r = v; } };

  action deny() { md.drop_ctl = 3w1; }
  action go_bypass(PortId_t port) { tm.ucast_egress_port = port; tm.bypass_egress = 1w1; }
  action go_egress(PortId_t port, bit<8> do_mir, bit<16> sid) {
    tm.ucast_egress_port = port; tm.bypass_egress = 1w0;
    hdr.bridge.setValid(); hdr.bridge.pkt_type = PT_NORMAL; hdr.bridge.do_mir = do_mir; hdr.bridge.sid = sid; }
  action go_reflect(PortId_t port, bit<8> do_mir, bit<16> sid) {
    /* Identical semantics to go_egress -- a distinct name only so the dependency graph and
       table_summary make the reflection path visually distinct from the original probe's. */
    tm.ucast_egress_port = port; tm.bypass_egress = 1w0;
    hdr.bridge.setValid(); hdr.bridge.pkt_type = PT_NORMAL; hdr.bridge.do_mir = do_mir; hdr.bridge.sid = sid; }

  /* Original xpipe_probe forwarding table, byte-for-byte unchanged: preserved as the fallback for
     anything the new MAC-keyed table doesn't specifically name (models "preserve the relay's
     existing forwarding"). */
  table fwd { key = { ig.ingress_port : exact; } actions = { go_bypass; go_egress; deny; } size = 512; default_action = deny(); }

  /* New: the one addition this probe exists to test. Keyed on (arrival port, destination MAC) so
     two addresses sharing one physical port can be told apart and reflected back to each other,
     something ig.ingress_port alone can never express.

     default_action is NoAction, not deny(): a miss here must mean "not specifically handled by
     this table", falling through to fwd's own default (deny) -- not drop the packet itself. Using
     deny() as the default was tried first and found wrong on the model: deny() sets md.drop_ctl as
     a side effect even on a miss, and fwd's subsequent go_egress() never clears it, so a port with
     no fwd_mac entry at all would have its packets silently dropped regardless of what fwd.apply()
     decided. This is exactly the kind of table-interaction bug the real forwarding rule must not
     have, so it is recorded here rather than only fixed silently. */
  table fwd_mac {
    key = { ig.ingress_port : exact; hdr.eth.dst : exact; }
    actions = { go_reflect; NoAction; }
    size = 16;
    default_action = NoAction();
  }

  apply {
    count_ig.execute(ig.ingress_port[6:0]);
    if (hdr.pfx.isValid()) { put_epoch.execute(0); put_gen.execute(0); }
    bool mac_hit = false;
    if (hdr.eth.isValid()) {
      mac_hit = fwd_mac.apply().hit;
    }
    if (!mac_hit) {
      fwd.apply();
    }
  }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in ingress_intrinsic_metadata_for_deparser_t md) {
  apply { pkt.emit(hdr.bridge); pkt.emit(hdr.eth); pkt.emit(hdr.pfx); }
}

parser EgParser(packet_in pkt, out headers_t hdr, out meta_t m, out egress_intrinsic_metadata_t eg) {
  state start { pkt.extract(eg); m.pkt_type = 0; m.sid = 0; m.do_mir = 0; transition meta; }
  state meta { transition select(pkt.lookahead<mirror_h>().pkt_type) { PT_MIRROR: mirror_md; PT_NORMAL: bridged; default: accept; } }
  state bridged { pkt.extract(hdr.bridge); m.pkt_type = PT_NORMAL; m.do_mir = hdr.bridge.do_mir; m.sid = hdr.bridge.sid[9:0]; transition eth; }
  state mirror_md { mirror_h mm; pkt.extract(mm); m.pkt_type = PT_MIRROR; transition eth; }
  state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { PROBE_TYPE: pfx; default: accept; } }
  state pfx { pkt.extract(hdr.pfx); transition accept; }
}

control Egress(inout headers_t hdr, inout meta_t m, in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t p, inout egress_intrinsic_metadata_for_deparser_t md,
               inout egress_intrinsic_metadata_for_output_port_t port) {
  Register<bit<32>, bit<7>>(128, 0) arr_eg;
  RegisterAction<bit<32>, bit<7>, bit<32>>(arr_eg) count_eg = { void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; } };
  apply {
    if (m.pkt_type == PT_NORMAL) {
      count_eg.execute(eg.egress_port[6:0]);
    }
  }
}

control EgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {
  apply { pkt.emit(hdr.eth); pkt.emit(hdr.pfx); }
}

/* Single pipeline, broadcast across whatever physical pipes the conf's pipe_scope names -- this
   mirrors case4_response_path.p4's own working structure. The original xpipe_probe.p4's
   Switch(p0,p1,p2,p3) main declares 4 DISTINCT compiled pipeline binaries, each individually bound
   to its own physical pipe index; that failed to load on the real switch, which has only 2 physical
   pipes ("BF_DVM ERROR - ... Pipeline "p2" cannot be assigned to device 0 pipe 2, only 2 pipe(s)
   available", 2026-10-10). This test only needs dev_port 9 (pipe 0), so a single broadcast pipeline
   avoids the whole question. */
Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
