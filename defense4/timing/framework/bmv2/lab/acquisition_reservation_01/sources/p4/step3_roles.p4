/* BMv2 steps 2-3: parse and re-emit every header unchanged, classify the packet role, set a queue priority.
 * Supported profile: IPv4 without options, TCP with no options or the 12-byte timestamp option, DNP3 on port 20000.
 * Anything else is forwarded untouched and counted as unsupported. No checksum is recomputed because no field changes. */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETYPE_IPV4 = 0x0800;
const bit<16> DNP3_PORT = 20000;
const bit<9>  PORT_MASTER = 0;
const bit<9>  PORT_OUTSTATION = 1;

const bit<8> ROLE_OTHER = 0;
const bit<8> ROLE_TCP_ACK = 1;        /* pure ACK, no payload */
const bit<8> ROLE_READ_REQ = 2;
const bit<8> ROLE_SELECT_REQ = 3;
const bit<8> ROLE_OPERATE_REQ = 4;
const bit<8> ROLE_READ_RESP = 5;
const bit<8> ROLE_CONTROL_RESP = 6;
const bit<8> ROLE_UNSUPPORTED = 7;

header eth_t  { bit<48> dst; bit<48> src; bit<16> etype; }
header ipv4_t { bit<4> ver; bit<4> ihl; bit<8> tos; bit<16> len; bit<16> id; bit<16> frag; bit<8> ttl; bit<8> proto; bit<16> csum; bit<32> src; bit<32> dst; }
header tcp_t  { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack; bit<4> doff; bit<4> res; bit<8> flags; bit<16> win; bit<16> csum; bit<16> urg; }
header tcp_ts_t { bit<96> opt; }
header link_t { bit<16> start; bit<8> len; bit<8> ctrl; bit<16> dst; bit<16> src; bit<16> crc; }
header app_t  { bit<8> transport; bit<8> appctl; bit<8> func; }
header iin_t  { bit<16> iin; }
header obj_t  { bit<8> group; bit<8> variation; }

struct headers_t { eth_t eth; ipv4_t ip; tcp_t tcp; tcp_ts_t tcp_ts; link_t link; app_t app; iin_t iin; obj_t obj; }
struct meta_t { bit<16> rest; bit<8> role; bit<1> supported; }

parser P(packet_in pkt, out headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    state start { m.supported = 1; m.role = ROLE_OTHER; pkt.extract(h.eth);
        transition select(h.eth.etype) { ETYPE_IPV4: parse_ip; default: unsupported; } }
    state parse_ip { pkt.extract(h.ip);
        transition select(h.ip.ihl, h.ip.proto) { (5, 6): parse_tcp; default: unsupported; } }
    state parse_tcp { pkt.extract(h.tcp);
        transition select(h.tcp.doff) { 5: tcp_done; 8: parse_ts; default: unsupported; } }
    state parse_ts { pkt.extract(h.tcp_ts); transition tcp_done; }
    state tcp_done {
        m.rest = h.ip.len - (bit<16>)(((bit<16>)h.ip.ihl << 2) + ((bit<16>)h.tcp.doff << 2));
        transition select(h.tcp.sport, h.tcp.dport, m.rest) {
            (DNP3_PORT, _, 0): accept;
            (_, DNP3_PORT, 0): accept;
            (DNP3_PORT, _, _): parse_link;
            (_, DNP3_PORT, _): parse_link;
            default: accept; } }
    state parse_link { pkt.extract(h.link);
        transition select(h.link.start) { 0x0564: parse_app; default: unsupported; } }
    state parse_app { pkt.extract(h.app);
        transition select(h.app.func) { 0x81: parse_iin; default: parse_obj; } }
    state parse_iin { pkt.extract(h.iin); transition parse_obj; }
    state parse_obj { pkt.extract(h.obj); transition accept; }
    state unsupported { m.supported = 0; transition accept; }
}
control VC(inout headers_t h, inout meta_t m) { apply { } }
control Ing(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    counter(8, CounterType.packets) role_ctr;
    action fwd(bit<9> port) { sm.egress_spec = port; }
    action drop() { mark_to_drop(sm); }
    table dmac { key = { h.eth.dst : exact; } actions = { fwd; drop; } default_action = drop(); size = 16; }
    apply {
        if (m.supported == 0) { m.role = ROLE_UNSUPPORTED; }
        else if (h.tcp.isValid() && m.rest == 0 && (h.tcp.sport == DNP3_PORT || h.tcp.dport == DNP3_PORT)) { m.role = ROLE_TCP_ACK; }
        else if (h.app.isValid()) {
            if (h.app.func == 0x01) { m.role = ROLE_READ_REQ; }
            else if (h.app.func == 0x03) { m.role = ROLE_SELECT_REQ; }
            else if (h.app.func == 0x04) { m.role = ROLE_OPERATE_REQ; }
            else if (h.app.func == 0x81 && h.obj.group == 10) { m.role = ROLE_READ_RESP; }
            else if (h.app.func == 0x81 && h.obj.group == 12) { m.role = ROLE_CONTROL_RESP; }
        }
        role_ctr.count((bit<32>)m.role);
        dmac.apply();
        log_msg("role={} ingress_port={} len={}", { m.role, sm.ingress_port, sm.packet_length });
    }
}
control Egr(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) { apply { } }
control CC(inout headers_t h, inout meta_t m) { apply { } }
control Dep(packet_out pkt, in headers_t h) {
    apply { pkt.emit(h.eth); pkt.emit(h.ip); pkt.emit(h.tcp); pkt.emit(h.tcp_ts); pkt.emit(h.link); pkt.emit(h.app); pkt.emit(h.iin); pkt.emit(h.obj); }
}
V1Switch(P(), VC(), Ing(), Egr(), CC(), Dep()) main;
