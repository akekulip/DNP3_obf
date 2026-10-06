/* Case 4 BMv2/v1model emulator. This is not a Tofino queue implementation.
 * Real packets recirculate through port 2 -> 3; token-count gating and direct
 * eligibility checks emulate holding. A separate internal service packet on
 * port 4 enforces absolute 30 ms readiness and post-gap completion cleanup.
 * BMv2 uses 48-bit microseconds and a 1 ms service period; the Tofino candidate
 * requests 100 us and uses masked low-32 nanoseconds. Observed service spacing
 * and wire captures are evidence; a configured period is not a wall-clock bound.
 *
 * Supported complete-frame profiles: READ20/response49, control35/response37,
 * and one SELECT/OPERATE pair expanded 35 -> 55 with response57 -> [28,29].
 * Decoy201/body100ms is an isolated codec fixture, never a physical inert-point
 * assertion. Source checks link CRCs, IP/TCP checksums, tuple/application/TCP
 * position. Two committed 440-bit images support whole/partial/overlapping
 * retransmission replay inside their native spans; initial segmented controls,
 * conflicting overlaps and spans extending outside the cache are unsupported.
 * No SACK, scaling or timestamp negotiation is admitted for insertion; records
 * persist through FIN/RST translation and retire at a new SYN after closure.
 *
 * Mode4 is the Case4 timing policy. Historical modes2/3 and DA=0 remain for
 * explanation-only compatibility, with no new campaign or generation claim.
 */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETYPE_IPV4 = 0x0800;
const bit<16> ETYPE_HELD = 0x88C3;
const bit<16> ETYPE_HEARTBEAT = 0x88B6;
const bit<16> ETYPE_BLK  = 0x88B5;
const bit<16> DNP3_PORT  = 20000;
const bit<9> PORT_MASTER = 0;
const bit<9> PORT_OUT = 1;
const bit<9> PORT_LOOP_TX = 2;
const bit<9> PORT_LOOP_RX = 3;
const bit<32> MIRROR_SESSION = 100;
const bit<8> KIND_ACK = 1;
const bit<8> KIND_RESP = 2;

header eth_t  { bit<48> dst; bit<48> src; bit<16> etype; }
header shim_t { bit<8> kind; bit<16> orig; bit<32> owner; }
header blk_t  { bit<8> slot; bit<32> budget; bit<32> owner; }
header ipv4_t { bit<4> ver; bit<4> ihl; bit<8> tos; bit<16> len; bit<16> id; bit<16> frag; bit<8> ttl; bit<8> proto; bit<16> csum; bit<32> src; bit<32> dst; }
header tcp_t  { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack; bit<4> doff; bit<4> res; bit<8> flags; bit<16> win; bit<16> csum; bit<16> urg; }
header tcp_mss_t { bit<32> opt; }
header tcp_ts_t { bit<96> opt; }
header link_t { bit<16> start; bit<8> len; bit<8> ctrl; bit<16> dst; bit<16> src; bit<16> crc; }
header app_t  { bit<8> transport; bit<8> appctl; bit<8> func; }
header iin_t  { bit<16> iin; }
header obj_t  { bit<8> group; bit<8> variation; }
header cache_image_t { bit<440> data; }
header read_tail_t { bit<24> data; bit<16> crc; }
header req_a_t { bit<88> data; bit<16> crc; }
header req_b_t { bit<40> data; }
header req_crc_t { bit<16> crc; }
header insert_a_t { bit<88> data; }
header insert_b_t { bit<56> data; bit<16> crc; }
header extra_t { bit<64> b; }
header control_tail_t { bit<72> b; }
header rest_a_t { bit<88> b; }      /* payload bytes 17..27 of an eligible 49-byte response */
header pl2_t  { bit<168> b; }       /* payload bytes 28..48 */

struct headers_t { eth_t eth; shim_t shim; blk_t blk; ipv4_t ip; tcp_t tcp; tcp_ts_t tcp_ts; tcp_mss_t tcp_mss; link_t link; app_t app; iin_t iin; obj_t obj; rest_a_t rest_a; pl2_t pl2; read_tail_t read_tail; req_a_t req_a; req_b_t req_b; req_crc_t req_b_crc; insert_a_t insert_a; insert_b_t insert_b; extra_t extra; control_tail_t control_tail; cache_image_t replay1; cache_image_t replay2; }
struct meta_t { bit<16> rest; bit<1> frame_ok; bit<1> rewritten; bit<32> old_seq; bit<32> old_ack; bit<16> old_win; bit<1> supported; bit<1> held; bit<1> carved; bit<8> rid; @field_list(1) bit<32> owner; bit<16> ptcp_len; }

parser P(packet_in pkt, out headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    state start { m.frame_ok = 0; m.rewritten = 0; m.supported = 1; m.rest = 0; m.held = 0; m.carved = 0; m.rid = 0; m.ptcp_len = 0; pkt.extract(h.eth);
        transition select(h.eth.etype) { ETYPE_IPV4: parse_ip; ETYPE_HELD: parse_shim; ETYPE_BLK: parse_blk; ETYPE_HEARTBEAT: accept; default: unsupported; } }
    state parse_shim { pkt.extract(h.shim); transition parse_ip; }
    state parse_blk { pkt.extract(h.blk); transition accept; }
    state parse_ip { pkt.extract(h.ip);
        transition select(h.ip.ihl, h.ip.proto) { (5, 6): parse_tcp; default: unsupported; } }
    state parse_tcp { pkt.extract(h.tcp);
        transition select(h.tcp.doff) { 5: tcp_done; 6: parse_mss; 8: parse_ts; default: unsupported; } }
    state parse_mss { pkt.extract(h.tcp_mss); transition tcp_done; }
    state parse_ts { pkt.extract(h.tcp_ts); transition tcp_done; }
    state tcp_done {
        m.ptcp_len = h.ip.len - 20;
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
    state parse_obj { pkt.extract(h.obj); transition select(h.app.func, m.rest) {
        (1, 20): parse_read; (3, 35): parse_request; (4, 35): parse_request;
        (0x81, 37): parse_control_response; (0x81, 49): parse_rest_a; (0x81, 57): parse_rest_a;
        default: accept; } }
    state parse_read { pkt.extract(h.read_tail); transition accept; }
    state parse_request { pkt.extract(h.req_a); pkt.extract(h.req_b); pkt.extract(h.req_b_crc); transition accept; }
    state parse_control_response { pkt.extract(h.rest_a); pkt.extract(h.control_tail); transition accept; }
    state parse_rest_a { pkt.extract(h.rest_a); pkt.extract(h.pl2); transition select(m.rest) { 57: parse_extra; default: accept; } }
    state parse_extra { pkt.extract(h.extra); transition accept; }
    state unsupported { m.supported = 0; transition accept; }
}
control VC(inout headers_t h, inout meta_t m) { apply {
    verify_checksum(h.ip.isValid() && h.ip.ihl == 5 && !h.shim.isValid(), {h.ip.ver,h.ip.ihl,h.ip.tos,h.ip.len,h.ip.id,h.ip.frag,h.ip.ttl,h.ip.proto,h.ip.src,h.ip.dst},h.ip.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && !h.link.isValid() && !h.tcp_ts.isValid() && !h.tcp_mss.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && !h.link.isValid() && h.tcp_ts.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_ts.opt},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.read_tail.isValid() && !h.tcp_ts.isValid() && !h.tcp_mss.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.obj.group,h.obj.variation,h.read_tail.data,h.read_tail.crc},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.read_tail.isValid() && h.tcp_ts.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_ts.opt,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.obj.group,h.obj.variation,h.read_tail.data,h.read_tail.crc},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.req_a.isValid() && !h.tcp_ts.isValid() && !h.tcp_mss.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.obj.group,h.obj.variation,h.req_a.data,h.req_a.crc,h.req_b.data,h.req_b_crc.crc},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.req_a.isValid() && h.tcp_ts.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_ts.opt,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.obj.group,h.obj.variation,h.req_a.data,h.req_a.crc,h.req_b.data,h.req_b_crc.crc},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.control_tail.isValid() && !h.tcp_ts.isValid() && !h.tcp_mss.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.iin.iin,h.obj.group,h.obj.variation,h.rest_a.b,h.control_tail.b},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.control_tail.isValid() && h.tcp_ts.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_ts.opt,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.iin.iin,h.obj.group,h.obj.variation,h.rest_a.b,h.control_tail.b},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.pl2.isValid() && !h.extra.isValid() && !h.tcp_ts.isValid() && !h.tcp_mss.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.iin.iin,h.obj.group,h.obj.variation,h.rest_a.b,h.pl2.b},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.pl2.isValid() && !h.extra.isValid() && h.tcp_ts.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_ts.opt,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.iin.iin,h.obj.group,h.obj.variation,h.rest_a.b,h.pl2.b},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.extra.isValid() && !h.tcp_ts.isValid() && !h.tcp_mss.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.iin.iin,h.obj.group,h.obj.variation,h.rest_a.b,h.pl2.b,h.extra.b},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp.isValid() && !h.shim.isValid() && h.extra.isValid() && h.tcp_ts.isValid(), {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_ts.opt,h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.iin.iin,h.obj.group,h.obj.variation,h.rest_a.b,h.pl2.b,h.extra.b},h.tcp.csum,HashAlgorithm.csum16);
    verify_checksum_with_payload(h.tcp_mss.isValid() && !h.link.isValid(),{h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_mss.opt},h.tcp.csum,HashAlgorithm.csum16);
} }

control Ing(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    /* policy parameters, written by the control plane */
    register<bit<8>>(1) p_padding;
    register<bit<8>>(1) l_closed; register<bit<32>>(1) l_syn; register<bit<8>>(1) l_count; register<bit<8>>(1) l_excluded;
    register<bit<32>>(1) l_base; register<bit<32>>(1) l_second;
    register<bit<440>>(2) l_image; register<bit<24>>(2) l_app; register<bit<88>>(1) l_objects_a; register<bit<40>>(1) l_objects_b;
    register<bit<32>>(1) l_src; register<bit<32>>(1) l_dst; register<bit<16>>(1) l_sport;
    register<bit<32>>(1) r_src; register<bit<32>>(1) r_dst; register<bit<16>>(1) r_sport; register<bit<32>>(1) r_resp_seq; register<bit<8>>(1) r_request_func;
    register<bit<48>>(1) p_readiness_us; register<bit<8>>(1) p_token_loss;
    register<bit<48>>(1) p_da_us;  register<bit<48>>(1) p_gap_us;  register<bit<32>>(1) p_budget;  register<bit<8>>(1) p_mode;  register<bit<8>>(1) p_shape;  register<bit<8>>(1) p_dropreq;  register<bit<8>>(1) r_dropped;
    /* transaction state */
    register<bit<8>>(1)  r_armed;   register<bit<32>>(1) r_expect_ack;  register<bit<8>>(1) r_app;
    register<bit<48>>(1) r_t0;      register<bit<48>>(1) r_deadline;     register<bit<8>>(1) r_resp_seen;
    register<bit<8>>(1)  r_ack_held; register<bit<8>>(1) r_ack_seen;
    register<bit<8>>(1) r_ack_released;
    register<bit<8>>(1)  r_tresp_armed; register<bit<48>>(1) r_tresp;
    register<bit<8>>(1)  r_live_ack; register<bit<8>>(1) r_live_resp;
    /* evidence */
    register<bit<48>>(1) r_hb_last; register<bit<48>>(1) r_hb_max_gap; register<bit<32>>(1) r_hb_count;
    register<bit<48>>(256) r_history; register<bit<8>>(32) r_history_state; register<bit<32>>(1) r_txn;
    register<bit<48>>(8) r_ev;       /* 0 t0, 1 ack release, 2 resp release, 3 ack arrival, 4 resp arrival, 5 tmo */
    counter(16, CounterType.packets) outcome;

    bit<8> lc; bit<32> base; bit<32> second; bit<32> src; bit<32> dst; bit<16> sport; bit<32> response_seq;
    bit<32> txn; bit<32> event_base;
    bit<8> armed; bit<8> mode; bit<48> now; bit<32> expect; bit<8> app; bit<8> request_func; bit<8> live_a; bit<8> live_r;
    bit<8> token_loss; bit<8> shape; bit<8> dropreq; bit<8> dropped; bit<8> seen; bit<8> ack_held; bit<8> tr_armed; bit<48> tr; bit<48> dl; bit<32> budget;

    action native_offset(in bit<32> wire, out bit<32> native) {
        native = wire;
        if (lc == 2 && wire >= second + 20) {
            if (wire < second + 40) { native = second + 20; } else { native = wire - 20; }
        }
        if (native >= 35) {
            if (native < 55) { native = 35; } else { native = native - 20; }
        }
    }
    /* Dispatch CRC work by the parser's complete-frame profile. Conditional
     * action calls are v1model-compatible; conditional hash calls inside one
     * action are not. Unsupported headers are never fed to CRC calculations. */
    action check_header() {
        bit<16> crc;
        hash(crc,HashAlgorithm.crc16_custom,16w0,{h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src},32w65536);
        if (h.link.crc == (crc[7:0] ++ crc[15:8]) && (h.app.transport & 0xc0) == 0xc0 && (h.app.appctl & 0xf0) == 0xc0) { m.frame_ok = 1; }
    }
    action check_read() {
        bit<16> crc;
        hash(crc,HashAlgorithm.crc16_custom,16w0,{h.app.transport,h.app.appctl,h.app.func,h.obj.group,h.obj.variation,h.read_tail.data},32w65536);
        if (h.link.len != 13 || h.obj.group != 10 || h.obj.variation != 2 || h.read_tail.crc != (crc[7:0] ++ crc[15:8])) { m.frame_ok = 0; }
    }
    action check_control_request() {
        bit<16> a; bit<16> b;
        hash(a,HashAlgorithm.crc16_custom,16w0,{h.app.transport,h.app.appctl,h.app.func,h.obj.group,h.obj.variation,h.req_a.data},32w65536);
        hash(b,HashAlgorithm.crc16_custom,16w0,{h.req_b.data},32w65536);
        if (h.link.len != 26 || h.obj.group != 12 || h.obj.variation != 1 || h.req_a.data[87:64] != 0x280100 || h.req_b.data[7:0] != 0 || h.req_a.crc != (a[7:0] ++ a[15:8]) || h.req_b_crc.crc != (b[7:0] ++ b[15:8])) { m.frame_ok = 0; }
    }
    action check_response_first_block() {
        bit<16> crc;
        hash(crc,HashAlgorithm.crc16_custom,16w0,{h.app.transport,h.app.appctl,h.app.func,h.iin.iin,h.obj.group,h.obj.variation,h.rest_a.b[87:16]},32w65536);
        if (h.rest_a.b[15:0] != (crc[7:0] ++ crc[15:8])) { m.frame_ok = 0; }
    }
    action check_control_response() {
        bit<16> crc;
        hash(crc,HashAlgorithm.crc16_custom,16w0,{h.control_tail.b[71:16]},32w65536);
        if (h.link.len != 28 || h.obj.group != 12 || h.obj.variation != 1 || h.control_tail.b[15:0] != (crc[7:0] ++ crc[15:8])) { m.frame_ok = 0; }
    }
    action check_read_response() {
        bit<16> b; bit<16> c;
        hash(b,HashAlgorithm.crc16_custom,16w0,{h.pl2.b[167:40]},32w65536);
        hash(c,HashAlgorithm.crc16_custom,16w0,{h.pl2.b[23:16]},32w65536);
        if (h.link.len != 38 || h.obj.group != 10 || h.obj.variation != 2 || h.pl2.b[39:24] != (b[7:0] ++ b[15:8]) || h.pl2.b[15:0] != (c[7:0] ++ c[15:8])) { m.frame_ok = 0; }
    }
    action check_padded_response() {
        bit<16> b; bit<16> c;
        hash(b,HashAlgorithm.crc16_custom,16w0,{h.pl2.b[167:40]},32w65536);
        hash(c,HashAlgorithm.crc16_custom,16w0,{h.pl2.b[23:0],h.extra.b[63:16]},32w65536);
        if (h.link.len != 46 || h.obj.group != 12 || h.obj.variation != 1 || h.pl2.b[39:24] != (b[7:0] ++ b[15:8]) || h.extra.b[15:0] != (c[7:0] ++ c[15:8])) { m.frame_ok = 0; }
    }
    action insert_decoy() {
        bit<16> crc;
        h.insert_a.setValid(); h.insert_a.data = 0x0c01280100c90001016400;
        h.insert_b.setValid(); h.insert_b.data = 0x00006400000000;
        h.link.len = 44; h.ip.len = h.ip.len + 20; m.rest = 55; m.rewritten = 1;
        hash(crc,HashAlgorithm.crc16_custom,16w0,{h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src},32w65536);
        h.link.crc = crc[7:0] ++ crc[15:8];
        hash(crc,HashAlgorithm.crc16_custom,16w0,{h.req_b.data,h.insert_a.data},32w65536);
        h.req_b_crc.crc = crc[7:0] ++ crc[15:8];
        hash(crc,HashAlgorithm.crc16_custom,16w0,{h.insert_b.data},32w65536);
        h.insert_b.crc = crc[7:0] ++ crc[15:8];
    }
    action fwd(bit<9> port) { sm.egress_spec = port; }
    action drop() { mark_to_drop(sm); }
    table dmac { key = { h.eth.dst : exact; } actions = { fwd; drop; } default_action = drop(); size = 16; }

    action to_loop() { sm.egress_spec = PORT_LOOP_TX; m.held = 1; }
    action split_to_master() { sm.mcast_grp = 2; }
    action release_to_master() { h.eth.etype = h.shim.orig; h.shim.setInvalid(); sm.egress_spec = PORT_MASTER; }

    action finish_transaction() {
        r_armed.write(0, 0); r_resp_seen.write(0, 0); r_ack_held.write(0, 0); r_ack_seen.write(0, 0);
        r_ack_released.write(0, 0); r_tresp_armed.write(0, 0); r_live_ack.write(0, 0); r_live_resp.write(0, 0);
    }
    action arm_response_deadline() {
        bit<48> gap; p_gap_us.read(gap, 0);
        r_tresp.write(0, now + gap); r_tresp_armed.write(0, 1);
    }

    apply {
        now = sm.ingress_global_timestamp;
        m.old_seq = h.tcp.seq; m.old_ack = h.tcp.ack; m.old_win = h.tcp.win;
        if (h.shim.isValid() && sm.ingress_port == PORT_LOOP_RX) { m.frame_ok = 1; }
        if (sm.checksum_error == 0 && !h.shim.isValid() && h.link.isValid() && h.app.isValid() && h.obj.isValid() && m.supported == 1 && (h.ip.frag & 0x3fff) == 0 && (h.tcp.flags & 0x16) == 0x10) {
            check_header();
            if (m.frame_ok == 1) {
                if (h.read_tail.isValid()) { check_read(); }
                else if (h.req_a.isValid() && h.req_b.isValid() && h.req_b_crc.isValid()) { check_control_request(); }
                else if (h.rest_a.isValid() && h.iin.isValid()) {
                    check_response_first_block();
                    if (h.control_tail.isValid()) { check_control_response(); }
                    else if (h.pl2.isValid() && h.extra.isValid()) { check_padded_response(); }
                    else if (h.pl2.isValid()) { check_read_response(); }
                    else { m.frame_ok = 0; }
                } else { m.frame_ok = 0; }
            }
        }
        lc = 0; base = 0; second = 0; src = 0; dst = 0; sport = 0; response_seq = 0; request_func = 0;
        if (h.tcp.isValid() && !h.blk.isValid()) { l_count.read(lc,0); l_base.read(base,0); l_second.read(second,0); }
        r_armed.read(armed, 0); p_mode.read(mode, 0); r_txn.read(txn, 0); event_base = ((txn - 1) & 31) * 8;
        token_loss = 0; if (h.blk.isValid()) { p_token_loss.read(token_loss, 0); }
        if (h.tcp.isValid() && (sm.ingress_port == PORT_OUT || (h.tcp.flags & 5) != 0)) { r_src.read(src,0); r_dst.read(dst,0); r_sport.read(sport,0); r_resp_seq.read(response_seq,0); r_request_func.read(request_func,0); }
        dmac.apply();                                            /* default forwarding; branches below override it */

        if (h.tcp.isValid() && !h.shim.isValid() && !h.blk.isValid() && sm.ingress_port == PORT_MASTER) {
            bit<8> padding; bit<8> excluded; bit<32> ls; bit<32> ld; bit<16> lp;
            p_padding.read(padding,0); l_excluded.read(excluded,0);
            l_src.read(ls,0); l_dst.read(ld,0); l_sport.read(lp,0);
            bit<8> closed; bit<32> syn_seq; l_closed.read(closed,0); l_syn.read(syn_seq,0);
            if ((h.tcp.flags & 5) != 0 && h.ip.src == ls && h.ip.dst == ld && h.tcp.sport == lp && h.tcp.dport == DNP3_PORT) { l_closed.write(0,1); }
            if ((h.tcp.flags & 2) != 0 && (lc == 0 || (closed == 1 && h.tcp.seq != syn_seq))) {
                lc = 0; l_count.write(0,0); l_closed.write(0,0); l_syn.write(0,h.tcp.seq);
                /* MSS-only SYN is supported. SACK/window scale/timestamp negotiation excludes insertion. */
                excluded = (h.tcp.doff == 5 || (h.tcp.doff == 6 && h.tcp_mss.opt[31:16] == 0x0204)) ? (bit<8>)0 : (bit<8>)1;
                l_excluded.write(0,excluded); l_src.write(0,h.ip.src); l_dst.write(0,h.ip.dst); l_sport.write(0,h.tcp.sport);
                ls = h.ip.src; ld = h.ip.dst; lp = h.tcp.sport;
            }
            if (sm.checksum_error == 0 && !h.replay1.isValid() && lc != 0 && h.ip.src == ls && h.ip.dst == ld && h.tcp.sport == lp && h.tcp.dport == DNP3_PORT && m.rest != 0 && h.tcp.doff == 5 && !h.tcp_ts.isValid()) {
                bit<32> offset = h.tcp.seq - base; bit<32> end = offset + (bit<32>)m.rest;
                bit<1> first_overlap = (offset < 35 && end > 0) ? (bit<1>)1 : (bit<1>)0;
                bit<1> second_overlap = (lc == 2 && offset < second && end > second - 35) ? (bit<1>)1 : (bit<1>)0;
                if (offset < 0x80000000 && end <= ((lc == 2) ? second : (bit<32>)35) && (first_overlap == 1 || second_overlap == 1)) {
                    /* TCP may trim duplicate prefix bytes; replay the exact committed stream image. */
                    h.replay1.setValid();
                    if (first_overlap == 1) { l_image.read(h.replay1.data,0); h.tcp.seq = base; }
                    else { l_image.read(h.replay1.data,1); h.tcp.seq = base + second - 15; }
                    m.rest = 55;
                    if (first_overlap == 1 && second_overlap == 1) { h.replay2.setValid(); l_image.read(h.replay2.data,1); m.rest = 110; }
                    h.ip.len = 40 + m.rest; m.rewritten = 1;
                    h.link.setInvalid(); h.app.setInvalid(); h.iin.setInvalid(); h.obj.setInvalid(); h.read_tail.setInvalid();
                    h.req_a.setInvalid(); h.req_b.setInvalid(); h.req_b_crc.setInvalid(); h.rest_a.setInvalid(); h.pl2.setInvalid(); h.extra.setInvalid(); h.control_tail.setInvalid();
                    truncate((bit<32>)h.ip.len + 14);
                }
            }
            if (!h.replay1.isValid() && padding == 1 && excluded == 0 && h.ip.src == ls && h.ip.dst == ld && h.tcp.sport == lp && h.tcp.dport == DNP3_PORT && h.tcp.doff == 5 && h.link.isValid() && h.app.isValid() && h.obj.isValid() && h.req_a.isValid() && h.req_b.isValid() && h.req_b_crc.isValid() && m.frame_ok == 1 && h.req_a.data[63:48] != 0xc900) {
                bit<88> oa; bit<40> ob; bit<24> previous; bit<24> current;
                l_objects_a.read(oa,0); l_objects_b.read(ob,0); current = h.app.transport ++ h.app.appctl ++ h.app.func;
                if (lc == 0 && h.app.func == 3) {
                    base = h.tcp.seq; l_base.write(0,base); l_count.write(0,1);
                    l_objects_a.write(0,h.req_a.data); l_objects_b.write(0,h.req_b.data); l_app.write(0,current);
                    insert_decoy();
                    l_image.write(0,h.link.start ++ h.link.len ++ h.link.ctrl ++ h.link.dst ++ h.link.src ++ h.link.crc ++ h.app.transport ++ h.app.appctl ++ h.app.func ++ h.obj.group ++ h.obj.variation ++ h.req_a.data ++ h.req_a.crc ++ h.req_b.data ++ h.insert_a.data ++ h.req_b_crc.crc ++ h.insert_b.data ++ h.insert_b.crc);
                } else if (lc == 1 && h.app.func == 4 && h.req_a.data == oa && h.req_b.data == ob) {
                    second = h.tcp.seq - base + 35; l_second.write(0,second); l_count.write(0,2); l_app.write(1,current);
                    insert_decoy();
                    l_image.write(1,h.link.start ++ h.link.len ++ h.link.ctrl ++ h.link.dst ++ h.link.src ++ h.link.crc ++ h.app.transport ++ h.app.appctl ++ h.app.func ++ h.obj.group ++ h.obj.variation ++ h.req_a.data ++ h.req_a.crc ++ h.req_b.data ++ h.insert_a.data ++ h.req_b_crc.crc ++ h.insert_b.data ++ h.insert_b.crc);
                } else if (lc > 0 && h.tcp.seq == base && h.req_a.data == oa && h.req_b.data == ob) {
                    l_app.read(previous,0); if (current == previous) { insert_decoy(); }
                } else if (lc == 2 && h.tcp.seq == base + second - 35 && h.req_a.data == oa && h.req_b.data == ob) {
                    l_app.read(previous,1); if (current == previous) { insert_decoy(); }
                }
            }
            if (!h.replay1.isValid() && lc != 0 && h.ip.src == ls && h.ip.dst == ld && h.tcp.sport == lp && h.tcp.dport == DNP3_PORT) {
                bit<32> offset = h.tcp.seq - base;
                if (offset < 0x80000000 && offset >= 35) { h.tcp.seq = h.tcp.seq + 20; }
                if (lc == 2 && offset < 0x80000000 && offset >= second) { h.tcp.seq = h.tcp.seq + 20; }
            }
        }
        if (armed == 1 && h.tcp.isValid() && (h.tcp.flags & 5) != 0 && !h.shim.isValid()) {
            if ((sm.ingress_port == PORT_MASTER && h.ip.src == src && h.ip.dst == dst && h.tcp.sport == sport && h.tcp.dport == DNP3_PORT) ||
                (sm.ingress_port == PORT_OUT && h.ip.src == dst && h.ip.dst == src && h.tcp.sport == DNP3_PORT && h.tcp.dport == sport)) {
                r_armed.write(0,0); r_live_ack.write(0,0); r_live_resp.write(0,0); armed = 0;
            }
        }
        if (h.eth.etype == ETYPE_HEARTBEAT) {
            /* Independent internal heartbeat: token survival is not the clock. */
            if (sm.ingress_port == 4) {
                bit<48> last; bit<48> maximum; bit<32> count;
                r_hb_last.read(last,0); r_hb_max_gap.read(maximum,0); r_hb_count.read(count,0);
                if (last != 0 && now - last > maximum) { r_hb_max_gap.write(0,now-last); }
                r_hb_last.write(0,now); r_hb_count.write(0,count+1);
            }
            if (sm.ingress_port == 4 && armed == 1) {
                bit<48> ready; bit<48> t0; bit<8> released;
                p_readiness_us.read(ready, 0); r_t0.read(t0, 0);
                r_ack_released.read(released, 0); r_resp_seen.read(seen, 0);
                r_deadline.read(dl, 0); r_tresp_armed.read(tr_armed, 0); r_tresp.read(tr, 0);
                if (seen == 1 && now >= dl) { r_live_ack.write(0, 0); }
                if (tr_armed == 1 && now >= tr) { r_live_resp.write(0, 0); }
                if (released == 0 && now >= t0 + ready) {
                    r_live_ack.write(0, 0); r_live_resp.write(0, 0); r_armed.write(0, 0);
                    r_ev.write(5, now); r_history.write(event_base + 5, now);
                    r_history_state.write((txn - 1) & 31, 3);
                } else if (released == 1 && tr_armed == 1 && now >= tr + 2000) {
                    /* Completion cleanup follows the full gap and drain allowance. */
                    r_armed.write(0, 0); r_live_ack.write(0, 0); r_live_resp.write(0, 0);
                }
            }
            mark_to_drop(sm);
        } else if (h.blk.isValid()) {
            /* ---- a blocker token arriving back from the loop ---- */
            bit<32> budget_left = h.blk.budget;
            if (sm.ingress_port != PORT_LOOP_RX || h.blk.owner != txn - 1 || armed == 0) { /* retired/foreign token cannot alter a new owner */
                mark_to_drop(sm); outcome.count(10);
            } else if (token_loss == 3 || (token_loss == 1 && h.blk.slot == 1) || (token_loss == 2 && h.blk.slot == 2)) {
                mark_to_drop(sm); outcome.count(11);
            } else if (budget_left == 0) {
                /* Reservoir exhaustion is observable; heartbeat still services eligibility/expiry. */
                mark_to_drop(sm); outcome.count(11);
            } else if (h.blk.slot == 1) {
                r_resp_seen.read(seen, 0); r_deadline.read(dl, 0);
                if (seen == 1 && now >= dl) { r_live_ack.write(0, 0); mark_to_drop(sm); outcome.count(12); }
                else { h.blk.budget = budget_left - 1; to_loop(); outcome.count(13); }
            } else {
                r_resp_seen.read(seen, 0); r_tresp_armed.read(tr_armed, 0); r_tresp.read(tr, 0);
                if (seen == 1 && tr_armed == 1 && now >= tr) { r_live_resp.write(0, 0); mark_to_drop(sm); outcome.count(14); }
                else { h.blk.budget = budget_left - 1; to_loop(); outcome.count(15); }
            }
        } else if (h.shim.isValid() && sm.ingress_port != PORT_LOOP_RX) { mark_to_drop(sm);
        } else if (h.shim.isValid()) {
            /* ---- a held packet back from the loop ---- */
            if (h.shim.owner != txn - 1) {
                release_to_master(); /* old data fail open without clearing a new owner */
            } else if (h.shim.kind == KIND_ACK) {
                r_resp_seen.read(seen,0); r_deadline.read(dl,0);
                if (armed == 1 && seen == 1 && now >= dl) { r_live_ack.write(0,0); }
                r_live_ack.read(live_a, 0);
                if (live_a == 0) { release_to_master(); r_ev.write(1, now); r_history.write(event_base + 1, now); r_ack_held.write(0, 0); if (armed == 1) { r_ack_released.write(0, 1); arm_response_deadline(); } outcome.count(1); }
                else { to_loop(); }
            } else {
                r_tresp_armed.read(tr_armed,0); r_tresp.read(tr,0);
                if (armed == 1 && tr_armed == 1 && now >= tr) { r_live_resp.write(0,0); }
                r_live_resp.read(live_r, 0);
                if (live_r == 0) { release_to_master(); r_ev.write(2, now); r_history.write(event_base + 2, now); if (armed == 1) { r_history_state.write((txn - 1) & 31, 2); } finish_transaction(); outcome.count(2);
                    p_shape.read(shape, 0); if (shape == 1 && (h.link.isValid() && h.pl2.isValid() && h.rest_a.isValid() && (h.link.len == 38 || h.link.len == 46) && m.frame_ok == 1 && (h.tcp.flags & 0x16) == 0x10 && (h.ip.frag & 0x3FFF) == 0)) { split_to_master(); outcome.count(4 + 8); } }
                else { to_loop(); }
            }
        } else if (mode != 0 && m.supported == 1 && h.tcp.isValid() && sm.ingress_port == PORT_MASTER && h.app.isValid() && m.frame_ok == 1 && (h.app.func == 1 || h.app.func == 3 || h.app.func == 4)) {
            /* ---- supported request ---- */
            if (armed == 0) {
                event_base = (txn & 31) * 8; r_txn.write(0, txn + 1); r_history_state.write(txn & 31, 1);
                r_history.write(event_base + 1, 0); r_history.write(event_base + 2, 0); r_history.write(event_base + 3, 0);
                r_history.write(event_base + 4, 0); r_history.write(event_base + 5, 0); r_ev.write(5, 0);
                bit<48> da; bit<32> bud; p_da_us.read(da, 0); p_budget.read(bud, 0);
                r_armed.write(0, 1); r_t0.write(0, now); r_deadline.write(0, now + da);
                r_src.write(0,h.ip.src); r_dst.write(0,h.ip.dst); r_sport.write(0,h.tcp.sport); r_resp_seq.write(0,h.tcp.ack);
                r_expect_ack.write(0, h.tcp.seq + (bit<32>)m.rest); r_app.write(0, h.app.appctl & 0x0F);
                r_request_func.write(0,h.app.func);
                r_resp_seen.write(0, 0); r_ack_held.write(0, 0); r_ack_seen.write(0, 0); r_tresp_armed.write(0, 0);
                r_live_ack.write(0, (mode == 4) ? (bit<8>)1 : (bit<8>)0); r_live_resp.write(0, 1);
                r_ev.write(0, now); r_history.write(event_base, now); r_ack_released.write(0, 0); m.owner = txn;
                if (mode == 3) { r_ack_seen.write(0, 1); arm_response_deadline(); r_ev.write(3, now); r_history.write(event_base + 3, now); }   /* generated ACK: its instant is now */

                clone_preserving_field_list(CloneType.I2E, MIRROR_SESSION, 1);           /* two blockers: rid 1 = ACK slot, rid 2 = response slot */
                outcome.count(0);
            } else { outcome.count(9); }                         /* busy: bypass */
        } else if (m.supported == 1 && sm.checksum_error == 0 && h.tcp.isValid() && sm.ingress_port == PORT_OUT && m.rest == 0 && armed == 1 && h.ip.src == dst && h.ip.dst == src && h.tcp.sport == DNP3_PORT && h.tcp.dport == sport && (h.tcp.flags & 0x17) == 0x10) {
            /* ---- candidate pure ACK from the outstation ---- */
            r_expect_ack.read(expect, 0); r_ack_held.read(ack_held, 0); r_ack_seen.read(seen, 0);
            if (h.tcp.ack == expect && seen == 0) {
                r_ack_seen.write(0, 1); r_ev.write(3, now); r_history.write(event_base + 3, now);
                if (mode == 2) { r_ack_released.write(0, 1); arm_response_deadline(); outcome.count(3); }   /* forwarded unheld */
                else {
                    r_live_ack.read(live_a, 0);
                    if (live_a == 0) { r_ack_released.write(0, 1); arm_response_deadline(); outcome.count(4); }   /* token already gone: leaves now */
                    else { h.shim.setValid(); h.shim.kind = KIND_ACK; h.shim.owner = txn - 1; h.shim.orig = h.eth.etype; h.eth.etype = ETYPE_HELD;
                           r_ack_held.write(0, 1); to_loop(); outcome.count(5); }
                }
            } else if (h.tcp.ack == expect && seen == 1 && ack_held == 1) { mark_to_drop(sm); outcome.count(6); }   /* duplicate while held */
        } else if (m.supported == 1 && h.tcp.isValid() && sm.ingress_port == PORT_OUT && m.rest != 0 && armed == 1 && h.app.isValid() && h.obj.isValid() && h.app.func == 0x81 && m.frame_ok == 1 && h.ip.src == dst && h.ip.dst == src && h.tcp.sport == DNP3_PORT && h.tcp.dport == sport && h.tcp.seq == response_seq &&
                   ((request_func == 1 && h.obj.group == 10 && m.rest == 49) || ((request_func == 3 || request_func == 4) && h.obj.group == 12 && (m.rest == 37 || m.rest == 57)))) {
            /* ---- candidate response from the outstation ---- */
            r_expect_ack.read(expect, 0); r_app.read(app, 0); r_resp_seen.read(seen, 0);
            if (h.tcp.ack == expect && (h.app.appctl & 0x0F) == app && seen == 0) {
                r_resp_seen.write(0, 1); r_ev.write(4, now); r_history.write(event_base + 4, now);
                h.shim.setValid(); h.shim.kind = KIND_RESP; h.shim.owner = txn - 1; h.shim.orig = h.eth.etype; h.eth.etype = ETYPE_HELD;
                to_loop(); outcome.count(7);
            } else { outcome.count(8); }                         /* stale / duplicate: forwarded unchanged */
        } else if (sm.ingress_port == PORT_LOOP_RX || sm.ingress_port == 4) {
            mark_to_drop(sm);
        }                                                        /* everything else keeps the dmac forwarding applied above */
        /* fault injection, every mode: the first READ request is lost on the switch -> outstation link, after any generated ACK */
        p_dropreq.read(dropreq, 0); r_dropped.read(dropped, 0);
        if (dropreq == 1 && dropped == 0 && sm.ingress_port == PORT_MASTER && h.app.isValid() && h.app.func == 0x01 && !h.shim.isValid() && !h.blk.isValid()) {
            r_dropped.write(0, 1); mark_to_drop(sm); outcome.count(11);
        }
        if (h.tcp.isValid() && !h.blk.isValid() && !h.shim.isValid() && (sm.ingress_port == PORT_OUT || sm.ingress_port == PORT_LOOP_RX) && lc != 0) {
            bit<32> ls; bit<32> ld; bit<16> lp;
            l_src.read(ls,0); l_dst.read(ld,0); l_sport.read(lp,0);
            if (h.ip.src == ld && h.ip.dst == ls && h.tcp.sport == DNP3_PORT && h.tcp.dport == lp) {
                if ((h.tcp.flags & 5) != 0) { l_closed.write(0,1); }
                bit<32> wire = h.tcp.ack - base; bit<32> left; bit<32> right;
                if ((h.tcp.flags & 16) != 0 && wire < 0x80000000) {
                    native_offset(wire,left); native_offset(wire + (bit<32>)h.tcp.win,right);
                    h.tcp.ack = base + left; h.tcp.win = (bit<16>)(right - left);
                }
            }
        }
        /* Incremental one's-complement repair for translation of unchanged payloads. */
        if (h.tcp.isValid() && m.rewritten == 0 && (h.tcp.seq != m.old_seq || h.tcp.ack != m.old_ack || h.tcp.win != m.old_win)) {
            bit<32> sum = (bit<32>)(~h.tcp.csum) + (bit<32>)(~m.old_seq[31:16]) + (bit<32>)h.tcp.seq[31:16]
                + (bit<32>)(~m.old_seq[15:0]) + (bit<32>)h.tcp.seq[15:0]
                + (bit<32>)(~m.old_ack[31:16]) + (bit<32>)h.tcp.ack[31:16]
                + (bit<32>)(~m.old_ack[15:0]) + (bit<32>)h.tcp.ack[15:0]
                + (bit<32>)(~m.old_win) + (bit<32>)h.tcp.win;
            sum = (bit<32>)sum[15:0] + (bit<32>)sum[31:16];
            sum = (bit<32>)sum[15:0] + (bit<32>)sum[31:16]; h.tcp.csum = ~(bit<16>)sum;
        }
        p_shape.read(shape, 0);
        if (shape == 1 && m.held == 0 && !h.blk.isValid() && !h.shim.isValid() && sm.ingress_port == PORT_OUT && h.app.isValid() && h.app.func == 0x81 && (h.link.isValid() && h.pl2.isValid() && h.rest_a.isValid() && (h.link.len == 38 || h.link.len == 46) && m.frame_ok == 1 && (h.tcp.flags & 0x16) == 0x10 && (h.ip.frag & 0x3FFF) == 0) && sm.egress_spec == PORT_MASTER) { split_to_master(); outcome.count(5); }
    }
}

control Egr(inout headers_t h, inout meta_t m, inout standard_metadata_t sm) {
    register<bit<32>>(1) e_budget;      /* mirrors p_budget for the blocker header; written by the control plane */
    counter(4, CounterType.packets) carve_ctr;
    register<bit<8>>(1) p_mode_e;      /* mirrors p_mode for the egress pipeline; written by the control plane */
    apply {
        if (sm.instance_type == 5 && h.pl2.isValid() && (sm.egress_rid == 1 || sm.egress_rid == 2)) {
            /* RID interpreter: rid 1 keeps payload[0:28], rid 2 keeps payload[28:49]; the rid is the whole instruction */
            bit<16> tcp_hdr = ((bit<16>)h.tcp.doff) << 2;
            m.carved = 1; m.rid = (bit<8>)sm.egress_rid;
            if (sm.egress_rid == 1) {
                h.extra.setInvalid(); h.pl2.setInvalid(); h.tcp.flags = h.tcp.flags & 0xF6;            /* clear PSH and FIN on the prefix */
                h.ip.len = h.ip.len - (h.link.len == 46 ? (bit<16>)29 : (bit<16>)21); m.ptcp_len = tcp_hdr + 28; carve_ctr.count(1);
            } else {
                h.link.setInvalid(); h.app.setInvalid(); h.iin.setInvalid(); h.obj.setInvalid(); h.rest_a.setInvalid();
                h.tcp.seq = h.tcp.seq + 28; h.ip.len = h.ip.len - 28; m.ptcp_len = tcp_hdr + (h.extra.isValid() ? (bit<16>)29 : (bit<16>)21); carve_ctr.count(2);
            }
        }
        bit<8> emode; p_mode_e.read(emode, 0);
        if (sm.instance_type == 1 && sm.egress_rid == 3 && emode != 3) { mark_to_drop(sm); }
        else if (sm.instance_type == 1 && sm.egress_rid == 3) {
            /* generated ACK for the request just seen: the switch speaks for the outstation. Window and options are the
             * switch's own invention (documented limitation); sequence numbers come from the request itself. */
            bit<48> tmp_mac = h.eth.src; h.eth.src = h.eth.dst; h.eth.dst = tmp_mac;
            bit<32> tmp_ip = h.ip.src; h.ip.src = h.ip.dst; h.ip.dst = tmp_ip;
            bit<16> tmp_p = h.tcp.sport; h.tcp.sport = h.tcp.dport; h.tcp.dport = tmp_p;
            bit<16> plen = h.ip.len - (((bit<16>)h.ip.ihl) << 2) - (((bit<16>)h.tcp.doff) << 2);
            bit<32> old_seq = h.tcp.seq;
            h.tcp.seq = h.tcp.ack; h.tcp.ack = old_seq + (bit<32>)plen; h.tcp.flags = 0x10; h.tcp.win = 16384;
            h.link.setInvalid(); h.app.setInvalid(); h.iin.setInvalid(); h.obj.setInvalid(); h.rest_a.setInvalid(); h.pl2.setInvalid();
            if (h.tcp_ts.isValid()) {
                h.tcp_ts.opt = h.tcp_ts.opt[95:64] ++ h.tcp_ts.opt[31:0] ++ h.tcp_ts.opt[63:32];   /* TSval <-> TSecr */
                h.ip.len = 52; m.ptcp_len = 32; truncate((bit<32>)66);
            } else { h.ip.len = 40; m.ptcp_len = 20; truncate((bit<32>)54); }
            m.carved = 1; m.rid = 3; carve_ctr.count(3);
        } else if (sm.instance_type == 1) {                      /* an ingress clone: turn it into a blocker */
            h.ip.setInvalid(); h.tcp.setInvalid(); h.tcp_ts.setInvalid(); h.link.setInvalid(); h.app.setInvalid();
            h.iin.setInvalid(); h.obj.setInvalid(); h.shim.setInvalid();
            h.eth.etype = ETYPE_BLK;
            h.blk.setValid(); h.blk.slot = (bit<8>)sm.egress_rid;
            e_budget.read(h.blk.budget, 0); h.blk.owner = m.owner;
            truncate((bit<32>)27);
        }
    }
}
control CC(inout headers_t h, inout meta_t m) {
    apply {
        update_checksum(m.carved == 1 || m.rewritten == 1, { h.ip.ver, h.ip.ihl, h.ip.tos, h.ip.len, h.ip.id, h.ip.frag, h.ip.ttl, h.ip.proto, h.ip.src, h.ip.dst }, h.ip.csum, HashAlgorithm.csum16);
        update_checksum(m.rewritten == 1 && !h.replay1.isValid(),
            {h.ip.src,h.ip.dst,8w0,h.ip.proto,16w75,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,
             h.link.start,h.link.len,h.link.ctrl,h.link.dst,h.link.src,h.link.crc,h.app.transport,h.app.appctl,h.app.func,h.obj.group,h.obj.variation,h.req_a.data,h.req_a.crc,h.req_b.data,h.insert_a.data,h.req_b_crc.crc,h.insert_b.data,h.insert_b.crc}, h.tcp.csum,HashAlgorithm.csum16);
        update_checksum(m.rewritten == 1 && h.replay1.isValid() && !h.replay2.isValid(),
            {h.ip.src,h.ip.dst,8w0,h.ip.proto,16w75,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.replay1.data},h.tcp.csum,HashAlgorithm.csum16);
        update_checksum(m.rewritten == 1 && h.replay1.isValid() && h.replay2.isValid(),
            {h.ip.src,h.ip.dst,8w0,h.ip.proto,16w130,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.replay1.data,h.replay2.data},h.tcp.csum,HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 1 && !h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg,
              h.link.start, h.link.len, h.link.ctrl, h.link.dst, h.link.src, h.link.crc, h.app.transport, h.app.appctl, h.app.func, h.iin.iin, h.obj.group, h.obj.variation, h.rest_a.b },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 1 && h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.tcp_ts.opt,
              h.link.start, h.link.len, h.link.ctrl, h.link.dst, h.link.src, h.link.crc, h.app.transport, h.app.appctl, h.app.func, h.iin.iin, h.obj.group, h.obj.variation, h.rest_a.b },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 2 && !h.tcp_ts.isValid() && !h.extra.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.pl2.b },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 2 && !h.tcp_ts.isValid() && h.extra.isValid(),
            {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.pl2.b,h.extra.b},h.tcp.csum,HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 2 && h.tcp_ts.isValid() && h.extra.isValid(),
            {h.ip.src,h.ip.dst,8w0,h.ip.proto,m.ptcp_len,h.tcp.sport,h.tcp.dport,h.tcp.seq,h.tcp.ack,h.tcp.doff,h.tcp.res,h.tcp.flags,h.tcp.win,h.tcp.urg,h.tcp_ts.opt,h.pl2.b,h.extra.b},h.tcp.csum,HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 3 && !h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 3 && h.tcp_ts.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.tcp_ts.opt },
            h.tcp.csum, HashAlgorithm.csum16);
        update_checksum(m.carved == 1 && m.rid == 2 && h.tcp_ts.isValid() && !h.extra.isValid(),
            { h.ip.src, h.ip.dst, 8w0, h.ip.proto, m.ptcp_len, h.tcp.sport, h.tcp.dport, h.tcp.seq, h.tcp.ack, h.tcp.doff, h.tcp.res, h.tcp.flags, h.tcp.win, h.tcp.urg, h.tcp_ts.opt, h.pl2.b },
            h.tcp.csum, HashAlgorithm.csum16);
    }
}
control Dep(packet_out pkt, in headers_t h) {
    apply { pkt.emit(h.eth); pkt.emit(h.shim); pkt.emit(h.blk); pkt.emit(h.ip); pkt.emit(h.tcp); pkt.emit(h.tcp_ts); pkt.emit(h.tcp_mss);
            pkt.emit(h.link); pkt.emit(h.app); pkt.emit(h.iin); pkt.emit(h.obj); pkt.emit(h.read_tail); pkt.emit(h.req_a); pkt.emit(h.req_b); pkt.emit(h.insert_a); pkt.emit(h.req_b_crc); pkt.emit(h.insert_b); pkt.emit(h.rest_a); pkt.emit(h.pl2); pkt.emit(h.extra); pkt.emit(h.control_tail); pkt.emit(h.replay1); pkt.emit(h.replay2); }
}
V1Switch(P(), VC(), Ing(), Egr(), CC(), Dep()) main;
