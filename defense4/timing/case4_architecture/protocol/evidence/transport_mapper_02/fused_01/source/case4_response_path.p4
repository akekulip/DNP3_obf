/* Option B' response path in ONE egress pass: the case4_pad58b_wire padder fused with the
   response-side transport mapper (TRANSPORT_MAPPER_SPEC.md; software model
   framework/size/case4_response_mapper.py).

   Differences from the two standalone programs, each deliberate:
   - The padder pads ONLY when the mapper says commit or replay (pad gate). case4_pad58b_wire.p4
     pads every eligible frame on every flow; that is unsafe on its own (a refused, native-mode or
     unconfigured flow would get a longer segment with no sequence translation). That frozen,
     model-verified file is left untouched; the gate lives here, where both halves meet.
   - The mapper's commit/replay verdict is the padder's own (profile shape AND every native link CRC),
     not the standalone build's shape-only stand-in.
   - One incremental TCP checksum serves every changed frame, padded or not: the parser subtracts
     ip.len, seq, ack, window and the old checksum, and automatically subtracts every header extracted
     after that (the whole DNP3 frame on eligible lengths); the deparser adds all of them back with
     their current values. Invalid headers contribute nothing, so the same list covers a native frame,
     its padded image and a frame that was only translated.
   - Packet classification (role) is computed in stage 0 from header bits alone (shape_t) and joined
     with the connection lookup by keying the register tables on (dir, shape).

   Register discipline as in case4_transport_mapper.p4: each register is touched by exactly one table;
   the only reverse-path write (acct.hi) is in the SALU that makes the forward commit decision. */
#include <core.p4>
#include <tna.p4>

const bit<8> SH_NONE = 0; const bit<8> SH_SYNACK_OK = 1; const bit<8> SH_SYN = 2; const bit<8> SH_ODD = 3;
const bit<8> SH_ACK = 4;  const bit<8> SH_NOACK = 5;     // 4 and 5 differ only in bit 0

const bit<8> OUT_COMMIT = 1;  const bit<8> OUT_TRANSLATE = 2; const bit<8> OUT_ZERO = 3;
const bit<8> OUT_REPLAY = 4;  const bit<8> OUT_STALE = 5;     const bit<8> OUT_DROP_OVERLAP = 6;
const bit<8> OUT_DROP_AHEAD = 7; const bit<8> OUT_DROP_ODD = 8;
const bit<8> OUT_REV_TRANSLATE = 9; const bit<8> OUT_REV_WITHHOLD = 10; const bit<8> OUT_REV_DROP_STALE = 11;
const bit<8> OUT_NATIVE = 12; const bit<8> OUT_ARM_MAP = 13; const bit<8> OUT_ARM_NAT = 14;

const bit<32> IMAGE_LEN = 58;

typedef bit<4> slot_t;
struct pair32 { bit<32> lo; bit<32> hi; }

header eth_h { bit<48> dst; bit<48> src; bit<16> type; }
header ip_h { bit<4> version; bit<4> ihl; bit<8> tos; bit<16> len; bit<16> id; bit<3> flags;
              bit<13> frag; bit<8> ttl; bit<8> proto; bit<16> checksum; bit<32> src; bit<32> dst; }
header tcp_h { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack; bit<4> offset; bit<4> reserved;
               bit<8> flags; bit<16> window; bit<16> checksum; bit<16> urgent; }
header mss_h { bit<8> kind; bit<8> len; bit<16> mss; }
/* DNP3 frame layout, verbatim from case4_pad58b_wire.p4 */
header dl_h{bit<16> start;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}
header read_b0_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<8> g_start;bit<8> g_stop;bit<48> data_mid;bit<16> crc0;}
header read_b1_h{bit<128> data;bit<16> crc1;}
header read_tail_n_h{bit<8> data_last;bit<16> crc2;}
header read_tail_p_h{bit<8> data_last;bit<72> filler;bit<16> crc2;}
header ctl_b0_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<16> g_count;bit<16> index;bit<8> crob_code;bit<8> crob_count;bit<16> on_hi;bit<16> crc0;}
header ctl_tail_n_h{bit<16> on_lo;bit<32> off;bit<8> status;bit<16> crc1;}
header ctl_tail_p1_h{bit<16> on_lo;bit<32> off;bit<8> status;bit<72> filler_a;bit<16> crc1;}
header ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}

struct headers_t { eth_h eth; ip_h ip; tcp_h tcp; mss_h mss; dl_h dl; read_b0_h rb0; read_b1_h rb1; read_tail_n_h rtn;
                   read_tail_p_h rtp; ctl_b0_h cb0; ctl_tail_n_h ctn; ctl_tail_p1_h ctp1; ctl_tail_p2_h ctp2; }

struct meta_t {
    bit<16> residual;
    bit<32> iplen32; bit<32> win32;      // parser copies: 32-bit, no PHV tie to the 16-bit header fields
    bit<8>  ip_odd; bit<8> tcp_odd; bit<8> has_mss;
    bit<8>  dir; slot_t idx; bit<8> enable; bit<8> shape; bit<8> mode;
    bit<32> leff; bit<32> s_end; bit<32> ina;
    bit<32> front_ret; bit<8> grant;
    /* forward / reverse share these (see case4_transport_mapper.p4 for the table) */
    bit<32> q; bit<32> p; bit<32> y; bit<32> z; bit<32> pm; bit<32> t; bit<32> qx; bit<32> r;
    bit<8>  result; bit<1> changed; bit<1> pad; bit<8> wide;
    /* padder verdict and CRC scratch (case4_pad58b_wire.p4) */
    bit<16> dlcrc; bit<16> rtcrc; bit<16> ctcrc1;
    bit<1> read_shape; bit<1> ctl_shape;
    bit<16> in_dl; bit<16> in_rb0; bit<16> in_rb1; bit<16> in_rt; bit<16> in_cb0; bit<16> in_ct;
    bit<1> badh; bit<1> rbad0; bit<1> rbad1; bit<1> rbadt; bit<1> cbad0; bit<1> cbadt;
}
/* Same reason as in case4_pad58b_wire.p4: independent single-bit writers must not share a container. */
@pa_solitary("egress","m.read_shape") @pa_solitary("egress","m.ctl_shape")
@pa_solitary("egress","m.badh") @pa_solitary("egress","m.rbad0") @pa_solitary("egress","m.rbad1")
@pa_solitary("egress","m.rbadt") @pa_solitary("egress","m.cbad0") @pa_solitary("egress","m.cbadt")

/* ------------------------------------------------------------------ ingress: port forwarding only */
parser IgParser(packet_in pkt, out headers_t hdr, out meta_t m, out ingress_intrinsic_metadata_t ig) {
    state start { pkt.extract(ig); pkt.advance(PORT_METADATA_SIZE); transition accept; }
}
control Ingress(inout headers_t hdr, inout meta_t m, in ingress_intrinsic_metadata_t ig,
                in ingress_intrinsic_metadata_from_parser_t p, inout ingress_intrinsic_metadata_for_deparser_t md,
                inout ingress_intrinsic_metadata_for_tm_t tm) {
    action deny() { md.drop_ctl = 3w1; }
    action route(PortId_t port) { tm.ucast_egress_port = port; }
    table forwarding { key = { ig.ingress_port : exact; } actions = { route; deny; } size = 8; default_action = deny(); }
    apply { forwarding.apply(); }
}
control IgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in ingress_intrinsic_metadata_for_deparser_t md) {
    apply { }
}

/* ------------------------------------------------------------------ egress parser */
parser EgParser(packet_in pkt, out headers_t hdr, out meta_t m, out egress_intrinsic_metadata_t eg) {
    Checksum() tcp_old;
    state start {
        pkt.extract(eg);
        m.ip_odd = 0; m.tcp_odd = 0; m.has_mss = 0; m.dir = 0; m.mode = 0; m.grant = 0;
        m.result = 0; m.changed = 0; m.pad = 0; m.wide = 0;
        m.read_shape = 0; m.ctl_shape = 0;
        m.badh = 0; m.rbad0 = 0; m.rbad1 = 0; m.rbadt = 0; m.cbad0 = 0; m.cbadt = 0;
        transition eth;
    }
    state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { 16w0x0800: ip; default: accept; } }
    state ip {
        pkt.extract(hdr.ip);
        m.iplen32 = (bit<32>)hdr.ip.len;
        tcp_old.subtract({hdr.ip.len});             // pseudo-header TCP length changes when padded
        transition select(hdr.ip.version, hdr.ip.ihl, hdr.ip.proto) { (4w4, 4w5, 8w6): ip_frag; (4w4, _, 8w6): ip_odd; default: accept; }
    }
    state ip_frag { transition select(hdr.ip.frag, hdr.ip.flags) { (13w0, 3w0): tcp; (13w0, 3w2): tcp; default: ip_odd; } }
    state ip_odd { m.ip_odd = 1; transition accept; }
    state tcp {
        pkt.extract(hdr.tcp);
        m.win32 = (bit<32>)hdr.tcp.window;
        /* Every header extracted after this deposit is subtracted too; the deparser adds them back. */
        tcp_old.subtract({hdr.tcp.seq, hdr.tcp.ack, hdr.tcp.window, hdr.tcp.checksum});
        tcp_old.subtract_all_and_deposit(m.residual);
        transition select(hdr.tcp.offset) { 4w5: dl_len; 4w6: mss; default: tcp_odd; }
    }
    state tcp_odd { m.tcp_odd = 1; transition accept; }
    state mss { pkt.extract(hdr.mss); m.has_mss = 1; transition accept; }
    /* Parse the leading DNP3 frame whenever the segment is long enough for the shorter profile
       (ip.len >= 77): a merged retransmission carries the frame first and native bytes after it, which
       stay unparsed and are re-emitted after the (possibly padded) frame headers. */
    state dl_len { transition select(hdr.ip.len) { 16w77 &&& 16w0xffff: dl; 16w78 &&& 16w0xfffe: dl; 16w80 &&& 16w0xfff0: dl; 16w96 &&& 16w0xffe0: dl; 16w128 &&& 16w0xff80: dl; 16w256 &&& 16w0xff00: dl; 16w512 &&& 16w0xfe00: dl; 16w1024 &&& 16w0xfc00: dl; 16w2048 &&& 16w0xf800: dl; 16w4096 &&& 16w0xf000: dl; 16w8192 &&& 16w0xe000: dl; 16w16384 &&& 16w0xc000: dl; 16w32768 &&& 16w0x8000: dl; default: accept; } }
    state dl {
        pkt.extract(hdr.dl);
        transition select(hdr.dl.len, hdr.ip.len) {
            (8w0x26, 16w77 &&& 16w0xffff): accept; (8w0x26, 16w78 &&& 16w0xfffe): accept; (8w0x26, 16w80 &&& 16w0xfff8): accept; (8w0x26, 16w88 &&& 16w0xffff): accept;           // READ frame needs ip.len >= 89
            (8w0x26, _): read_b0; (8w0x1c, _): ctl_b0; default: accept;
        }
    }
    state read_b0 { pkt.extract(hdr.rb0); pkt.extract(hdr.rb1); pkt.extract(hdr.rtn); transition accept; }
    state ctl_b0 { pkt.extract(hdr.cb0); pkt.extract(hdr.ctn); transition accept; }
}

/* ------------------------------------------------------------------ egress */
control Egress(inout headers_t hdr, inout meta_t m, in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t prs, inout egress_intrinsic_metadata_for_deparser_t md,
               inout egress_intrinsic_metadata_for_output_port_t port) {

    /* ============ stage-0 lookups ============ */
    action fwd_conn(slot_t idx, bit<8> enable) { m.dir = 1; m.idx = idx; m.enable = enable; }
    action rev_conn(slot_t idx) { m.dir = 2; m.idx = idx; m.enable = 0; }
    table conn {
        key = { hdr.ip.src : exact; hdr.ip.dst : exact; hdr.tcp.sport : exact; hdr.tcp.dport : exact; }
        actions = { fwd_conn; rev_conn; NoAction; } size = 32; default_action = NoAction();
    }
    action odd_conn(slot_t idx) { m.dir = 3; m.idx = idx; }
    table odd_ip_t {
        key = { hdr.ip.src : exact; hdr.ip.dst : exact; }
        actions = { odd_conn; NoAction; } size = 32; default_action = NoAction();
    }
    action set_shape(bit<8> shape) { m.shape = shape; }
    table shape_t {
        key = { m.ip_odd : ternary; hdr.tcp.flags : ternary; m.has_mss : ternary; hdr.mss.kind : ternary;
                hdr.mss.len : ternary; m.tcp_odd : ternary; }
        actions = { set_shape; } size = 8; const default_action = set_shape(SH_NOACK);
        const entries = {
            (1, _, _, _, _, _)                          : set_shape(SH_ODD);       // no TCP header parsed
            (0, 8w0x12 &&& 8w0x12, 1, 8w2, 8w4, 0)      : set_shape(SH_SYNACK_OK); // MSS is the only option
            (0, 8w0x02 &&& 8w0x02, _, _, _, _)          : set_shape(SH_SYN);
            (0, _, _, _, _, 1)                          : set_shape(SH_ODD);       // TCP options on non-SYN
            (0, _, 1, _, _, _)                          : set_shape(SH_ODD);
            (0, 8w0x10 &&& 8w0x10, _, _, _, _)          : set_shape(SH_ACK);
        }
    }
    action leff_data() { m.leff = m.iplen32 + 32w0xFFFFFFD8; }   // ip.len - 40
    action leff_fin()  { m.leff = m.iplen32 + 32w0xFFFFFFD9; }   // ip.len - 40 + FIN
    table leff_t {
        key = { hdr.tcp.flags : ternary; }
        actions = { leff_data; leff_fin; } size = 2; const default_action = leff_data();
        const entries = { 8w0x01 &&& 8w0x01 : leff_fin(); }
    }
    /* SALU operand staging by header bits only: acct reads {ina, leff}; img_wend reads {qx, t}. */
    action prep_syn() { m.ina = hdr.tcp.seq + 1; m.qx = hdr.tcp.seq + 1; }
    action prep_ack() { m.ina = hdr.tcp.ack; m.qx = hdr.tcp.ack; }
    table prep_t {
        key = { hdr.tcp.flags : ternary; }
        actions = { prep_syn; prep_ack; } size = 2; const default_action = prep_ack();
        const entries = { 8w0x02 &&& 8w0x02 : prep_syn(); }
    }

    /* ============ padder verdict (case4_pad58b_wire.p4, unchanged logic) ============ */
    action read_shape(){m.read_shape=1w1;}
    table read_profile{key={hdr.dl.start:exact;hdr.dl.len:exact;hdr.rb0.tpctrl:ternary;hdr.rb0.appctrl:ternary;hdr.rb0.func:exact;hdr.rb0.g_group:exact;hdr.rb0.g_var:exact;hdr.rb0.g_qual:exact;hdr.rb0.g_start:exact;hdr.rb0.g_stop:exact;}
     actions={read_shape;NoAction;}size=1;const default_action=NoAction();
     const entries={(16w0x0564,8w0x26,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x0a,8w0x02,8w0x00,8w0x00,8w0x16):read_shape();}}
    action ctl_shape(){m.ctl_shape=1w1;}
    table ctl_profile{key={hdr.dl.start:exact;hdr.dl.len:exact;hdr.cb0.tpctrl:ternary;hdr.cb0.appctrl:ternary;hdr.cb0.func:exact;hdr.cb0.g_group:exact;hdr.cb0.g_var:exact;hdr.cb0.g_qual:exact;hdr.cb0.g_count:exact;hdr.ctn.status:exact;}
     actions={ctl_shape;NoAction;}size=1;const default_action=NoAction();
     const entries={(16w0x0564,8w0x1c,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x0c,8w0x01,8w0x28,16w0x0100,8w0x00):ctl_shape();}}
    CRCPolynomial<bit<16>>(16w0x3D65,true,false,false,16w0,16w0xFFFF) poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_dl;
    action in_dl(){m.in_dl=hash_in_dl.get({hdr.dl.start,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
    table in_dl_t{actions={in_dl;}size=1;const default_action=in_dl();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rb0;
    action in_rb0(){m.in_rb0=hash_in_rb0.get({hdr.rb0.tpctrl,hdr.rb0.appctrl,hdr.rb0.func,hdr.rb0.iin,hdr.rb0.g_group,hdr.rb0.g_var,hdr.rb0.g_qual,hdr.rb0.g_start,hdr.rb0.g_stop,hdr.rb0.data_mid});}
    table in_rb0_t{actions={in_rb0;}size=1;const default_action=in_rb0();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rb1;
    action in_rb1(){m.in_rb1=hash_in_rb1.get({hdr.rb1.data});}
    table in_rb1_t{actions={in_rb1;}size=1;const default_action=in_rb1();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rt;
    action in_rt(){m.in_rt=hash_in_rt.get({hdr.rtn.data_last});}
    table in_rt_t{actions={in_rt;}size=1;const default_action=in_rt();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_cb0;
    action in_cb0(){m.in_cb0=hash_in_cb0.get({hdr.cb0.tpctrl,hdr.cb0.appctrl,hdr.cb0.func,hdr.cb0.iin,hdr.cb0.g_group,hdr.cb0.g_var,hdr.cb0.g_qual,hdr.cb0.g_count,hdr.cb0.index,hdr.cb0.crob_code,hdr.cb0.crob_count,hdr.cb0.on_hi});}
    table in_cb0_t{actions={in_cb0;}size=1;const default_action=in_cb0();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_ct;
    action in_ct(){m.in_ct=hash_in_ct.get({hdr.ctn.on_lo,hdr.ctn.off,hdr.ctn.status});}
    table in_ct_t{actions={in_ct;}size=1;const default_action=in_ct();}

    /* ============ mapper registers ============ */
    Register<bit<8>, slot_t>(16, 0) mode;
    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_arm_map = { void apply(inout bit<8> v) { v = 1; } };
    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_arm_nat = { void apply(inout bit<8> v) { v = 0; } };
    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_read = { void apply(inout bit<8> v, out bit<8> rv) { rv = v; } };
    action do_mode_arm_map() { mode_arm_map.execute(m.idx); }
    action do_mode_arm_nat() { mode_arm_nat.execute(m.idx); }
    action do_mode_read() { m.mode = mode_read.execute(m.idx); }
    table mode_t {
        key = { m.dir : exact; m.shape : ternary; }
        actions = { do_mode_arm_map; do_mode_arm_nat; do_mode_read; NoAction; } size = 8; const default_action = NoAction();
        const entries = { (1, SH_SYNACK_OK) : do_mode_arm_map(); (1, SH_SYN) : do_mode_arm_nat();
                          (1, _) : do_mode_read(); (2, SH_ACK) : do_mode_read(); (2, SH_ODD) : do_mode_read();
                          (3, _) : do_mode_read(); }
    }

    Register<bit<32>, slot_t>(16, 0) front;
    RegisterAction<bit<32>, slot_t, bit<32>>(front) front_arm = {
        void apply(inout bit<32> v) { v = hdr.tcp.seq + 1; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(front) front_step = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq - v; if (v == hdr.tcp.seq) { v = v + m.leff; } } };
    action do_front_arm() { front_arm.execute(m.idx); }
    action do_front_step() { m.front_ret = front_step.execute(m.idx); }
    table front_t {
        key = { m.dir : exact; m.shape : ternary; }
        actions = { do_front_arm; do_front_step; NoAction; } size = 4; const default_action = NoAction();
        const entries = { (1, SH_SYNACK_OK) : do_front_arm(); (1, 8w4 &&& 8w0xFE) : do_front_step(); }
    }

    /* acct = {lo: W, hi: U = W - A}; a commit adds the whole 58-byte image (L + d = 58 for both
       profiles), any other frontier segment adds Leff. */
    Register<pair32, slot_t>(16, {0, 0}) acct;
    RegisterAction<pair32, slot_t, bit<8>>(acct) acct_arm = {
        void apply(inout pair32 v) { v.lo = m.ina; v.hi = 0; } };
    RegisterAction<pair32, slot_t, bit<8>>(acct) acct_try = {
        void apply(inout pair32 v, out bit<8> rv) {
            rv = 0;
            if (v.hi == 0) { v.lo = v.lo + IMAGE_LEN; v.hi = v.hi + IMAGE_LEN; rv = 1; }
            else { v.lo = v.lo + m.leff; v.hi = v.hi + m.leff; }
        } };
    RegisterAction<pair32, slot_t, bit<8>>(acct) acct_grow = {
        void apply(inout pair32 v) { v.lo = v.lo + m.leff; v.hi = v.hi + m.leff; } };
    RegisterAction<pair32, slot_t, bit<8>>(acct) acct_rev = {
        void apply(inout pair32 v) { v.hi = v.lo - m.ina; } };
    action do_acct_arm() { acct_arm.execute(m.idx); }
    action do_acct_try() { m.grant = acct_try.execute(m.idx); }
    action do_acct_grow() { acct_grow.execute(m.idx); }
    action do_acct_rev() { acct_rev.execute(m.idx); }
    table acct_t {   // commit candidates: frontier, policy on, no SYN/RST/FIN, padder verdict good
        key = { m.dir : exact; m.shape : ternary; m.front_ret : ternary; m.enable : ternary; hdr.tcp.flags : ternary;
                m.leff : ternary; m.read_shape : ternary; m.ctl_shape : ternary; m.badh : ternary;
                m.rbad0 : ternary; m.rbad1 : ternary; m.rbadt : ternary; m.cbad0 : ternary; m.cbadt : ternary; }
        actions = { do_acct_arm; do_acct_try; do_acct_grow; do_acct_rev; NoAction; } size = 8;
        const default_action = NoAction();
        const entries = {
            (1, SH_SYNACK_OK, _, _, _, _, _, _, _, _, _, _, _, _)                    : do_acct_arm();
            (1, 8w4 &&& 8w0xFE, 0, 1, 8w0 &&& 8w0x07, 49, 1, _, 0, 0, 0, 0, _, _)    : do_acct_try();  // exactly one READ frame
            (1, 8w4 &&& 8w0xFE, 0, 1, 8w0 &&& 8w0x07, 37, _, 1, 0, _, _, _, 0, 0)    : do_acct_try();  // exactly one CONTROL frame
            (1, 8w4 &&& 8w0xFE, 0, _, _, _, _, _, _, _, _, _, _, _)                  : do_acct_grow();
            (2, SH_ACK, _, _, _, _, _, _, _, _, _, _, _, _)                          : do_acct_rev();
        }
    }

    Register<bit<32>, slot_t>(16, 0) img_end;
    RegisterAction<bit<32>, slot_t, bit<32>>(img_end) end_arm = {
        void apply(inout bit<32> v) { v = hdr.tcp.seq + 1; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_end) end_commit = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq - v; v = m.s_end; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_end) end_fwd = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq - v; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_end) end_rev = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; } };
    action do_end_arm() { end_arm.execute(m.idx); }
    action do_end_commit() { m.q = end_commit.execute(m.idx); }
    action do_end_fwd() { m.q = end_fwd.execute(m.idx); }
    action do_end_rev() { m.q = end_rev.execute(m.idx); }
    table img_end_t {
        key = { m.dir : exact; m.shape : ternary; m.grant : ternary; }
        actions = { do_end_arm; do_end_commit; do_end_fwd; do_end_rev; NoAction; } size = 8;
        const default_action = NoAction();
        // grant is the SALU predicate word (nonzero = granted, encoding not assumed): 0 first
        const entries = { (1, SH_SYNACK_OK, _) : do_end_arm(); (1, 8w4 &&& 8w0xFE, 0) : do_end_fwd();
                          (1, 8w4 &&& 8w0xFE, _) : do_end_commit(); (2, SH_ACK, _) : do_end_rev(); }
    }

    Register<bit<32>, slot_t>(16, 0) img_start;
    RegisterAction<bit<32>, slot_t, bit<32>>(img_start) start_arm = {     // virtual image: ISN+1-58
        void apply(inout bit<32> v) { v = hdr.tcp.seq + 32w0xFFFFFFC7; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_start) start_commit = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq - v; v = hdr.tcp.seq; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_start) start_fwd = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq - v; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_start) start_rev = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; } };
    action do_start_arm() { start_arm.execute(m.idx); }
    action do_start_commit() { m.p = start_commit.execute(m.idx); }
    action do_start_fwd() { m.p = start_fwd.execute(m.idx); }
    action do_start_rev() { m.p = start_rev.execute(m.idx); }
    table img_start_t {
        key = { m.dir : exact; m.shape : ternary; m.grant : ternary; }
        actions = { do_start_arm; do_start_commit; do_start_fwd; do_start_rev; NoAction; } size = 8;
        const default_action = NoAction();
        const entries = { (1, SH_SYNACK_OK, _) : do_start_arm(); (1, 8w4 &&& 8w0xFE, 0) : do_start_fwd();
                          (1, 8w4 &&& 8w0xFE, _) : do_start_commit(); (2, SH_ACK, _) : do_start_rev(); }
    }

    action derive_end() { m.s_end = hdr.tcp.seq + m.leff; }
    table derive_t { actions = { derive_end; } size = 1; const default_action = derive_end(); }

    /* ============ forward classification (spec section 5) ============ */
    action fwd_prep() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + 32w0xFFFFFFC6; m.t = m.q + IMAGE_LEN; }
    table fwd_prep_t { actions = { fwd_prep; } size = 1; const default_action = fwd_prep(); }

    action out_commit()    { m.qx = m.q;  m.result = OUT_COMMIT;    m.pad = 1; m.changed = 1; }
    action out_translate() { m.qx = m.q;  m.result = OUT_TRANSLATE; m.changed = 1; }
    action out_zero()      { m.qx = m.pm; m.result = OUT_ZERO;      m.changed = 1; }
    action out_replay()    { m.qx = m.pm; m.result = OUT_REPLAY;    m.pad = 1; m.changed = 1; }
    action out_stale()     { m.qx = m.pm; m.result = OUT_STALE;     m.changed = 1; }
    action out_drop(bit<8> why) { m.result = why; md.drop_ctl = 3w1; }
    table classify_fwd {
        key = { m.front_ret : ternary; m.grant : ternary; m.q : ternary; m.leff : ternary;
                m.p : ternary; m.y : ternary; m.z : ternary;
                m.read_shape : ternary; m.ctl_shape : ternary; m.badh : ternary;
                m.rbad0 : ternary; m.rbad1 : ternary; m.rbadt : ternary; m.cbad0 : ternary; m.cbadt : ternary; }
        actions = { out_commit; out_translate; out_zero; out_replay; out_stale; out_drop; } size = 16;
        const default_action = out_drop(OUT_DROP_OVERLAP);
        const entries = {
            (0, 0, _, _, _, _, _, _, _, _, _, _, _, _, _)                                 : out_translate();
            (0, _, _, _, _, _, _, _, _, _, _, _, _, _, _)                                 : out_commit();
            (32w0 &&& 32w0x80000000, _, _, _, _, _, _, _, _, _, _, _, _, _, _)            : out_drop(OUT_DROP_AHEAD);
            (_, _, 32w0 &&& 32w0x80000000, _, _, _, _, _, _, _, _, _, _, _, _)            : out_translate();
            (_, _, _, 0, _, _, _, _, _, _, _, _, _, _, _)                                 : out_zero();
            // replay: starts at the image (p == 0) and covers it (y = q + Leff >= 0), leading frame good
            (_, _, _, _, 0, 32w0 &&& 32w0x80000000, _, 1, _, 0, 0, 0, 0, _, _)            : out_replay();  // READ
            (_, _, _, _, 0, 32w0 &&& 32w0x80000000, _, _, 1, 0, _, _, _, 0, 0)            : out_replay();  // CONTROL
            (_, _, _, _, _, _, 0, _, _, _, _, _, _, _, _)                                 : out_stale();
            (_, _, _, _, _, _, 32w0x80000000 &&& 32w0x80000000, _, _, _, _, _, _, _, _)   : out_stale();
        }
    }

    Register<bit<32>, slot_t>(16, 0) img_wend;
    RegisterAction<bit<32>, slot_t, bit<32>>(img_wend) wend_arm = {
        void apply(inout bit<32> v) { v = m.qx; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_wend) wend_commit = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v + m.qx; v = v + m.t; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_wend) wend_fwd = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v + m.qx; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(img_wend) wend_rev = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = m.qx - v; } };
    action do_wend_arm() { wend_arm.execute(m.idx); }
    action do_wend_commit() { hdr.tcp.seq = wend_commit.execute(m.idx); }
    action do_wend_fwd() { hdr.tcp.seq = wend_fwd.execute(m.idx); }
    action do_wend_rev() { m.r = wend_rev.execute(m.idx); }
    table img_wend_t {
        key = { m.dir : exact; m.shape : ternary; m.result : ternary; }
        actions = { do_wend_arm; do_wend_commit; do_wend_fwd; do_wend_rev; NoAction; } size = 8;
        const default_action = NoAction();
        const entries = { (1, SH_SYNACK_OK, _) : do_wend_arm(); (1, 8w4 &&& 8w0xFE, OUT_COMMIT) : do_wend_commit();
                          (1, 8w4 &&& 8w0xFE, _) : do_wend_fwd(); (2, SH_ACK, _) : do_wend_rev(); }
    }

    /* ============ padder transform, gated by the mapper's pad decision ============ */
    action read_eligible(){hdr.rtp.setValid();hdr.rtp.data_last=hdr.rtn.data_last;hdr.rtp.filler=72w0x290106290206290306;hdr.rtn.setInvalid();hdr.dl.len=8w0x2f;hdr.ip.len=hdr.ip.len+16w9;}
    table read_pad_t{actions={read_eligible;}size=1;const default_action=read_eligible();}
    action ctl_eligible(){hdr.ctp1.setValid();hdr.ctp1.on_lo=hdr.ctn.on_lo;hdr.ctp1.off=hdr.ctn.off;hdr.ctp1.status=hdr.ctn.status;hdr.ctp1.filler_a=72w0x29032802002d010000;hdr.ctp2.setValid();hdr.ctp2.filler_b=80w0x2041002e010000a04100;hdr.ctp2.crc2=16w0xf995;hdr.ctn.setInvalid();hdr.dl.len=8w0x2f;hdr.ip.len=hdr.ip.len+16w21;}
    table ctl_pad_t{actions={ctl_eligible;}size=1;const default_action=ctl_eligible();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_dl;
    action crc_dl(){m.dlcrc=hash_dl.get({hdr.dl.start,hdr.dl.len,hdr.dl.ctrl,hdr.dl.dst,hdr.dl.src});}
    table crc_dl_t{actions={crc_dl;}size=1;const default_action=crc_dl();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_read_tail;
    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.rtp.data_last,hdr.rtp.filler});}
    table crc_read_tail_t{actions={crc_read_tail;}size=1;const default_action=crc_read_tail();}
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail1;
    action crc_ctl_tail1(){m.ctcrc1=hash_ctl_tail1.get({hdr.ctp1.on_lo,hdr.ctp1.off,hdr.ctp1.status,hdr.ctp1.filler_a});}
    table crc_ctl_tail1_t{actions={crc_ctl_tail1;}size=1;const default_action=crc_ctl_tail1();}
    action render_dl_crc(){hdr.dl.crc=m.dlcrc[7:0]++m.dlcrc[15:8];}
    table render_dl_crc_t{actions={render_dl_crc;}size=1;const default_action=render_dl_crc();}
    action render_read_crc(){hdr.rtp.crc2=m.rtcrc[7:0]++m.rtcrc[15:8];}
    table render_read_crc_t{actions={render_read_crc;}size=1;const default_action=render_read_crc();}
    action render_ctl_crc(){hdr.ctp1.crc1=m.ctcrc1[7:0]++m.ctcrc1[15:8];}
    table render_ctl_crc_t{actions={render_ctl_crc;}size=1;const default_action=render_ctl_crc();}

    /* ============ reverse: monotone inverse on both window edges (spec section 6) ============ */
    action rev_prep() { m.y = m.r + m.win32; m.z = m.r + IMAGE_LEN; m.pm = m.q + m.r; m.t = m.q - m.p; }
    table rev_prep_t { actions = { rev_prep; } size = 1; const default_action = rev_prep(); }
    action rev_translate() { hdr.tcp.ack = m.pm; m.result = OUT_REV_TRANSLATE; m.changed = 1; }
    action rev_withhold_zero() { hdr.tcp.ack = m.p; hdr.tcp.window = 0; m.result = OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_withhold_open() { hdr.tcp.ack = m.p; m.s_end = m.y + m.t; m.wide = 1;
                                 m.result = OUT_REV_WITHHOLD; m.changed = 1; }
    action rev_drop() { m.result = OUT_REV_DROP_STALE; md.drop_ctl = 3w1; }
    table classify_rev {
        key = { m.r : ternary; m.z : ternary; m.y : ternary; }
        actions = { rev_translate; rev_withhold_zero; rev_withhold_open; rev_drop; } size = 4;
        const default_action = rev_drop();
        const entries = {
            (32w0 &&& 32w0x80000000, _, _)                                    : rev_translate();
            (_, 32w0 &&& 32w0x80000000, 32w0x80000000 &&& 32w0x80000000)     : rev_withhold_zero();
            (_, 32w0 &&& 32w0x80000000, 32w0 &&& 32w0x80000000)              : rev_withhold_open();
        }
    }
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;
    action window_exact() { hdr.tcp.window = narrow_win.get({m.s_end[15:0]}); }
    action window_clamp() { hdr.tcp.window = 0xffff; }
    table window_t {
        key = { m.s_end : ternary; }
        actions = { window_exact; window_clamp; } size = 2; const default_action = window_clamp();
        const entries = { 32w0 &&& 32w0xFFFF0000 : window_exact(); 32w0 &&& 32w0 : window_clamp(); }
    }

    /* ============ outcome bookkeeping (observability; not needed for correctness) ============ */
    Counter<bit<32>, bit<8>>(32, CounterType_t.PACKETS) outcome;
    action count() { outcome.count(m.result); }
    table count_t { actions = { count; } size = 1; const default_action = count(); }
    action drop_odd() { m.result = OUT_DROP_ODD; md.drop_ctl = 3w1; }
    action native() { m.result = OUT_NATIVE; }
    action armed_map() { m.result = OUT_ARM_MAP; }
    action armed_nat() { m.result = OUT_ARM_NAT; }
    table settle_t {
        key = { m.dir : ternary; m.shape : ternary; m.mode : ternary; }
        actions = { drop_odd; native; armed_map; armed_nat; NoAction; } size = 8; const default_action = NoAction();
        const entries = { (0, _, _) : NoAction(); (1, SH_SYNACK_OK, _) : armed_map(); (1, SH_SYN, _) : armed_nat();
                          (_, SH_ODD, 1) : drop_odd(); (_, _, 0) : native(); }
    }

    apply {
        /* stage 0 */
        if (hdr.tcp.isValid()) { conn.apply(); leff_t.apply(); prep_t.apply(); }
        else if (m.ip_odd == 1) { odd_ip_t.apply(); }
        shape_t.apply();
        if (hdr.dl.isValid()) { in_dl_t.apply(); }
        if (hdr.rb0.isValid()) { read_profile.apply(); in_rb0_t.apply(); in_rb1_t.apply(); in_rt_t.apply(); }
        if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); }
        /* padder native-CRC verdict */
        if (hdr.dl.crc != (m.in_dl[7:0] ++ m.in_dl[15:8])) { m.badh = 1; }
        if (hdr.rb0.crc0 != (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { m.rbad0 = 1; }
        if (hdr.rb1.crc1 != (m.in_rb1[7:0] ++ m.in_rb1[15:8])) { m.rbad1 = 1; }
        if (hdr.rtn.crc2 != (m.in_rt[7:0] ++ m.in_rt[15:8])) { m.rbadt = 1; }
        if (hdr.cb0.crc0 != (m.in_cb0[7:0] ++ m.in_cb0[15:8])) { m.cbad0 = 1; }
        if (hdr.ctn.crc1 != (m.in_ct[7:0] ++ m.in_ct[15:8])) { m.cbadt = 1; }
        /* mapper state */
        mode_t.apply();
        settle_t.apply();      // outcomes no classifier produces; the classifiers overwrite m.result later
        front_t.apply();
        derive_t.apply();
        acct_t.apply();
        img_end_t.apply();
        img_start_t.apply();
        if (m.dir == 1 && (m.shape == SH_ACK || m.shape == SH_NOACK)) {
            fwd_prep_t.apply();
            if (m.mode == 1) { classify_fwd.apply(); }
        }
        if ((m.dir == 1 && m.shape == SH_SYNACK_OK) || m.mode == 1) { img_wend_t.apply(); }
        /* pad only on commit or replay; the verdict that allowed either also fixes the profile */
        if (m.pad == 1) {
            if (m.read_shape == 1) { read_pad_t.apply(); } else { ctl_pad_t.apply(); }
            crc_dl_t.apply(); render_dl_crc_t.apply();
            if (hdr.rtp.isValid()) { crc_read_tail_t.apply(); render_read_crc_t.apply(); }
            if (hdr.ctp1.isValid()) { crc_ctl_tail1_t.apply(); render_ctl_crc_t.apply(); }
        } else if (m.dir == 2 && m.shape == SH_ACK && m.mode == 1) {   // exclusive with padding
            rev_prep_t.apply(); classify_rev.apply();
            if (m.wide == 1) { window_t.apply(); }
        }
        count_t.apply();
    }
}

control EgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {
    Checksum() ip_new; Checksum() tcp_new;
    apply {
        if (m.pad == 1w1) {
            hdr.ip.checksum = ip_new.update({hdr.ip.version, hdr.ip.ihl, hdr.ip.tos, hdr.ip.len, hdr.ip.id, hdr.ip.flags,
                                             hdr.ip.frag, hdr.ip.ttl, hdr.ip.proto, hdr.ip.src, hdr.ip.dst});
        }
        if (m.changed == 1w1) {
            /* Incremental: residual + current values of every word the parser subtracted. Field order keeps
               each header's byte parity equal to its parity in the segment; 8w0 pads the odd-length ones. */
            hdr.tcp.checksum = tcp_new.update({hdr.tcp.seq, hdr.tcp.ack, hdr.tcp.window, hdr.ip.len,
                hdr.mss.kind, hdr.mss.len, hdr.mss.mss,
                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,
                hdr.rb0.tpctrl, hdr.rb0.appctrl, hdr.rb0.func, hdr.rb0.iin, hdr.rb0.g_group, hdr.rb0.g_var, hdr.rb0.g_qual,
                hdr.rb0.g_start, hdr.rb0.g_stop, hdr.rb0.data_mid, hdr.rb0.crc0,
                hdr.rb1.data, hdr.rb1.crc1,
                hdr.rtn.data_last, hdr.rtn.crc2, 8w0,
                hdr.rtp.data_last, hdr.rtp.filler, hdr.rtp.crc2,
                hdr.cb0.tpctrl, hdr.cb0.appctrl, hdr.cb0.func, hdr.cb0.iin, hdr.cb0.g_group, hdr.cb0.g_var, hdr.cb0.g_qual,
                hdr.cb0.g_count, hdr.cb0.index, hdr.cb0.crob_code, hdr.cb0.crob_count, hdr.cb0.on_hi, hdr.cb0.crc0,
                hdr.ctn.on_lo, hdr.ctn.off, hdr.ctn.status, hdr.ctn.crc1, 8w0,
                hdr.ctp1.on_lo, hdr.ctp1.off, hdr.ctp1.status, hdr.ctp1.filler_a, hdr.ctp1.crc1,
                hdr.ctp2.filler_b, hdr.ctp2.crc2,
                m.residual});
        }
        pkt.emit(hdr.eth); pkt.emit(hdr.ip); pkt.emit(hdr.tcp); pkt.emit(hdr.mss); pkt.emit(hdr.dl);
        pkt.emit(hdr.rb0); pkt.emit(hdr.rb1); pkt.emit(hdr.rtn); pkt.emit(hdr.rtp);
        pkt.emit(hdr.cb0); pkt.emit(hdr.ctn); pkt.emit(hdr.ctp1); pkt.emit(hdr.ctp2);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
