/* Response-side TCP sequence/ACK/window mapper for Option B' padding (outstation -> master).
   Spec: TRANSPORT_MAPPER_SPEC.md. Software model: framework/size/case4_response_mapper.py, whose
   six fields are the six registers below and whose case names are the OUT_* codes.

   Standalone build. Egress-resident, because pipe-0 ingress is already full and the real verdict
   comes from case4_pad58b_wire.p4's egress CRC gate. Here a shape-only stand-in (IP length plus
   DNP3 link start/length) supplies that verdict, and the pad decision is exported as a per-outcome
   counter instead of by padding (spec section 9).

   Register discipline (see integration/core/M_RECIRCULATION_VERDICT.md): each register is touched
   by exactly one table, and the only state a reverse packet writes (acct.hi = A) lives in the same
   stateful ALU that makes the forward commit decision, so no register is read early and written
   late. */
#include <core.p4>
#include <tna.p4>

const bit<8> R_NONE = 0;        // not a configured connection: untouched
const bit<8> R_FWD = 1;         // outstation -> master, plain segment
const bit<8> R_REV = 2;         // master -> outstation, ACK set
const bit<8> R_PASS = 3;        // configured, never translated (master SYN, ACK-less segment)
const bit<8> R_ARM_MAP = 4;     // outstation SYN-ACK, MSS-only: arm mapped
const bit<8> R_ARM_NAT = 5;     // any other outstation SYN-ACK: native for life
const bit<8> R_ODD = 6;         // shape the mapper cannot translate

const bit<8> OUT_COMMIT = 1;  const bit<8> OUT_TRANSLATE = 2; const bit<8> OUT_ZERO = 3;
const bit<8> OUT_REPLAY = 4;  const bit<8> OUT_STALE = 5;     const bit<8> OUT_DROP_OVERLAP = 6;
const bit<8> OUT_DROP_AHEAD = 7; const bit<8> OUT_DROP_ODD = 8;
const bit<8> OUT_REV_TRANSLATE = 9; const bit<8> OUT_REV_WITHHOLD = 10; const bit<8> OUT_REV_DROP_STALE = 11;
const bit<8> OUT_NATIVE = 12; const bit<8> OUT_ARM_MAP = 13; const bit<8> OUT_ARM_NAT = 14;

const bit<32> IMAGE_LEN = 58;

typedef bit<4> slot_t;          // 16 connection slots
struct pair32 { bit<32> lo; bit<32> hi; }

header eth_h { bit<48> dst; bit<48> src; bit<16> type; }
header ip_h { bit<4> version; bit<4> ihl; bit<8> tos; bit<16> len; bit<16> id; bit<3> flags;
              bit<13> frag; bit<8> ttl; bit<8> proto; bit<16> checksum; bit<32> src; bit<32> dst; }
header tcp_h { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack; bit<4> offset; bit<4> reserved;
               bit<8> flags; bit<16> window; bit<16> checksum; bit<16> urgent; }
header mss_h { bit<8> kind; bit<8> len; bit<16> mss; }
header peek_h { bit<16> start; bit<8> len; }      // first three DNP3 link bytes (verdict stand-in)

struct headers_t { eth_h eth; ip_h ip; tcp_h tcp; mss_h mss; peek_h peek; }

/* seq and ack are rewritten whole from one metadata source each; keep each in its own 32-bit
   container so the writes never share a container with untouched TCP fields (Class 13). */
@pa_container_size("egress", "hdr.tcp.seq", 32) @pa_container_size("egress", "hdr.tcp.ack", 32)

struct meta_t {
    bit<16> residual;            // TCP checksum minus old seq/ack/window/checksum words
    bit<8>  odd;                 // parser: unsupported IP/TCP shape
    bit<8>  has_mss;
    bit<8>  dir; slot_t idx; bit<8> enable; bit<8> role; bit<8> mode;
    bit<8>  cls; bit<32> d;      // padder verdict: class 0/1(READ)/2(CONTROL), growth 0/9/21
    bit<32> leff; bit<32> s_end; bit<32> ina;   // acct operand: W growth / ISN+1 / ACK by role
    bit<32> front_ret;           // s - N
    bit<8>  grant;
    /* Forward and reverse temporaries share fields (a packet is one or the other):
         field  forward            reverse
         q      s - e_end          e_end
         p      s - e_start        e_start
         y      q + Leff           r2 = r + window
         z      p + Leff           r + 58
         pm     p - 58             e_end + r
         t      q + Leff + d       e_end - e_start
         s_end  s + Leff           opened window (32-bit, before clamp)
         qx     wire offset        ACK (operand of img_wend)          */
    bit<32> q; bit<32> p; bit<32> y; bit<32> z; bit<32> pm; bit<32> t; bit<32> qx; bit<32> r;
    bit<8>  result; bit<1> changed; bit<8> pad; bit<8> wide;
}

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
        m.odd = 0; m.has_mss = 0; m.dir = 0; m.mode = 0; m.cls = 0; m.d = 0; m.grant = 0;
        m.result = 0; m.changed = 0; m.pad = 0; m.wide = 0;
        transition eth;
    }
    state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { 16w0x0800: ip; default: accept; } }
    state ip {
        pkt.extract(hdr.ip);
        transition select(hdr.ip.version, hdr.ip.ihl, hdr.ip.proto) { (4w4, 4w5, 8w6): ip_frag; (4w4, _, 8w6): odd; default: accept; }
    }
    state ip_frag { transition select(hdr.ip.frag, hdr.ip.flags) { (13w0, 3w0): tcp; (13w0, 3w2): tcp; default: odd; } }
    state odd { m.odd = 1; transition accept; }     // no TCP header parsed; odd_ip_t classifies it
    state tcp {
        pkt.extract(hdr.tcp);
        tcp_old.subtract({hdr.tcp.seq, hdr.tcp.ack, hdr.tcp.window, hdr.tcp.checksum});
        m.residual = tcp_old.get();
        transition select(hdr.tcp.offset) { 4w5: peek_len; 4w6: mss; default: tcp_odd; }
    }
    state tcp_odd { m.odd = 1; transition accept; }
    state mss { pkt.extract(hdr.mss); m.has_mss = 1; transition accept; }
    state peek_len { transition select(hdr.ip.len) { 16w89: peek; 16w77: peek; default: accept; } }
    state peek { pkt.extract(hdr.peek); transition accept; }
}

/* ------------------------------------------------------------------ egress: the mapper */
control Egress(inout headers_t hdr, inout meta_t m, in egress_intrinsic_metadata_t eg,
               in egress_intrinsic_metadata_from_parser_t prs, inout egress_intrinsic_metadata_for_deparser_t md,
               inout egress_intrinsic_metadata_for_output_port_t port) {

    /* stage-0 lookups -------------------------------------------------------------------------- */
    action fwd_conn(slot_t idx, bit<8> enable) { m.dir = 1; m.idx = idx; m.enable = enable; }
    action rev_conn(slot_t idx) { m.dir = 2; m.idx = idx; m.enable = 0; }
    table conn {
        key = { hdr.ip.src : exact; hdr.ip.dst : exact; hdr.tcp.sport : exact; hdr.tcp.dport : exact; }
        actions = { fwd_conn; rev_conn; NoAction; } size = 32; default_action = NoAction();
    }
    action odd_conn(slot_t idx) { m.dir = 3; m.idx = idx; }
    table odd_ip_t {       // IP options / fragments between configured endpoints (no TCP header parsed)
        key = { hdr.ip.src : exact; hdr.ip.dst : exact; }
        actions = { odd_conn; NoAction; } size = 32; default_action = NoAction();
    }

    action verdict(bit<8> cls, bit<32> d) { m.cls = cls; m.d = d; }
    table verdict_standin {    // STAND-IN for case4_pad58b_wire's (shape AND native CRCs) verdict
        key = { hdr.ip.len : exact; hdr.peek.start : exact; hdr.peek.len : exact; hdr.tcp.flags : ternary; }
        actions = { verdict; NoAction; } size = 2; const default_action = NoAction();
        const entries = {
            (16w89, 16w0x0564, 8w0x26, 8w0x00 &&& 8w0x07) : verdict(1, 9);    // READ 49 -> 58, no SYN/RST/FIN
            (16w77, 16w0x0564, 8w0x1c, 8w0x00 &&& 8w0x07) : verdict(2, 21);   // CONTROL 37 -> 58
        }
    }
    /* 16 -> 32-bit widening through identity hashes: a plain cast ties the 16-bit header field's
       container alignment to every 32-bit field it is added to (tcp.seq), which PHV cannot place. */
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) widen_len;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) widen_win;
    action leff_data() { m.leff = widen_len.get({hdr.ip.len}) + 32w0xFFFFFFD8; }   // ip.len - 40
    action leff_fin()  { m.leff = widen_len.get({hdr.ip.len}) + 32w0xFFFFFFD9; }   // ip.len - 40 + FIN
    table leff_t {
        key = { hdr.tcp.flags : ternary; }
        actions = { leff_data; leff_fin; NoAction; } size = 2; const default_action = NoAction();
        // both cases are entries: an action reading a hash must run on the hit pathway
        const entries = { 8w0x01 &&& 8w0x01 : leff_fin(); 8w0x00 &&& 8w0x01 : leff_data(); }
    }

    /* stage-1: role and derived lengths ----------------------------------------------------------- */
    action set_role(bit<8> role) { m.role = role; }
    table role_t {
        key = { m.dir : exact; m.odd : ternary; hdr.tcp.flags : ternary; m.has_mss : ternary;
                hdr.mss.kind : ternary; hdr.mss.len : ternary; }
        actions = { set_role; } size = 16; const default_action = set_role(R_NONE);
        const entries = {
            (1, 0, 8w0x12 &&& 8w0x12, 1, 8w2, 8w4)       : set_role(R_ARM_MAP);
            (1, _, 8w0x02 &&& 8w0x02, _, _, _)                : set_role(R_ARM_NAT);
            (2, _, 8w0x02 &&& 8w0x02, _, _, _)                : set_role(R_PASS);
            (1, 1, _, _, _, _)                                : set_role(R_ODD);
            (2, 1, _, _, _, _)                                : set_role(R_ODD);
            (3, _, _, _, _, _)                                : set_role(R_ODD);
            (1, 0, _, 0, _, _)                            : set_role(R_FWD);
            (2, 0, 8w0x10 &&& 8w0x10, 0, _, _)            : set_role(R_REV);
            (2, 0, _, 0, _, _)                            : set_role(R_PASS);
        }
    }
    /* A stateful ALU reads at most two PHV fields across all its actions, so each register's
       operands are staged into shared slots here, by role: acct reads {ina, leff}; img_wend reads
       {qx, t}. */
    action derive_fwd() { m.s_end = hdr.tcp.seq + m.leff; m.ina = m.leff + m.d; }
    action derive_arm() { m.ina = hdr.tcp.seq + 1; m.qx = hdr.tcp.seq + 1; }
    action derive_rev() { m.ina = hdr.tcp.ack; m.qx = hdr.tcp.ack; }
    table derive_t {
        key = { m.role : exact; }
        actions = { derive_fwd; derive_arm; derive_rev; NoAction; } size = 4; const default_action = NoAction();
        const entries = { R_FWD : derive_fwd(); R_ARM_MAP : derive_arm(); R_REV : derive_rev(); }
    }

    /* mode: 0 native, 1 mapped. Written only by SYN-ACKs. --------------------------------------- */
    Register<bit<8>, slot_t>(16, 0) mode;
    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_arm_map = { void apply(inout bit<8> v) { v = 1; } };
    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_arm_nat = { void apply(inout bit<8> v) { v = 0; } };
    RegisterAction<bit<8>, slot_t, bit<8>>(mode) mode_read = { void apply(inout bit<8> v, out bit<8> rv) { rv = v; } };
    action do_mode_arm_map() { mode_arm_map.execute(m.idx); }
    action do_mode_arm_nat() { mode_arm_nat.execute(m.idx); }
    action do_mode_read() { m.mode = mode_read.execute(m.idx); }
    table mode_t {
        key = { m.role : exact; }
        actions = { do_mode_arm_map; do_mode_arm_nat; do_mode_read; NoAction; } size = 8; const default_action = NoAction();
        const entries = { R_ARM_MAP : do_mode_arm_map(); R_ARM_NAT : do_mode_arm_nat();
                          R_FWD : do_mode_read(); R_REV : do_mode_read(); R_ODD : do_mode_read(); }
    }

    /* front = N, the native frontier. Forward only. --------------------------------------------- */
    Register<bit<32>, slot_t>(16, 0) front;
    RegisterAction<bit<32>, slot_t, bit<32>>(front) front_arm = {
        void apply(inout bit<32> v) { v = hdr.tcp.seq + 1; } };
    RegisterAction<bit<32>, slot_t, bit<32>>(front) front_step = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = hdr.tcp.seq - v; if (v == hdr.tcp.seq) { v = v + m.leff; } } };
    action do_front_arm() { front_arm.execute(m.idx); }
    action do_front_step() { m.front_ret = front_step.execute(m.idx); }
    table front_t {
        key = { m.role : exact; }
        actions = { do_front_arm; do_front_step; NoAction; } size = 4; const default_action = NoAction();
        const entries = { R_ARM_MAP : do_front_arm(); R_FWD : do_front_step(); }
    }

    /* acct = {lo: W wire frontier, hi: U = W - A, wire bytes the master has not acknowledged}.
       Commit iff U == 0. (A Tofino-1 SALU compare takes one memory operand, so "W == A" is kept as
       a difference.) Forward growth adds to both words; a master ACK sets U = W - ACK. */
    Register<pair32, slot_t>(16, {0, 0}) acct;
    RegisterAction<pair32, slot_t, bit<8>>(acct) acct_arm = {
        void apply(inout pair32 v) { v.lo = m.ina; v.hi = 0; } };
    RegisterAction<pair32, slot_t, bit<8>>(acct) acct_try = {
        void apply(inout pair32 v, out bit<8> rv) {
            rv = 0;
            if (v.hi == 0) { v.lo = v.lo + m.ina; v.hi = v.hi + m.ina; rv = 1; }
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
    table acct_t {
        key = { m.role : exact; m.front_ret : ternary; m.enable : ternary; m.cls : ternary; }
        actions = { do_acct_arm; do_acct_try; do_acct_grow; do_acct_rev; NoAction; } size = 8;
        const default_action = NoAction();
        const entries = {
            (R_ARM_MAP, _, _, _)   : do_acct_arm();
            (R_FWD, 0, 1, 1)       : do_acct_try();
            (R_FWD, 0, 1, 2)       : do_acct_try();
            (R_FWD, 0, _, _)       : do_acct_grow();
            (R_REV, _, _, _)       : do_acct_rev();
        }
    }

    /* image edges: e_end, e_start (native). ---------------------------------------------------- */
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
        key = { m.role : exact; m.grant : ternary; }
        actions = { do_end_arm; do_end_commit; do_end_fwd; do_end_rev; NoAction; } size = 8;
        const default_action = NoAction();
        // grant is the SALU predicate word (nonzero = granted, encoding not assumed): 0 first
        const entries = { (R_ARM_MAP, _) : do_end_arm(); (R_FWD, 0) : do_end_fwd();
                          (R_FWD, _) : do_end_commit(); (R_REV, _) : do_end_rev(); }
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
        key = { m.role : exact; m.grant : ternary; }
        actions = { do_start_arm; do_start_commit; do_start_fwd; do_start_rev; NoAction; } size = 8;
        const default_action = NoAction();
        const entries = { (R_ARM_MAP, _) : do_start_arm(); (R_FWD, 0) : do_start_fwd();
                          (R_FWD, _) : do_start_commit(); (R_REV, _) : do_start_rev(); }
    }

    /* forward classification (spec section 5) ---------------------------------------------------- */
    action fwd_prep() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + 32w0xFFFFFFC6; m.t = m.q + m.ina; }
    table fwd_prep_t { actions = { fwd_prep; } size = 1; const default_action = fwd_prep(); }

    action out_commit()    { m.qx = m.q;  m.result = OUT_COMMIT;    m.pad = 1; m.changed = 1; }
    action out_translate() { m.qx = m.q;  m.result = OUT_TRANSLATE; m.changed = 1; }
    action out_zero()      { m.qx = m.pm; m.result = OUT_ZERO;      m.changed = 1; }
    action out_replay()    { m.qx = m.pm; m.result = OUT_REPLAY;    m.pad = 1; m.changed = 1; }
    action out_stale()     { m.qx = m.pm; m.result = OUT_STALE;     m.changed = 1; }
    action out_drop(bit<8> why) { m.result = why; md.drop_ctl = 3w1; }
    table classify_fwd {
        key = { m.front_ret : ternary; m.grant : ternary; m.q : ternary; m.leff : ternary;
                m.p : ternary; m.y : ternary; m.z : ternary; m.cls : ternary; }
        actions = { out_commit; out_translate; out_zero; out_replay; out_stale; out_drop; } size = 16;
        const default_action = out_drop(OUT_DROP_OVERLAP);
        const entries = {
            (0, 0, _, _, _, _, _, _)                                   : out_translate();   // frontier: q >= 0
            (0, _, _, _, _, _, _, _)                                   : out_commit();      // grant != 0
            (32w0 &&& 32w0x80000000, _, _, _, _, _, _, _)              : out_drop(OUT_DROP_AHEAD);
            (_, _, 32w0 &&& 32w0x80000000, _, _, _, _, _)              : out_translate();
            (_, _, _, 0, _, _, _, _)                                   : out_zero();
            (_, _, _, _, 0, 0, _, 1)                                   : out_replay();
            (_, _, _, _, 0, 0, _, 2)                                   : out_replay();
            (_, _, _, _, _, _, 0, _)                                   : out_stale();
            (_, _, _, _, _, _, 32w0x80000000 &&& 32w0x80000000, _)     : out_stale();
        }
    }

    /* we, the image's wire end (ws = we - 58). Forward output is the wire sequence number. ------- */
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
        key = { m.role : exact; m.result : ternary; }
        actions = { do_wend_arm; do_wend_commit; do_wend_fwd; do_wend_rev; NoAction; } size = 8;
        const default_action = NoAction();
        const entries = { (R_ARM_MAP, _) : do_wend_arm(); (R_FWD, OUT_COMMIT) : do_wend_commit();
                          (R_FWD, _) : do_wend_fwd(); (R_REV, _) : do_wend_rev(); }
    }

    /* reverse: monotone inverse on both window edges (spec section 6) ---------------------------- */
    action rev_prep() { m.y = m.r + widen_win.get({hdr.tcp.window}); m.z = m.r + IMAGE_LEN;
                        m.pm = m.q + m.r; m.t = m.q - m.p; }
    table rev_prep_t {   // keyed so the hash-reading action runs on the hit pathway
        key = { m.role : exact; } actions = { rev_prep; NoAction; } size = 1;
        const default_action = NoAction(); const entries = { R_REV : rev_prep(); }
    }

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
    /* Narrowed through an identity hash for the same reason as the widening above: a direct slice
       ties tcp.window's container (shared with the TCP flag bytes) to the 32-bit arithmetic chain. */
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;
    action window_exact() { hdr.tcp.window = narrow_win.get({m.s_end[15:0]}); }
    action window_clamp() { hdr.tcp.window = 0xffff; }
    table window_t {
        key = { m.s_end : ternary; }
        actions = { window_exact; window_clamp; } size = 2; const default_action = window_clamp();
        const entries = { 32w0 &&& 32w0xFFFF0000 : window_exact(); 32w0 &&& 32w0 : window_clamp(); }
    }

    /* outcome counter: the observable record of every decision, including pad ------------------- */
    Counter<bit<32>, bit<8>>(32, CounterType_t.PACKETS) outcome;
    action count() { outcome.count(m.result); }
    table count_t { actions = { count; } size = 1; const default_action = count(); }
    action drop_odd() { m.result = OUT_DROP_ODD; md.drop_ctl = 3w1; }
    action native() { m.result = OUT_NATIVE; }
    action armed_map() { m.result = OUT_ARM_MAP; }
    action armed_nat() { m.result = OUT_ARM_NAT; }
    table settle_t {    // outcomes not produced by the classifiers
        key = { m.role : exact; m.mode : ternary; }
        actions = { drop_odd; native; armed_map; armed_nat; NoAction; } size = 8; const default_action = NoAction();
        const entries = { (R_ODD, 1) : drop_odd(); (R_ODD, _) : native(); (R_FWD, 0) : native(); (R_REV, 0) : native();
                          (R_PASS, _) : native(); (R_ARM_MAP, _) : armed_map(); (R_ARM_NAT, _) : armed_nat(); }
    }

    apply {
        if (hdr.tcp.isValid()) {
            conn.apply();
            if (hdr.peek.isValid()) { verdict_standin.apply(); }
            leff_t.apply();
        }
        else if (hdr.ip.isValid() && m.odd == 1) { odd_ip_t.apply(); }
        role_t.apply();
        derive_t.apply();
        mode_t.apply();
        front_t.apply();
        acct_t.apply();
        img_end_t.apply();
        img_start_t.apply();
        if (m.role == R_FWD) { fwd_prep_t.apply(); if (m.mode == 1) { classify_fwd.apply(); } }
        if (m.role == R_ARM_MAP || m.mode == 1) { img_wend_t.apply(); }
        if (m.role == R_REV && m.mode == 1) {
            rev_prep_t.apply(); classify_rev.apply();
            if (m.wide == 1) { window_t.apply(); }
        }
        settle_t.apply();
        count_t.apply();
    }
}

control EgDeparser(packet_out pkt, inout headers_t hdr, in meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {
    Checksum() tcp_new;
    apply {
        if (m.changed == 1w1) {
            hdr.tcp.checksum = tcp_new.update({hdr.tcp.seq, hdr.tcp.ack, hdr.tcp.window, m.residual});
        }
        pkt.emit(hdr.eth); pkt.emit(hdr.ip); pkt.emit(hdr.tcp); pkt.emit(hdr.mss); pkt.emit(hdr.peek);
    }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
