"""The two-READ-target profile (m12p_c21+): mixed READ 91 -> 141 and full integrity READ 247 -> 271 by the
pipe-1 egress prefix padder, E mapping of the already-padded READ, and N admission of the mixed READ."""
import json

from .common import CONSTANTS_TWO, neg, once
from .read_policy import PASSTHROUGH_READS, _neg_entry_rows, transform_read_prepadded_e


TWO_MIXED, TWO_FULL = 'mixed_g1v2_g30v1_91', 'integrity_247'


def two_read_shapes():
    """The two-READ-target profile's per-shape constants (read_complete_01/vectors/derive_two_read.py: proved
    construct == pad_read(targets=[141, 271]) on 512 varied natives per shape and on the live captures)."""
    doc = json.loads(CONSTANTS_TWO.read_text())
    return doc['shapes'][TWO_MIXED], doc['shapes'][TWO_FULL]


def _ones_fold(data, acc):
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) | data[i + 1]
        acc = (acc & 0xFFFF) + (acc >> 16)
    return acc


def transform_two_read_pad_pipe1(src, _image=None):
    """Two-READ-target prefix padder in PIPE-1 EGRESS (replaces the range padder of read_prefix_p1).

    Same placement, handoff and gating as transform_read_prefix_p1 (egress port 180, tev kind 11 stage 0, p1_conn
    size enable, block-0 CRC verified before any rewrite), for two single-frame READ responses selected by link LEN:
      mixed   ip.len 131, dl.len 0x4c -> 50-B prefix (22 points in it) + rewritten frame = 141 (prefix_mx)
      full    ip.len 287, dl.len 0xd6 -> 24-B prefix (0 points in it) + rewritten frame = 271 (prefix_full)
    Both natives start block 0 with the same g1v2 q00 [0,15] object header, so link LEN is the discriminator; the
    profile also requires the response function, FIR+FIN transport and that object header. In both, the original
    frame becomes the FIN continuation: transport renumbered, its 4 application-header octets become the last 4
    padding points (zeros), block-0 CRC recomputed on chip. Every live field (addresses, sequences, app control,
    IIN, measurements) is carried from the packet; the compile constants are the padding object header, the zero
    padding points with their block CRCs, the prefix link LEN, and the link-header CRC delta for the LEN change --
    all invariant across samples (constants_two_read.json). The original native tail is not parsed (it rides
    m.residual through the incremental TCP checksum): this padder validates the link header CRC only by delta and
    block 0 by recomputation, not the native tail."""
    cm, cf = two_read_shapes()
    if len(cm['block0_tail']) != 22 or len(cm['rest']) != 44 or cf['rest'] or len(cf['padobj_head']) != 14:
        raise SystemExit('unexpected two-read prefix constant layout')
    words = [(64, cm['rest'][0:16]), (64, cm['rest'][16:32]), (48, cm['rest'][32:44])]
    tp_rows = ''.join('(8w0x%02x):set_tp(8w0x%02x,8w0x%02x);' % (0xC0 | s, 0x40 | s, 0x80 | ((s + 1) & 0x3f)) for s in range(64))
    zdecl = ''.join('bit<%d> w%d;' % (w, i) for i, (w, _) in enumerate(words))
    zset = ''.join('hdr.plz.w%d=%dw0x%s;' % (i, w, h) for i, (w, h) in enumerate(words))
    # mixed: TCP length growth + the one's-complement sum of the constant remainder (it starts at the even payload
    # offset 28 = pll 10 + plu 16 + pluc 2, so its 16-bit words align with the packet's)
    folded_mx = _ones_fold(bytes.fromhex(cm['rest']), cm['added'])
    obj = tuple(cm['response_headers'][0])
    if obj != tuple(cf['response_headers'][0]) or obj != (1, 2, 0, 0, 15):
        raise SystemExit('both two-READ responses must start with the g1v2 q00 [0,15] header, got %r / %r'
                         % (cm['response_headers'][0], cf['response_headers'][0]))
    p = dict(zdecl=zdecl, zset=zset, tp_rows=tp_rows,
             mx_len=cm['native_link_len'], mx_ip=cm['native_ip_len'], mx_plen=cm['prefix_link_len'],
             mx_ldelta=cm['link_crc_delta'], mx_hi=int(cm['block0_tail'][:14], 16), mx_lo=int(cm['block0_tail'][14:], 16),
             mx_delta=cm['added'], mx_folded=folded_mx,
             f_len=cf['native_link_len'], f_ip=cf['native_ip_len'], f_plen=cf['prefix_link_len'],
             f_ldelta=cf['link_crc_delta'], f_obj=int(cf['padobj_head'], 16), f_delta=cf['added'],
             obj_g=obj[0], obj_v=obj[1], obj_q=obj[2], obj_lo=obj[3], obj_hi=obj[4])
    code = '''
/* ==== pipe-1 egress: two-READ-target prefix padder (see make_m12.transform_two_read_pad_pipe1) ==== */
header x_ip_h { bit<4> version; bit<4> ihl; bit<8> tos; bit<16> len; bit<16> id; bit<3> flags;
              bit<13> frag; bit<8> ttl; bit<8> proto; bit<16> checksum; bit<32> src; bit<32> dst; }
header x_tcp_h { bit<16> sport; bit<16> dport; bit<32> seq; bit<32> ack; bit<4> offset; bit<4> reserved;
               bit<8> flags; bit<16> window; bit<16> checksum; bit<16> urgent; }
header x_dl_h { bit<16> start; bit<8> len; bit<8> ctrl; bit<16> dst; bit<16> src; bit<16> crc; }
header x_rh_h { bit<8> tpctrl; bit<8> appctrl; bit<8> func; bit<16> iin; }
header x_robj_h { bit<8> g_group; bit<8> g_var; bit<8> g_qual; bit<8> g_start; bit<8> g_stop; }
header x_d32_h { bit<32> d; }
header x_d16_h { bit<16> d; }
header x_crc_h { bit<16> crc; }
header x_pl_u_h { bit<8> tp; bit<32> app; bit<56> padobj; bit<32> padobj2; }   // mixed prefix block 0 (16 B)
header x_pl_u2_h { bit<8> tp; bit<32> app; bit<56> padobj; }                   // full prefix block 0 (12 B)
header x_pl_z_h { %(zdecl)s }                                                  // mixed prefix blocks 1-2 (22 B)
struct x_headers_t { t_tev_t tev; t_ethernet_t eth; x_ip_h ip; x_tcp_h tcp; x_dl_h pll; x_pl_u_h plu; x_pl_u2_h plu2;
                     x_crc_h pluc; x_pl_z_h plz; x_dl_h dl; x_rh_h rh; x_robj_h robj; x_d32_h p03; x_d16_h p45; x_crc_h c0; }
struct x_meta_t { bit<16> residual; bit<16> len_delta; bit<8> pl_tp; bit<8> co_tp; bit<16> pl_uc; bit<16> pl_uc2;
                  bit<16> co_c0; bit<16> in_rb0; bit<1> pad; bit<1> full; bit<1> conn_ok; bit<2> p1_res; }
parser x_EgParser(packet_in pkt, out x_headers_t hdr, out x_meta_t m, out egress_intrinsic_metadata_t eg) {
    Checksum() tcp_old;
    state start { pkt.extract(eg); m.pad = 0; m.full = 0; m.len_delta = 0; m.conn_ok = 0;
        transition select(eg.egress_port) { 9w180: tev; default: accept; } }
    state tev { pkt.extract(hdr.tev); transition select(hdr.tev.kind, hdr.tev.stage) { (8w11, 8w0): eth; default: accept; } }
    state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { 16w0x0800: ip; default: accept; } }
    state ip { pkt.extract(hdr.ip);
        transition select(hdr.ip.version, hdr.ip.ihl, hdr.ip.proto) { (4w4, 4w5, 8w6): ip_len; default: accept; } }
    state ip_len { transition select(hdr.ip.len) { 16w%(mx_ip)d: ip_frag; 16w%(f_ip)d: ip_frag; default: accept; } }
    state ip_frag { transition select(hdr.ip.frag, hdr.ip.flags) { (13w0, 3w0): tcp; (13w0, 3w2): tcp; default: accept; } }
    state tcp { pkt.extract(hdr.tcp);
        tcp_old.subtract({hdr.tcp.checksum});
        tcp_old.subtract_all_and_deposit(m.residual);
        transition select(hdr.tcp.offset) { 4w5: dl; default: accept; } }
    state dl { pkt.extract(hdr.dl); transition select(hdr.dl.len) { 8w0x%(mx_len)02x: dl_start; 8w0x%(f_len)02x: dl_start; default: accept; } }
    state dl_start { transition select(hdr.dl.start) { 16w0x0564: b0; default: accept; } }
    state b0 { pkt.extract(hdr.rh); pkt.extract(hdr.robj); pkt.extract(hdr.p03); pkt.extract(hdr.p45); pkt.extract(hdr.c0); transition accept; }
}
control x_Egress(inout x_headers_t hdr, inout x_meta_t m, in egress_intrinsic_metadata_t eg,
                 in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
                 inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
                 inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    CRCPolynomial<bit<16>>(16w0x3D65, true, false, false, 16w0, 16w0xFFFF) poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_in_rb0;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_pl_uc;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_pl_uc2;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_co_c0;
    action in_rb0() { m.in_rb0 = hash_in_rb0.get({hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group,
        hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d}); }
    table in_rb0_t { actions = { in_rb0; } size = 1; const default_action = in_rb0(); }
    action set_tp(bit<8> a, bit<8> b) { m.pl_tp = a; m.co_tp = b; }
    table set_tp_t { key = { hdr.rh.tpctrl : exact; } actions = { set_tp; NoAction; } size = 64; const default_action = NoAction();
        const entries = { %(tp_rows)s } }
    action crc_pl_uc() { m.pl_uc = hash_pl_uc.get({m.pl_tp, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, 56w%(mx_hi)d, 32w%(mx_lo)d}); }
    table crc_pl_uc_t { actions = { crc_pl_uc; } size = 1; const default_action = crc_pl_uc(); }
    action crc_pl_uc2() { m.pl_uc2 = hash_pl_uc2.get({m.pl_tp, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, 56w%(f_obj)d}); }
    table crc_pl_uc2_t { actions = { crc_pl_uc2; } size = 1; const default_action = crc_pl_uc2(); }
    action crc_co_c0() { m.co_c0 = hash_co_c0.get({m.co_tp, 32w0, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,
        hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d}); }
    table crc_co_c0_t { actions = { crc_co_c0; } size = 1; const default_action = crc_co_c0(); }
    action pad_mx() { m.pad = 1; m.full = 0; }
    action pad_full() { m.pad = 1; m.full = 1; }
    /* Size enable per connection, installed by the control plane exactly when E's fwd_conn row enables padding
       for the same outstation->master 4-tuple (cp.p1_pad_rows). No row = no padding: a size-off arm or a native
       connection stays native end to end. */
    action p1_pad_ok() { m.conn_ok = 1; }
    table p1_conn { key = { hdr.ip.src : exact; hdr.ip.dst : exact; hdr.tcp.sport : exact; hdr.tcp.dport : exact; }
        actions = { p1_pad_ok; NoAction; } size = 16; const default_action = NoAction(); }
    /* observability: one count per mixed/full READ frame seen: 1 padded, 2 declined (no size-enabled
       connection), 3 declined (block-0 CRC or profile); the sum of the three is the number seen */
    Counter<bit<32>, bit<2>>(4, CounterType_t.PACKETS) p1_outcome;
    /* the shape is the exact (IP length, link LEN) PAIR, as N's parser dispatches it (review of m12p_c23: keying LEN
       alone would let an IP-287 frame with LEN 0x4c be padded as mixed) */
    table read_profile { key = { hdr.ip.len : exact; hdr.dl.len : exact; hdr.rh.tpctrl : ternary; hdr.rh.appctrl : ternary; hdr.rh.func : exact;
            hdr.robj.g_group : exact; hdr.robj.g_var : exact; hdr.robj.g_qual : exact; hdr.robj.g_start : exact; hdr.robj.g_stop : exact; }
        actions = { pad_mx; pad_full; NoAction; } size = 2; const default_action = NoAction();
        const entries = { (16w%(mx_ip)d, 8w0x%(mx_len)02x, 8w0xC0 &&& 8w0xC0, 8w0xC0 &&& 8w0xF0, 8w0x81, 8w0x%(obj_g)02x, 8w0x%(obj_v)02x, 8w0x%(obj_q)02x, 8w0x%(obj_lo)02x, 8w0x%(obj_hi)02x): pad_mx();
                          (16w%(f_ip)d, 8w0x%(f_len)02x, 8w0xC0 &&& 8w0xC0, 8w0xC0 &&& 8w0xF0, 8w0x81, 8w0x%(obj_g)02x, 8w0x%(obj_v)02x, 8w0x%(obj_q)02x, 8w0x%(obj_lo)02x, 8w0x%(obj_hi)02x): pad_full(); } }
    action prefix_mx() {
        hdr.pll.setValid(); hdr.pll.start = 16w0x0564; hdr.pll.len = 8w%(mx_plen)d; hdr.pll.ctrl = hdr.dl.ctrl;
        hdr.pll.dst = hdr.dl.dst; hdr.pll.src = hdr.dl.src; hdr.pll.crc = hdr.dl.crc ^ 16w%(mx_ldelta)d;
        hdr.plu.setValid(); hdr.plu.tp = m.pl_tp; hdr.plu.app = hdr.rh.appctrl ++ hdr.rh.func ++ hdr.rh.iin;
        hdr.plu.padobj = 56w%(mx_hi)d; hdr.plu.padobj2 = 32w%(mx_lo)d;
        hdr.pluc.setValid(); hdr.pluc.crc = m.pl_uc[7:0] ++ m.pl_uc[15:8];
        hdr.plz.setValid(); %(zset)s
        hdr.rh.tpctrl = m.co_tp; hdr.rh.appctrl = 8w0; hdr.rh.func = 8w0; hdr.rh.iin = 16w0;
        hdr.c0.crc = m.co_c0[7:0] ++ m.co_c0[15:8];
        hdr.ip.len = hdr.ip.len + 16w%(mx_delta)d; m.len_delta = 16w%(mx_folded)d;
    }
    table prefix_mx_t { actions = { prefix_mx; } size = 1; const default_action = prefix_mx(); }
    action prefix_full() {
        hdr.pll.setValid(); hdr.pll.start = 16w0x0564; hdr.pll.len = 8w%(f_plen)d; hdr.pll.ctrl = hdr.dl.ctrl;
        hdr.pll.dst = hdr.dl.dst; hdr.pll.src = hdr.dl.src; hdr.pll.crc = hdr.dl.crc ^ 16w%(f_ldelta)d;
        hdr.plu2.setValid(); hdr.plu2.tp = m.pl_tp; hdr.plu2.app = hdr.rh.appctrl ++ hdr.rh.func ++ hdr.rh.iin;
        hdr.plu2.padobj = 56w%(f_obj)d;
        hdr.pluc.setValid(); hdr.pluc.crc = m.pl_uc2[7:0] ++ m.pl_uc2[15:8];
        hdr.rh.tpctrl = m.co_tp; hdr.rh.appctrl = 8w0; hdr.rh.func = 8w0; hdr.rh.iin = 16w0;
        hdr.c0.crc = m.co_c0[7:0] ++ m.co_c0[15:8];
        hdr.ip.len = hdr.ip.len + 16w%(f_delta)d; m.len_delta = 16w%(f_delta)d;
    }
    table prefix_full_t { actions = { prefix_full; } size = 1; const default_action = prefix_full(); }
    apply {
        if (hdr.c0.isValid()) {
            p1_conn.apply();
            in_rb0_t.apply(); set_tp_t.apply(); crc_pl_uc_t.apply(); crc_pl_uc2_t.apply(); crc_co_c0_t.apply();
            if (m.conn_ok == 1w1 && hdr.c0.crc == (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { read_profile.apply(); }
            if (m.pad == 1w1) {
                if (m.full == 1w0) { prefix_mx_t.apply(); } else { prefix_full_t.apply(); }
                m.p1_res = 2w1;
            }
            else if (m.conn_ok == 1w0) { m.p1_res = 2w2; }
            else { m.p1_res = 2w3; }
            p1_outcome.count(m.p1_res);
        }
    }
}
control x_EgDeparser(packet_out pkt, inout x_headers_t hdr, in x_meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {
    Checksum() ip_new; Checksum() tcp_mx; Checksum() tcp_full;
    apply {
        if (m.pad == 1w1) {
            hdr.ip.checksum = ip_new.update({hdr.ip.version, hdr.ip.ihl, hdr.ip.tos, hdr.ip.len, hdr.ip.id, hdr.ip.flags,
                                             hdr.ip.frag, hdr.ip.ttl, hdr.ip.proto, hdr.ip.src, hdr.ip.dst});
        }
        if (hdr.plz.isValid()) {   // mixed: 50-B prefix (the 22-B constant remainder is folded into m.len_delta)
            hdr.tcp.checksum = tcp_mx.update({m.len_delta,
                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,
                hdr.plu.tp, hdr.plu.app, hdr.plu.padobj, hdr.plu.padobj2, hdr.pluc.crc,
                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,
                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,
                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,
                m.residual});
        }
        if (hdr.plu2.isValid()) {  // full: 24-B prefix
            hdr.tcp.checksum = tcp_full.update({m.len_delta,
                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,
                hdr.plu2.tp, hdr.plu2.app, hdr.plu2.padobj, hdr.pluc.crc,
                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,
                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,
                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,
                m.residual});
        }
        pkt.emit(hdr.tev); pkt.emit(hdr.eth); pkt.emit(hdr.ip); pkt.emit(hdr.tcp);
        pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.plu2); pkt.emit(hdr.pluc); pkt.emit(hdr.plz);
        pkt.emit(hdr.dl); pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0);
    }
}
''' % p
    anchor = 'Pipeline(n_IgParser(), n_Ingress(), n_IgDeparser(), r_EgParser(), r_Egress(), r_EgDeparser()) p0;'
    src = once(src, anchor, code + anchor)
    src = once(src, 'Pipeline(t_IngressParser(), t_Ingress(), t_IngressDeparser(), t_EmptyEgressParser(), t_EmptyEgress(), t_EmptyEgressDeparser()) p1;',
               'Pipeline(t_IngressParser(), t_Ingress(), t_IngressDeparser(), x_EgParser(), x_Egress(), x_EgDeparser()) p1;')
    return src


def transform_two_read_e(src, _image=None):
    """E (pipe-0 egress) maps BOTH pre-padded READ images of the two-READ-target profile (141 and 271) beside the
    SBO image (61), each by its own committed length -- no max-image boundary.

    Built on transform_read_prepadded_e (applied for the mixed shape: removes the old in-E READ re-encode, parses
    only the prefix frame's headers, recognises it, and takes the NATIVE length as ip.len - 40 - added), then extends
    every per-image site to the full shape, selected by the prefix link LEN (0x27 mixed, 0x11 full) -- a parser field
    already in PHV, so no new metadata enters the saturated mapper cluster:
      read_pp dispatch, read_profile and leff_t (native = ip.len - 90 / - 64)  -> one row more each
      ina_img_t (acct commit image) and fwd_prep_t (wire advance / replay back-off) keyed + dl.len: 141 / 271 / 61
      acct_t's READ commit row (native 49) -> one row per READ native (91, 247)
      out_reset_front_49 (RST exactly one READ ahead) -> a parameterised action, one row per READ native
    The reverse C3 boundary and the C5 forward start-ACK rows come from per_image {91:141, 247:271, 37:61, 61:61}
    (transform_mapper_var, c3 cimg: keyed on the committed native length mod 256 -- 0x5b, 0xf7, 0x25, 0x3d)."""
    cm, cf = two_read_shapes()
    src = transform_read_prepadded_e(src, cm)
    first = int(cf['padobj_head'][:10], 16).to_bytes(5, 'big')
    if first != int(cm['padobj_head'][:10], 16).to_bytes(5, 'big'):
        raise SystemExit('the two prefixes must share the pad object header g/v/q/start')
    mx, fl = cm['prefix_link_len'], cf['prefix_link_len']
    # 1) parse the full shape's prefix frame like the mixed one
    src = once(src, "            (8w0x%02x, _): read_pp; (8w0x1c, _): ctl_b0; default: accept;" % mx,
               "            (8w0x%02x, _): read_pp; (8w0x%02x, _): read_pp; (8w0x1c, _): ctl_b0; default: accept;" % (mx, fl))
    # 2) recognise it
    row = ('(16w0x0564,8w0x%02x,8w0x40&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x%02x,8w0x%02x,8w0x%02x,8w0x%02x,8w0x%02x):read_shape();'
           % ((mx,) + tuple(first)))
    src = once(src, row, row + row.replace('8w0x%02x,8w0x40' % mx, '8w0x%02x,8w0x40' % fl, 1))
    src = once(src, 'actions={read_shape;NoAction;}size=1;const default_action=NoAction();\n     const entries={(16w0x0564,8w0x%02x' % mx,
               'actions={read_shape;NoAction;}size=2;const default_action=NoAction();\n     const entries={(16w0x0564,8w0x%02x' % mx)
    # 3) native length of each pre-padded READ (and FIN), keyed on the prefix LEN and the pad object header
    leff_mx = ('(8w0x00 &&& 8w0x01, true, 8w0x%02x, true, 8w0x%02x, 8w0x%02x, 8w0x%02x) : leff_off(%s);'
               % ((mx,) + tuple(first[:3]) + (neg(40 + cm['added']),)))
    leff_full = ('\n                          (8w0x01 &&& 8w0x01, true, 8w0x%02x, true, 8w0x%02x, 8w0x%02x, 8w0x%02x) : leff_off(%s);'
                 '\n                          (8w0x00 &&& 8w0x01, true, 8w0x%02x, true, 8w0x%02x, 8w0x%02x, 8w0x%02x) : leff_off(%s);'
                 % ((fl,) + tuple(first[:3]) + (neg(40 + cf['added'] - 1), fl) + tuple(first[:3]) + (neg(40 + cf['added']),)))
    src = once(src, leff_mx, leff_mx + leff_full)
    src = once(src, '        actions = { leff_off; NoAction; } size = 4; const default_action = NoAction();',
               '        actions = { leff_off; NoAction; } size = 6; const default_action = NoAction();')
    # 4) commit image per READ shape (acct SALU input m.ina) -- table data only; acct keeps arm/try/grow/rev
    src = once(src, '    table ina_img_t { key = { m.read_shape : exact; m.ctl_shape : exact; }\n'
                    '        actions = { set_ina; NoAction; } size = 4; const default_action = NoAction();\n'
                    '        const entries = { (1, 0) : set_ina(%d); (0, 1) : set_ina(61); } }' % cm['target'],
               '    table ina_img_t { key = { m.read_shape : exact; m.ctl_shape : exact; hdr.dl.len : ternary; }\n'
               '        actions = { set_ina; NoAction; } size = 4; const default_action = NoAction();\n'
               '        const entries = { (1, 0, 8w0x%02x) : set_ina(%d); (1, 0, 8w0x%02x) : set_ina(%d); (0, 1, _) : set_ina(61); } }'
               % (mx, cm['target'], fl, cf['target']))
    # 5) wire advance / replay back-off per READ image: ONE parameterised action (separate constant actions add
    #    compiler temporaries to the saturated mapper cluster, m12p_b02); SBO keeps its constant action
    src = once(src, '    action fwd_prep_read() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + %s; m.t = m.q + 32w%d; }\n'
               % (neg(cm['target']), cm['target']),
               '    action fwd_prep_read(bit<32> negimg, bit<32> img) { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + negimg; m.t = m.q + img; }\n')
    src = once(src, '    table fwd_prep_t { key = { m.read_shape : ternary; m.ctl_shape : ternary; }\n'
                    '        actions = { fwd_prep_read;fwd_prep_ctl; fwd_prep_native; } size = 4; const default_action = fwd_prep_native();\n'
                    '        const entries = { (1, _): fwd_prep_read();(_, 1): fwd_prep_ctl(); } }',
               '    table fwd_prep_t { key = { m.read_shape : ternary; m.ctl_shape : ternary; hdr.dl.len : ternary; }\n'
               '        actions = { fwd_prep_read;fwd_prep_ctl; fwd_prep_native; } size = 4; const default_action = fwd_prep_native();\n'
               '        const entries = { (1, _, 8w0x%02x): fwd_prep_read(%s, 32w%d);(1, _, 8w0x%02x): fwd_prep_read(%s, 32w%d);(_, 1, _): fwd_prep_ctl(); } }'
               % (mx, neg(cm['target']), cm['target'], fl, neg(cf['target']), cf['target']))
    # 6) acct commit row per READ native (the per_image path never retargeted m11_09's native-49 row)
    old = '(_, 1, 3w4 &&& 3w7, 0, 1, 8w0 &&& 8w0x07, 49, 1, _, 0, 0, 0, 0, _, _): do_acct_try();'
    src = once(src, old, old.replace(', 49, 1,', ', %d, 1,' % cm['native_total']) + old.replace(', 49, 1,', ', %d, 1,' % cf['native_total']))
    # 7) RST exactly one READ ahead restarts the front: one parameterised action, one row per READ native -- the two
    #    profile READs AND the range READ (admitted native; review of m12p_c23: dropping its row regressed it). The
    #    action ADDS the negated length: Tofino rejects action data as the second operand of a subtraction (m12p_c21:
    #    "Second operand of arithmetic subtraction cannot be sourced from action data").
    src = once(src, 'action out_reset_front_49() { m.qx = m.q - 32w49; m.result = r_OUT_RESET_FRONT; m.changed = 1; }',
               'action out_reset_front_rd(bit<32> negn) { m.qx = m.q + negn; m.result = r_OUT_RESET_FRONT; m.changed = 1; }')
    src = once(src, 'out_reset_front_49; out_reset_front_37;', 'out_reset_front_rd; out_reset_front_37;')
    src = once(src, '(32w49, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_49();',
               ''.join('(32w%d, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_rd(%s);' % (n, neg(n))
                       for n in (49, cm['native_total'], cf['native_total'])))   # 49: the range READ keeps its row
    return src


def transform_two_read_admit_n(src, _image=None):
    """N READ admission of the two-READ-target profile (m12p_c23+): the integrity READ and the mixed READ only.

    m12p_c22 STACKED the mixed admission (transform_two_read_n) on c12's pass-through admission and needed a 13th
    pipe-0 stage in both gresses; the isolation probes placed every E/pipe-1 change at N12/E12 (m12p_c22_probe_e)
    and c12 + the mixed N admission alone at 13/13 (m12p_c22_probe_n). This build therefore REPLACES the analog and
    class0 READ admission -- not part of this profile -- by the mixed one, instead of adding to it: request headers
    rd_req_full (integrity, 27 B) and rd_req_mx (mixed, 25 B), one exact profile each, and ONE request-CRC table
    keyed on which header is valid (2 x 16 immediate hash bits, the per-table limit; a hash action is never the
    default). Responses (first block only, as the pass-through classes): 247 (integrity/class0 shape) and 91 (mixed).
    Disposition of the replaced classes, MEASURED on the model (two_read_robust X, m12p_c24): N does not admit an
    analog or class0 READ request on an admitted connection -- it is WITHHELD, nothing reaching the outstation or
    the master, also when retransmitted -- and the connection state is unchanged (a supported READ at the same
    client sequence still pads byte-exact). A master that issues one stalls until its application times out. (The
    c23 review's reading, "forwarded natively, not dropped", was a source reading that the model contradicted; the
    m12p_c24 profile text carried it and is corrected from m12p_c25.) The range READ keeps m11_09's own admission and
    timing (native, unpadded).

    Validation, stated exactly: requests are fully parsed (link and block CRCs, TCP checksum verified); responses
    are parsed first block only -- link-header and block-0 CRCs checked, block-1+ CRCs derived from block 0, and the
    TCP checksum WAIVED (finish_shallow writes m.tcp_sum = 0xffeb, the network table's accept residual, instead of
    computing it). Sequence: native lengths 27/25 (requests), 247/91 (responses); every retransmission row keyed on
    the range lengths (-20 request, -49 response) is repeated for -27/-25 and -247/-91."""
    cm, cf = two_read_shapes()
    full_req, mx_req = PASSTHROUGH_READS['integrity'], (cm['request_len'], cm['request_link_len'])
    objs = bytes.fromhex(cm['request_objects'])
    o1, o2 = int.from_bytes(objs[:5], 'big'), int.from_bytes(objs[5:], 'big')
    req = {'full': (full_req[0], full_req[1]), 'mx': mx_req}                       # name -> (octets, dl.len)
    rsp = {(cf['native_link_len'], cf['native_ip_len']), (cm['native_link_len'], cm['native_ip_len'])}
    if (full_req[2], full_req[3]) != (cf['native_total'], cf['native_link_len']) or mx_req != (25, 0x12) or \
            (full_req[0], full_req[1]) != (cf['request_len'], cf['request_link_len']) or \
            cf['request_objects'] != '3c02063c03063c04063c0106' or \
            tuple(cm['response_headers'][0]) != (1, 2, 0, 0, 15) or tuple(cf['response_headers'][0]) != (1, 2, 0, 0, 15):
        raise SystemExit('two-READ admission shapes disagree with the derived constants')
    # 1) request headers, overlaid with the range request header (mutually exclusive parse paths)
    src = once(src, 'header n_read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}',
               'header n_read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}\n'
               'header n_read_req_full_h{bit<8> tp;bit<8> app;bit<8> func;bit<24> o1;bit<24> o2;bit<24> o3;bit<24> o4;bit<16> crc;}\n'
               'header n_read_req_mx_h{bit<8> tp;bit<8> app;bit<8> func;bit<40> o1;bit<40> o2;bit<16> crc;}')
    src = once(src, 'n_read_req_h rd_req;', 'n_read_req_h rd_req;n_read_req_full_h rd_req_full;n_read_req_mx_h rd_req_mx;')
    hdrs = ('hdr.rd_req', 'hdr.rd_req_full', 'hdr.rd_req_mx')
    pragmas = ''.join('@pa_mutually_exclusive("ingress", "%s", "%s")\n' % (a, b)
                      for i, a in enumerate(hdrs) for b in hdrs[i + 1:])
    src = once(src, '@pa_container_size("ingress", "m.expected_work_phase", 32)\n',
               pragmas + '@pa_container_size("ingress", "m.expected_work_phase", 32)\n')
    # 2) parser: exact (dl.len, ip.len) dispatch for the two requests and two responses, else accept (unparsed)
    src = once(src, '(4w4,4w5,8w6,16w60):read_ip_flags;',
               '(4w4,4w5,8w6,16w60):read_ip_flags;' + ''.join('(4w4,4w5,8w6,16w%d):rx_ip_flags;' % (40 + v[0])
                                                              for v in sorted(req.values())))
    src = once(src, '(4w4,4w5,8w6,16w89):read_response_ip_flags;',
               '(4w4,4w5,8w6,16w89):read_response_ip_flags;' + ''.join('(4w4,4w5,8w6,16w%d):rx_response_ip_flags;' % ip
                                                                      for _dl, ip in sorted(rsp, key=lambda k: k[1])))
    req_cases = ''.join('(8w0x%02x,16w%d):read_request_%s;' % (v[1], 40 + v[0], n) for n, v in sorted(req.items()))
    rsp_cases = ''.join('(8w0x%02x,16w%d):read_response_fb;' % k for k in sorted(rsp))
    states = (' state rx_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):rx_tcp;(13w0,3w2):rx_tcp;default:accept;}}\n'
              ' state rx_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.flags){(4w5,8w16):rx_dl;(4w5,8w24):rx_dl;default:accept;}}\n'
              ' state rx_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition select(hdr.dl.len,hdr.ip.len){%sdefault:accept;}}\n'
              ' state read_request_full{pkt.extract(hdr.rd_req_full);tc.subtract(hdr.rd_req_full);m.packet_kind=8w9;transition finish;}\n'
              ' state read_request_mx{pkt.extract(hdr.rd_req_mx);tc.subtract(hdr.rd_req_mx);m.packet_kind=8w9;transition finish;}\n'
              ' state rx_response_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):rx_response_tcp;(13w0,3w2):rx_response_tcp;default:accept;}}\n'
              ' state rx_response_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.flags){(4w5,8w16):rx_response_dl;(4w5,8w24):rx_response_dl;default:accept;}}\n'
              ' state rx_response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition select(hdr.dl.len,hdr.ip.len){%sdefault:accept;}}\n'
              ' state read_response_fb{pkt.extract(hdr.first);tc.subtract(hdr.first);m.packet_kind=8w11;transition finish_shallow;}\n'
              ' state finish_shallow{m.tcp_sum=16w0xffeb;m.parsed=(bit<1>)(8w1);m.shape_valid=(bit<1>)(8w1);transition accept;}\n'
              % (req_cases, rsp_cases))
    src = once(src, ' state read_request{pkt.extract(hdr.rd_req);', states + ' state read_request{pkt.extract(hdr.rd_req);')
    # 3) request profiles (exact declared objects; tp/app as exact slices, as the c12 pass-through profiles) and the
    #    response profile rows for the 247 and 91 block 0 (both g1v2 q00 [0,15]; the link LEN tells them apart)
    prof = ('table read_request_full_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req_full.tp[7:6]:exact;hdr.rd_req_full.app[7:4]:exact;hdr.rd_req_full.func:exact;hdr.rd_req_full.o1:exact;hdr.rd_req_full.o2:exact;hdr.rd_req_full.o3:exact;hdr.rd_req_full.o4:exact;}\n'
            ' actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w0x%02x,8w0xc4,2w3,4w0xc,8w1,24w0x3c0206,24w0x3c0306,24w0x3c0406,24w0x3c0106):eligible();}}\n'
            'table read_request_mx_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req_mx.tp[7:6]:exact;hdr.rd_req_mx.app[7:4]:exact;hdr.rd_req_mx.func:exact;hdr.rd_req_mx.o1:exact;hdr.rd_req_mx.o2:exact;}\n'
            ' actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w0x%02x,8w0xc4,2w3,4w0xc,8w1,40w0x%010x,40w0x%010x):eligible();}}\n'
            % (req['full'][1], req['mx'][1], o1, o2))
    src = once(src, '(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}\n',
               '(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}\n' + prof)
    src = once(src, 'actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();}}',
               'actions={eligible;NoAction;}size=3;const default_action=NoAction();const entries={(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();'
               + ''.join('(16w0x0564,8w0x%02x,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();' % dl
                         for dl, _ip in sorted(rsp)) + '}}')
    # 4) ONE request-CRC table for both new requests, keyed on header validity (32 immediate hash bits)
    crcs = ('Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_request_full;\n'
            'action rd_request_full_crc(){m.bcrc=hash_rd_request_full.get({hdr.rd_req_full.tp,hdr.rd_req_full.app,hdr.rd_req_full.func,'
            'hdr.rd_req_full.o1,hdr.rd_req_full.o2,hdr.rd_req_full.o3,hdr.rd_req_full.o4,hdr.rd_req_full.crc});}\n'
            'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_request_mx;\n'
            'action rd_request_mx_crc(){m.bcrc=hash_rd_request_mx.get({hdr.rd_req_mx.tp,hdr.rd_req_mx.app,hdr.rd_req_mx.func,'
            'hdr.rd_req_mx.o1,hdr.rd_req_mx.o2,hdr.rd_req_mx.crc});}\n'
            'table rd_request_two_crc_t{key={hdr.rd_req_full.isValid():exact;}actions={rd_request_full_crc;rd_request_mx_crc;NoAction;}size=2;'
            'const entries={true:rd_request_full_crc();false:rd_request_mx_crc();}const default_action=NoAction();}\n')
    src = once(src, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_tail;\n', crcs + 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_tail;\n')
    src = once(src, 'action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value,hdr.rd_tail.crc});}',
               'action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value,hdr.rd_tail.crc});}\n'
               'action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;}\n'
               'table read_shallow_admit_t{actions={read_shallow_admit;}size=1;const default_action=read_shallow_admit();}')
    src = once(src, 'if(m.packet_kind==8w9){read_request_profile.apply();rd_request_crc_t.apply();}else{read_response_profile.apply();rd_second_crc_t.apply();rd_tail_crc_t.apply();}',
               'if(m.packet_kind==8w9){if(hdr.rd_req.isValid()){read_request_profile.apply();rd_request_crc_t.apply();}'
               'else{if(hdr.rd_req_full.isValid()){read_request_full_profile.apply();}else{read_request_mx_profile.apply();}'
               'rd_request_two_crc_t.apply();}}'
               'else{read_response_profile.apply();if(hdr.second.isValid()){rd_second_crc_t.apply();rd_tail_crc_t.apply();}else{read_shallow_admit_t.apply();}}')
    # 5) sequence accounting per shape: native length by (kind, dl.len); range rows unchanged as the fallbacks
    rows = ''.join('(8w9,8w0x%02x):next_read_len(%d);' % (v[1], v[0]) for _n, v in sorted(req.items()))
    rows += ''.join('(8w11,8w0x%02x):next_read_len(%d);' % (dl, ip - 40) for dl, ip in sorted(rsp))
    src = once(src, ' table next_seq_t{key={m.packet_kind:exact;}actions={next_seq;next_control;next_response;next_read_request;next_read_response;}size=5;'
               'const entries={8w5:next_control();8w7:next_control();8w6:next_response();8w9:next_read_request();8w11:next_read_response();}const default_action=next_seq();}',
               ' action next_read_len(bit<32> n){m.new_seq=hdr.tcp.seq+n;}\n'
               ' table next_seq_t{key={m.packet_kind:exact;hdr.dl.len:ternary;}actions={next_seq;next_control;next_response;next_read_request;next_read_response;next_read_len;}size=10;'
               'const entries={(8w5,_):next_control();(8w7,_):next_control();(8w6,_):next_response();%s(8w9,_):next_read_request();(8w11,_):next_read_response();}const default_action=next_seq();}' % rows)
    # 6) application-sequence input from whichever request header is valid (response side reads hdr.first as before)
    src = once(src, 'table read_input_t{key={m.packet_kind:exact;}actions={read_request_input;read_response_input;NoAction;}size=2;const entries={8w9:read_request_input();8w11:read_response_input();}const default_action=NoAction();}',
               'action read_request_full_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_full.app[3:0]);}\n'
               'action read_request_mx_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_mx.app[3:0]);}\n'
               'table read_input_t{key={m.packet_kind:exact;hdr.rd_req_full.isValid():exact;hdr.rd_req_mx.isValid():exact;}'
               'actions={read_request_input;read_request_full_input;read_request_mx_input;read_response_input;NoAction;}size=4;'
               'const entries={(8w9,false,false):read_request_input();(8w9,true,false):read_request_full_input();'
               '(8w9,false,true):read_request_mx_input();(8w11,false,false):read_response_input();}const default_action=NoAction();}')
    # 7) retransmission recognition per shape (sequence_guard, first_event, retry_dup_t)
    mirrors = {neg(20): sorted({neg(v[0]) for v in req.values()}), neg(49): sorted({neg(ip - 40) for _dl, ip in rsp})}
    for table in ('sequence_guard', 'first_event', 'retry_dup_t'):
        src = _neg_entry_rows(src, table, mirrors)
    return src


def transform_two_read_reduce(src, _image=None):
    """Resource reduction of the two-READ build (candidate m12p_c26), behavior-preserving; each edit was checked against
    the source it replaces (overnight 2026-10-22, scratch compiles bf-p4c 9.13.1).

    pipe-1 egress padder (x1):
      - block-0 CRC by residue: hash the block WITH its received CRC field and compare to the DNP3 residue 0x993a,
        instead of comparing the field to a byte-swapped hash (two temporary-table stages). Equivalent to the old
        compare for every field value (checked exhaustively over 20 random blocks x 65,536 field values).
      - the outcome index is written where the outcome is decided (parser default 2, p1_pad_ok 3, pad_mx/pad_full 1)
        instead of an if/else chain after the tables; padding requires conn_ok, so the three cases are unchanged.
      - IP length set to the constants 181/311: read_profile matches ip.len 131/287 exactly.
      - deparser checksum conditions on one-bit flags set by pad_mx/pad_full instead of hdr.plz/plu2 validity
        (those headers become valid only in prefix_mx/prefix_full, which run exactly for those actions).
    E (e1): drop the rbad0/rbad1/rbadt compares. Their headers c0/c1/c2 are extracted only by parser state read_b0,
    which no transition reaches after the two-READ E transform, and E never sets them valid, so the compares never
    fired (rbad* stay at their zero initialisation, as before)."""
    src = once(src,
               '        if (hdr.c0.isValid() && hdr.c0.crc != (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { m.rbad0 = 1; }\n'
               '        if (hdr.c1.isValid() && hdr.c1.crc != (m.in_rb1[7:0] ++ m.in_rb1[15:8])) { m.rbad1 = 1; }\n'
               '        if (hdr.c2.isValid() && hdr.c2.crc != (m.in_rt[7:0] ++ m.in_rt[15:8])) { m.rbadt = 1; }\n', '')
    src = once(src, '        if (hdr.ctn.crc1 != (m.in_ct[7:0] ++ m.in_ct[15:8])) { m.cbadt = 1; }\n',
               '        if (hdr.ctn.crc1 != (m.in_ct[7:0] ++ m.in_ct[15:8])) { m.cbadt = 1; }\n'
               '        /* rbad0/rbad1/rbadt checks removed: c0/c1/c2 are only extracted by read_b0, which no state reaches */\n')
    src = once(src, 'bit<16> co_c0; bit<16> in_rb0; bit<1> pad; bit<1> full; bit<1> conn_ok; bit<2> p1_res; }',
               'bit<16> co_c0; bit<16> in_rb0; bit<1> pad; bit<1> full; bit<1> conn_ok; bit<2> p1_res; bit<1> mx; bit<1> fl; }')
    src = once(src, '    state start { pkt.extract(eg); m.pad = 0; m.full = 0; m.len_delta = 0; m.conn_ok = 0;\n',
               '    state start { pkt.extract(eg); m.pad = 0; m.full = 0; m.len_delta = 0; m.conn_ok = 0; m.mx = 0; m.fl = 0; m.p1_res = 2w2;\n')
    src = once(src, 'hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d}); }\n'
               '    table in_rb0_t',
               'hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc}); }\n'
               '    table in_rb0_t')
    src = once(src, '    action pad_mx() { m.pad = 1; m.full = 0; }\n    action pad_full() { m.pad = 1; m.full = 1; }',
               '    action pad_mx() { m.pad = 1; m.full = 0; m.mx = 1; m.p1_res = 2w1; }\n'
               '    action pad_full() { m.pad = 1; m.full = 1; m.fl = 1; m.p1_res = 2w1; }')
    src = once(src, '    action p1_pad_ok() { m.conn_ok = 1; }', '    action p1_pad_ok() { m.conn_ok = 1; m.p1_res = 2w3; }')
    src = once(src, 'hdr.ip.len = hdr.ip.len + 16w50; m.len_delta = 16w50;', 'hdr.ip.len = 16w181; m.len_delta = 16w50;')
    src = once(src, 'hdr.ip.len = hdr.ip.len + 16w24; m.len_delta = 16w24;', 'hdr.ip.len = 16w311; m.len_delta = 16w24;')
    src = once(src, 'if (m.conn_ok == 1w1 && hdr.c0.crc == (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { read_profile.apply(); }',
               'if (m.conn_ok == 1w1 && m.in_rb0 == 16w0x993a) { read_profile.apply(); }   // CRC residue: block CRC correct')
    src = once(src, '                m.p1_res = 2w1;\n            }\n'
               '            else if (m.conn_ok == 1w0) { m.p1_res = 2w2; }\n'
               '            else { m.p1_res = 2w3; }\n'
               '            p1_outcome.count(m.p1_res);',
               '            }\n'
               '            p1_outcome.count(m.p1_res);   // 1 padded (read_profile), 3 conn ok not padded (p1_conn), 2 no conn (parser)')
    src = once(src, '        if (hdr.plz.isValid()) {   // mixed', '        if (m.mx == 1w1) {   // mixed')
    src = once(src, '        if (hdr.plu2.isValid()) {  // full', '        if (m.fl == 1w1) {  // full')
    return src


def transform_n_busy_ack_retry(src, _image=None):
    """F1 (candidate m12p_c27 = c26 + this): a pure ACK that finds N's work cell busy is retried instead of passed.

    Defect (read_complete_01/evidence/forwarding_loss_20261023): busy_t had no row for kind 3 (master final ACK) or
    kind 10 (outstation ACK), so the default busy_pass forwarded the frame still carrying N's prefix; E rejected it
    (kind 0xe1/0xe2 -> reject_lifetime -> drop_lifetime). A lost final ACK is unrecoverable once the master has sent
    data, so one busy collision killed the connection (hardware c26 reference off t0, c25_04 size_only t0; reproduced
    on the model by injecting the SYN-ACK and the final ACK back to back).
    Fix: busy_retry_ack recirculates on the RST retry path (event 0x0800 -> retry_rst_input, origin carried so the
    lap's wire ACK and normalized epoch survive), keeping the ACK's own allocated generation and the 32-lap budget;
    count_busy[6] counts first retries; guard admits the retried ACK (go_retry(3), go_retry(10))."""
    src = once(src, 'action busy_exhausted(){',
               'action busy_retry_ack(){hdr.envelope.epoch=m.epoch;hdr.work_generation.generation=m.generation;'
               'hdr.event.event=16w0x0800;hdr.event.reserved=16w0;hdr.origin.setValid();hdr.origin.wire_ack=m.wire_ack;'
               'hdr.origin.normalized_epoch=m.normalized_epoch;hdr.expected_cell.expected_cell=n_RETRY_BUDGET;'
               'tm.ucast_egress_port=n_RETURN_PORT;tm.bypass_egress=1w1;count_busy_bump.execute(4w6);}\n'
               'action busy_exhausted(){')
    src = once(src, 'actions={busy_drop;busy_pass;busy_retry;busy_retry_next;busy_retry_rst;busy_retry_rst_next;'
                    'busy_exhausted;retry_stale;}size=16;const entries={(_,2w2,_):retry_stale();',
               'actions={busy_drop;busy_pass;busy_retry;busy_retry_next;busy_retry_rst;busy_retry_rst_next;'
               'busy_retry_ack;busy_exhausted;retry_stale;}size=22;const entries={(_,2w2,_):retry_stale();'
               '(8w3,2w0,_):busy_retry_ack();(8w3,2w1,6w1):busy_exhausted();(8w3,2w1,_):busy_retry_rst_next();'
               '(8w10,2w0,_):busy_retry_ack();(8w10,2w1,6w1):busy_exhausted();(8w10,2w1,_):busy_retry_rst_next();')
    src = once(src, '(_,_,_,_,_,_,_,_,_,_,_,_,_,2w1):go_stale()',
               '(2w0,8w3,8w0,2w1,1w1,_,_,_,_,_,_,_,_,2w1):go_retry(8w3);'
               '(2w0,8w3,8w0,2w2,1w1,_,_,_,_,_,_,_,_,2w1):go_retry(8w10);(_,_,_,_,_,_,_,_,_,_,_,_,_,2w1):go_stale()')
    src = once(src, 'size=50;const default_action=NoAction();const entries={(2w0,8w6,8w0,2w2',
               'size=52;const default_action=NoAction();const entries={(2w0,8w6,8w0,2w2')
    return src
