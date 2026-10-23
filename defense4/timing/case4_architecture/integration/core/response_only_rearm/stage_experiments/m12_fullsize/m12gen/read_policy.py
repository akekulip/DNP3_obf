"""The read_complete_01 policy READ transforms (range READ 49 -> 141 prefix build and the pass-through READ
classes in N). Live for candidates b08 and c12/c20; the two-READ build reuses the E mapper and the N row helpers."""
import json
import re

from .common import CONSTANTS, neg, once


def policy_shape(name='range_g10v2_23'):
    """Per-shape prefix constants derived from the reference encoder by read_complete_01/vectors/derive.py
    (verified byte-exact against general_read_padding.pad_read on 512 varied natives). No hand constants."""
    return json.loads(CONSTANTS.read_text())['shapes'][name]


# transform_read_prefix_policy (the policy prefix padder in E, pipe-0 egress) was removed after attempts
# m12p_a01..a04 failed PHV allocation (evidence under m12_fullsize/evidence/m12p_a0*; bisect in
# read_complete_01/P4_PLACEMENT_FINDINGS.md). Its construction moved to pipe-1 egress below.


def _prefix_constants(c):
    """Shared per-shape constants for the prefix padder (from vectors/constants.json)."""
    words = [c['rest'][i:i + 16] for i in range(0, len(c['rest']), 16)]
    if any(len(w) != 16 for w in words) or len(c['block0_tail']) != 22:
        raise SystemExit('unexpected prefix constant layout')
    rest = bytes.fromhex(c['rest'])
    folded = c['added']                       # pseudo-header TCP length growth ...
    for i in range(0, len(rest), 2):          # ... plus the constant remainder (even payload offset 28)
        folded += (rest[i] << 8) | rest[i + 1]
        folded = (folded & 0xFFFF) + (folded >> 16)
    return dict(words=words, tail_hi=int(c['block0_tail'][:14], 16), tail_lo=int(c['block0_tail'][14:], 16),
                folded=folded)


def transform_read_prefix_p1(src, c):
    """READ prefix padder in PIPE-1 EGRESS (replaces T's empty egress), for the frozen policy's range READ.

    Why here: pipe 0 (N ingress + E egress) is ~95% PHV in the placing 49->73 build and every attempt to add
    the 92-octet prefix in E failed PHV allocation (attempts m12p_a01..a04, ablations A-G, Y, Z). Pipe 1's
    egress was empty, and every READ response N admits leaves N through emit_tev to n_READ_HANDOFF_PORT =
    t_T_IN = 180, a pipe-1 port, so it traverses pipe-1 egress exactly once on that handoff (held returns use
    182 and are not touched). The padder acts only on egress port 180, tev kind 11 stage 0, IPv4 len 89, TCP
    without options, a range READ response frame (LEN 0x26) whose block-0 CRC verifies and whose profile
    matches; everything else is re-emitted unchanged. T parses the tev and treats the frame as opaque.
    Construction = prepend (verified byte-exact against pad_read by vectors/derive.py). TCP checksum is
    incremental: the parser subtracts the old checksum and every header after TCP (residual); the deparser
    adds the new prefix, the rewritten block 0, and the TCP-length growth folded with the constant
    remainder's sum. The IP checksum is recomputed (IP is fully parsed)."""
    k = _prefix_constants(c)
    tp_rows = ''.join('(8w0x%02x):set_tp(8w0x%02x,8w0x%02x);' % (0xC0 | s, 0x40 | s, 0x80 | ((s + 1) & 0x3f)) for s in range(64))
    zdecl = ''.join('bit<64> w%d;' % i for i in range(len(k['words'])))
    zset = ''.join('hdr.plz.w%d=64w0x%s;' % (i, w) for i, w in enumerate(k['words']))
    code = '''
/* ==== pipe-1 egress: READ prefix padder (read_complete_01 policy; see make_m12.transform_read_prefix_p1) ==== */
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
header x_pl_u_h { bit<8> tp; bit<32> app; bit<56> padobj; bit<32> padobj2; }
header x_pl_z_h { %(zdecl)s }
struct x_headers_t { t_tev_t tev; t_ethernet_t eth; x_ip_h ip; x_tcp_h tcp; x_dl_h pll; x_pl_u_h plu; x_crc_h pluc;
                     x_pl_z_h plz; x_dl_h dl; x_rh_h rh; x_robj_h robj; x_d32_h p03; x_d16_h p45; x_crc_h c0; }
struct x_meta_t { bit<16> residual; bit<16> len_delta; bit<8> pl_tp; bit<8> co_tp; bit<16> pl_uc; bit<16> co_c0;
                  bit<16> in_rb0; bit<1> pad; bit<1> conn_ok; bit<2> p1_res; }
parser x_EgParser(packet_in pkt, out x_headers_t hdr, out x_meta_t m, out egress_intrinsic_metadata_t eg) {
    Checksum() tcp_old;
    state start { pkt.extract(eg); m.pad = 0; m.len_delta = 0; m.conn_ok = 0;
        transition select(eg.egress_port) { 9w180: tev; default: accept; } }
    state tev { pkt.extract(hdr.tev); transition select(hdr.tev.kind, hdr.tev.stage) { (8w11, 8w0): eth; default: accept; } }
    state eth { pkt.extract(hdr.eth); transition select(hdr.eth.type) { 16w0x0800: ip; default: accept; } }
    state ip { pkt.extract(hdr.ip);
        transition select(hdr.ip.version, hdr.ip.ihl, hdr.ip.proto) { (4w4, 4w5, 8w6): ip_len; default: accept; } }
    state ip_len { transition select(hdr.ip.len) { 16w89: ip_frag; default: accept; } }
    state ip_frag { transition select(hdr.ip.frag, hdr.ip.flags) { (13w0, 3w0): tcp; (13w0, 3w2): tcp; default: accept; } }
    state tcp { pkt.extract(hdr.tcp);
        tcp_old.subtract({hdr.tcp.checksum});
        tcp_old.subtract_all_and_deposit(m.residual);
        transition select(hdr.tcp.offset) { 4w5: dl; default: accept; } }
    state dl { pkt.extract(hdr.dl); transition select(hdr.dl.len) { 8w0x26: dl_start; default: accept; } }
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
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_co_c0;
    action in_rb0() { m.in_rb0 = hash_in_rb0.get({hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group,
        hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d}); }
    table in_rb0_t { actions = { in_rb0; } size = 1; const default_action = in_rb0(); }
    action set_tp(bit<8> a, bit<8> b) { m.pl_tp = a; m.co_tp = b; }
    table set_tp_t { key = { hdr.rh.tpctrl : exact; } actions = { set_tp; NoAction; } size = 64; const default_action = NoAction();
        const entries = { %(tp_rows)s } }
    action crc_pl_uc() { m.pl_uc = hash_pl_uc.get({m.pl_tp, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, 56w%(tail_hi)d, 32w%(tail_lo)d}); }
    table crc_pl_uc_t { actions = { crc_pl_uc; } size = 1; const default_action = crc_pl_uc(); }
    action crc_co_c0() { m.co_c0 = hash_co_c0.get({m.co_tp, 32w0, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,
        hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d}); }
    table crc_co_c0_t { actions = { crc_co_c0; } size = 1; const default_action = crc_co_c0(); }
    action range_read() { m.pad = 1; }
    /* Size enable per connection, installed by the control plane exactly when E's fwd_conn row enables padding
       for the same outstation->master 4-tuple (cp.p1_pad_rows). No row = no padding: a size-off arm or a native
       connection stays native end to end (review C1 of m12p_b06: an ungated padder corrupted size-off arms). */
    action p1_pad_ok() { m.conn_ok = 1; }
    table p1_conn { key = { hdr.ip.src : exact; hdr.ip.dst : exact; hdr.tcp.sport : exact; hdr.tcp.dport : exact; }
        actions = { p1_pad_ok; NoAction; } size = 16; const default_action = NoAction(); }
    /* observability on silicon, one count per range-READ frame seen: 1 padded, 2 declined (no size-enabled
       connection), 3 declined (block-0 CRC or profile); the sum of the three is the number seen */
    Counter<bit<32>, bit<2>>(4, CounterType_t.PACKETS) p1_outcome;
    table read_profile { key = { hdr.dl.len : exact; hdr.rh.tpctrl : ternary; hdr.rh.appctrl : ternary; hdr.rh.func : exact;
            hdr.robj.g_group : exact; hdr.robj.g_var : exact; hdr.robj.g_qual : exact; hdr.robj.g_start : exact; hdr.robj.g_stop : exact; }
        actions = { range_read; NoAction; } size = 1; const default_action = NoAction();
        const entries = { (8w0x26, 8w0xC0 &&& 8w0xC0, 8w0xC0 &&& 8w0xF0, 8w0x81, 8w0x0a, 8w0x02, 8w0x00, 8w0x00, 8w0x16): range_read(); } }
    action prefix() {
        hdr.pll.setValid(); hdr.pll.start = 16w0x0564; hdr.pll.len = 8w%(plen)d; hdr.pll.ctrl = hdr.dl.ctrl;
        hdr.pll.dst = hdr.dl.dst; hdr.pll.src = hdr.dl.src; hdr.pll.crc = hdr.dl.crc ^ 16w%(ldelta)d;
        hdr.plu.setValid(); hdr.plu.tp = m.pl_tp; hdr.plu.app = hdr.rh.appctrl ++ hdr.rh.func ++ hdr.rh.iin;
        hdr.plu.padobj = 56w%(tail_hi)d; hdr.plu.padobj2 = 32w%(tail_lo)d;
        hdr.pluc.setValid(); hdr.pluc.crc = m.pl_uc[7:0] ++ m.pl_uc[15:8];
        hdr.plz.setValid(); %(zset)s
        hdr.rh.tpctrl = m.co_tp; hdr.rh.appctrl = 8w0; hdr.rh.func = 8w0; hdr.rh.iin = 16w0;
        hdr.c0.crc = m.co_c0[7:0] ++ m.co_c0[15:8];
        hdr.ip.len = hdr.ip.len + 16w%(delta)d; m.len_delta = 16w%(folded)d;
    }
    table prefix_t { actions = { prefix; } size = 1; const default_action = prefix(); }
    apply {
        if (hdr.c0.isValid()) {
            p1_conn.apply();
            in_rb0_t.apply(); set_tp_t.apply(); crc_pl_uc_t.apply(); crc_co_c0_t.apply();
            if (m.conn_ok == 1w1 && hdr.c0.crc == (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { read_profile.apply(); }
            if (m.pad == 1w1) { prefix_t.apply(); m.p1_res = 2w1; }
            else if (m.conn_ok == 1w0) { m.p1_res = 2w2; }
            else { m.p1_res = 2w3; }
            p1_outcome.count(m.p1_res);
        }
    }
}
control x_EgDeparser(packet_out pkt, inout x_headers_t hdr, in x_meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {
    Checksum() ip_new; Checksum() tcp_new;
    apply {
        if (m.pad == 1w1) {
            hdr.ip.checksum = ip_new.update({hdr.ip.version, hdr.ip.ihl, hdr.ip.tos, hdr.ip.len, hdr.ip.id, hdr.ip.flags,
                                             hdr.ip.frag, hdr.ip.ttl, hdr.ip.proto, hdr.ip.src, hdr.ip.dst});
            hdr.tcp.checksum = tcp_new.update({m.len_delta,
                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,
                hdr.plu.tp, hdr.plu.app, hdr.plu.padobj, hdr.plu.padobj2, hdr.pluc.crc,
                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,
                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,
                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,
                m.residual});
        }
        pkt.emit(hdr.tev); pkt.emit(hdr.eth); pkt.emit(hdr.ip); pkt.emit(hdr.tcp);
        pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc); pkt.emit(hdr.plz);
        pkt.emit(hdr.dl); pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0);
    }
}
''' % dict(zdecl=zdecl, tp_rows=tp_rows, tail_hi=k['tail_hi'], tail_lo=k['tail_lo'], plen=c['prefix_link_len'],
           ldelta=c['link_crc_delta'], zset=zset, delta=c['added'], folded=k['folded'])
    anchor = 'Pipeline(n_IgParser(), n_Ingress(), n_IgDeparser(), r_EgParser(), r_Egress(), r_EgDeparser()) p0;'
    src = once(src, anchor, code + anchor)
    src = once(src, 'Pipeline(t_IngressParser(), t_Ingress(), t_IngressDeparser(), t_EmptyEgressParser(), t_EmptyEgress(), t_EmptyEgressDeparser()) p1;',
               'Pipeline(t_IngressParser(), t_Ingress(), t_IngressDeparser(), x_EgParser(), x_Egress(), x_EgDeparser()) p1;')
    return src


def transform_read_prepadded_e(src, c):
    """E (pipe-0 egress) maps the READ that pipe-1 egress already padded; E adds no READ bytes any more.

    The pre-padded response's first frame is the prefix (LEN = prefix_link_len, FIR/!FIN transport octet,
    live application header, G1V2 qualifier-0x01 object header starting at the reserved index). E parses
    only that frame's application and object headers, recognises the shape by them (read_shape), takes the
    NATIVE length as ip.len - 40 - added (so the native frontier/acct/fwd_prep arithmetic stays native), and
    commits the per-shape wire image exactly as before. read_eligible no longer inserts or rewrites READ
    bytes; it only marks the segment changed so the plain TCP-checksum branch carries the new seq/ack/window.
    A native 49-octet READ frame is no longer a READ shape in E (it would be mapped natively, never with the
    141 image), and its old re-encode path is removed."""
    first = int(c['padobj_head'][:10], 16).to_bytes(5, 'big')    # g, v, qual, start_lo, start_hi of the pad object
    src = once(src, "            (8w0x26, _): read_b0; (8w0x1c, _): ctl_b0; default: accept;",
               "            (8w0x%02x, _): read_pp; (8w0x1c, _): ctl_b0; default: accept;" % c['prefix_link_len'])
    src = once(src, '    state ctl_b0 { pkt.extract(hdr.cb0); pkt.extract(hdr.ctn); transition accept; }',
               '    state ctl_b0 { pkt.extract(hdr.cb0); pkt.extract(hdr.ctn); transition accept; }\n'
               '    state read_pp { pkt.extract(hdr.rh); pkt.extract(hdr.robj); transition accept; }')
    src = once(src, '(16w0x0564,8w0x26,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x0a,8w0x02,8w0x00,8w0x00,8w0x16):read_shape();',
               '(16w0x0564,8w0x%02x,8w0x40&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x%02x,8w0x%02x,8w0x%02x,8w0x%02x,8w0x%02x):read_shape();'
               % ((c['prefix_link_len'],) + tuple(first)))
    # native length of the pre-padded READ: ip.len - 40 - added (FIN: +1). ONE action with the offset as
    # action data for every case: separate constant actions added compiler temporaries to the saturated
    # mapper arithmetic cluster (m12p_b02: $tmp100..103 unallocated).
    src = once(src, '    action leff_data() { m.leff = widen_len.get({hdr.ip.len}) + 32w0xFFFFFFD8; }   // ip.len - 40\n'
                    '    action leff_fin()  { m.leff = widen_len.get({hdr.ip.len}) + 32w0xFFFFFFD9; }   // ip.len - 40 + FIN',
               '    action leff_off(bit<32> off) { m.leff = widen_len.get({hdr.ip.len}) + off; }   // ip.len - 40 [- prefix] [+ FIN]')
    src = once(src, '''        key = { hdr.tcp.flags : ternary; }
        actions = { leff_data; leff_fin; NoAction; } size = 2; const default_action = NoAction();
        const entries = { 8w0x01 &&& 8w0x01 : leff_fin(); 8w0x00 &&& 8w0x01 : leff_data(); }''',
               '''        key = { hdr.tcp.flags : ternary; hdr.dl.isValid() : ternary; hdr.dl.len : ternary; hdr.robj.isValid() : ternary;
                hdr.robj.g_group : ternary; hdr.robj.g_var : ternary; hdr.robj.g_qual : ternary; }
        actions = { leff_off; NoAction; } size = 4; const default_action = NoAction();
        const entries = { (8w0x01 &&& 8w0x01, true, 8w0x%02x, true, 8w0x%02x, 8w0x%02x, 8w0x%02x) : leff_off(%s);
                          (8w0x00 &&& 8w0x01, true, 8w0x%02x, true, 8w0x%02x, 8w0x%02x, 8w0x%02x) : leff_off(%s);
                          (8w0x01 &&& 8w0x01, _, _, _, _, _, _) : leff_off(32w0xFFFFFFD9); (8w0x00 &&& 8w0x01, _, _, _, _, _, _) : leff_off(32w0xFFFFFFD8); }'''
               % ((c['prefix_link_len'],) + tuple(first[:3]) + (neg(40 + c['added'] - 1), c['prefix_link_len']) + tuple(first[:3])
                  + (neg(40 + c['added']),)))
    # (review W1 of m12p_b06: the pre-padded entries also require the pad object's group/variation/qualifier, so
    #  no other frame with this link LEN takes the pre-padded native length)
    # E no longer adds READ bytes: the commit only marks the segment changed (plain checksum branch)
    old_re = ('    action read_eligible(){hdr.ra.setValid();hdr.ra.v=40w0x0a02000005;hdr.ca.setValid();'
              'hdr.ca.crc=hdr.c0.crc^16w0x6222;hdr.rbh.setValid();hdr.rbh.v=40w0x0a02000609;hdr.rc.setValid();'
              'hdr.rc.v=56w0x0a02010a001600;hdr.cb.setValid();hdr.cb.crc=m.rtcrc_b[7:0]++m.rtcrc_b[15:8];'
              'hdr.c2.crc=m.rtcrc[7:0]++m.rtcrc[15:8];hdr.robj.setInvalid();hdr.c0.setInvalid();hdr.c1.setInvalid();'
              'hdr.dl.len=8w0x32;hdr.dl.crc=hdr.dl.crc^16w0xaf35;hdr.ip.len=hdr.ip.len+16w12;m.len_delta=16w12;}')
    src = once(src, old_re, '    action read_eligible(){m.changed=1;}')
    src = once(src, 'read_profile.apply(); in_rb0_t.apply(); in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); crc_read_b_t.apply();',
               'read_profile.apply();')
    # The obsolete READ re-encode path is removed, not stacked: its checksum branch kept the never-valid
    # ra/ca/rbh/rc/cb headers live in pipe-0 PHV.
    start = src.index('        if (hdr.ra.isValid()) {\n')
    end = src.index('        if (hdr.cd2.isValid()) {\n', start)
    src = src[:start] + src[end:]
    for h in ('rc.v', 'ra.v', 'ca.crc', 'rbh.v', 'cb.crc'):
        src = once(src, '@pa_no_overlay("egress", "hdr.%s")\n' % h, '')
    src = once(src, ' pkt.emit(hdr.ra);', '')
    src = once(src, ' pkt.emit(hdr.ca);', '')
    src = once(src, '        pkt.emit(hdr.rbh); pkt.emit(hdr.p69); pkt.emit(hdr.rc); pkt.emit(hdr.cb);',
               '        pkt.emit(hdr.p69);')
    # A verdict about a block the parser did not extract is no verdict (the pre-padded READ parses only the
    # prefix frame's headers; its native blocks were validated by N and rewritten/verified by pipe-1 egress).
    for blk, h in (('c0', 'in_rb0'), ('c1', 'in_rb1'), ('c2', 'in_rt')):
        bit = {'c0': 'rbad0', 'c1': 'rbad1', 'c2': 'rbadt'}[blk]
        src = once(src, '        if (hdr.%s.crc != (m.%s[7:0] ++ m.%s[15:8])) { m.%s = 1; }' % (blk, h, h, bit),
                   '        if (hdr.%s.isValid() && hdr.%s.crc != (m.%s[7:0] ++ m.%s[15:8])) { m.%s = 1; }' % (blk, blk, h, h, bit))
    return src


# Pass-through READ classes of the frozen policy (read_complete_01/policy/policy.json targets 141/247/401): the
# response is already at a target, so it keeps its native size. Exact shapes decoded from the fixture endpoint's
# loopback capture evidence/rearm_01/repeat_sbo_endpoint/loopback_evidence_20261021/b_rotate4_base (TCP options
# aside; hardware runs without them): name -> (request octets, request dl.len, response octets, response dl.len).
PASSTHROUGH_READS = {'analog': (22, 0x0f, 141, 0x78), 'class0': (18, 0x0b, 247, 0xd6), 'integrity': (27, 0x14, 247, 0xd6)}


def _neg_entry_rows(src, table, mirrors):
    """Repeat every const entry of N's `table` that names a range-READ length constant once per pass-through length
    (mirrors: old literal -> [new literals]); each copy follows its original, so entry priority order is kept."""
    head = src.index(' table %s{' % table)
    start = src.index('const entries={', head) + len('const entries={')
    depth, end = 1, start
    while depth:
        depth += {'{': 1, '}': -1}.get(src[end], 0)
        end += 1
    body = src[start:end - 1]
    rows = re.findall(r'\([^()]*\):\w+\([^()]*\);', body)
    if ''.join(rows) != body:
        raise SystemExit('unexpected const-entry layout in %s' % table)
    out = []
    for r in rows:
        out.append(r)
        for old, news in mirrors.items():
            if old in r:
                out += [r.replace(old, n) for n in news]
    size_at = src.index('size=', head)
    size_end = src.index(';', size_at)
    size = max(int(src[size_at + 5:size_end]), len(out))
    return src[:size_at + 5] + str(size) + src[size_end:start] + ''.join(out) + src[end - 1:]


def transform_read_passthrough_n(src):
    """N admits, times and accounts the policy's pass-through READ classes at native size (step S1).

    Requests (all fully parsed, real block CRC, TCP checksum verified as before): analog 22 octets (G30 V0 q01
    [0,20], ip.len 62, dl.len 0x0f), class0 18 (G60V1 q06, ip.len 58, dl.len 0x0b), integrity 27 (G60V2/V3/V4/V1
    q06, ip.len 67, dl.len 0x14). Responses: analog 141 (ip.len 181, dl.len 0x78) and class0/integrity 247 (ip.len
    287, dl.len 0xd6), one link frame each, parsed FIRST BLOCK ONLY: the link-header and block-0 CRCs are really
    checked, block-1+ CRCs are derived from block 0 (m.crc1 = m.tcrc = m.bcrc) and the TCP checksum is waived
    (m.tcp_sum = 0xffeb, set by the parser's finish_shallow state: m12p_c06 wrote it in MAU, which moved N's
    network table from stage 0 to 3 and N from 11 to 12 stages) -- the documented shallow-parse limitation of transform_read_prefix_full; the master's
    stack validates the tail. New lengths enter through their own parser states that dispatch on the exact
    (dl.len, ip.len) pair, so the range path (ip.len 60/89, and the timestamp variants) is byte-for-byte unchanged.
    Their TCP states match only (offset, flags): m12p_c05 repeated the range states' (offset, reserved, urgent,
    flags) select and ran out of ingress parser match registers; reserved == 0 and urgent == 0 are still required
    by N's network table (exact keys), so admission is unchanged.
    Sequence: next_seq_t adds each shape's native length; every retransmission row keyed on the range lengths
    (-20 request, -49 response) is repeated for each pass-through length. E maps these responses natively (no
    read_shape: acct_grow + translate) and the pipe-1 padder parses only ip.len 89 / dl.len 0x26."""
    # 1) request headers, overlaid with the range request header (mutually exclusive parse paths)
    src = once(src, 'header n_read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}',
               'header n_read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}\n'
               'header n_read_req_an_h{bit<8> tp;bit<8> app;bit<8> func;bit<24> o1;bit<16> start;bit<16> stop;bit<16> crc;}\n'
               'header n_read_req_c0_h{bit<8> tp;bit<8> app;bit<8> func;bit<24> o1;bit<16> crc;}\n'
               'header n_read_req_full_h{bit<8> tp;bit<8> app;bit<8> func;bit<24> o1;bit<24> o2;bit<24> o3;bit<24> o4;bit<16> crc;}')
    src = once(src, 'n_read_req_h rd_req;', 'n_read_req_h rd_req;n_read_req_an_h rd_req_an;n_read_req_c0_h rd_req_c0;n_read_req_full_h rd_req_full;')
    hdrs = ('hdr.rd_req', 'hdr.rd_req_an', 'hdr.rd_req_c0', 'hdr.rd_req_full')
    pragmas = ''.join('@pa_mutually_exclusive("ingress", "%s", "%s")\n' % (a, b)
                      for i, a in enumerate(hdrs) for b in hdrs[i + 1:])
    src = once(src, '@pa_container_size("ingress", "m.expected_work_phase", 32)\n',
               pragmas + '@pa_container_size("ingress", "m.expected_work_phase", 32)\n')
    # 2) parser: new ip.len values -> dedicated states, exact (dl.len, ip.len) dispatch, else accept (unparsed)
    src = once(src, '(4w4,4w5,8w6,16w60):read_ip_flags;',
               '(4w4,4w5,8w6,16w60):read_ip_flags;' + ''.join('(4w4,4w5,8w6,16w%d):rx_ip_flags;' % (40 + v[0])
                                                              for v in sorted(PASSTHROUGH_READS.values())))
    rsp_ip = sorted({40 + v[2] for v in PASSTHROUGH_READS.values()})
    src = once(src, '(4w4,4w5,8w6,16w89):read_response_ip_flags;',
               '(4w4,4w5,8w6,16w89):read_response_ip_flags;' + ''.join('(4w4,4w5,8w6,16w%d):rx_response_ip_flags;' % n for n in rsp_ip))
    req_cases = ''.join('(8w0x%02x,16w%d):read_request_%s;' % (v[1], 40 + v[0], {'analog': 'an', 'class0': 'c0', 'integrity': 'full'}[n])
                        for n, v in sorted(PASSTHROUGH_READS.items()))
    rsp_cases = ''.join('(8w0x%02x,16w%d):read_response_fb;' % k for k in sorted({(v[3], 40 + v[2]) for v in PASSTHROUGH_READS.values()}))
    states = (' state rx_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):rx_tcp;(13w0,3w2):rx_tcp;default:accept;}}\n'
              ' state rx_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.flags){(4w5,8w16):rx_dl;(4w5,8w24):rx_dl;default:accept;}}\n'
              ' state rx_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition select(hdr.dl.len,hdr.ip.len){%sdefault:accept;}}\n'
              ' state read_request_an{pkt.extract(hdr.rd_req_an);tc.subtract(hdr.rd_req_an);m.packet_kind=8w9;transition finish;}\n'
              ' state read_request_c0{pkt.extract(hdr.rd_req_c0);tc.subtract(hdr.rd_req_c0);m.packet_kind=8w9;transition finish;}\n'
              ' state read_request_full{pkt.extract(hdr.rd_req_full);tc.subtract(hdr.rd_req_full);m.packet_kind=8w9;transition finish;}\n'
              ' state rx_response_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):rx_response_tcp;(13w0,3w2):rx_response_tcp;default:accept;}}\n'
              ' state rx_response_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.flags){(4w5,8w16):rx_response_dl;(4w5,8w24):rx_response_dl;default:accept;}}\n'
              ' state rx_response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition select(hdr.dl.len,hdr.ip.len){%sdefault:accept;}}\n'
              ' state read_response_fb{pkt.extract(hdr.first);tc.subtract(hdr.first);m.packet_kind=8w11;transition finish_shallow;}\n'
              ' state finish_shallow{m.tcp_sum=16w0xffeb;m.parsed=(bit<1>)(8w1);m.shape_valid=(bit<1>)(8w1);transition accept;}\n'
              % (req_cases, rsp_cases))
    src = once(src, ' state read_request{pkt.extract(hdr.rd_req);', states + ' state read_request{pkt.extract(hdr.rd_req);')
    # 3) request profiles (exact declared objects; tp FIR/FIN and app FIR/FIN/!CON/!UNS as EXACT slice keys, the
    #    same match as the range profile's ternary c0&&&c0 / c0&&&f0 -- in m12p_c07 the three ternary profiles took
    #    stage-1 TCAM and displaced retry_valid_t, one cause of N's 12th stage) + real block CRCs; response profile rows for the 141/247 block 0
    prof = ('table read_request_an_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req_an.tp[7:6]:exact;hdr.rd_req_an.app[7:4]:exact;hdr.rd_req_an.func:exact;hdr.rd_req_an.o1:exact;hdr.rd_req_an.start:exact;hdr.rd_req_an.stop:exact;}\n'
            ' actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w0x0f,8w0xc4,2w3,4w0xc,8w1,24w0x1e0001,16w0x0000,16w0x1400):eligible();}}\n'
            'table read_request_c0_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req_c0.tp[7:6]:exact;hdr.rd_req_c0.app[7:4]:exact;hdr.rd_req_c0.func:exact;hdr.rd_req_c0.o1:exact;}\n'
            ' actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w0x0b,8w0xc4,2w3,4w0xc,8w1,24w0x3c0106):eligible();}}\n'
            'table read_request_full_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req_full.tp[7:6]:exact;hdr.rd_req_full.app[7:4]:exact;hdr.rd_req_full.func:exact;hdr.rd_req_full.o1:exact;hdr.rd_req_full.o2:exact;hdr.rd_req_full.o3:exact;hdr.rd_req_full.o4:exact;}\n'
            ' actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w0x14,8w0xc4,2w3,4w0xc,8w1,24w0x3c0206,24w0x3c0306,24w0x3c0406,24w0x3c0106):eligible();}}\n')
    src = once(src, '(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}\n',
               '(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}\n' + prof)
    src = once(src, 'actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();}}',
               'actions={eligible;NoAction;}size=3;const default_action=NoAction();const entries={(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();'
               '(16w0x0564,8w0x78,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w0x1e,8w1,8w0,8w0,8w0x14):eligible();'
               '(16w0x0564,8w0xd6,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();}}')
    # Two tables compute the three new request CRCs: analog+class0 share one (one action each by header validity;
    # 2 x 16 = 32 immediate hash bits, the per-table limit -- m12p_c10's single three-CRC table needed 48 and failed),
    # integrity has its own. m12p_c09 used one table per shape: stages 0-2 have no free hash-distribution unit and
    # stages 3-4 no free logical table ID (both shared with E), so the extra tables displaced E's stage-3 tables.
    crcs = ''
    for h, fields in (('an', 'tp,app,func,o1,start,stop,crc'), ('c0', 'tp,app,func,o1,crc'), ('full', 'tp,app,func,o1,o2,o3,o4,crc')):
        crcs += ('Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_request_%s;\n'
                 'action rd_request_%s_crc(){m.bcrc=hash_rd_request_%s.get({%s});}\n'
                 % (h, h, h, ','.join('hdr.rd_req_%s.%s' % (h, f) for f in fields.split(','))))
    crcs += ('table rd_request_x_crc_t{key={hdr.rd_req_an.isValid():exact;}'
             'actions={rd_request_an_crc;rd_request_c0_crc;NoAction;}size=2;'   # a hash action cannot be the default (m12p_c11)
             'const entries={true:rd_request_an_crc();false:rd_request_c0_crc();}const default_action=NoAction();}\n'
             'table rd_request_full_crc_t{actions={rd_request_full_crc;}size=1;const default_action=rd_request_full_crc();}\n')
    src = once(src, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_tail;\n', crcs + 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_tail;\n')
    src = once(src, 'action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value,hdr.rd_tail.crc});}',
               'action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value,hdr.rd_tail.crc});}\n'
               'action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;}\n'
               'table read_shallow_admit_t{actions={read_shallow_admit;}size=1;const default_action=read_shallow_admit();}')
    src = once(src, 'if(m.packet_kind==8w9){read_request_profile.apply();rd_request_crc_t.apply();}else{read_response_profile.apply();rd_second_crc_t.apply();rd_tail_crc_t.apply();}',
               'if(m.packet_kind==8w9){if(hdr.rd_req.isValid()){read_request_profile.apply();rd_request_crc_t.apply();}'
               'else if(hdr.rd_req_full.isValid()){read_request_full_profile.apply();rd_request_full_crc_t.apply();}'
               'else{if(hdr.rd_req_an.isValid()){read_request_an_profile.apply();}else{read_request_c0_profile.apply();}'
               'rd_request_x_crc_t.apply();}}'
               'else{read_response_profile.apply();if(hdr.second.isValid()){rd_second_crc_t.apply();rd_tail_crc_t.apply();}else{read_shallow_admit_t.apply();}}')
    # 4) sequence accounting per shape: native length by (kind, dl.len); range rows unchanged as the fallbacks
    rows = ''.join('(8w9,8w0x%02x):next_read_len(%d);' % (v[1], v[0]) for _, v in sorted(PASSTHROUGH_READS.items()))
    rows += ''.join('(8w11,8w0x%02x):next_read_len(%d);' % k for k in sorted({(v[3], v[2]) for v in PASSTHROUGH_READS.values()}))
    src = once(src, ' table next_seq_t{key={m.packet_kind:exact;}actions={next_seq;next_control;next_response;next_read_request;next_read_response;}size=5;'
               'const entries={8w5:next_control();8w7:next_control();8w6:next_response();8w9:next_read_request();8w11:next_read_response();}const default_action=next_seq();}',
               ' action next_read_len(bit<32> n){m.new_seq=hdr.tcp.seq+n;}\n'
               ' table next_seq_t{key={m.packet_kind:exact;hdr.dl.len:ternary;}actions={next_seq;next_control;next_response;next_read_request;next_read_response;next_read_len;}size=12;'
               'const entries={(8w5,_):next_control();(8w7,_):next_control();(8w6,_):next_response();%s(8w9,_):next_read_request();(8w11,_):next_read_response();}const default_action=next_seq();}' % rows)
    # 5) application-sequence input from whichever request header is valid (response side reads hdr.first as before)
    src = once(src, 'table read_input_t{key={m.packet_kind:exact;}actions={read_request_input;read_response_input;NoAction;}size=2;const entries={8w9:read_request_input();8w11:read_response_input();}const default_action=NoAction();}',
               'action read_request_an_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_an.app[3:0]);}\n'
               'action read_request_c0_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_c0.app[3:0]);}\n'
               'action read_request_full_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_full.app[3:0]);}\n'
               'table read_input_t{key={m.packet_kind:exact;hdr.rd_req_an.isValid():exact;hdr.rd_req_c0.isValid():exact;hdr.rd_req_full.isValid():exact;}'
               'actions={read_request_input;read_request_an_input;read_request_c0_input;read_request_full_input;read_response_input;NoAction;}size=5;'
               'const entries={(8w9,false,false,false):read_request_input();(8w9,true,false,false):read_request_an_input();'
               '(8w9,false,true,false):read_request_c0_input();(8w9,false,false,true):read_request_full_input();'
               '(8w11,false,false,false):read_response_input();}const default_action=NoAction();}')
    # 6) retransmission recognition per shape (sequence_guard, first_event, retry_dup_t)
    req_neg = sorted({neg(v[0]) for v in PASSTHROUGH_READS.values()})
    rsp_neg = sorted({neg(v[2]) for v in PASSTHROUGH_READS.values()})
    mirrors = {neg(20): req_neg, neg(49): rsp_neg}
    for table in ('sequence_guard', 'first_event', 'retry_dup_t'):
        src = _neg_entry_rows(src, table, mirrors)
    return src
