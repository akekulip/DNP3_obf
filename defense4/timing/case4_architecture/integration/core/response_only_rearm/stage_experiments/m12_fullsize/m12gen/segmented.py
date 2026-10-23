"""The faithful two-segment 377 -> 401 READ investigation (candidate m12p_c20; historical, out of the current
milestone): T second response child, pipe-1 segmented padder, N two-segment classifier."""
import json

from .common import CONSTANTS_SEG, once


def transform_segmented_t(src):
    """SEGMENTED probe (opt-in, --segmented only). Smallest T extension toward a two-link-frame
    377 -> 401 READ: let the transaction core admit a SECOND response child (tev.stage 1 / ladder.child 1)
    so the FIN continuation segment is a child of the same READ generation as the FIR segment.

    The base (m11_09) already declares md.seen1_diff/md.seen2_diff and the go/verdict tables already key
    on them ternary; only child 0 is wired (child_seen0_reg) and children 1/2 are stubbed as 0xffffffff
    ('never admitted'). This adds a real child_seen1_reg (one more ingress SALU/stage) plus the parser
    paths for stage/child 1, mirroring child 0 exactly. It does NOT yet dispatch the 332/125 segments in N,
    account the 401 image in the mapper, or prepend the 24-B prefix -- those land on p0, which is already
    12/12 stages. This probe isolates whether T can represent the second child at all (T p1-ingress has one
    free stage in m12p_c12). Byte-identical to c12 when --segmented is off."""
    # 1) parser: admit stage 1 as a second response child, and ladder child 1
    src = once(src,
        '    state single_response_child { transition select(hdr.tev.stage) { 0: opaque_ethernet; default: reject; } }',
        '    state single_response_child { transition select(hdr.tev.stage) { 0: opaque_ethernet; 1: opaque_ethernet; default: reject; } }')
    src = once(src,
        '        transition select(hdr.ladder.child) { 0: single_ladder_role; default: reject; }',
        '        transition select(hdr.ladder.child) { 0: single_ladder_role; 1: single_ladder_role; default: reject; }')
    # 2) a real second-child seen register + access table, mirroring child 0
    seen1 = (
        '\n    // ---- SEGMENTED probe: second response child (make_m12.transform_segmented_t) ----\n'
        '    Register<bit<32>, bit<1>>(1, 0xffffffff) child_seen1_reg;\n'
        '    RegisterAction<bit<32>, bit<1>, bit<32>>(child_seen1_reg) child_try1 = {\n'
        '        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; value = md.cur_gen; }\n'
        '    };\n'
        '    RegisterAction<bit<32>, bit<1>, bit<32>>(child_seen1_reg) child_read1 = {\n'
        '        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }\n'
        '    };\n'
        '    action read_seen1() { md.seen1_diff = child_read1.execute(0); }\n'
        '    action try_seen1() { md.seen1_diff = child_try1.execute(0); }\n'
        '    table child_seen1_access {\n'
        '        key = { ig_intr_md.ingress_port : ternary; md.event_kind : ternary;\n'
        '                hdr.tev.stage : ternary; md.e_bad : ternary; md.enabled : ternary; }\n'
        '        actions = { read_seen1; try_seen1; NoAction; }\n'
        '        const entries = {\n'
        '            (t_HELD_RETURN, _, _, _, _) : read_seen1();\n'
        '            (t_T_IN, t_KIND_RESPONSE, 1, _, 0) : NoAction();\n'
        '            (t_T_IN, t_KIND_RESPONSE, 1, 0, _) : try_seen1();\n'
        '        }\n'
        '        default_action = NoAction(); size = 3;\n'
        '    }\n')
    src = once(src,
        '            (t_T_IN, t_KIND_RESPONSE, 0, 0, _) : try_seen0();\n'
        '        }\n'
        '        default_action = NoAction(); size = 3;\n'
        '    }\n',
        '            (t_T_IN, t_KIND_RESPONSE, 0, 0, _) : try_seen0();\n'
        '        }\n'
        '        default_action = NoAction(); size = 3;\n'
        '    }\n' + seen1)
    # 3) apply the second-child table (keep the not-seen default so stage-0 passes are unchanged)
    src = once(src,
        '        child_seen0_access.apply(); md.seen1_diff = 32w0xffffffff; md.seen2_diff = 32w0xffffffff;',
        '        child_seen0_access.apply(); md.seen1_diff = 32w0xffffffff; child_seen1_access.apply(); md.seen2_diff = 32w0xffffffff;')
    return src


def segmented_shape(name='segmented_integrity_377'):
    """Per-shape segmented-prefix constants, derived + proven byte-exact vs pad_read on 512 samples by
    read_complete_01/vectors/derive.py (construct()==pad_read). No hand constants."""
    return json.loads(CONSTANTS_SEG.read_text())['shapes'][name]


def transform_segmented_pad_pipe1(src, c):
    """FAITHFUL two-frame 377 -> 401 READ padder in PIPE-1 EGRESS (extends the range prefix padder of
    transform_read_prefix_p1). The large-DB integrity/class0 READ response is two TCP segments on the
    N->T handoff (port 180): segment 1 = the 292-B FIR link frame (ip.len 332, dl.len 0xff), segment 2 =
    the 85-B FIN link frame (ip.len 125, dl.len 0x46). Each traverses pipe-1 egress once; the padder acts
    per segment:

      seg0 (ip.len 332): PREPEND the 24-B synthetic FIR frame (link LEN 0x11, moved application header +
        padding-object header g1v2 q01 [1024..1027]) and REWRITE block 0 (transport FIR|s -> s+1 as a middle
        segment, the 4 application-header octets -> 0, block-0 CRC recomputed); ip.len += 24; TCP seq unchanged.
      seg1 (ip.len 125): REWRITE block 0 only (transport FIN|s1 -> FIN|s1+1, block-0 CRC recomputed); ip.len
        unchanged; TCP seq += 24 (the prefix inserted 24 B earlier in the master-facing byte stream).

    Only padobj_head, the prefix link LEN and the prefix link-CRC delta are compile constants
    (constants_segmented.json); every block-0 CRC, the moved application header, the link addresses and the
    IP/TCP checksums are derived on chip from live fields. The two continuation block-0s parse with the SAME
    rh/robj/p03/p45/c0 headers as the range frame (16 user octets + CRC), so no new parser depth is needed;
    the 274-B seg0 tail and the 57-B seg1 tail ride m.residual unparsed (the full-READ first-block pattern).
    Byte-exactness is validated against derive.construct()/pad_read at the source-interpreter tier; the
    deparser IP/TCP checksum externs are not executed there, so their incremental correctness is bounded to
    the compiled model/ASIC exactly as the range padder's checksum is."""
    delta = c['prefix_link_crc_delta']
    padobj = int(c['padobj_head'], 16)
    plen = c['prefix_link_len']
    seg0_rows = ''.join('(8w0x%02x):set_tp(8w0x%02x,8w0x%02x);' % (0x40 | s, 0x40 | s, (s + 1) & 0x3f) for s in range(64))
    seg1_rows = ''.join('(8w0x%02x):set_tp(8w0x00,8w0x%02x);' % (0x80 | s, 0x80 | ((s + 1) & 0x3f)) for s in range(64))

    # --- 1) headers + metadata ---
    src = once(src, 'header x_pl_u_h { bit<8> tp; bit<32> app; bit<56> padobj; bit<32> padobj2; }',
               'header x_pl_u_h { bit<8> tp; bit<32> app; bit<56> padobj; bit<32> padobj2; }\n'
               'header x_pl_u2_h { bit<8> tp; bit<32> app; bit<56> padobj; }   // 12-B segmented-prefix user (no padobj2/plz)\n'
               'header x_segmark_h { bit<8> v; }   // seg1 deparser-branch marker (validity only; never emitted)')
    src = once(src, 'x_pl_u_h plu; x_crc_h pluc;', 'x_pl_u_h plu; x_pl_u2_h plu2; x_segmark_h segmark; x_crc_h pluc;')
    src = once(src, 'bit<1> conn_ok; bit<2> p1_res; }',
               'bit<1> conn_ok; bit<2> p1_res; bit<2> seg; bit<16> pl_uc2; bit<16> s1_c0; }')

    # --- 2) parser: admit both segment lengths, reuse the one block-0 extraction ---
    src = once(src, 'transition select(hdr.tev.kind, hdr.tev.stage) { (8w11, 8w0): eth; default: accept; }',
               'transition select(hdr.tev.kind, hdr.tev.stage) { (8w11, 8w0): eth; (8w11, 8w1): eth; default: accept; }')
    src = once(src, 'state ip_len { transition select(hdr.ip.len) { 16w89: ip_frag; default: accept; } }',
               'state ip_len { transition select(hdr.ip.len) { 16w89: ip_frag; 16w332: ip_frag; 16w125: ip_frag; default: accept; } }')
    src = once(src, 'state dl { pkt.extract(hdr.dl); transition select(hdr.dl.len) { 8w0x26: dl_start; default: accept; } }',
               'state dl { pkt.extract(hdr.dl); transition select(hdr.dl.len) { 8w0x26: dl_start; 8w0xff: dl_start; 8w0x46: dl_start; default: accept; } }')

    # --- 3) control: segment class, extra CRC derivations, transport renumber rows, profiles, pad actions ---
    src = once(src, '    action set_tp(bit<8> a, bit<8> b) { m.pl_tp = a; m.co_tp = b; }',
               '    action set_seg(bit<2> s) { m.seg = s; }\n'
               '    table seg_class_t { key = { hdr.dl.len : exact; } actions = { set_seg; NoAction; } size = 4;\n'
               '        const default_action = set_seg(2w0);\n'
               '        const entries = { (8w0xff): set_seg(2w1); (8w0x46): set_seg(2w2); } }\n'
               '    action set_tp(bit<8> a, bit<8> b) { m.pl_tp = a; m.co_tp = b; }')
    src = once(src, 'actions = { set_tp; NoAction; } size = 64;', 'actions = { set_tp; NoAction; } size = 192;')
    src = once(src, '(8w0xff):set_tp(8w0x7f,8w0x80); } }',
               '(8w0xff):set_tp(8w0x7f,8w0x80);' + seg0_rows + seg1_rows + ' } }')
    # seg0 prefix block-0 CRC (12-B user, no padobj2) and seg1 block-0 CRC (16-B user, app header kept)
    src = once(src, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_co_c0;',
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_co_c0;\n'
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_pl_uc2;\n'
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_s1_c0;')
    src = once(src, '    table crc_co_c0_t { actions = { crc_co_c0; } size = 1; const default_action = crc_co_c0(); }',
               '    table crc_co_c0_t { actions = { crc_co_c0; } size = 1; const default_action = crc_co_c0(); }\n'
               '    action crc_pl_uc2() { m.pl_uc2 = hash_pl_uc2.get({m.pl_tp, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, 56w%d}); }\n'
               '    table crc_pl_uc2_t { actions = { crc_pl_uc2; } size = 1; const default_action = crc_pl_uc2(); }\n'
               '    action crc_s1_c0() { m.s1_c0 = hash_s1_c0.get({m.co_tp, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin,\n'
               '        hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d}); }\n'
               '    table crc_s1_c0_t { actions = { crc_s1_c0; } size = 1; const default_action = crc_s1_c0(); }' % padobj)
    # seg0/seg1 gates (reuse range_read -> m.pad = 1). seg0: g1v2 q00 [0,15] FIR frame; seg1: FIN continuation.
    # SCOPE ASSUMPTION (review 33e21fd07): fix_s1 is stateless -- seg_class_t classifies seg1 purely by
    # (dl.len==0x46 && FIN) and fix_s1 then applies tcp.seq += 24 unconditionally, with NO per-flow state
    # confirming this flow's seg0 (FIR) was actually prefixed. This is correct ONLY because the obfuscated
    # connection carries exactly the 292+85 integrity/class0 segmented shape: every 70-byte FIN link frame on
    # it IS the continuation of a prefixed seg0. A different multi-frame response ending in a 70-byte FIN frame
    # would be mis-renumbered (+24 with no inserted bytes), desynchronizing the master's TCP stream. No guard is
    # added here (a per-flow "seg0 prefixed" register costs stages and the connection is single-shape by scope);
    # hardware bring-up of the segmented class MUST cover a mixed-response flow before this assumption is relied on.
    src = once(src, '    action prefix() {',
               '    table seg0_profile { key = { hdr.dl.len : exact; hdr.rh.tpctrl : ternary; hdr.rh.func : exact;\n'
               '            hdr.robj.g_group : exact; hdr.robj.g_var : exact; hdr.robj.g_qual : exact; hdr.robj.g_start : exact; hdr.robj.g_stop : exact; }\n'
               '        actions = { range_read; NoAction; } size = 1; const default_action = NoAction();\n'
               '        const entries = { (8w0xff, 8w0x40 &&& 8w0xc0, 8w0x81, 8w0x01, 8w0x02, 8w0x00, 8w0x00, 8w0x0f): range_read(); } }\n'
               '    table seg1_gate { key = { hdr.dl.len : exact; hdr.rh.tpctrl : ternary; }\n'
               '        actions = { range_read; NoAction; } size = 1; const default_action = NoAction();\n'
               '        const entries = { (8w0x46, 8w0x80 &&& 8w0x80): range_read(); } }\n'
               '    action prefix_s0() {\n'
               '        hdr.pll.setValid(); hdr.pll.start = 16w0x0564; hdr.pll.len = 8w0x%02x; hdr.pll.ctrl = hdr.dl.ctrl;\n'
               '        hdr.pll.dst = hdr.dl.dst; hdr.pll.src = hdr.dl.src; hdr.pll.crc = hdr.dl.crc ^ 16w%d;\n'
               '        hdr.plu2.setValid(); hdr.plu2.tp = m.pl_tp; hdr.plu2.app = hdr.rh.appctrl ++ hdr.rh.func ++ hdr.rh.iin; hdr.plu2.padobj = 56w%d;\n'
               '        hdr.pluc.setValid(); hdr.pluc.crc = m.pl_uc2[7:0] ++ m.pl_uc2[15:8];\n'
               '        hdr.rh.tpctrl = m.co_tp; hdr.rh.appctrl = 8w0; hdr.rh.func = 8w0; hdr.rh.iin = 16w0;\n'
               '        hdr.c0.crc = m.co_c0[7:0] ++ m.co_c0[15:8];\n'
               '        hdr.ip.len = hdr.ip.len + 16w24; m.len_delta = 16w24;\n'
               '    }\n'
               '    table prefix_s0_t { actions = { prefix_s0; } size = 1; const default_action = prefix_s0(); }\n'
               '    action fix_s1() {\n'
               '        hdr.rh.tpctrl = m.co_tp;\n'
               '        hdr.c0.crc = m.s1_c0[7:0] ++ m.s1_c0[15:8];\n'
               '        hdr.tcp.seq = hdr.tcp.seq + 32w24;\n'
               '        hdr.segmark.setValid(); hdr.segmark.v = 8w0;\n'
               '    }\n'
               '    table fix_s1_t { actions = { fix_s1; } size = 1; const default_action = fix_s1(); }\n'
               '    action prefix() {' % (plen, delta, padobj))

    # --- 4) apply: branch on segment class ---
    src = once(src,
               '        if (hdr.c0.isValid()) {\n'
               '            p1_conn.apply();\n'
               '            in_rb0_t.apply(); set_tp_t.apply(); crc_pl_uc_t.apply(); crc_co_c0_t.apply();\n'
               '            if (m.conn_ok == 1w1 && hdr.c0.crc == (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { read_profile.apply(); }\n'
               '            if (m.pad == 1w1) { prefix_t.apply(); m.p1_res = 2w1; }\n'
               '            else if (m.conn_ok == 1w0) { m.p1_res = 2w2; }\n'
               '            else { m.p1_res = 2w3; }\n'
               '            p1_outcome.count(m.p1_res);\n'
               '        }',
               '        if (hdr.c0.isValid()) {\n'
               '            p1_conn.apply();\n'
               '            seg_class_t.apply();\n'
               '            in_rb0_t.apply(); set_tp_t.apply();\n'
               '            crc_pl_uc_t.apply(); crc_pl_uc2_t.apply(); crc_co_c0_t.apply(); crc_s1_c0_t.apply();\n'
               '            if (m.conn_ok == 1w1 && hdr.c0.crc == (m.in_rb0[7:0] ++ m.in_rb0[15:8])) {\n'
               '                if (m.seg == 2w0) { read_profile.apply(); }\n'
               '                else if (m.seg == 2w1) { seg0_profile.apply(); }\n'
               '                else { seg1_gate.apply(); }\n'
               '            }\n'
               '            if (m.pad == 1w1) {\n'
               '                if (m.seg == 2w0) { prefix_t.apply(); }\n'
               '                else if (m.seg == 2w1) { prefix_s0_t.apply(); }\n'
               '                else { fix_s1_t.apply(); }\n'
               '                m.p1_res = 2w1;\n'
               '            }\n'
               '            else if (m.conn_ok == 1w0) { m.p1_res = 2w2; }\n'
               '            else { m.p1_res = 2w3; }\n'
               '            p1_outcome.count(m.p1_res);\n'
               '        }')

    # --- 5) deparser: emit plu2; per-segment IP/TCP checksum (incremental; verified offline by checksum_oracle) ---
    src = once(src, 'pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc); pkt.emit(hdr.plz);',
               'pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.plu2); pkt.emit(hdr.pluc); pkt.emit(hdr.plz);')
    # extra Checksum engines for the two segmented paths (the TNA deparser branches on header validity, the
    # same pattern as E's prefix padder -- nested metadata conditionals are rejected by the deparser frontend)
    src = once(src, 'control x_EgDeparser(packet_out pkt, inout x_headers_t hdr, in x_meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {\n'
               '    Checksum() ip_new; Checksum() tcp_new;',
               'control x_EgDeparser(packet_out pkt, inout x_headers_t hdr, in x_meta_t m, in egress_intrinsic_metadata_for_deparser_t md) {\n'
               '    Checksum() ip_new; Checksum() tcp_new; Checksum() tcp_seg0; Checksum() tcp_seg1;')
    # the existing range TCP checksum is guarded by plz validity (range sets plz valid); seg0 by plu2; seg1 by segmark
    src = once(src,
               '            hdr.tcp.checksum = tcp_new.update({m.len_delta,\n'
               '                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,\n'
               '                hdr.plu.tp, hdr.plu.app, hdr.plu.padobj, hdr.plu.padobj2, hdr.pluc.crc,\n'
               '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
               '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,\n'
               '                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
               '                m.residual});\n'
               '        }',
               '        }\n'
               '        if (hdr.plz.isValid()) {   // range: existing 92-B prefix path\n'
               '            hdr.tcp.checksum = tcp_new.update({m.len_delta,\n'
               '                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,\n'
               '                hdr.plu.tp, hdr.plu.app, hdr.plu.padobj, hdr.plu.padobj2, hdr.pluc.crc,\n'
               '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
               '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,\n'
               '                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
               '                m.residual});\n'
               '        }\n'
               '        if (hdr.plu2.isValid()) {   // seg0: 24-B prefix + rewritten block 0 (len +24)\n'
               '            hdr.tcp.checksum = tcp_seg0.update({m.len_delta,\n'
               '                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,\n'
               '                hdr.plu2.tp, hdr.plu2.app, hdr.plu2.padobj, hdr.pluc.crc,\n'
               '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
               '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,\n'
               '                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
               '                m.residual});\n'
               '        }\n'
               '        if (hdr.segmark.isValid()) {   // seg1: block-0 rewrite + tcp.seq += 24 (len unchanged)\n'
               '            hdr.tcp.checksum = tcp_seg1.update({hdr.tcp.seq,\n'
               '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
               '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,\n'
               '                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
               '                m.residual});\n'
               '        }')
    return src


def transform_segmented_classifier(src):
    """N (pipe-0 ingress) classifies the two link frames of the 377 READ response as ONE READ transaction and
    tags the child index into the tev handoff (step 1 of the faithful path, built on the c13/c14/c15 probes).

    seg0 (ip.len 332, dl.len 0xff): FIR frame, first-block parse, admitted through the ordinary response
      profile (g1v2 q00 [0,15], the same object header as the 247 class0/integrity response) -> child 0.
    seg1 (ip.len 125, dl.len 0x46): FIN continuation whose block 0 is mid-stream object data (no object
      header to profile); admitted by a dedicated continuation table keyed on dl.len + FIN transport, with its
      real block-0 CRC checked (crc_head_first) and the shallow-admit of the pass-through classes -> child 1.
    The child index is written into the handoff event (emit_tev set 0x0b00; child_tag_t rewrites it to 0x0b01
    for seg1 so T's parser sees tev.stage 1); sequence accounting advances by each frame's native length
    (seg0 +292, seg1 +85 = 377). This is the p0-ingress half of the integration; its ADMISSION of both
    segments is checked at the source-interpreter tier, while the child-tag -> T handoff and the two-frame
    transaction commit are structural here (they need the compiled model, not run in this task)."""
    # a) ip + dl length admission (reuses the pass-through rx_response path; 0 MAU per probe segmented_n)
    src = once(src, '(4w4,4w5,8w6,16w287):rx_response_ip_flags;',
               '(4w4,4w5,8w6,16w287):rx_response_ip_flags;(4w4,4w5,8w6,16w332):rx_response_ip_flags;(4w4,4w5,8w6,16w125):rx_response_ip_flags;')
    src = once(src, 'transition select(hdr.dl.len,hdr.ip.len){(8w0x78,16w181):read_response_fb;(8w0xd6,16w287):read_response_fb;default:accept;}',
               'transition select(hdr.dl.len,hdr.ip.len){(8w0x78,16w181):read_response_fb;(8w0xd6,16w287):read_response_fb;(8w0xff,16w332):read_response_fb;(8w0x46,16w125):read_response_fb;default:accept;}')
    # b) seg0 response profile row (FIR g1v2 q00 [0,15]); bump the table size
    src = once(src, 'size=3;const default_action=NoAction();const entries={(16w0x0564,8w38',
               'size=5;const default_action=NoAction();const entries={(16w0x0564,8w38')
    src = once(src, '(16w0x0564,8w0xd6,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();}}',
               '(16w0x0564,8w0xd6,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();'
               '(16w0x0564,8w0xff,8w0x44,8w0x40&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();}}')
    # c) seg1 continuation admit (dl.len 0x46 + FIN transport -> eligible), applied after the response profile
    src = once(src, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_second;',
               'table seg1_admit_t{key={hdr.dl.len:exact;hdr.first.w0[31:24]:ternary;}actions={eligible;NoAction;}size=1;'
               'const default_action=NoAction();const entries={(8w0x46,8w0x80&&&8w0xc0):eligible();}}\n'
               'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_second;')
    src = once(src, 'else{read_response_profile.apply();if(hdr.second.isValid()){rd_second_crc_t.apply();rd_tail_crc_t.apply();}else{read_shallow_admit_t.apply();}}',
               'else{read_response_profile.apply();seg1_admit_t.apply();if(hdr.second.isValid()){rd_second_crc_t.apply();rd_tail_crc_t.apply();}else{read_shallow_admit_t.apply();}}')
    # d) sequence accounting per segment native length (seg0 +292, seg1 +85)
    src = once(src, '(8w11,8w0xd6):next_read_len(247);(8w9,_):next_read_request();',
               '(8w11,8w0xd6):next_read_len(247);(8w11,8w0xff):next_read_len(292);(8w11,8w0x46):next_read_len(85);(8w9,_):next_read_request();')
    src = once(src, 'next_read_response;next_read_len;}size=12;', 'next_read_response;next_read_len;}size=14;')
    # e) child-index tag into the handoff event: emit_tev set 0x0b00; seg1 (kind 11, dl.len 0x46) -> 0x0b01
    src = once(src, 'action emit_tev(bit<16> event){',
               'action set_child1(){hdr.event.event=16w0x0b01;}\n'
               'table child_tag_t{key={m.kind:exact;hdr.dl.len:exact;}actions={set_child1;NoAction;}size=1;'
               'const default_action=NoAction();const entries={(8w11,8w0x46):set_child1();}}\n'
               'action emit_tev(bit<16> event){')
    src = once(src, '}else if(m.work_phase==32w3){read_terminal_t.apply();}',
               '}else if(m.work_phase==32w3){read_terminal_t.apply();child_tag_t.apply();}')
    return src
