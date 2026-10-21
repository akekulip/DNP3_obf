"""Generate the integrated READ+SBO timing+size candidate m12, branching from m11_09.

Branches from m11_09 (the committed baseline, preserved on branch baseline-m11_09-20261019). Applies,
as text transforms over the frozen m11_09 source, the integrated size replacement:
  - mapper: single constant image length T (default 269); classify_rev regenerated to a T-byte window.
  - READ: replace the re-encode with an append-a-frame measurement-object padder to T.
  - SBO: reframe the 22-byte control fragment to T (= 22+13k) preserving application bytes.
  - N: carry the full-READ (247) and padded shapes through the timing lanes.

Correctness: live bytes pass through; CRCs/checksums/sequences over live bytes are derived in P4.
Only the synthetic padding frame's own content and its data-block CRCs are compile constants.

Transforms are applied in a fixed order and each is a once()-style anchored edit, so a missing/duplicate
anchor fails loudly. Run with --only to stop after a subset (for incremental compiles).

  python3 make_m12.py OUT_DIR [--image 269] [--only mapper]
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parent
M11_09 = STAGE / 'ctl_timing_01/evidence/m11_09/response_only.p4'
M11_09_SHA = 'f1de2b30e9f00fb93b20df51c3ddfafd3fcfd18e9b6dfcaadd62146dddbe5af8'
sys.path.insert(0, str(HERE / 'probe'))
from make_classify_rev_probe import rev_entries  # noqa: E402
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location('m12_combined', STAGE / 'combined_nt_01/generate.py')
_combined = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_combined)


def once(text, old, new):
    n = text.count(old)
    if n != 1:
        raise SystemExit('anchor %r found %d times (need 1)' % (old[:80], n))
    return text.replace(old, new, 1)


def neg(n):
    return '32w0x%08x' % ((0x100000000 - n) & 0xFFFFFFFF)


def transform_mapper(src, image):
    """Single constant image length = `image`; classify_rev window regenerated to it. (Legacy
    single-target mapper; superseded by transform_mapper_var. Kept for the single-target fallback.)"""
    src = once(src, 'const bit<32> r_IMAGE_LEN = 61;', 'const bit<32> r_IMAGE_LEN = %d;' % image)
    # start_arm: seq + (-(image-1)); was -60 (0xFFFFFFC4) for the 61-byte image
    src = once(src, 'void apply(inout bit<32> v) { v = hdr.tcp.seq + 32w0xFFFFFFC4; } };',
               'void apply(inout bit<32> v) { v = hdr.tcp.seq + %s; } };' % neg(image - 1))
    # fwd_prep: m.pm = m.p - image; was -61 (0xFFFFFFC3)
    src = once(src, 'm.pm = m.p + 32w0xFFFFFFC3;', 'm.pm = m.p + %s;' % neg(image))
    # classify_rev: regenerate the per-byte withhold window to the image size
    src = once(src, 'size = 124; const default_action = rev_drop();', 'size = %d; const default_action = rev_drop();' % (2 * image + 2))
    body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    src = src[:body_start] + '\n' + rev_entries(image) + '\n        ' + src[body_end:]
    return src


# per-shape encoded image lengths (new-encoded length = native + len_delta). The mapper carries each
# response to its own target (option A, variable image). Must equal each padder's output size.
SHAPE_IMAGE = {'read': 73, 'ctl': 61}   # range READ 49->73 (prefix), SBO 37->61 (k=3). full READ 247->269 added in M5.
STALE_GUARD = False   # C3 via extended window-range ladder (hypothesis a: covers full 269 image)


def rev_ternary_window(image, width=32):
    """Minimal ternary (value, mask) entries covering m.r in [-image, -1] = [2^w-image, 2^w-1]: the reverse
    ACKs that fall WITHIN the committed image (withheld, not dropped). Prefix decomposition of the range, so
    the classify_rev C3 boundary needs no window-range key (which expands in TCAM) and no register."""
    full = (1 << width) - 1
    lo = (1 << width) - image
    hi = full
    out, v = [], lo
    while v <= hi:
        size = v & (-v)
        while v + size - 1 > hi:
            size >>= 1
        mask = full ^ (size - 1)
        out.append((v & mask, mask))
        v += size
    return out


def transform_mapper_var(src, shape_image, stale_guard=True, read_native=49):
    """Per-response VARIABLE image length (option A), PHV-cluster-safe. The per-response encoded size is
    a COMPILE CONSTANT per shape in BOTH the acct SALU (acct_try_<shape>) and fwd_prep (fwd_prep_<shape>),
    so NO new 32-bit metadata enters the saturated mapper arithmetic cluster (m.q/p/y/z/pm/t/qx/r/seq/ack).
    A per-response image_len FIELD could not place: a 32-bit one joins the cluster and a 16-bit one's
    cast-temp does too (bf-p4c 2026-10-20, 33-36 slices unallocated).

    The three lengths stay distinct: native m.leff (unchanged), new-encoded = the per-shape constant in
    acct_try_<shape>/fwd_prep_<shape>, committed-image = the per-shape constant stored by the reverse
    stale guard. start_arm stays virtual (-60): the first response commits via classify_fwd's
    (front_ret=0)->out_commit row (ignores m.p); replays use post-commit img_start=seq giving m.p=0, so
    m.pm=m.p-<const> maps to the image start for any shape. (Traced 2026-10-20.)

    shape_image maps 'read'->target / 'ctl'->target (the full READ adds a 'read' at its own size later).
    Requires <= 4 RegisterActions on acct (arm + one try per shape + grow + rev); with 2 shapes that is 5,
    so step 1 uses ONE try action whose constant is the single small-op size when read and ctl share it,
    else per-shape try actions and the action-count limit is tested."""
    max_image = max(shape_image.values())
    sizes = sorted(set(shape_image.values()))
    # 0) Tofino allows <=4 RegisterActions per Register. m11_09's acct has 4 (arm/try/grow/rev); a second
    #    constant-image try would make 5. Drop acct_grow (+= m.leff): its acct_t row matches only
    #    frontier-forward ACK-shaped packets that are NOT the READ(49)/SBO(37) commit rows -- in this
    #    workload only pure keepalive ACKs (m.leff == 0, so the add was a no-op). READ=read_shape and
    #    SELECT/OPERATE=ctl_shape go through the try rows. That leaves arm/rev + two per-size try = 4
    #    actions, input crossbar still {m.ina, m.leff} = 2. (Assumes no unsolicited/event data responses
    #    in the read lane -- consistent with m11_09's single-segment scope.)
    src = once(src, '    RegisterAction<r_pair32, r_slot_t, bit<8>>(acct) acct_grow = {\n'
               '        void apply(inout r_pair32 v) { v.lo = v.lo + m.leff; v.hi = v.hi + m.leff; } };\n', '')
    src = once(src, '    action do_acct_grow() { acct_grow.execute(m.idx); }\n', '')
    src = once(src, '(_, 1, 3w4 &&& 3w7, 0, _, _, _, _, _, _, _, _, _, _, _): do_acct_grow();', '')
    # Committed-image length carried as a 1-BIT flag (two sizes: big=1 -> read image, big=0 -> ctl image),
    # avoiding the 32-bit committed_len register that overflowed PHV. The reverse stale/window computations
    # REUSE m.y and m.z (forward-only fields, dead on the reverse path), so no new 32-bit cluster field is
    # added -- only the 1-byte m.big.
    # No new PHV field for the committed length: it lives in the img_len register, and rstale is computed
    # into m.y (forward-dead on the reverse path). classify_rev keys on m.r and m.y.
    # 1) acct_try per DISTINCT size (constant image; no PHV field). acct_t rows route each shape to its
    #    size's try action. Keeps the acct SALU inputs at {m.leff, m.ina} = 2 (unchanged from m11_09).
    try_acts = ''
    for v in sizes:
        try_acts += ('    RegisterAction<r_pair32, r_slot_t, bit<8>>(acct) acct_try_%d = {\n'
                     '        void apply(inout r_pair32 vv, out bit<8> rv) {\n'
                     '            rv = 0;\n'
                     '            if (vv.hi == 0) { vv.lo = vv.lo + 32w%d; vv.hi = vv.hi + 32w%d; rv = 1; }\n'
                     '            else { vv.lo = vv.lo + m.leff; vv.hi = vv.hi + m.leff; }\n'
                     '        } };\n'
                     '    action do_acct_try_%d() { m.grant = (bit<1>)(acct_try_%d.execute(m.idx)); }\n'
                     % (v, v, v, v, v))
    # replace the single acct_try RegisterAction + its do_acct_try with the per-size set
    src = once(src,
               '    RegisterAction<r_pair32, r_slot_t, bit<8>>(acct) acct_try = {\n'
               '        void apply(inout r_pair32 v, out bit<8> rv) {\n'
               '            rv = 0;\n'
               '            if (v.hi == 0) { v.lo = v.lo + r_IMAGE_LEN; v.hi = v.hi + r_IMAGE_LEN; rv = 1; }\n'
               '            else { v.lo = v.lo + m.leff; v.hi = v.hi + m.leff; }\n'
               '        } };',
               try_acts.rstrip('\n'))
    src = once(src, '    action do_acct_try() { m.grant = (bit<1>)(acct_try.execute(m.idx)); }\n', '')
    # acct_t entries: READ commit row -> its size's try; SBO commit row -> its size's try. The READ row
    # keys on the READ response native length (49 range / 247 full), set by read_native.
    src = once(src, '8w0 &&& 8w0x07, 49, 1, _, 0, 0, 0, 0, _, _): do_acct_try();',
               '8w0 &&& 8w0x07, %d, 1, _, 0, 0, 0, 0, _, _): do_acct_try_%d();' % (read_native, shape_image['read']))
    src = once(src, '8w0 &&& 8w0x07, 37, _, 1, 0, _, _, _, 0, 0): do_acct_try();',
               '8w0 &&& 8w0x07, 37, _, 1, 0, _, _, _, 0, 0): do_acct_try_%d();' % shape_image['ctl'])
    if read_native != 49:
        # out_reset_front keys on the READ native offset m.q; retarget 49 -> read_native.
        src = once(src, 'action out_reset_front_49() { m.qx = m.q - 32w49; m.result = r_OUT_RESET_FRONT; m.changed = 1; }',
                   'action out_reset_front_49() { m.qx = m.q - 32w%d; m.result = r_OUT_RESET_FRONT; m.changed = 1; }' % read_native)
        src = once(src, '(32w49, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_49();',
                   '(32w%d, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_49();' % read_native)
    # acct_t action list: swap do_acct_try for the per-size set
    src = once(src, 'actions = { do_acct_arm; do_acct_try; do_acct_grow; do_acct_rev; NoAction; } size = 10;',
               'actions = { do_acct_arm; %s do_acct_rev; NoAction; } size = 10;'
               % ''.join('do_acct_try_%d;' % v for v in sizes))
    # 2) fwd_prep per shape: m.t (wire advance) and m.pm (replay back-off) use a CONSTANT image per shape.
    fp_acts = ''
    for s, v in shape_image.items():
        fp_acts += ('    action fwd_prep_%s() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + %s; m.t = m.q + 32w%d; }\n'
                    % (s, neg(v), v))
    fp_acts += '    action fwd_prep_native() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p - m.leff; m.t = m.q + m.leff; }\n'
    fp_rows = ';'.join('(%s): fwd_prep_%s()' % (('1, _' if s == 'read' else '_, 1'), s) for s in shape_image)
    fp_tab = ('    table fwd_prep_t { key = { m.read_shape : ternary; m.ctl_shape : ternary; }\n'
              '        actions = { %s fwd_prep_native; } size = 4; const default_action = fwd_prep_native();\n'
              '        const entries = { %s; } }'
              % (''.join('fwd_prep_%s;' % s for s in shape_image), fp_rows))
    src = once(src,
               '    action fwd_prep() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + 32w0xFFFFFFC3; m.t = m.q + r_IMAGE_LEN; }\n'
               '    table fwd_prep_t { actions = { fwd_prep; } size = 1; const default_action = fwd_prep(); }',
               fp_acts + fp_tab)
    # 3) classify_rev C3 boundary. INTENDED: per-committed-image (m.r in [-L,-1] withhold, m.r<-L stale,
    #    L = m.q-m.p via reverse_gap) so an SBO (61) ACK at m.r=-62 stale-drops. MEASURED 2026-10-20: the
    #    per-image boundary does NOT fit the FULL build's PHV -- any per-image reverse computation (a
    #    committed-length register's 1-bit rstale output, OR the arithmetic m.z = m.s_end + m.r) evicts the
    #    SAME 8 small PHV slices (the full-READ prefix padder already sits at the egress+ingress PHV
    #    ceiling). The window-range ladder to the full image (540 entries) compiles but overflows the TCAM
    #    group at load. So the SHIPPED boundary is the pure-m.r form sized to the MAX image (269): withhold
    #    m.r in [-maximg,-1] (4 ternary prefixes), translate m.r>=0, stale m.r<-maximg. This is EXACT for
    #    the READ (269) image and over-withholds a smaller SBO (61) image's pre-start region (m.r in
    #    [-269,-62] withheld, not stale). PER-IMAGE EXACTNESS and the window zero/open split remain OPEN
    #    (need PHV headroom in the full build -- see WORKING_NOTES C3). No window-range key / register /
    #    extra stage; fits and loads.
    maximg = max(shape_image.values())
    src = once(src, '    table classify_rev {\n'
               '        key = { m.r : ternary; hdr.tcp.window : range; }',
               '    table classify_rev {\n'
               '        key = { m.r : ternary; }')
    body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    withhold = rev_ternary_window(maximg)
    new_entries = ('\n            (32w0 &&& 32w0x80000000) : rev_translate();\n'
                   + ''.join('            (32w0x%08x &&& 32w0x%08x) : rev_withhold_open();\n' % (v, m)
                             for v, m in withhold)
                   + '        ')
    src = once(src, 'size = 124; const default_action = rev_drop();',
               'size = %d; const default_action = rev_drop();' % (len(withhold) + 2))
    src = src[:body_start] + new_entries + src[body_end:]
    return src


def transform_read_prefix(src, image):
    """Replace the READ re-encode with the PREFIX padder (prepend.py construction). Range READ 49->73
    (T=73) here; the full READ and other targets extend the same construction. Parses only the first
    block (28 B), emits a leading FIR/!FIN frame carrying the live app header + padding object header,
    rewrites the original first block into a !FIR/FIN continuation (app-header bytes -> 4 padding points,
    CRC Hash-derived over all changes), and re-emits the original tail verbatim as unparsed payload."""
    if image not in (73, 269):
        raise SystemExit('transform_read_prefix: target set per shape (range READ 49->73 here)')
    PREFIX_LEN = 0x11          # leading frame link LEN for 49->73
    LINK_DELTA = 0x7d57        # leading link CRC delta in P4-space (hdr.dl.crc is big-endian of the LE wire)
    PADOBJ = 0x01020010150000  # g1v2 qual0 [16,21] + 2 synthetic points (56 bits), const
    DELTA = 24                 # 73 - 49
    # 1) meta
    src = once(src, '    bit<16> rtcrc; bit<16> rtcrc_b; bit<16> ctcrc2; bit<16> ctcrc3;',
               '    bit<16> rtcrc; bit<16> rtcrc_b; bit<16> ctcrc2; bit<16> ctcrc3; bit<8> pl_tp; bit<8> co_tp; bit<16> pl_uc; bit<16> co_c0;')
    # 2) headers for the leading frame
    decls = ('header r_pl_link_h{bit<16> start;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}\n'
             'header r_pl_u_h{bit<8> tp;bit<32> app;bit<56> padobj;}\n'
             'header r_pl_uc_h{bit<16> crc;}\n')
    src = once(src, 'header r_ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}',
               'header r_ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}\n' + decls.rstrip())
    src = once(src, 'r_ctl_dl_h cd3; r_ctl_seg3_h cs3; }',
               'r_ctl_dl_h cd3; r_ctl_seg3_h cs3; r_pl_link_h pll; r_pl_u_h plu; r_pl_uc_h pluc; }')
    # 3) parser: keep the full native read parse (49 B, < 160 B budget) so the tail blocks are parsed
    # 4) derive leading/continuation transport octets (0x40|seq, 0x80|((seq+1)&0x3f)) by table, and the two CRCs
    tp_rows = ''.join('(8w0x%02x):set_tp(8w0x%02x,8w0x%02x);' % (0xC0 | s, 0x40 | s, 0x80 | ((s + 1) & 0x3f)) for s in range(64))
    src = once(src, '    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});}',
               '    action set_tp(bit<8> a, bit<8> b){m.pl_tp=a;m.co_tp=b;}\n'
               '    table set_tp_t{key={hdr.rh.tpctrl:exact;}actions={set_tp;NoAction;}size=64;const default_action=NoAction();const entries={' + tp_rows + '}}\n'
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_pl_uc;\n'
               '    action crc_pl_uc(){m.pl_uc=hash_pl_uc.get({m.pl_tp, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, 56w%d});}\n'
               '    table crc_pl_uc_t{actions={crc_pl_uc;}size=1;const default_action=crc_pl_uc();}\n'
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_co_c0;\n'
               '    action crc_co_c0(){m.co_c0=hash_co_c0.get({m.co_tp, 32w0, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d});}\n'
               '    table crc_co_c0_t{actions={crc_co_c0;}size=1;const default_action=crc_co_c0();}\n'
               '    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});}' % PADOBJ)
    # 5) the prefix action (replace read_eligible)
    old_re = ('    action read_eligible(){hdr.ra.setValid();hdr.ra.v=40w0x0a02000005;hdr.ca.setValid();'
              'hdr.ca.crc=hdr.c0.crc^16w0x6222;hdr.rbh.setValid();hdr.rbh.v=40w0x0a02000609;hdr.rc.setValid();'
              'hdr.rc.v=56w0x0a02010a001600;hdr.cb.setValid();hdr.cb.crc=m.rtcrc_b[7:0]++m.rtcrc_b[15:8];'
              'hdr.c2.crc=m.rtcrc[7:0]++m.rtcrc[15:8];hdr.robj.setInvalid();hdr.c0.setInvalid();hdr.c1.setInvalid();'
              'hdr.dl.len=8w0x32;hdr.dl.crc=hdr.dl.crc^16w0xaf35;hdr.ip.len=hdr.ip.len+16w12;m.len_delta=16w12;}')
    new_pad = ('    action read_eligible(){'
               'hdr.pll.setValid();hdr.pll.start=16w0x0564;hdr.pll.len=8w0x%02x;hdr.pll.ctrl=hdr.dl.ctrl;'
               'hdr.pll.dst=hdr.dl.dst;hdr.pll.src=hdr.dl.src;hdr.pll.crc=hdr.dl.crc ^ 16w0x%04x;'
               'hdr.plu.setValid();hdr.plu.tp=m.pl_tp;hdr.plu.app=hdr.rh.appctrl ++ hdr.rh.func ++ hdr.rh.iin;hdr.plu.padobj=56w0x%x;'
               'hdr.pluc.setValid();hdr.pluc.crc=m.pl_uc[7:0]++m.pl_uc[15:8];'
               'hdr.rh.tpctrl=m.co_tp;hdr.rh.appctrl=8w0;hdr.rh.func=8w0;hdr.rh.iin=16w0;'
               'hdr.c0.crc=m.co_c0[7:0]++m.co_c0[15:8];'
               'hdr.ip.len=hdr.ip.len+16w%d;m.len_delta=16w%d;}'
               % (PREFIX_LEN, LINK_DELTA, PADOBJ, DELTA, DELTA))
    src = once(src, old_re, new_pad)
    # 6) apply: swap the re-encode CRC helpers for the prefix derivations
    src = once(src, 'read_profile.apply(); in_rb0_t.apply(); in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); crc_read_b_t.apply();',
               'read_profile.apply(); in_rb0_t.apply(); set_tp_t.apply(); crc_pl_uc_t.apply(); crc_co_c0_t.apply();')
    # 7) deparser emit: leading frame BEFORE dl... but dl is emitted earlier in the list. Re-emit: pll/plu/pluc then dl+first block, drop tail-block emits (now unparsed)
    src = once(src,
               'pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.ra); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0); pkt.emit(hdr.ca);\n'
               '        pkt.emit(hdr.rbh); pkt.emit(hdr.p69); pkt.emit(hdr.rc); pkt.emit(hdr.cb);\n'
               '        pkt.emit(hdr.p1012); pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);',
               'pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc);\n'
               '        pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0);\n'
               '        pkt.emit(hdr.p69); pkt.emit(hdr.p1012); pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);')
    # dl is emitted before rh already in the deparser (pkt.emit(hdr.dl) earlier). Move pll/plu/pluc before dl:
    src = once(src, 'pkt.emit(hdr.mss); pkt.emit(hdr.dl);\n        pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc);',
               'pkt.emit(hdr.mss); pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc); pkt.emit(hdr.dl);')
    # 8) checksum branch for the prefix (pll valid): leading frame + dl + modified first block; tail unparsed (in old checksum)
    old_ck = '        if (hdr.ra.isValid()) {\n'
    new_ck = ('        if (hdr.pll.isValid()) {\n'
              '            hdr.tcp.checksum = tcp_read.update({hdr.tcp.seq, hdr.tcp.ack, m.ack_inv, hdr.tcp.window, m.len_delta,\n'
              '                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,\n'
              '                hdr.plu.tp, hdr.plu.app, hdr.plu.padobj, hdr.pluc.crc,\n'
              '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
              '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop,\n'
              '                hdr.p03.d, hdr.p45.d, hdr.c0.crc, hdr.p69.d, hdr.p1012.d, hdr.p1321.d, hdr.c1.crc, hdr.p22.d, hdr.c2.crc, 8w0,\n'
              '                m.r_residual});\n'
              '        }\n'
              '        if (hdr.ra.isValid()) {\n')
    src = once(src, old_ck, new_ck)   # insert the pll checksum branch before the (now dead) ra branch
    # Fix 3: first-block-only parse does not reach c1/c2; drop their verdicts (they read unparsed
    # headers into m.rbad1/m.rbadt). Left at 0, the keys match the good path; the master validates
    # the untouched tail's original CRCs.
    src = once(src, 'if (hdr.c1.crc != (m.in_rb1[7:0] ++ m.in_rb1[15:8])) { m.rbad1 = 1; }', '')
    src = once(src, 'if (hdr.c2.crc != (m.in_rt[7:0] ++ m.in_rt[15:8])) { m.rbadt = 1; }', '')
    # drop the now-dead block-1/tail CRC tables and their actions
    src = once(src, '    action in_rb1(){m.in_rb1=hash_in_rb1.get({hdr.p69.d,hdr.p1012.d,hdr.p1321.d});}\n', '')
    src = once(src, '    table in_rb1_t{actions={in_rb1;}size=1;const default_action=in_rb1();}\n', '')
    src = once(src, '    action in_rt(){m.in_rt=hash_in_rt.get({hdr.p22.d});}\n', '')
    src = once(src, '    table in_rt_t{actions={in_rt;}size=1;const default_action=in_rt();}\n', '')
    return src

def transform_read_prefix_full(src, image):
    """Full integrity READ (247 -> 269) PREFIX padder with a FIRST-BLOCK-ONLY egress parse.

    The 247-byte response exceeds the 160-byte egress parser-depth limit, so read_b0 is retargeted to the
    full-READ frame (dl.len=0xd6) and extracts ONLY block0 (rh,robj,p03,p45,c0); the 219-byte tail stays
    UNPARSED and is emitted verbatim after the parsed headers. Its checksum contribution rides m.r_residual
    (subtract_all_and_deposit deposited after hdr.tcp subtracts only the headers extracted after it), so the
    deparser list adds the prefix + block0 and the tail stays in the residual -- no tail headers are listed.
    Construction is identical to the range prefix otherwise (prepend.py, validated on the real 247 capture).
    Constants (extracted from prepend.py on native_integrity_base): PREFIX_LEN, LINK_DELTA (P4-space),
    PADOBJ (g1v2 qual0 [16,19] header, 40 bits), DELTA=22."""
    if image != 269:
        raise SystemExit('transform_read_prefix_full targets the 247->269 full READ only')
    PREFIX_LEN = 0x0F
    LINK_DELTA = 0x04e8
    PADOBJ = 0x0102001013       # g1v2 qual0 [16,19] object header only (40 bits); 4 points go in the continuation
    DELTA = 22
    # 1) meta (same staging fields as the range prefix)
    src = once(src, '    bit<16> rtcrc; bit<16> rtcrc_b; bit<16> ctcrc2; bit<16> ctcrc3;',
               '    bit<16> rtcrc; bit<16> rtcrc_b; bit<16> ctcrc2; bit<16> ctcrc3; bit<8> pl_tp; bit<8> co_tp; bit<16> pl_uc; bit<16> co_c0;')
    # 2) leading-frame headers (padobj is 40 bits here: just the object header)
    decls = ('header r_pl_link_h{bit<16> start;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}\n'
             'header r_pl_u_h{bit<8> tp;bit<32> app;bit<40> padobj;}\n'
             'header r_pl_uc_h{bit<16> crc;}\n')
    src = once(src, 'header r_ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}',
               'header r_ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}\n' + decls.rstrip())
    src = once(src, 'r_ctl_dl_h cd3; r_ctl_seg3_h cs3; }',
               'r_ctl_dl_h cd3; r_ctl_seg3_h cs3; r_pl_link_h pll; r_pl_u_h plu; r_pl_uc_h pluc; }')
    # 3) parser: retarget the read frame dispatch to the full READ (dl.len=0xd6) and make read_b0
    #    FIRST-BLOCK-ONLY (drop the p69..c2 extracts; those 219 B stay unparsed).
    src = once(src, '(8w0x26, _): read_b0; (8w0x1c, _): ctl_b0; default: accept;',
               '(8w0xd6, _): read_b0; (8w0x1c, _): ctl_b0; default: accept;')
    src = once(src,
               'state read_b0 { pkt.extract(hdr.rh); pkt.extract(hdr.robj); pkt.extract(hdr.p03); pkt.extract(hdr.p45); pkt.extract(hdr.c0);\n'
               '        pkt.extract(hdr.p69); pkt.extract(hdr.p1012); pkt.extract(hdr.p1321); pkt.extract(hdr.c1); pkt.extract(hdr.p22); pkt.extract(hdr.c2); transition accept; }',
               'state read_b0 { pkt.extract(hdr.rh); pkt.extract(hdr.robj); pkt.extract(hdr.p03); pkt.extract(hdr.p45); pkt.extract(hdr.c0); transition accept; }')
    # 4) derive the two transport octets + the two leading/continuation CRCs (padobj 40 bits)
    tp_rows = ''.join('(8w0x%02x):set_tp(8w0x%02x,8w0x%02x);' % (0xC0 | s, 0x40 | s, 0x80 | ((s + 1) & 0x3f)) for s in range(64))
    src = once(src, '    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});}',
               '    action set_tp(bit<8> a, bit<8> b){m.pl_tp=a;m.co_tp=b;}\n'
               '    table set_tp_t{key={hdr.rh.tpctrl:exact;}actions={set_tp;NoAction;}size=64;const default_action=NoAction();const entries={' + tp_rows + '}}\n'
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_pl_uc;\n'
               '    action crc_pl_uc(){m.pl_uc=hash_pl_uc.get({m.pl_tp, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, 40w%d});}\n'
               '    table crc_pl_uc_t{actions={crc_pl_uc;}size=1;const default_action=crc_pl_uc();}\n'
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_co_c0;\n'
               '    action crc_co_c0(){m.co_c0=hash_co_c0.get({m.co_tp, 32w0, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d});}\n'
               '    table crc_co_c0_t{actions={crc_co_c0;}size=1;const default_action=crc_co_c0();}\n'
               '    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});}' % PADOBJ)
    # 5) read_profile: match the full READ frame (dl.len=0xd6, robj g1v2 qual0 [0,15]) -> read_shape
    src = once(src, '(16w0x0564,8w0x26,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x0a,8w0x02,8w0x00,8w0x00,8w0x16):read_shape();',
               '(16w0x0564,8w0xd6,8w0xC0&&&8w0xC0,8w0xC0&&&8w0xF0,8w0x81,8w0x01,8w0x02,8w0x00,8w0x00,8w0x0f):read_shape();')
    # 6) the prefix action (replace read_eligible) -- identical shape to the range prefix, full constants
    old_re = ('    action read_eligible(){hdr.ra.setValid();hdr.ra.v=40w0x0a02000005;hdr.ca.setValid();'
              'hdr.ca.crc=hdr.c0.crc^16w0x6222;hdr.rbh.setValid();hdr.rbh.v=40w0x0a02000609;hdr.rc.setValid();'
              'hdr.rc.v=56w0x0a02010a001600;hdr.cb.setValid();hdr.cb.crc=m.rtcrc_b[7:0]++m.rtcrc_b[15:8];'
              'hdr.c2.crc=m.rtcrc[7:0]++m.rtcrc[15:8];hdr.robj.setInvalid();hdr.c0.setInvalid();hdr.c1.setInvalid();'
              'hdr.dl.len=8w0x32;hdr.dl.crc=hdr.dl.crc^16w0xaf35;hdr.ip.len=hdr.ip.len+16w12;m.len_delta=16w12;}')
    new_pad = ('    action read_eligible(){'
               'hdr.pll.setValid();hdr.pll.start=16w0x0564;hdr.pll.len=8w0x%02x;hdr.pll.ctrl=hdr.dl.ctrl;'
               'hdr.pll.dst=hdr.dl.dst;hdr.pll.src=hdr.dl.src;hdr.pll.crc=hdr.dl.crc ^ 16w0x%04x;'
               'hdr.plu.setValid();hdr.plu.tp=m.pl_tp;hdr.plu.app=hdr.rh.appctrl ++ hdr.rh.func ++ hdr.rh.iin;hdr.plu.padobj=40w0x%x;'
               'hdr.pluc.setValid();hdr.pluc.crc=m.pl_uc[7:0]++m.pl_uc[15:8];'
               'hdr.rh.tpctrl=m.co_tp;hdr.rh.appctrl=8w0;hdr.rh.func=8w0;hdr.rh.iin=16w0;'
               'hdr.c0.crc=m.co_c0[7:0]++m.co_c0[15:8];'
               'hdr.ip.len=hdr.ip.len+16w%d;m.len_delta=16w%d;}'
               % (PREFIX_LEN, LINK_DELTA, PADOBJ, DELTA, DELTA))
    src = once(src, old_re, new_pad)
    # 7) apply: swap the re-encode CRC helpers for the prefix derivations
    src = once(src, 'read_profile.apply(); in_rb0_t.apply(); in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); crc_read_b_t.apply();',
               'read_profile.apply(); in_rb0_t.apply(); set_tp_t.apply(); crc_pl_uc_t.apply(); crc_co_c0_t.apply();')
    # 8) deparser emit: pll/plu/pluc + dl + block0 ONLY; the 219-B tail is unparsed and follows verbatim.
    src = once(src,
               'pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.ra); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0); pkt.emit(hdr.ca);\n'
               '        pkt.emit(hdr.rbh); pkt.emit(hdr.p69); pkt.emit(hdr.rc); pkt.emit(hdr.cb);\n'
               '        pkt.emit(hdr.p1012); pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);',
               'pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc);\n'
               '        pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0);')
    src = once(src, 'pkt.emit(hdr.mss); pkt.emit(hdr.dl);\n        pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc);',
               'pkt.emit(hdr.mss); pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc); pkt.emit(hdr.dl);')
    # 9) checksum branch (pll valid): prefix + dl + block0 + r_residual (tail is IN the residual, not listed)
    old_ck = '        if (hdr.ra.isValid()) {\n'
    new_ck = ('        if (hdr.pll.isValid()) {\n'
              '            hdr.tcp.checksum = tcp_read.update({hdr.tcp.seq, hdr.tcp.ack, m.ack_inv, hdr.tcp.window, m.len_delta,\n'
              '                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,\n'
              '                hdr.plu.tp, hdr.plu.app, hdr.plu.padobj, hdr.pluc.crc,\n'
              '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
              '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop,\n'
              '                hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
              '                m.r_residual});\n'
              '        }\n'
              '        if (hdr.ra.isValid()) {\n')
    src = once(src, old_ck, new_ck)
    # Fix 3: block1/tail CRC verdicts read now-unparsed headers; drop them (master validates the tail).
    src = once(src, 'if (hdr.c1.crc != (m.in_rb1[7:0] ++ m.in_rb1[15:8])) { m.rbad1 = 1; }', '')
    src = once(src, 'if (hdr.c2.crc != (m.in_rt[7:0] ++ m.in_rt[15:8])) { m.rbadt = 1; }', '')
    src = once(src, '    action in_rb1(){m.in_rb1=hash_in_rb1.get({hdr.p69.d,hdr.p1012.d,hdr.p1321.d});}\n', '')
    src = once(src, '    table in_rb1_t{actions={in_rb1;}size=1;const default_action=in_rb1();}\n', '')
    src = once(src, '    action in_rt(){m.in_rt=hash_in_rt.get({hdr.p22.d});}\n', '')
    src = once(src, '    table in_rt_t{actions={in_rt;}size=1;const default_action=in_rt();}\n', '')
    # ---- N pipe (pipe-0 ingress): classify + first-block-parse the 247 response so it traverses N->E ----
    # Without this the 247 response (ip.len=287) has no N dispatch, stays kind=0xFF, and read_terminal_t
    # aborts it (same drop as an unbound control request). N only needs block0 for classify/timing.
    # a) ip dispatch: route the full READ response (ip.len=287) to the read-response parse.
    src = once(src, '(4w4,4w5,8w6,16w89):read_response_ip_flags;',
               '(4w4,4w5,8w6,16w287):read_response_ip_flags;(4w4,4w5,8w6,16w89):read_response_ip_flags;')
    # b) first-block-only N parse for the full READ frame (dl.len=0xd6); range path (0x26) unchanged.
    src = once(src, 'state read_response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition read_response_block;}',
               'state read_response_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition select(hdr.dl.len){8w0xd6:read_response_fb;default:read_response_block;}}\n'
               ' state read_response_fb{pkt.extract(hdr.first);tc.subtract(hdr.first);m.packet_kind=8w11;transition finish;}')
    # c) N read_response_profile: match the full READ first block (dl.len=0xd6, g1v2 qual0 [0,15]).
    src = once(src, '(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();',
               '(16w0x0564,8w0xd6,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();')
    # d) next expected seq advances by the full READ native length (247), not 49 (candidate is full-only).
    src = once(src, 'action next_read_response(){m.new_seq=hdr.tcp.seq+32w49;}',
               'action next_read_response(){m.new_seq=hdr.tcp.seq+32w247;}')
    # e) SHALLOW-PARSE ADMISSION (honest; C2). The full READ parses only block0. hcrc (link) and bcrc
    #    (block0 DNP3 CRC) are REALLY computed by crc_head_first, so a corrupt block0 fails the guard and is
    #    dropped. block1/tail DNP3 CRCs (crc1/tcrc) are NOT independently validated by the switch -- they are
    #    DERIVED from the real block0 CRC (m.crc1=m.tcrc=m.bcrc), so admission gates on block0 validity
    #    (corrupt block0 -> bcrc!=0x993a -> guard miss -> drop) and does NOT falsely claim the tail is valid.
    #    The whole-segment TCP checksum cannot be computed under the shallow parse (219 B unparsed), so it is
    #    explicitly WAIVED (m.tcp_sum=0xffeb) -- endpoint-owned, the master's TCP validates it. This is a
    #    documented shallow-parse limitation, not whole-response validation; corrupt-TCP-checksum and
    #    corrupt-tail packets are forwarded and recovered at the endpoint (verified by the C2 regressions).
    src = once(src, 'action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value,hdr.rd_tail.crc});}',
               'action rd_tail_crc(){m.tcrc=hash_rd_tail.get({hdr.rd_tail.value,hdr.rd_tail.crc});}\n'
               'action full_read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;m.tcp_sum=16w0xffeb;}\n'
               'table full_read_shallow_admit_t{actions={full_read_shallow_admit;}size=1;const default_action=full_read_shallow_admit();}')
    src = once(src, 'else{read_response_profile.apply();rd_second_crc_t.apply();rd_tail_crc_t.apply();}',
               'else{read_response_profile.apply();if(hdr.second.isValid()){rd_second_crc_t.apply();rd_tail_crc_t.apply();}else{full_read_shallow_admit_t.apply();}}')
    # f) REQUEST SIDE (C1): recognize the real 27-byte integrity request (G60V2/V3/V4/V1 qual 0x06,
    #    ip.len=67, dl.len=0x14). N had only the old range request (ip.len=60). Add a 4-object request
    #    header, a first-block parse state, its profile + real block CRC, and +27 seq accounting.
    src = once(src, 'header n_read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}',
               'header n_read_req_h{bit<8> tp;bit<8> app;bit<8> func;bit<8> group;bit<8> variation;bit<8> qualifier;bit<8> first;bit<8> last;bit<16> crc;}\n'
               'header n_read_req_full_h{bit<8> tp;bit<8> app;bit<8> func;bit<24> o1;bit<24> o2;bit<24> o3;bit<24> o4;bit<16> crc;}\n'
               '@pa_mutually_exclusive("ingress","hdr.rd_req","hdr.rd_req_full")')
    src = once(src, 'n_read_req_h rd_req;', 'n_read_req_h rd_req;n_read_req_full_h rd_req_full;')
    src = once(src, '(4w4,4w5,8w6,16w60):read_ip_flags;', '(4w4,4w5,8w6,16w60):read_ip_flags;(4w4,4w5,8w6,16w67):read_ip_flags;')
    src = once(src, 'state read_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition read_request;}',
               'state read_dl{pkt.extract(hdr.dl);tc.subtract(hdr.dl);transition select(hdr.dl.len){8w0x14:read_request_full;default:read_request;}}\n'
               ' state read_request_full{pkt.extract(hdr.rd_req_full);tc.subtract(hdr.rd_req_full);m.packet_kind=8w9;transition finish;}')
    src = once(src, 'action rd_request_crc(){m.bcrc=hash_rd_request.get({hdr.rd_req.tp,hdr.rd_req.app,hdr.rd_req.func,hdr.rd_req.group,hdr.rd_req.variation,hdr.rd_req.qualifier,hdr.rd_req.first,hdr.rd_req.last,hdr.rd_req.crc});}',
               'action rd_request_crc(){m.bcrc=hash_rd_request.get({hdr.rd_req.tp,hdr.rd_req.app,hdr.rd_req.func,hdr.rd_req.group,hdr.rd_req.variation,hdr.rd_req.qualifier,hdr.rd_req.first,hdr.rd_req.last,hdr.rd_req.crc});}\n'
               'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_request_full;\n'
               'action rd_request_full_crc(){m.bcrc=hash_rd_request_full.get({hdr.rd_req_full.tp,hdr.rd_req_full.app,hdr.rd_req_full.func,hdr.rd_req_full.o1,hdr.rd_req_full.o2,hdr.rd_req_full.o3,hdr.rd_req_full.o4,hdr.rd_req_full.crc});}\n'
               'table rd_request_full_crc_t{actions={rd_request_full_crc;}size=1;const default_action=rd_request_full_crc();}')
    # integrity request profile (G60V2 q06 first object, func READ): sets eligibility like the range one
    src = once(src, '(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}',
               '(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();}}\n'
               'table read_request_full_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req_full.tp:ternary;hdr.rd_req_full.app:ternary;hdr.rd_req_full.func:exact;hdr.rd_req_full.o1:exact;}\n'
               ' actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w0x14,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,24w0x3c0206):eligible();}}')
    src = once(src, 'if(m.packet_kind==8w9){read_request_profile.apply();rd_request_crc_t.apply();}',
               'if(m.packet_kind==8w9){if(hdr.rd_req_full.isValid()){read_request_full_profile.apply();rd_request_full_crc_t.apply();}else{read_request_profile.apply();rd_request_crc_t.apply();}}')
    src = once(src, 'action next_read_request(){m.new_seq=hdr.tcp.seq+32w20;}',
               'action next_read_request(){m.new_seq=hdr.tcp.seq+32w27;}')
    # read_app matching reads the request's app seq nibble from hdr.rd_req; for the integrity request it
    # lives in hdr.rd_req_full.app. Add the full variant and branch (same seq-nibble semantics).
    src = once(src, 'action read_request_input(){m.compare_read_app=(bit<32>)(hdr.rd_req.app[3:0]);}',
               'action read_request_input(){m.compare_read_app=(bit<32>)(hdr.rd_req.app[3:0]);}\n'
               'action read_request_full_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_full.app[3:0]);}\n'
               'table read_request_full_input_t{actions={read_request_full_input;}size=1;const default_action=read_request_full_input();}')
    src = once(src, 'ack_native_t.apply();read_input_t.apply();',
               'ack_native_t.apply();if(hdr.rd_req_full.isValid()){read_request_full_input_t.apply();}else{read_input_t.apply();}')
    return src


TRANSFORMS = ['mapper_var', 'read_prefix']  # step 1: variable image (READ 73 + inherited SBO 61); full READ uses read_prefix_full


def build(image, only=None, full=False):
    src = M11_09.read_text()
    if hashlib.sha256(src.encode()).hexdigest() != M11_09_SHA:
        raise SystemExit('m11_09 source changed')
    # full candidate: full integrity READ (247->269) + SBO (61); else the range-READ (73)+SBO(61) proof build
    transforms = ['mapper_var', 'read_prefix_full'] if full else TRANSFORMS
    shape_image = {'read': 269, 'ctl': 61} if full else SHAPE_IMAGE
    read_native = 247 if full else 49
    applied = []
    for name in transforms:
        if name == 'mapper_var':
            src = transform_mapper_var(src, shape_image, stale_guard=STALE_GUARD, read_native=read_native)
        else:
            src = globals()['transform_' + name](src, image)
        applied.append(name)
        if only and name == only:
            break
    return src, applied


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--image', type=int, default=73)
    ap.add_argument('--only', default=None)
    ap.add_argument('--full', action='store_true', help='full integrity READ (247->269) + SBO (61) candidate')
    a = ap.parse_args()
    if a.full:
        a.image = 269
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    src, applied = build(a.image, a.only, full=a.full)
    (out / 'response_only.p4').write_text(src)
    sha = hashlib.sha256(src.encode()).hexdigest()
    # The candidate is runnable only when the mapper AND every size-path transform agree. A partial set
    # (e.g. mapper alone: image=269 while the encoders still emit 61) is an intermediate placement
    # experiment, NOT a working candidate, and is flagged non-runnable so nothing treats it as integrated.
    # Per-build scope + metadata. The full build REPLACES the response profile and seq delta (full
    # integrity READ 247->269); it does NOT still support the old range READ merely because the old parser
    # dispatch remains. The range-proof build keeps the inherited-SBO scope.
    if a.full:
        required = {'mapper_var', 'read_prefix_full'}
        read_native, read_out = 247, 269
        scope = 'full integrity READ 247->269 + SELECT/OPERATE 37->61; range READ not supported'
    else:
        required = {'mapper_var', 'read_prefix'}
        read_native, read_out = 49, a.image
        scope = 'range READ 49->%d + inherited SBO 37->61 (variable-image proof build)' % a.image
    runnable = required.issubset(set(applied))
    segs = {role: hashlib.sha256(_combined.segment(src, role).encode()).hexdigest() for role in ('N', 'E', 'T')}
    profile = {'candidate': {'build': str(out), 'milestone': 'm12', 'source_sha256': sha, 'segment_sha256': segs,
                             'artifact_sha256': {}},
               'reset_restart_required': True, 't_child_count': 1}
    (out / 'response_only.inputs.json').write_text(json.dumps({
        'milestone': 'm12', 'image_len': read_out, 'transforms_applied': applied, 'scope': scope,
        'full_target': runnable, 'runnable': runnable,
        'intermediate_note': None if runnable else
        'PARTIAL build: %s not applied — placement experiment only, not a working integrated candidate'
        % sorted(required - set(applied)),
        'source_sha256': sha, 'segment_sha256': segs, 'supported_profile': profile,
        't_time': {'unit_ns': 256, 'grid_ns': 512, 'source': 'global_tstamp[39:8] & ~1'},
        't_lifetime_encoding': 'sealed_low31',
        'native_lengths': {'READ': read_native, 'SELECT_OPERATE': 37},
        'output_lengths': {'READ': read_out, 'SELECT_OPERATE': 61},
        'read_growth': read_out - read_native, 'control_growth': 24,
        'port_map': {'relay_port': 9, 'n_ack_return': 48, 't_in': 180, 'hb_return': 181, 'held_return': 182},
        'successor_of': {'build': 'm11_09', 'source_sha256': M11_09_SHA}}, indent=2) + '\n')
    (out / 'supported_profile.json').write_text(json.dumps(profile, indent=2) + '\n')
    print('wrote %s (image=%d, transforms=%s, sha=%s)' % (out / 'response_only.p4', a.image, applied, sha[:12]))


if __name__ == '__main__':
    main()
