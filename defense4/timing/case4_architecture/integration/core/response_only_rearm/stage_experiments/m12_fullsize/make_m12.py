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


def once(text, old, new):
    n = text.count(old)
    if n != 1:
        raise SystemExit('anchor %r found %d times (need 1)' % (old[:80], n))
    return text.replace(old, new, 1)


def neg(n):
    return '32w0x%08x' % ((0x100000000 - n) & 0xFFFFFFFF)


def transform_mapper(src, image):
    """Single constant image length = `image`; classify_rev window regenerated to it."""
    src = once(src, 'const bit<32> r_IMAGE_LEN = 61;', 'const bit<32> r_IMAGE_LEN = %d;' % image)
    # start_arm: seq + (-(image-1)); was -60 (0xFFFFFFC4) for the 61-byte image
    src = once(src, 'void apply(inout bit<32> v) { v = hdr.tcp.seq + 32w0xFFFFFFC4; } };',
               'void apply(inout bit<32> v) { v = hdr.tcp.seq + %s; } };' % neg(image - 1))
    # fwd_prep: m.pm = m.p - image; was -61 (0xFFFFFFC3)
    src = once(src, 'm.pm = m.p + 32w0xFFFFFFC3;', 'm.pm = m.p + %s;' % neg(image))
    # acct_t: add a do_acct_try row for the full-READ native length 247 (read_shape), beside 49/37
    src = once(src,
               '(_, 1, 3w4 &&& 3w7, 0, 1, 8w0 &&& 8w0x07, 49, 1, _, 0, 0, 0, 0, _, _): do_acct_try();',
               '(_, 1, 3w4 &&& 3w7, 0, 1, 8w0 &&& 8w0x07, 49, 1, _, 0, 0, 0, 0, _, _): do_acct_try();'
               '(_, 1, 3w4 &&& 3w7, 0, 1, 8w0 &&& 8w0x07, 247, 1, _, 0, 0, 0, 0, _, _): do_acct_try();')
    src = once(src, 'actions = { do_acct_arm; do_acct_try; do_acct_grow; do_acct_rev; NoAction; } size = 10;',
               'actions = { do_acct_arm; do_acct_try; do_acct_grow; do_acct_rev; NoAction; } size = 11;')
    # classify_fwd: out_reset_front_247 for an RST one full-READ ahead
    src = once(src, '    action out_reset_front_37() { m.qx = m.q - 32w37; m.result = r_OUT_RESET_FRONT; m.changed = 1; }',
               '    action out_reset_front_37() { m.qx = m.q - 32w37; m.result = r_OUT_RESET_FRONT; m.changed = 1; }\n'
               '    action out_reset_front_247() { m.qx = m.q - 32w247; m.result = r_OUT_RESET_FRONT; m.changed = 1; }')
    src = once(src, 'out_reset_front_49; out_reset_front_37; } size = 24;',
               'out_reset_front_49; out_reset_front_37; out_reset_front_247; } size = 24;')
    src = once(src, '(32w37, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_37();',
               '(32w37, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_37();'
               '(32w247, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_247();')
    # classify_rev: regenerate the per-byte withhold window to the image size
    start = src.index('    table classify_rev {')
    src = once(src, 'size = 124; const default_action = rev_drop();', 'size = %d; const default_action = rev_drop();' % (2 * image + 2))
    body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    src = src[:body_start] + '\n' + rev_entries(image) + '\n        ' + src[body_end:]
    return src


def transform_read_prefix(src, image):
    """Replace the READ re-encode with the PREFIX padder (prepend.py construction). Range READ 49->73
    (T=73) here; the full READ and other targets extend the same construction. Parses only the first
    block (28 B), emits a leading FIR/!FIN frame carrying the live app header + padding object header,
    rewrites the original first block into a !FIR/FIN continuation (app-header bytes -> 4 padding points,
    CRC Hash-derived over all changes), and re-emits the original tail verbatim as unparsed payload."""
    if image != 269:
        raise SystemExit('transform_read_prefix: image length set by the mapper; target set per shape')
    PREFIX_LEN = 0x11          # leading frame link LEN for 49->73
    LINK_DELTA = 0x577d        # leading link CRC = dl.crc ^ this (len 0x26 -> 0x11)
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
    # 3) parser: first-block-only read (stop after c0; leave the rest unparsed)
    src = once(src,
               '    state read_b0 { pkt.extract(hdr.rh); pkt.extract(hdr.robj); pkt.extract(hdr.p03); pkt.extract(hdr.p45); pkt.extract(hdr.c0);\n'
               '        pkt.extract(hdr.p69); pkt.extract(hdr.p1012); pkt.extract(hdr.p1321); pkt.extract(hdr.c1); pkt.extract(hdr.p22); pkt.extract(hdr.c2); transition accept; }',
               '    state read_b0 { pkt.extract(hdr.rh); pkt.extract(hdr.robj); pkt.extract(hdr.p03); pkt.extract(hdr.p45); pkt.extract(hdr.c0); transition accept; }')
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
               '        pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0);')
    # dl is emitted before rh already in the deparser (pkt.emit(hdr.dl) earlier). Move pll/plu/pluc before dl:
    src = once(src, 'pkt.emit(hdr.mss); pkt.emit(hdr.dl);\n        pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc);',
               'pkt.emit(hdr.mss); pkt.emit(hdr.pll); pkt.emit(hdr.plu); pkt.emit(hdr.pluc); pkt.emit(hdr.dl);')
    # 8) checksum branch for the prefix (pll valid): leading frame + dl + modified first block; tail unparsed (in old checksum)
    old_ck = '        if (hdr.ra.isValid()) {\n'
    new_ck = ('        if (hdr.pll.isValid()) {\n'
              '            hdr.tcp.checksum = tcp_read.update({hdr.tcp.seq, hdr.tcp.ack, m.ack_inv, hdr.tcp.window, m.len_delta,\n'
              '                hdr.pll.start, hdr.pll.len, hdr.pll.ctrl, hdr.pll.dst, hdr.pll.src, hdr.pll.crc,\n'
              '                hdr.plu.tp, hdr.plu.app, hdr.plu.padobj, hdr.pluc.crc, 8w0,\n'
              '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
              '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop,\n'
              '                hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
              '                m.r_residual});\n'
              '        }\n'
              '        if (hdr.ra.isValid()) {\n')
    src = once(src, old_ck, new_ck)
    return src

TRANSFORMS = ['mapper', 'read_prefix']  # grown incrementally: 'sbo_frame', 'n_lane'


def build(image, only=None):
    src = M11_09.read_text()
    if hashlib.sha256(src.encode()).hexdigest() != M11_09_SHA:
        raise SystemExit('m11_09 source changed')
    applied = []
    for name in TRANSFORMS:
        src = globals()['transform_' + name](src, image)
        applied.append(name)
        if only and name == only:
            break
    return src, applied


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--image', type=int, default=269)
    ap.add_argument('--only', default=None)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    src, applied = build(a.image, a.only)
    (out / 'response_only.p4').write_text(src)
    sha = hashlib.sha256(src.encode()).hexdigest()
    # The candidate is runnable only when the mapper AND every size-path transform agree. A partial set
    # (e.g. mapper alone: image=269 while the encoders still emit 61) is an intermediate placement
    # experiment, NOT a working candidate, and is flagged non-runnable so nothing treats it as integrated.
    required = {'mapper', 'read_pad', 'sbo_frame', 'n_lane'}
    runnable = required.issubset(set(applied))
    (out / 'response_only.inputs.json').write_text(json.dumps({
        'milestone': 'm12', 'image_len': a.image, 'transforms_applied': applied,
        'full_target': runnable, 'runnable': runnable,
        'intermediate_note': None if runnable else
        'PARTIAL build: mapper image=%d but %s not yet applied; encoders/N still at the old lengths — '
        'placement experiment only, not a working integrated candidate' % (a.image, sorted(required - set(applied))),
        'source_sha256': sha, 'successor_of': {'build': 'm11_09', 'source_sha256': M11_09_SHA}}, indent=2) + '\n')
    print('wrote %s (image=%d, transforms=%s, sha=%s)' % (out / 'response_only.p4', a.image, applied, sha[:12]))


if __name__ == '__main__':
    main()
