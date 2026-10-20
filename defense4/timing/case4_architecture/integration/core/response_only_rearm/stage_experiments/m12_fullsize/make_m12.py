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


def transform_read_pad(src, image):
    """Replace the READ re-encode with the append-a-frame measurement-object padder (range READ 49->T).

    Keeps the native response's blocks LIVE (not re-encoded): clears FIN on the first transport segment
    (affine CRC delta 0x370c), and appends ONE padding link frame sized to reach T. The appended frame is
    synthetic padding (g1v2 points, value 0, flags 0x00): its content and data-block CRCs are compile
    constants; its link header is DERIVED (copy dl.ctrl/dst/src, const len, CRC = dl.crc ^ 0x4679); its
    first user block's transport octet is DERIVED (native seq+1 | FIN) so that block's CRC is Hash-derived.
    Only 49->269 (T=269) is implemented here; other native READ sizes/targets extend the same construction.
    """
    if image != 269:
        raise SystemExit('transform_read_pad currently targets T=269 only')
    B0CONST = '0x01020010c300000000000000000000'   # objhdr(g1v2 qual0 16..195) + pts 16-25, 15 bytes
    TAIL = [  # 4 x 48 bytes of constant tail (blocks 1..11 with their CRCs), from pad_oracle
        '0x00000000000000000000000000000000ffff00000000000000000000000000000000ffff000000000000000000000000',
        '0x00000000ffff00000000000000000000000000000000ffff00000000000000000000000000000000ffff000000000000',
        '0x00000000000000000000ffff00000000000000000000000000000000ffff00000000000000000000000000000000ffff',
        '0x00000000000000000000000000000000ffff00000000000000000000000000000000ffff00000000000000000000ffff']
    # 1) meta fields for the derived transport octet and its CRC
    src = once(src, '    bit<16> rtcrc; bit<16> rtcrc_b; bit<16> ctcrc2; bit<16> ctcrc3;',
               '    bit<16> rtcrc; bit<16> rtcrc_b; bit<16> ctcrc2; bit<16> ctcrc3; bit<8> pad_tp; bit<16> pad_c0;')
    # 2) header declarations for the appended padding frame
    decls = ('header r_pad_link_h{bit<16> start;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}\n'
             'header r_pad_b0_h{bit<8> tp;bit<120> body;}\n'
             'header r_pad_c0_h{bit<16> crc;}\n'
             'header r_pad_t0_h{bit<384> v;}\nheader r_pad_t1_h{bit<384> v;}\n'
             'header r_pad_t2_h{bit<384> v;}\nheader r_pad_t3_h{bit<384> v;}\n')
    src = once(src, 'header r_ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}',
               'header r_ctl_tail_p2_h{bit<80> filler_b;bit<16> crc2;}\n' + decls.rstrip())
    # 3) struct members (appended after cs3)
    src = once(src, 'r_ctl_dl_h cd3; r_ctl_seg3_h cs3; }',
               'r_ctl_dl_h cd3; r_ctl_seg3_h cs3; r_pad_link_h padl; r_pad_b0_h padb0; r_pad_c0_h padc0; '
               'r_pad_t0_h padt0; r_pad_t1_h padt1; r_pad_t2_h padt2; r_pad_t3_h padt3; }')
    # 4) derive pad_tp and pad_c0 (replace the re-encode CRC helpers' apply with these)
    # native single-frame READ response transport = 0xC0|seq (FIR+FIN); map it -> appended tp = ((seq+1)&0x3f)|0x80
    tp_rows = ''.join('(8w0x%02x):set_pad_tp(8w0x%02x);' % (0xC0 | s, (((s + 1) & 0x3f) | 0x80)) for s in range(64))
    src = once(src, '    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});}',
               '    action set_pad_tp(bit<8> v){m.pad_tp=v;}\n'
               '    table derive_pad_tp_t{key={hdr.rh.tpctrl:exact;}actions={set_pad_tp;NoAction;}size=64;'
               'const default_action=NoAction();const entries={' + tp_rows + '}}\n'
               '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_pad_c0;\n'
               '    action crc_pad_c0(){m.pad_c0=hash_pad_c0.get({m.pad_tp, 120w%s});}\n'
               '    table crc_pad_c0_t{actions={crc_pad_c0;}size=1;const default_action=crc_pad_c0();}\n'
               '    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});}' % B0CONST)
    # 5) the padder action (replace read_eligible body)
    old_re = ('    action read_eligible(){hdr.ra.setValid();hdr.ra.v=40w0x0a02000005;hdr.ca.setValid();'
              'hdr.ca.crc=hdr.c0.crc^16w0x6222;hdr.rbh.setValid();hdr.rbh.v=40w0x0a02000609;hdr.rc.setValid();'
              'hdr.rc.v=56w0x0a02010a001600;hdr.cb.setValid();hdr.cb.crc=m.rtcrc_b[7:0]++m.rtcrc_b[15:8];'
              'hdr.c2.crc=m.rtcrc[7:0]++m.rtcrc[15:8];hdr.robj.setInvalid();hdr.c0.setInvalid();hdr.c1.setInvalid();'
              'hdr.dl.len=8w0x32;hdr.dl.crc=hdr.dl.crc^16w0xaf35;hdr.ip.len=hdr.ip.len+16w12;m.len_delta=16w12;}')
    new_pad = ('    action read_eligible(){'
               'hdr.rh.tpctrl=hdr.rh.tpctrl & 8w0x7f;'                       # clear FIN on native first segment
               'hdr.c0.crc=hdr.c0.crc ^ 16w0x370c;'                          # native block0 CRC after FIN clear
               'hdr.padl.setValid();hdr.padl.start=16w0x0564;hdr.padl.len=8w0xbf;hdr.padl.ctrl=hdr.dl.ctrl;'
               'hdr.padl.dst=hdr.dl.dst;hdr.padl.src=hdr.dl.src;hdr.padl.crc=hdr.dl.crc ^ 16w0x4679;'
               'hdr.padb0.setValid();hdr.padb0.tp=m.pad_tp;hdr.padb0.body=120w%s;'
               'hdr.padc0.setValid();hdr.padc0.crc=m.pad_c0[7:0]++m.pad_c0[15:8];'
               'hdr.padt0.setValid();hdr.padt0.v=384w%s;hdr.padt1.setValid();hdr.padt1.v=384w%s;'
               'hdr.padt2.setValid();hdr.padt2.v=384w%s;hdr.padt3.setValid();hdr.padt3.v=384w%s;'
               'hdr.ip.len=hdr.ip.len+16w220;m.len_delta=16w220;}'
               % (B0CONST, TAIL[0], TAIL[1], TAIL[2], TAIL[3]))
    src = once(src, old_re, new_pad)
    # 6) apply: swap the re-encode CRC helpers for the padder derivations
    src = once(src, 'read_profile.apply(); in_rb0_t.apply(); in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); crc_read_b_t.apply();',
               'read_profile.apply(); in_rb0_t.apply(); in_rb1_t.apply(); in_rt_t.apply(); derive_pad_tp_t.apply(); crc_pad_c0_t.apply();')
    # 7) deparser emit: native blocks live (no ra/ca/rbh/rc/cb) + appended frame
    src = once(src,
               'pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.ra); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0); pkt.emit(hdr.ca);\n'
               '        pkt.emit(hdr.rbh); pkt.emit(hdr.p69); pkt.emit(hdr.rc); pkt.emit(hdr.cb);\n'
               '        pkt.emit(hdr.p1012); pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);',
               'pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0);\n'
               '        pkt.emit(hdr.p69); pkt.emit(hdr.p1012); pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);\n'
               '        pkt.emit(hdr.padl); pkt.emit(hdr.padb0); pkt.emit(hdr.padc0); pkt.emit(hdr.padt0); pkt.emit(hdr.padt1); pkt.emit(hdr.padt2); pkt.emit(hdr.padt3);')
    # 8) deparser checksum: new read-pad branch (native live fields + appended frame), mirroring parity
    old_ck = ('        if (hdr.ra.isValid()) {\n')
    new_ck_head = ('        if (hdr.padl.isValid()) {\n'
                   '            hdr.tcp.checksum = tcp_read.update({hdr.tcp.seq, hdr.tcp.ack, m.ack_inv, hdr.tcp.window, m.len_delta,\n'
                   '                hdr.dl.start, hdr.dl.len, hdr.dl.ctrl, hdr.dl.dst, hdr.dl.src, hdr.dl.crc,\n'
                   '                hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual, hdr.robj.g_start, hdr.robj.g_stop,\n'
                   '                hdr.p03.d, hdr.p45.d, hdr.c0.crc, hdr.p69.d, hdr.p1012.d, hdr.p1321.d, hdr.c1.crc, hdr.p22.d, hdr.c2.crc, 8w0,\n'
                   '                hdr.padl.start, hdr.padl.len, hdr.padl.ctrl, hdr.padl.dst, hdr.padl.src, hdr.padl.crc,\n'
                   '                hdr.padb0.tp, hdr.padb0.body, hdr.padc0.crc,\n'  # tail (192 const bytes) sums to 0xffff = ~0, omitted
                   '                m.r_residual});\n'
                   '        }\n'
                   '        if (hdr.ra.isValid()) {\n')
    src = once(src, old_ck, new_ck_head)
    return src


TRANSFORMS = ['mapper', 'read_pad']  # grown incrementally: 'sbo_frame', 'n_lane'


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
