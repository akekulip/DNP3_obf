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
import re
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


def transform_mapper_var(src, shape_image, stale_guard=True, read_native=49, per_image=None, c3_exact=False,
                         c3_cimg=False):
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
    if per_image is not None:
        # read_complete_01 policy build (review HIGH 1 of m12p_b07): keep m11_09's acct_grow and its acct_t rows
        # (size-off connections need grow: without it acct.lo never advances, smoke_sizeoff -123). The per-shape
        # image length reaches the ONE acct_try through m.ina -- already an acct SALU input, and unused by the
        # forward try/grow rows (prep_t leaves the arriving ACK there) -- set by ina_img_t from the shape flags.
        # RegisterActions on acct stay arm/try/grow/rev = 4.
        src = once(src, '            if (v.hi == 0) { v.lo = v.lo + r_IMAGE_LEN; v.hi = v.hi + r_IMAGE_LEN; rv = 1; }',
                   '            if (v.hi == 0) { v.lo = v.lo + m.ina; v.hi = v.hi + m.ina; rv = 1; }')
        src = once(src, '    Register<r_pair32, r_slot_t>(16, {0, 0}) acct;',
                   '    action set_ina(bit<32> v) { m.ina = v; }\n'
                   '    table ina_img_t { key = { m.read_shape : exact; m.ctl_shape : exact; }\n'
                   '        actions = { set_ina; NoAction; } size = 4; const default_action = NoAction();\n'
                   '        const entries = { (1, 0) : set_ina(%d); (0, 1) : set_ina(%d); } }\n'
                   '    Register<r_pair32, r_slot_t>(16, {0, 0}) acct;' % (shape_image['read'], shape_image['ctl']))
        src = once(src, '        acct_t.apply();\n', '        ina_img_t.apply();\n        acct_t.apply();\n')
    else:
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
    if per_image is not None and c3_cimg:
        return _policy_c5(_c3_committed_image(src, per_image), per_image)
    if per_image is not None and not c3_exact:
        # read_complete_01 policy build: m11_09's own reverse classifier, regenerated for the max image -- key
        # (m.r ternary, window range), per distance d: window <= d-1 -> rev_withhold_zero (window 0), else
        # rev_withhold_open (N + window - d >= N, never negative); translate d <= 0; stale before the max image.
        # This restores the qualified window rule exactly (rearm inverse_distance cases) with no new field: the
        # m.y-carried sign (m12p_b07 first form) shifted the forward chain to 14 pipe-0 stages.
        body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
        body_end = src.index('        }\n    }', body_start)
        src = once(src, 'size = 124; const default_action = rev_drop();',
                   'size = %d; const default_action = rev_drop();' % (2 * maximg + 2))
        body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
        body_end = src.index('        }\n    }', body_start)
        src = src[:body_start] + '\n' + rev_entries(maximg) + '\n        ' + src[body_end:]
        return _policy_c5(src, per_image)
    if per_image is None or not c3_exact:
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
        if per_image is None:
            return src
        # policy build without the per-image key (c3_exact=False): keying classify_rev on the committed native
        # length (m.y written in reverse_gap, then matched) needs a 13th pipe-0 stage (m12p_b04/b05; ablation
        # noC3 places in 12). The boundary stays the max-image window: exact for the READ image; an SBO image's
        # pre-start region is withheld (duplicate ACK at the native image start), not stale-dropped.
        return _policy_window_and_c5(src, per_image)
    # ---- read_complete_01 policy build: per-image C3 boundary, C5 forward mapping, zero-window guard ----
    # per_image maps COMMITTED NATIVE LENGTH -> committed WIRE IMAGE LENGTH, for every image that can be
    # outstanding: each shaped response, plus the handshake's virtual image (start_arm = ISN+1-61 -> 61).
    # C3: on the reverse path reverse_gap already computes the committed native length (m.q - m.p, the
    # img_end/img_start of the LAST commit); it now also lands in m.y (forward-only, dead on reverse), and
    # classify_rev keys on (m.r, m.y): withhold exactly m.r in [-I(N), -1], translate m.r >= 0, and stale-drop
    # anything before the CURRENT image's start, for each image size separately.
    src = once(src, '    action reverse_gap() { m.s_end = m.q - m.p; }',
               '    action reverse_gap() { m.s_end = m.q - m.p; m.y = m.q - m.p; }')
    src = once(src, '    table classify_rev {\n'
               '        key = { m.r : ternary; hdr.tcp.window : range; }',
               '    table classify_rev {\n'
               '        key = { m.r : ternary; m.y[7:0] : ternary; }')
    # c3_exact is OFF in the policy build: with the 32-bit key (m12p_b04) and with this 8-bit key (m12p_b05) the
    # write-then-match dependency needs a 13th pipe-0 stage. Kept only as the recorded exact construction.
    if len({n & 0xFF for n in per_image}) != len(per_image) or any(n > 0xFF for n in per_image):
        raise SystemExit('per-image C3 key needs distinct committed native lengths below 256')
    body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    rows = ['            (32w0 &&& 32w0x80000000, _) : rev_translate();\n']
    for n, img in sorted(per_image.items()):
        rows += ['            (32w0x%08x &&& 32w0x%08x, 8w%d) : rev_withhold_open();\n' % (v, m, n)
                 for v, m in rev_ternary_window(img)]
    src = once(src, 'size = 124; const default_action = rev_drop();',
               'size = %d; const default_action = rev_drop();' % (len(rows) + 1))
    src = src[:body_start] + '\n' + ''.join(rows) + '        ' + src[body_end:]
    return _policy_window_and_c5(src, per_image)


def _c3_committed_image(src, per_image):
    """Committed-image reverse boundary, no new PHV field (review of d531918e2, finding 2).

    Attempts: m12p_c01 keyed an 8-bit m.cimg = m.q[7:0] - m.p[7:0] (+16-bit window field): PHV allocation failed (the
    slice arithmetic split m.q/m.p/m.r into 8-bit pieces). m12p_c02 kept N in m.s_end and added the window after
    classify_rev: 13 pipe-0 stages (classify_rev cannot precede img_wend_t at stage 9, so a later add costs a stage).
    m12p_c03 wrote the forward-only m.t on the reverse path: 14 stages (fwd_prep_t, which also writes m.t, was ordered
    after reverse_window_base_t although the branches are exclusive -- the same false dependency as the m.y forms).
    This form keeps b08's stage layout with ONE dedicated reverse-only field m.wnd (bit<32>): reverse_window_base
    still runs beside img_wend_t and writes m.wnd = N + window, leaving m.s_end = N for the key. classify_rev keys on (m.r ternary,
    m.s_end[7:0] ternary): translate m.r >= 0 for any image; withhold exactly m.r in [-I, -1] for the committed image
    I of that N (prefix rows, rev_ternary_window); anything earlier, or an unknown N, is stale (default rev_drop).
    per_image's native lengths must be distinct mod 256. Window rule (m11_09's, qualified): a withheld ACK at
    distance d advertises window 0 when window < d, else N + window - d (clamped to 0xffff). rev_withhold_open sets
    m.wnd = N + window - d and the reverse-only m.r = window - d; window_t zeroes on negative m.r, else narrows m.wnd."""
    if len({n & 0xFF for n in per_image}) != len(per_image):
        raise SystemExit('committed native lengths must be distinct mod 256: %r' % sorted(per_image))
    src = once(src, '    bit<8>  result; bit<1> changed; bit<1> pad; bit<1> wide;',
               '    bit<8>  result; bit<1> changed; bit<1> pad; bit<1> wide; bit<32> wnd;')
    src = once(src, '    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) widen_win;',
               '    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) widen_win;\n'
               '    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) widen_win_d;')
    src = once(src, '    action reverse_window_base() { m.s_end = m.s_end + widen_win.get({hdr.tcp.window}); }',
               '    action reverse_window_base() { m.wnd = m.s_end + widen_win.get({hdr.tcp.window}); }')
    src = once(src, '    action rev_withhold_open() { hdr.tcp.ack = m.p; m.s_end = m.s_end + m.r; m.wide = (bit<1>)(1);',
               '    action rev_withhold_open() { hdr.tcp.ack = m.p; m.wnd = m.wnd + m.r;\n'
               '                                 m.r = m.r + widen_win_d.get({hdr.tcp.window}); m.wide = (bit<1>)(1);')
    src = once(src, '    table classify_rev {\n'
               '        key = { m.r : ternary; hdr.tcp.window : range; }',
               '    table classify_rev {\n'
               '        key = { m.r : ternary; m.s_end[7:0] : ternary; }')
    body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    rows = ['            (32w0 &&& 32w0x80000000, _) : rev_translate();\n']
    for n, img in sorted(per_image.items()):
        rows += ['            (32w0x%08x &&& 32w0x%08x, 8w%d) : rev_withhold_open();\n' % (v, m, n & 0xFF)
                 for v, m in rev_ternary_window(img)]
    src = once(src, 'size = 124; const default_action = rev_drop();',
               'size = %d; const default_action = rev_drop();' % len(rows))
    src = src[:body_start] + '\n' + ''.join(rows) + '        ' + src[body_end:]
    src = once(src, '    action window_exact() { hdr.tcp.window = narrow_win.get({m.s_end[15:0]}); }',
               '    action window_exact() { hdr.tcp.window = narrow_win.get({m.wnd[15:0]}); }')
    src = once(src, '    action window_clamp() { hdr.tcp.window = 0xffff; }',
               '    action window_clamp() { hdr.tcp.window = 0xffff; }\n'
               '    action window_zero() { hdr.tcp.window = 0; }')
    src = once(src, 'key = { m.s_end : ternary; }\n'
               '        actions = { window_exact; window_clamp; } size = 2; const default_action = window_clamp();\n'
               '        const entries = { 32w0 &&& 32w0xFFFF0000 : window_exact(); 32w0 &&& 32w0 : window_clamp(); }',
               'key = { m.wnd : ternary; m.r : ternary; }\n'
               '        actions = { window_exact; window_clamp; window_zero; } size = 3; const default_action = window_clamp();\n'
               '        const entries = { (_, 32w0x80000000 &&& 32w0x80000000) : window_zero();'
               ' (32w0 &&& 32w0xFFFF0000, _) : window_exact(); (_, _) : window_clamp(); }')
    return src


def _policy_window_and_c5(src, per_image):
    """Pure-m.r classify_rev variants (full build / c3_exact): window sign carried in m.y, then C5."""
    # reverse window (review of m12p_b06; rearm inverse_distance cases): restore m11_09's qualified rule. A
    # withheld ACK at distance d into the image with window win advertised window 0 when win < d, else
    # N + win - d. Without the window-range key the sign of (win - d) is carried in m.y (forward-only, free on
    # the reverse path in this build): reverse_window_base records the widened window, rev_withhold_open adds
    # m.r (= -d), and window_t zeroes the window when m.y is negative. Negative s_end implies negative m.y.
    src = once(src, '    action reverse_window_base() { m.s_end = m.s_end + widen_win.get({hdr.tcp.window}); }',
               '    action reverse_window_base() { m.y = widen_win.get({hdr.tcp.window}); m.s_end = m.s_end + m.y; }')
    src = once(src, '    action rev_withhold_open() { hdr.tcp.ack = m.p; m.s_end = m.s_end + m.r; m.wide = (bit<1>)(1);',
               '    action rev_withhold_open() { hdr.tcp.ack = m.p; m.s_end = m.s_end + m.r; m.y = m.y + m.r; m.wide = (bit<1>)(1);')
    src = once(src, '    action window_clamp() { hdr.tcp.window = 0xffff; }',
               '    action window_clamp() { hdr.tcp.window = 0xffff; }\n'
               '    action window_zero() { hdr.tcp.window = 0; }')
    src = once(src, 'key = { m.s_end : ternary; }\n'
               '        actions = { window_exact; window_clamp; } size = 2; const default_action = window_clamp();\n'
               '        const entries = { 32w0 &&& 32w0xFFFF0000 : window_exact(); 32w0 &&& 32w0 : window_clamp(); }',
               'key = { m.s_end : ternary; m.y : ternary; }\n'
               '        actions = { window_exact; window_clamp; window_zero; } size = 3; const default_action = window_clamp();\n'
               '        const entries = { (_, 32w0x80000000 &&& 32w0x80000000) : window_zero(); (32w0 &&& 32w0xFFFF0000, _) : window_exact(); (_, _) : window_clamp(); }')
    return _policy_c5(src, per_image)


def _policy_c5(src, per_image):
    # C5: a forward pure ACK (leff 0) carrying the native START of the last committed image (m.p == 0,
    # m.q == -N) maps to the wire START of that image (wend - I), not to the wire end (old out_zero used
    # m.pm = m.p - 0 = 0 -> wend). Constant per committed size; no PHV field. Other leff-0 seqs unchanged.
    acts = ''.join('    action out_zero_img_%d() { m.qx = %s; m.result = r_OUT_ZERO; m.changed = 1; }\n' % (img, neg(img))
                   for img in sorted(set(per_image.values())))
    src = once(src, '    action out_reset_front_37() {', acts + '    action out_reset_front_37() {')
    src = once(src, 'actions = { out_commit; out_translate; out_zero; out_replay; out_stale; out_drop; out_reset_front_49; out_reset_front_37; } size = 24;',
               'actions = { out_commit; out_translate; out_zero; out_replay; out_stale; out_drop; out_reset_front_49; out_reset_front_37; %s } size = %d;'
               % (''.join('out_zero_img_%d;' % i for i in sorted(set(per_image.values()))), 24 + len(per_image)))
    zrows = ''.join('(_, _, %s, 0, 32w0, _, _, _, _, _, _, _, _, _, _, _): out_zero_img_%d();' % (neg(n), img)
                    for n, img in sorted(per_image.items()))
    src = once(src, '(_, _, _, 0, _, _, _, _, _, _, _, _, _, _, _, _): out_zero();',
               zrows + '(_, _, _, 0, _, _, _, _, _, _, _, _, _, _, _, _): out_zero();')
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

CONSTANTS = STAGE / 'read_complete_01/vectors/constants.json'


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


CONSTANTS_TWO = STAGE / 'read_complete_01/vectors/constants_two_read.json'
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
    p = dict(zdecl=zdecl, zset=zset, tp_rows=tp_rows,
             mx_len=cm['native_link_len'], mx_ip=cm['native_ip_len'], mx_plen=cm['prefix_link_len'],
             mx_ldelta=cm['link_crc_delta'], mx_hi=int(cm['block0_tail'][:14], 16), mx_lo=int(cm['block0_tail'][14:], 16),
             mx_delta=cm['added'], mx_folded=folded_mx,
             f_len=cf['native_link_len'], f_ip=cf['native_ip_len'], f_plen=cf['prefix_link_len'],
             f_ldelta=cf['link_crc_delta'], f_obj=int(cf['padobj_head'], 16), f_delta=cf['added'])
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
    table read_profile { key = { hdr.dl.len : exact; hdr.rh.tpctrl : ternary; hdr.rh.appctrl : ternary; hdr.rh.func : exact;
            hdr.robj.g_group : exact; hdr.robj.g_var : exact; hdr.robj.g_qual : exact; hdr.robj.g_start : exact; hdr.robj.g_stop : exact; }
        actions = { pad_mx; pad_full; NoAction; } size = 2; const default_action = NoAction();
        const entries = { (8w0x%(mx_len)02x, 8w0xC0 &&& 8w0xC0, 8w0xC0 &&& 8w0xF0, 8w0x81, 8w0x01, 8w0x02, 8w0x00, 8w0x00, 8w0x0f): pad_mx();
                          (8w0x%(f_len)02x, 8w0xC0 &&& 8w0xC0, 8w0xC0 &&& 8w0xF0, 8w0x81, 8w0x01, 8w0x02, 8w0x00, 8w0x00, 8w0x0f): pad_full(); } }
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
    # 7) RST exactly one READ ahead restarts the front: one parameterised action, one row per READ native. The
    #    action ADDS the negated length: Tofino rejects action data as the second operand of a subtraction (m12p_c21:
    #    "Second operand of arithmetic subtraction cannot be sourced from action data").
    src = once(src, 'action out_reset_front_49() { m.qx = m.q - 32w49; m.result = r_OUT_RESET_FRONT; m.changed = 1; }',
               'action out_reset_front_rd(bit<32> negn) { m.qx = m.q + negn; m.result = r_OUT_RESET_FRONT; m.changed = 1; }')
    src = once(src, 'out_reset_front_49; out_reset_front_37;', 'out_reset_front_rd; out_reset_front_37;')
    src = once(src, '(32w49, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_49();',
               ''.join('(32w%d, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_rd(%s);' % (n, neg(n))
                       for n in (cm['native_total'], cf['native_total'])))
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


def transform_two_read_n(src, _image=None):
    """N admits, times and accounts the mixed READ (applied after transform_read_passthrough_n, which already admits
    the 247-octet class0/integrity response and the integrity request).

    Request: ONE READ with two 5-octet range headers, g1v2 q00 [0,15] + g30v1 q00 [0,7] (25 octets, dl.len 0x12,
    ip.len 65), fully parsed: its own header type, an exact profile on both objects with the same exact-slice
    tp/app keys as the pass-through profiles, and a real block CRC (computed in rd_request_full_crc_t, now keyed on
    which of the two headers is valid: 2 x 16 = 32 immediate hash bits, the per-table limit). Response: one 91-octet
    link frame (ip.len 131, dl.len 0x4c) parsed FIRST BLOCK ONLY like the pass-through responses: the link-header and
    block-0 CRCs are really checked, block-1+ CRCs are derived from block 0 and the TCP checksum is WAIVED
    (finish_shallow writes m.tcp_sum = 0xffeb: a validation waiver, not a computed checksum). Sequence accounting
    advances by 25 / 91; every retransmission row keyed on the range lengths (-20 request, -49 response) is repeated
    for -25 / -91."""
    cm, _ = two_read_shapes()
    req_len, req_dl, rsp_len, rsp_dl = cm['request_len'], cm['request_link_len'], cm['native_total'], cm['native_link_len']
    objs = bytes.fromhex(cm['request_objects'])
    if (req_len, req_dl, rsp_len, rsp_dl, len(objs)) != (25, 0x12, 91, 0x4c, 10):
        raise SystemExit('unexpected mixed READ shape %r' % ((req_len, req_dl, rsp_len, rsp_dl, len(objs)),))
    o1, o2 = int.from_bytes(objs[:5], 'big'), int.from_bytes(objs[5:], 'big')
    # 1) header, mutually exclusive with every other request header
    src = once(src, 'header n_read_req_full_h{bit<8> tp;bit<8> app;bit<8> func;bit<24> o1;bit<24> o2;bit<24> o3;bit<24> o4;bit<16> crc;}',
               'header n_read_req_full_h{bit<8> tp;bit<8> app;bit<8> func;bit<24> o1;bit<24> o2;bit<24> o3;bit<24> o4;bit<16> crc;}\n'
               'header n_read_req_mx_h{bit<8> tp;bit<8> app;bit<8> func;bit<40> o1;bit<40> o2;bit<16> crc;}')
    src = once(src, 'n_read_req_full_h rd_req_full;', 'n_read_req_full_h rd_req_full;n_read_req_mx_h rd_req_mx;')
    pragmas = ''.join('@pa_mutually_exclusive("ingress", "%s", "hdr.rd_req_mx")\n' % h
                      for h in ('hdr.rd_req', 'hdr.rd_req_an', 'hdr.rd_req_c0', 'hdr.rd_req_full'))
    src = once(src, '@pa_container_size("ingress", "m.expected_work_phase", 32)\n',
               pragmas + '@pa_container_size("ingress", "m.expected_work_phase", 32)\n')
    # 2) parser: the new request and response lengths, exact (dl.len, ip.len) dispatch
    src = once(src, '(4w4,4w5,8w6,16w67):rx_ip_flags;', '(4w4,4w5,8w6,16w67):rx_ip_flags;(4w4,4w5,8w6,16w%d):rx_ip_flags;' % (40 + req_len))
    src = once(src, '(4w4,4w5,8w6,16w287):rx_response_ip_flags;',
               '(4w4,4w5,8w6,16w287):rx_response_ip_flags;(4w4,4w5,8w6,16w%d):rx_response_ip_flags;' % (40 + rsp_len))
    src = once(src, '(8w0x14,16w67):read_request_full;',
               '(8w0x14,16w67):read_request_full;(8w0x%02x,16w%d):read_request_mx;' % (req_dl, 40 + req_len))
    src = once(src, '(8w0xd6,16w287):read_response_fb;',
               '(8w0xd6,16w287):read_response_fb;(8w0x%02x,16w%d):read_response_fb;' % (rsp_dl, 40 + rsp_len))
    src = once(src, ' state read_request_full{pkt.extract(hdr.rd_req_full);tc.subtract(hdr.rd_req_full);m.packet_kind=8w9;transition finish;}\n',
               ' state read_request_full{pkt.extract(hdr.rd_req_full);tc.subtract(hdr.rd_req_full);m.packet_kind=8w9;transition finish;}\n'
               ' state read_request_mx{pkt.extract(hdr.rd_req_mx);tc.subtract(hdr.rd_req_mx);m.packet_kind=8w9;transition finish;}\n')
    # 3) request profile (exact) and the response profile row for the 91-octet block 0 (same g1v2 q00 [0,15] header
    #    as the 247 response; the response's link LEN tells them apart)
    src = once(src, 'table read_request_full_profile{',
               'table read_request_mx_profile{key={hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.rd_req_mx.tp[7:6]:exact;'
               'hdr.rd_req_mx.app[7:4]:exact;hdr.rd_req_mx.func:exact;hdr.rd_req_mx.o1:exact;hdr.rd_req_mx.o2:exact;}\n'
               ' actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={(16w0x0564,8w0x%02x,8w0xc4,2w3,4w0xc,8w1,40w0x%010x,40w0x%010x):eligible();}}\n'
               'table read_request_full_profile{' % (req_dl, o1, o2))
    rsp_row = '(16w0x0564,8w0xd6,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();}}'
    src = once(src, 'actions={eligible;NoAction;}size=3;const default_action=NoAction();const entries={(16w0x0564,8w38,',
               'actions={eligible;NoAction;}size=4;const default_action=NoAction();const entries={(16w0x0564,8w38,')
    src = once(src, rsp_row, rsp_row[:-2] + '(16w0x0564,8w0x%02x,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w1,8w2,8w0,8w0,8w0x0f):eligible();}}' % rsp_dl)
    # 4) request CRC: the integrity table now computes the integrity OR the mixed CRC by header validity
    src = once(src, 'table rd_request_full_crc_t{actions={rd_request_full_crc;}size=1;const default_action=rd_request_full_crc();}\n',
               'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_rd_request_mx;\n'
               'action rd_request_mx_crc(){m.bcrc=hash_rd_request_mx.get({hdr.rd_req_mx.tp,hdr.rd_req_mx.app,hdr.rd_req_mx.func,'
               'hdr.rd_req_mx.o1,hdr.rd_req_mx.o2,hdr.rd_req_mx.crc});}\n'
               'table rd_request_full_crc_t{key={hdr.rd_req_full.isValid():exact;}actions={rd_request_full_crc;rd_request_mx_crc;NoAction;}size=2;'
               'const entries={true:rd_request_full_crc();false:rd_request_mx_crc();}const default_action=NoAction();}\n')
    src = once(src, 'else if(hdr.rd_req_full.isValid()){read_request_full_profile.apply();rd_request_full_crc_t.apply();}',
               'else if(hdr.rd_req_full.isValid()||hdr.rd_req_mx.isValid()){if(hdr.rd_req_full.isValid()){read_request_full_profile.apply();}'
               'else{read_request_mx_profile.apply();}rd_request_full_crc_t.apply();}')
    # 5) sequence accounting
    src = once(src, '(8w9,_):next_read_request();',
               '(8w9,8w0x%02x):next_read_len(%d);(8w11,8w0x%02x):next_read_len(%d);(8w9,_):next_read_request();'
               % (req_dl, req_len, rsp_dl, rsp_len))
    src = once(src, 'actions={next_seq;next_control;next_response;next_read_request;next_read_response;next_read_len;}size=12;',
               'actions={next_seq;next_control;next_response;next_read_request;next_read_response;next_read_len;}size=14;')
    # 6) application-sequence input
    src = once(src, 'action read_request_full_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_full.app[3:0]);}\n',
               'action read_request_full_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_full.app[3:0]);}\n'
               'action read_request_mx_input(){m.compare_read_app=(bit<32>)(hdr.rd_req_mx.app[3:0]);}\n')
    src = once(src, 'hdr.rd_req_full.isValid():exact;}'
                    'actions={read_request_input;read_request_an_input;read_request_c0_input;read_request_full_input;read_response_input;NoAction;}size=5;'
                    'const entries={(8w9,false,false,false):read_request_input();(8w9,true,false,false):read_request_an_input();'
                    '(8w9,false,true,false):read_request_c0_input();(8w9,false,false,true):read_request_full_input();'
                    '(8w11,false,false,false):read_response_input();}',
               'hdr.rd_req_full.isValid():exact;hdr.rd_req_mx.isValid():exact;}'
               'actions={read_request_input;read_request_an_input;read_request_c0_input;read_request_full_input;read_request_mx_input;read_response_input;NoAction;}size=6;'
               'const entries={(8w9,false,false,false,false):read_request_input();(8w9,true,false,false,false):read_request_an_input();'
               '(8w9,false,true,false,false):read_request_c0_input();(8w9,false,false,true,false):read_request_full_input();'
               '(8w9,false,false,false,true):read_request_mx_input();(8w11,false,false,false,false):read_response_input();}')
    # 7) retransmission recognition (sequence_guard, first_event, retry_dup_t): -25 request, -91 response
    for table in ('sequence_guard', 'first_event', 'retry_dup_t'):
        src = _neg_entry_rows(src, table, {neg(20): [neg(req_len)], neg(49): [neg(rsp_len)]})
    return src


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


def transform_segmented_n(src):
    """SEGMENTED probe step 2 (opt-in, --seg-n on top of --segmented). Add N's admission of the two
    link-frame segments of the 377 native: the FIR segment is a 292-B TCP payload (ip.len 332) and the
    FIN segment is an 85-B payload (ip.len 125). Reuses the existing rx_response path and the shallow
    block-0 parse (read_response_fb / finish_shallow); no new header or table. This isolates whether the
    already-full p0 ingress (12/12 MAU stages, PHV ~91%) can admit even the two new lengths. It does not
    yet tag child 0 vs child 1 or change the handoff to T."""
    src = once(src,
        '(4w4,4w5,8w6,16w287):rx_response_ip_flags;',
        '(4w4,4w5,8w6,16w287):rx_response_ip_flags;(4w4,4w5,8w6,16w332):rx_response_ip_flags;(4w4,4w5,8w6,16w125):rx_response_ip_flags;')
    src = once(src,
        '(8w0xd6,16w287):read_response_fb;default:accept;}}',
        '(8w0xd6,16w287):read_response_fb;(8w0xff,16w332):read_response_fb;(8w0x46,16w125):read_response_fb;default:accept;}}')
    return src


def transform_segmented_n2(src):
    """SEGMENTED probe step 3 (opt-in, --seg-n2 on top of --segmented --seg-n). Add ONE representative
    new MAU table to N (p0 ingress): the child-index tag the two-segment READ needs, keyed on ip.len,
    setting m.stage to child 0 (FIR, ip.len 332) or child 1 (FIN, ip.len 125). This directly tests
    whether the already-full p0 ingress (12/12 MAU stages) can absorb even one extra match-action table.
    It is a placement probe, not a correct classifier (it overwrites m.stage unconditionally for those
    lengths)."""
    src = once(src,
        ' action network_accept(){m.network_valid=(bit<1>)(8w1);}',
        ' action set_seg_child(bit<2> c){m.stage=c;}'
        ' table seg_child_t{key={hdr.ip.len:exact;}actions={set_seg_child;NoAction;}size=2;'
        'const entries={(16w332):set_seg_child(2w0);(16w125):set_seg_child(2w1);}const default_action=NoAction();}'
        ' action network_accept(){m.network_valid=(bit<1>)(8w1);}')
    src = once(src,
        '  ports.apply();network.apply();retry_valid_t.apply();',
        '  seg_child_t.apply();\n  ports.apply();network.apply();retry_valid_t.apply();')
    return src


CONSTANTS_SEG = STAGE / 'read_complete_01/vectors/constants_segmented.json'


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


TRANSFORMS = ['mapper_var', 'read_prefix']  # step 1: variable image (READ 73 + inherited SBO 61); full READ uses read_prefix_full


def build(image, only=None, full=False, policy=False, c3='ladder', shapes='none', segmented=False, seg_n=False, seg_n2=False,
          segmented_pad=False, segmented_full=False, two_read=False):
    src = M11_09.read_text()
    if hashlib.sha256(src.encode()).hexdigest() != M11_09_SHA:
        raise SystemExit('m11_09 source changed')
    # full candidate: full integrity READ (247->269) + SBO (61); else the range-READ (73)+SBO(61) proof build.
    # policy: the frozen read_complete_01 policy (range READ 49 -> 141 from derived constants) + SBO 61.
    per_image = None
    if two_read:
        # two-READ-target profile (m12p_c21): mixed READ 91 -> 141 and base full (integrity/class0) READ 247 -> 271
        # REPLACE the range READ transformation; SBO 37 -> 61 unchanged. Same N/E/T topology and pipe-1 padder slot.
        cm, cf = two_read_shapes()
        transforms = ['mapper_var', 'two_read_pad_pipe1', 'two_read_e', 'read_passthrough_n', 'two_read_n']
        shape_image = {'read': cm['target'], 'ctl': 61}
        read_native = cm['native_total']
        per_image = {cm['native_total']: cm['target'], cf['native_total']: cf['target'], 37: 61, 61: 61}
    elif policy:
        c = policy_shape()
        transforms = ['mapper_var', 'read_prefix_p1', 'read_prepadded_e']
        if shapes == 'passthrough':
            transforms.append('read_passthrough_n')
        if segmented:
            transforms.append('segmented_t')
        if seg_n:
            transforms.append('segmented_n')
        if seg_n2:
            transforms.append('segmented_n2')
        if segmented_pad:
            transforms.append('segmented_pad_pipe1')
        if segmented_full:
            transforms += ['segmented_pad_pipe1', 'segmented_classifier', 'segmented_t']
        shape_image = {'read': c['target'], 'ctl': 61}
        read_native = c['native_total']
        per_image = {c['native_total']: c['target'], 37: 61, 61: 61}   # 61: handshake virtual image
        if segmented_full:
            # step 4 (E mapper): the committed 401-octet segmented image needs its own reverse-ACK withhold
            # window so the master's ACKs are remapped across the +24 shift for the WHOLE 401 image (not just
            # the 141 range image). native 377 -> image 401; keyed in classify_rev on native length mod 256
            # (377 & 0xFF = 121, distinct). This is the documented p0-egress risk: the per-image reverse window
            # extended to 401 stresses classify_rev's TCAM.
            per_image[segmented_shape()['native_total']] = segmented_shape()['target']
    else:
        transforms = ['mapper_var', 'read_prefix_full'] if full else TRANSFORMS
        shape_image = {'read': 269, 'ctl': 61} if full else SHAPE_IMAGE
        read_native = 247 if full else 49
    applied = []
    for name in transforms:
        if name == 'mapper_var':
            src = transform_mapper_var(src, shape_image, stale_guard=STALE_GUARD, read_native=read_native,
                                       per_image=per_image, c3_cimg=((policy or two_read) and c3 == 'cimg'))
        elif name == 'read_passthrough_n':
            src = transform_read_passthrough_n(src)
        elif name == 'segmented_t':
            src = transform_segmented_t(src)
        elif name == 'segmented_n':
            src = transform_segmented_n(src)
        elif name == 'segmented_n2':
            src = transform_segmented_n2(src)
        elif name == 'segmented_pad_pipe1':
            src = transform_segmented_pad_pipe1(src, segmented_shape())
        elif name == 'segmented_classifier':
            src = transform_segmented_classifier(src)
        elif name in ('read_prefix_p1', 'read_prepadded_e'):
            src = globals()['transform_' + name](src, policy_shape())
        elif name in ('two_read_pad_pipe1', 'two_read_e', 'two_read_n'):
            src = globals()['transform_' + name](src)
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
    ap.add_argument('--policy', action='store_true', help='read_complete_01 frozen policy: range READ 49->141 + SBO 61')
    ap.add_argument('--c3', choices=('ladder', 'cimg'), default='ladder',
                    help='policy build reverse boundary: max-image ladder (m12p_b08) or per committed image (cimg)')
    ap.add_argument('--shapes', choices=('none', 'passthrough'), default='none',
                    help='policy build: also admit the pass-through READ classes (analog 141, class0/integrity 247) at native size')
    ap.add_argument('--segmented', action='store_true',
                    help='opt-in SEGMENTED probe: add the T second-response-child wiring toward the two-frame 377->401 READ (see transform_segmented_t)')
    ap.add_argument('--seg-n', dest='seg_n', action='store_true',
                    help='SEGMENTED probe step 2: also add N admission of the 332/125 segment lengths (requires --segmented)')
    ap.add_argument('--seg-n2', dest='seg_n2', action='store_true',
                    help='SEGMENTED probe step 3: also add the N child-index MAU table (requires --seg-n)')
    ap.add_argument('--segmented-pad', dest='segmented_pad', action='store_true',
                    help='FAITHFUL segmented 377->401 READ padder in pipe-1 egress (requires --policy; builds m12p_c16+)')
    ap.add_argument('--segmented-full', dest='segmented_full', action='store_true',
                    help='FULL faithful segmented path: pipe-1 padder + N two-segment classifier/child-tag + T second child (requires --policy)')
    ap.add_argument('--two-read', dest='two_read', action='store_true',
                    help='two-READ-target profile (m12p_c21): mixed READ 91->141 + full READ 247->271 replace the range READ; '
                         'SBO 37->61 unchanged (requires --policy --c3 cimg --shapes passthrough)')
    a = ap.parse_args()
    if a.two_read and not (a.policy and a.c3 == 'cimg' and a.shapes == 'passthrough'):
        ap.error('--two-read requires --policy --c3 cimg --shapes passthrough')
    if a.two_read and (a.segmented or a.seg_n or a.seg_n2 or a.segmented_pad or a.segmented_full):
        ap.error('--two-read excludes the segmented probes (the native 377 segment work is not in this profile)')
    if a.shapes != 'none' and not a.policy:
        ap.error('--shapes requires --policy')
    if a.segmented and not a.policy:
        ap.error('--segmented requires --policy')
    if a.seg_n and not a.segmented:
        ap.error('--seg-n requires --segmented')
    if a.seg_n2 and not a.seg_n:
        ap.error('--seg-n2 requires --seg-n')
    if a.segmented_pad and not a.policy:
        ap.error('--segmented-pad requires --policy')
    if a.segmented_full and not a.policy:
        ap.error('--segmented-full requires --policy')
    if a.segmented_full and a.segmented_pad:
        ap.error('--segmented-full already includes the padder; do not combine with --segmented-pad')
    if a.full:
        a.image = 269
    if a.policy:
        a.image = two_read_shapes()[0]['target'] if a.two_read else policy_shape()['target']
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    src, applied = build(a.image, a.only, full=a.full, policy=a.policy, c3=a.c3, shapes=a.shapes, segmented=a.segmented, seg_n=a.seg_n, seg_n2=a.seg_n2,
                         segmented_pad=a.segmented_pad, segmented_full=a.segmented_full, two_read=a.two_read)
    (out / 'response_only.p4').write_text(src)
    sha = hashlib.sha256(src.encode()).hexdigest()
    # The candidate is runnable only when the mapper AND every size-path transform agree. A partial set
    # (e.g. mapper alone: image=269 while the encoders still emit 61) is an intermediate placement
    # experiment, NOT a working candidate, and is flagged non-runnable so nothing treats it as integrated.
    # Per-build scope + metadata. The full build REPLACES the response profile and seq delta (full
    # integrity READ 247->269); it does NOT still support the old range READ merely because the old parser
    # dispatch remains. The range-proof build keeps the inherited-SBO scope.
    if a.two_read:
        cm, cf = two_read_shapes()
        c = cm
        required = {'mapper_var', 'two_read_pad_pipe1', 'two_read_e', 'read_passthrough_n', 'two_read_n'}
        read_native, read_out = cm['native_total'], cm['target']
        scope = ('two-READ-target profile (Claude_Two_READ_Targets_Hardware_Directive.md): mixed READ (one request, '
                 'g1v2 q00 0-15 + g30v1 q00 0-7) %d->%d as [%s] with %d G1V2 points %d..%d, and the base-database full '
                 'READ (integrity; class0 has the same response and is padded alike) %d->%d as [%s] with %d points '
                 '%d..%d, both by the pipe-1 prefix construction; SELECT/OPERATE 37->61 unchanged. NOT padded, by '
                 'declaration: range READ 49 and analog READ 141 pass at native size; the native two-segment 377 '
                 'response is out of scope. Responses are admitted by N first-block only (link and block-0 CRCs '
                 'checked; TCP checksum WAIVED, not computed)'
                 % (cm['native_total'], cm['target'], ', '.join(map(str, cm['frames_out'])), cm['padding_points'],
                    cm['padding_indices'][0], cm['padding_indices'][1], cf['native_total'], cf['target'],
                    ', '.join(map(str, cf['frames_out'])), cf['padding_points'], cf['padding_indices'][0],
                    cf['padding_indices'][1]))
    elif a.policy:
        c = policy_shape()
        required = {'mapper_var', 'read_prefix_p1', 'read_prepadded_e'}
        read_native, read_out = c['native_total'], c['target']
        scope = ('read_complete_01 policy hardware shape set, phase A: range READ 49->%d (prefix, G1V2 %d..%d '
                 'synthetic) + SELECT/OPERATE 37->61; analog/class0/integrity/segmented READ classes NOT yet in '
                 'this build' % (c['target'], c['reserved_first_index'], c['reserved_first_index'] + c['padding_points'] - 1))
        if a.shapes == 'passthrough':
            required.add('read_passthrough_n')
            scope = ('read_complete_01 policy hardware shape set, phase S1: range READ 49->%d (prefix) + SELECT/OPERATE '
                     '37->61 + pass-through READ classes at native size (analog 22->141, class0 18->247, integrity '
                     '27->247; one link frame each, first-block-only N admission, TCP checksum of the response waived '
                     'in N); segmented READ classes NOT yet in this build' % c['target'])
    elif a.full:
        required = {'mapper_var', 'read_prefix_full'}
        read_native, read_out = 247, 269
        scope = 'full integrity READ 247->269 + SELECT/OPERATE 37->61; range READ not supported'
    else:
        required = {'mapper_var', 'read_prefix'}
        read_native, read_out = 49, a.image
        scope = 'range READ 49->%d + inherited SBO 37->61 (variable-image proof build)' % a.image
    runnable = required.issubset(set(applied))
    segs = {role: hashlib.sha256(_combined.segment(src, role).encode()).hexdigest() for role in ('N', 'E', 'T')}
    # segmented_t adds the second response-child register (child_seen1_reg), so the sealed profile must declare two
    # T child banks for the segmented build; every other build keeps the single child_seen0_reg (t_child_count 1).
    t_child_count = 2 if 'segmented_t' in applied else 1
    profile = {'candidate': {'build': str(out), 'milestone': 'm12', 'source_sha256': sha, 'segment_sha256': segs,
                             'artifact_sha256': {}},
               'reset_restart_required': True, 't_child_count': t_child_count}
    if a.policy:
        # complete supported profile (candidate_campaign's control-timing contract): N/T values inherited
        # unchanged from m11_09; the READ image is stated separately from the control image
        m11 = json.loads((STAGE / 'ctl_timing_01/evidence/m11_09/supported_profile.json').read_text())
        profile.update({k: m11[k] for k in ('profile_version', 'clock', 'timing_ns', 'n', 'ports')})
        if not a.two_read:     # the two-READ build writes its own note below
            profile['_note'] = ('read_complete_01 policy build: N/T values unchanged from m11_09 (T segment and timing '
                                'parameters inherited); encoding differs: SELECT/OPERATE output 61 (output_octets), READ '
                                'output %d (read_output_octets, pipe-1 egress prefix, %d synthetic G1V2 points %d..%d). '
                                'Arbitrary input sizes are not supported.'
                                % (c['target'], c['padding_points'], c['reserved_first_index'],
                                   c['reserved_first_index'] + c['padding_points'] - 1))
        profile['encoding'] = {
            'native_input_octets': {'READ': 49, 'SELECT': 37, 'OPERATE': 37}, 'output_octets': 61,
            'output_octets_note': 'SELECT/OPERATE image (the control-timing contract field); the READ image is read_output_octets',
            'read_output_octets': c['target'],
            'read_construction': 'prefix (read_complete_01/vectors/constants.json shape %s)' % c['shape'],
            'control_application_partition': m11['encoding']['control_application_partition'],
            'control_partition_note': m11['encoding']['control_partition_note']}
        if a.two_read:
            cm, cf = two_read_shapes()
            profile['_note'] = ('two-READ-target build (m12p_c21): N/T values unchanged from m11_09 (T segment and timing '
                                'parameters inherited); encoding: SELECT/OPERATE output 61 (output_octets); READ images per '
                                'native length (read_images): mixed %d->%d and full %d->%d by the pipe-1 egress prefix '
                                '(G1V2 points 1024..). Other READ lengths are not padded; arbitrary input sizes are not '
                                'supported.' % (cm['native_total'], cm['target'], cf['native_total'], cf['target']))
            profile['encoding'].update({
                'native_input_octets': {'READ': [cm['native_total'], cf['native_total']], 'SELECT': 37, 'OPERATE': 37},
                'read_output_octets': [cm['target'], cf['target']],
                'read_images': {str(cm['native_total']): cm['target'], str(cf['native_total']): cf['target']},
                'read_construction': 'prefix (read_complete_01/vectors/constants_two_read.json shapes %s, %s)'
                                     % (cm['shape'], cf['shape'])})
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
        **({'read_boundary': 'cimg' if a.c3 == 'cimg' else 'max_image_ladder'} if a.policy else {}),
        **({'passthrough_reads': {n: {'request_octets': v[0], 'request_dl_len': v[1], 'response_octets': v[2],
                                      'response_dl_len': v[3], 'output_octets': v[2]}
                                  for n, v in PASSTHROUGH_READS.items()
                                  # two-READ build: class0/integrity 247 responses are PADDED (to 271), not passed through
                                  if not (a.two_read and v[2] == two_read_shapes()[1]['native_total'])}}
           if a.shapes == 'passthrough' else {}),
        **({'read_images': {str(s['native_total']): s['target'] for s in two_read_shapes()},
            'read_shapes': {name: {k: s[k] for k in ('native_total', 'native_link_len', 'native_ip_len', 'target',
                                                     'frames_out', 'added', 'padding_points', 'padding_indices',
                                                     'prefix_link_len', 'request_len', 'request_link_len',
                                                     'request_ip_len', 'request_objects')}
                            for name, s in zip(('mixed', 'full'), two_read_shapes())}} if a.two_read else {}),
        'output_lengths': ({'READ': {'mixed': two_read_shapes()[0]['target'], 'full': two_read_shapes()[1]['target']},
                            'SELECT_OPERATE': 61} if a.two_read else {'READ': read_out, 'SELECT_OPERATE': 61}),
        'policy': (dict(constants_file='read_complete_01/vectors/constants_two_read.json',
                        constants_sha256=hashlib.sha256(CONSTANTS_TWO.read_bytes()).hexdigest(),
                        policy_targets=json.loads(CONSTANTS_TWO.read_text())['policy_targets'],
                        p1_read_pad_conn_table='p1.x_Egress.p1_conn') if a.two_read else
                   dict(constants_sha256=hashlib.sha256(CONSTANTS.read_bytes()).hexdigest(),
                        policy_targets=json.loads(CONSTANTS.read_text())['policy_targets'],
                        p1_read_pad_conn_table='p1.x_Egress.p1_conn') if a.policy else None),
        'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'read_growth': read_out - read_native, 'control_growth': 24,
        'port_map': {'relay_port': 9, 'n_ack_return': 48, 't_in': 180, 'hb_return': 181, 'held_return': 182},
        'successor_of': {'build': 'm11_09', 'source_sha256': M11_09_SHA}}, indent=2) + '\n')
    (out / 'supported_profile.json').write_text(json.dumps(profile, indent=2) + '\n')
    print('wrote %s (image=%d, transforms=%s, sha=%s)' % (out / 'response_only.p4', a.image, applied, sha[:12]))


if __name__ == '__main__':
    main()
