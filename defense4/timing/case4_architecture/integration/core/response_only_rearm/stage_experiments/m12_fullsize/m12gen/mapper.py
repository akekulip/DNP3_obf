"""Mapper boundaries (E, pipe-0 egress): per-shape image lengths in the accounting SALU and fwd_prep, the
reverse-ACK classifier (classify_rev) per committed image, and the C5 forward start-ACK mapping."""
from .common import neg, once, rev_entries


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


def transform_mapper_var(src, shape_image, per_image, c3_cimg=False):
    """Per-response VARIABLE image length (option A), PHV-cluster-safe, for the policy builds.

    shape_image maps 'read' / 'ctl' to their encoded image lengths; per_image maps every COMMITTED NATIVE length
    that can be outstanding to its committed wire image (each shaped response, plus the handshake's virtual image
    61). The image length reaches m11_09's single acct_try through m.ina, set by ina_img_t from the shape flags, so
    acct keeps its four RegisterActions (arm/try/grow/rev) and no 32-bit field joins the saturated mapper cluster.
    fwd_prep uses a constant image per shape. The reverse boundary is either per committed image (c3_cimg,
    _c3_committed_image) or m11_09's window-range ladder regenerated for the maximum image; both end with the C5
    forward start-ACK rows (_policy_c5). Historical variants (no per_image, pure-m.r windows, c3_exact) were removed
    from the generator after 0c475ebc2 and are recoverable there."""
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
    maximg = max(shape_image.values())
    if c3_cimg:
        return _policy_c5(_c3_committed_image(src, per_image), per_image)
    # read_complete_01 policy build: m11_09's own reverse classifier, regenerated for the max image -- key
    # (m.r ternary, window range), per distance d: window <= d-1 -> rev_withhold_zero (window 0), else
    # rev_withhold_open (N + window - d >= N, never negative); translate d <= 0; stale before the max image.
    # This restores the qualified window rule exactly (rearm inverse_distance cases) with no new field: the
    # m.y-carried sign (m12p_b07 first form) shifted the forward chain to 14 pipe-0 stages.
    src = once(src, 'size = 124; const default_action = rev_drop();',
               'size = %d; const default_action = rev_drop();' % (2 * maximg + 2))
    body_start = src.index('const entries = {', src.index('    table classify_rev {')) + len('const entries = {')
    body_end = src.index('        }\n    }', body_start)
    src = src[:body_start] + '\n' + rev_entries(maximg) + '\n        ' + src[body_end:]
    return _policy_c5(src, per_image)


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
