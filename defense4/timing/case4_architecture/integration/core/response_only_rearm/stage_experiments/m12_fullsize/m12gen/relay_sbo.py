"""Opt-in physical SEL-751 two-CROB whole49 path. No native TCP split reassembly.

Both guarded CROBs are validated, including the second point's command fields.
Only link and transport framing changes: the 32 application octets survive exactly.
"""
import re
import struct

from .common import combined, once, neg
from .mapper import rev_ternary_window


def crc(data):
    value = 0
    for octet in data:
        value ^= octet
        for _ in range(8):
            value = (value >> 1) ^ (0xa6bc if value & 1 else 0)
    return (~value) & 0xffff


def frame(header, user):
    header = header[:2] + bytes([5 + len(user)]) + header[3:8]
    out = header + struct.pack('<H', crc(header))
    for p in range(0, len(user), 16):
        block = user[p:p + 16]
        out += block + struct.pack('<H', crc(block))
    return out


def deframe(raw):
    if len(raw) < 10 or raw[:2] != b'\x05\x64' or crc(raw[:8]) != int.from_bytes(raw[8:10], 'little'):
        raise ValueError('invalid link header/CRC')
    count, p, user = raw[2] - 5, 10, b''
    while count:
        n = min(16, count)
        block = raw[p:p + n]
        if len(block) != n or crc(block) != int.from_bytes(raw[p + n:p + n + 2], 'little'):
            raise ValueError('invalid data CRC')
        user += block; p += n + 2; count -= n
    if p != len(raw):
        raise ValueError('extra link bytes')
    return raw[:8], user


def split_frames(raw):
    frames = []
    while raw:
        user = raw[2] - 5
        n = 10 + user + 2 * ((user + 15) // 16)
        frames.append(raw[:n]); raw = raw[n:]
    return frames


def control_objects(app, response=False):
    start = 4 if response else 2
    if len(app) != start + 28 or app[start:start + 4] != bytes.fromhex('0c011702'):
        raise ValueError('expected two G12V1 q17 CROBs')
    if (app[1] != 0x81 if response else app[1] not in (3, 4)):
        raise ValueError('wrong control function')
    out = []
    for p in (start + 4, start + 16):
        index, code, count, on, off, status = struct.unpack('<BBB I I B', app[p:p + 12])
        if (index, code, count, on, off) != ((1 if not out else 3), 1, 1, 200, 0):
            raise ValueError('outside guarded two-CROB profile')
        out.append(dict(index=index, code=code, count=count, on=on, off=off, status=status))
    return out


def encode(native):
    header, user = deframe(native)
    if len(native) != 49 or user[0] & 0xc0 != 0xc0:
        raise ValueError('expected whole single transport frame49')
    control_objects(user[1:], response=True)
    seq = user[0] & 63
    return (frame(header, bytes([0x40 | seq]) + user[1:16]) +
            frame(header, bytes([0x80 | ((seq + 1) & 63)]) + user[16:]))


def replace_action(src, name, body):
    pattern = r'action ' + re.escape(name) + r'\([^)]*\)\s*\{'
    matches = list(re.finditer(pattern, src))
    assert len(matches) == 1, (name, len(matches))
    match = matches[0]
    end, depth = match.end(), 1
    while depth:
        depth += (src[end] == '{') - (src[end] == '}'); end += 1
    return src[:match.start()] + 'action ' + name + '(){' + body + '}' + src[end:]


def replace_table(src, name, text):
    start = src.index('table ' + name + '{')
    p, depth = start + src[start:].index('{'), 1
    end = p + 1
    while depth:
        depth += (src[end] == '{') - (src[end] == '}'); end += 1
    return src[:start] + text + src[end:]


def transform(src):
    n = combined.segment(src, 'N')
    old_n = n
    # c29 reproduced: stage2 half-close used to invalidate queued same-epoch FINs.
    # Keep the current incarnation through all half-close phases, clear only a
    # qualified terminal0x10f close or reset0x200. The epoch compare in the SALU
    # still prevents an old-generation packet from clearing the new incarnation.
    n = replace_table(n, 'retry_epoch_t',
        'table retry_epoch_t{key={m.stage:exact;m.kind:exact;m.retry:exact;hdr.origin.normalized_epoch[15:0]:ternary;}'
        'actions={retry_epoch_check;retry_epoch_note;retry_epoch_clear;NoAction;}size=5;const default_action=NoAction();'
        'const entries={(2w0,8w0,2w1,_):retry_epoch_check();(2w2,8w1,2w0,_):retry_epoch_note();'
        '(2w2,8w4,2w0,16w0x200):retry_epoch_clear();(2w2,8w4,2w0,16w0x10f):retry_epoch_clear();'
        '(2w2,8w17,2w0,16w0x10f):retry_epoch_clear();}}')
    n = once(n, 'header n_tail_h{bit<32> off;bit<8> status;bit<16> crc;}',
             'header n_tail_h{bit<16> off;bit<8> status;bit<8> index2;bit<8> code2;bit<8> count2;bit<32> on2;bit<32> off2;bit<8> status2;bit<16> crc;}')
    n = once(n, 'header n_rtail_h{bit<16> on_lo;bit<32> off;bit<8> status;bit<16> crc;}',
             'header n_rtail_h{bit<32> off;bit<8> status;bit<8> index2;bit<8> code2;bit<8> count2;bit<32> on2;bit<32> off2;bit<16> crc;}\n'
             'header n_cstatus_h{bit<8> status;bit<16> crc;}')
    n = once(n, 'n_rtail_h rtail;', 'n_rtail_h rtail;n_cstatus_h cstatus;')
    n = once(n, '(4w4,4w5,8w6,16w75):native_ip_flags;', '(4w4,4w5,8w6,16w85):native_ip_flags;')
    # Native SBO49 and range READ49 share IP length89: validated link control chooses the parser.
    n = once(n, 'transition read_response_block;}',
             'transition select(hdr.dl.ctrl,hdr.dl.len){(8w0x44,8w0x26):response_or_read;default:accept;}}\n'
             ' state response_or_read{pkt.extract(hdr.first);tc.subtract(hdr.first);transition select(hdr.first.w1[23:0]){24w0x0c0117:rtail37;default:read_response_second;}}')
    n = once(n, 'state rtail37{pkt.extract(hdr.rtail);tc.subtract(hdr.rtail);m.response=',
             'state rtail37{pkt.extract(hdr.rtail);tc.subtract(hdr.rtail);pkt.extract(hdr.cstatus);tc.subtract(hdr.cstatus);m.response=')
    n = n.replace('32w35', '32w45').replace('32w37', '32w49')
    n = n.replace(neg(35), neg(45)).replace(neg(37), neg(49))
    req_fields = ('hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;'
                  'hdr.first.w0[31:24]:ternary;hdr.first.w0[23:16]:ternary;hdr.first.w0[15:8]:exact;'
                  'hdr.first.w0[7:0]:exact;hdr.first.w1:exact;hdr.first.w2:exact;hdr.first.w3:exact;'
                  'hdr.tail.off:exact;hdr.tail.status:exact;hdr.tail.index2:exact;hdr.tail.code2:exact;'
                  'hdr.tail.count2:exact;hdr.tail.on2:exact;hdr.tail.off2:exact;hdr.tail.status2:exact;')
    rows = ''.join('(16w0x0564,8w36,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w%d,'
                   '8w12,32w0x01170201,32w0x0101c800,32w0,16w0,8w0,8w3,8w1,8w1,32w0xc8000000,32w0,8w0):eligible();' % fc for fc in (3, 4))
    n = replace_table(n, 'profile', 'table profile{key={' + req_fields + '}actions={eligible;NoAction;}size=2;const default_action=NoAction();const entries={' + rows + '}}')
    rsp_fields = ('hdr.dl.magic:exact;hdr.dl.len:exact;hdr.dl.ctrl:exact;hdr.first.w0[31:24]:ternary;'
                  'hdr.first.w0[23:16]:ternary;hdr.first.w0[15:0]:ternary;hdr.first.w1:ternary;'
                  'hdr.first.w2:exact;hdr.first.w3:exact;hdr.rtail.off:exact;hdr.rtail.index2:exact;'
                  'hdr.rtail.code2:exact;hdr.rtail.count2:exact;hdr.rtail.on2:exact;hdr.rtail.off2:exact;')
    n = replace_table(n, 'response_profile', 'table response_profile{key={' + rsp_fields + '}'
                      'actions={eligible;NoAction;}size=1;const default_action=NoAction();const entries={'
                      '(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,16w0x8100&&&16w0xff00,'
                      '32w0x000c0117&&&32w0x00ffffff,32w0x02010101,32w0xc8000000,32w0,8w3,8w1,8w1,32w0xc8000000,32w0):eligible();}}')
    n = replace_action(n, 'input_tail', 'm.tcrc=hash_tail.get({hdr.tail.off,hdr.tail.status,hdr.tail.index2,hdr.tail.code2,hdr.tail.count2,hdr.tail.on2,hdr.tail.off2,hdr.tail.status2,hdr.tail.crc});')
    n = replace_action(n, 'response_crct', 'm.tcrc=hash_response_tail.get({hdr.rtail.off,hdr.rtail.status,hdr.rtail.index2,hdr.rtail.code2,hdr.rtail.count2,hdr.rtail.on2,hdr.rtail.off2,hdr.rtail.crc});m.crc1=hash_response_status.get({hdr.cstatus.status,hdr.cstatus.crc});')
    n = once(n, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_tail;',
             'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_status;\nHash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_tail;')
    # Both fixed guarded points participate in admission. Context stores a canonical pair identity;
    # tuple, application sequence, native boundaries and owner generation retain their existing checks.
    n = n.replace('hdr.first.w2[15:0]++hdr.first.w3[31:16]', '16w0x0103++16w0x0101')
    n = n.replace('hdr.first.w3[15:0]++hdr.rtail.on_lo', '32w200')
    n = n.replace('hdr.first.w2[31:16]++hdr.first.w2[15:8]++hdr.first.w2[7:0]', '32w0x01030101')
    n = n.replace('m.compare_real_on=(bit<32>)(hdr.first.w3);', 'm.compare_real_on=32w200;')
    n = n.replace('m.compare_real_off=(bit<32>)(hdr.tail.off);', 'm.compare_real_off=32w0;')
    n = n.replace('m.compare_real_off=(bit<32>)(hdr.rtail.off);', 'm.compare_real_off=32w0;')
    # A failed status is delivered faithfully but cannot establish successful SELECT association.
    n = once(n, 'action publish_response(){',
        'action publish_response_failure(){m.expected=hdr.expected_cell.expected_cell;m.desired=16w5++hdr.expected_cell.expected_cell[15:0];m.owner_op=1w1;}\n'
        'action publish_response(){')
    start = n.index('table owner_command{')
    end = n.index('action owner_read()', start)
    owner = n[start:end]
    owner = once(owner, 'm.return_abort:ternary;}',
                 'm.return_abort:ternary;hdr.rtail.status:ternary;hdr.cstatus.status:ternary;hdr.first.w1[31:24]:ternary;}')
    owner = owner.replace('publish_response;claim_operate;', 'publish_response;publish_response_failure;claim_operate;')
    owner = owner.replace('size=22;', 'size=23;')
    def status_rows(match):
        terms, action = match[1], match[2]
        if len(terms.split(',')) != 5:
            return match[0]
        if action == 'publish_response()':
            return '(' + terms + ',8w0,8w0,8w0):publish_response();(' + terms + ',_,_,_):publish_response_failure();'
        return '(' + terms + ',_,_,_):' + action + ';'
    owner = re.sub(r'\(([^()]*)\):([^;]+);', status_rows, owner)
    n = n[:start] + owner + n[end:]

    # CRC of final status octet must join every control response guard row.
    start = n.index('table guard{'); end = n.index('\n apply{', start)
    guard = n[start:end]
    rows = re.compile(r'\(([^()]*)\):([^;]+);')
    def response_crc(match):
        vals = match[1].split(',')
        if len(vals) == 14 and vals[1] == '8w6':
            vals[10] = '16w0x993a'
        return '(' + ','.join(vals) + '):' + match[2] + ';'
    n = n[:start] + rows.sub(response_crc, guard) + n[end:]
    # This profile admits exactly the two declared READ shapes. The obsolete G10
    # range49 request/response is rejected by protocol shape, never treated as SBO49.
    n = once(n, '(16w0x0564,8w13,8w0xc4,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w1,8w10,8w2,8w0,8w0,8w22):eligible();', '')
    n = once(n, '(16w0x0564,8w38,8w0x44,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w10,8w2,8w0,8w0,8w22):eligible();', '')
    src = once(src, 'const PortId_t t_RELAY_PORT    = 9w9;', 'const PortId_t t_RELAY_PORT    = 9w64;')
    src = once(src, old_n, n)
    return separate_checksum_conditions(transform_profile_crc(transform_status_lookup(transform_e(src))))


def transform_e(src):
    # Header names remain stable for the existing mapper and PHV placement annotations.
    # New nativecontrol fields occur in tcp_plain's checksum list even on ACKs
    # that parse no DNP3 header. Protect their containers from live metadata,
    # on the instantiated egress control rather than the unused r_IgParser.
    protected = ('hdr.ctn.index2', 'hdr.ctn.code2', 'hdr.ctn.count2', 'hdr.ctn.on2',
                 'hdr.cstatus.status', 'hdr.cstatus.crc')
    pragmas = ''.join('@pa_no_overlay("egress","%s")\n' % field for field in protected)
    src = once(src, 'control r_Egress(inout r_headers_t hdr,', pragmas + 'control r_Egress(inout r_headers_t hdr,')

    src = once(src, 'header r_ctl_b0_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<16> g_count;bit<16> index;bit<8> crob_code;bit<8> crob_count;bit<16> on_hi;bit<16> crc0;}',
               'header r_ctl_b0_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<8> g_count;bit<8> index;bit<8> crob_code;bit<8> crob_count;bit<32> on_hi;bit<16> crc0;}')
    src = once(src, 'header r_ctl_tail_n_h{bit<16> on_lo;bit<32> off;bit<8> status;bit<16> crc1;}',
               'header r_ctl_tail_n_h{bit<32> off;bit<8> status;bit<8> index2;bit<8> code2;bit<8> count2;bit<32> on2;bit<32> off2;bit<16> crc1;}\nheader r_ctl_status_h{bit<8> status;bit<16> crc;}')
    src = once(src, 'header r_ctl_seg2_h{bit<8> tpctrl;bit<16> on_lo;bit<32> off;bit<16> crc;}',
               'header r_ctl_seg2_h{bit<8> tpctrl;bit<32> off;bit<8> status;bit<8> index2;bit<8> code2;bit<8> count2;bit<32> on2;bit<24> off_hi;bit<16> crc;}')
    src = once(src, 'header r_ctl_seg3_h{bit<8> tpctrl;bit<8> status;bit<16> crc;}',
               'header r_ctl_seg3_h{bit<8> off_lo;bit<8> status;bit<16> crc;}')
    src = once(src, 'r_ctl_tail_n_h ctn;', 'r_ctl_tail_n_h ctn; r_ctl_status_h cstatus;')
    src = src.replace('@pa_no_overlay("egress", "hdr.ctn.on_lo")', '@pa_no_overlay("egress", "hdr.ctn.off2")')
    src = once(src, 'pkt.extract(hdr.cb0); pkt.extract(hdr.ctn); transition accept;', 'pkt.extract(hdr.cb0); pkt.extract(hdr.ctn); pkt.extract(hdr.cstatus); transition accept;')
    src = once(src, '(8w0x1c, _): ctl_b0;', '(8w0x26, _): ctl_b0;')
    src = replace_table(src, 'ctl_profile', 'table ctl_profile{key={hdr.dl.start:exact;hdr.dl.len:exact;hdr.cb0.tpctrl:ternary;hdr.cb0.appctrl:ternary;hdr.cb0.func:exact;hdr.cb0.g_group:exact;hdr.cb0.g_var:exact;hdr.cb0.g_qual:exact;hdr.cb0.g_count:exact;}'
                        'actions={ctl_shape;NoAction;}size=1;const default_action=NoAction();const entries={'
                        '(16w0x0564,8w38,8w0xc0&&&8w0xc0,8w0xc0&&&8w0xf0,8w0x81,8w12,8w1,8w0x17,8w2):ctl_shape();}}')
    src = replace_action(src, 'in_ct', 'm.in_ct=hash_in_ct.get({hdr.ctn.off,hdr.ctn.status,hdr.ctn.index2,hdr.ctn.code2,hdr.ctn.count2,hdr.ctn.on2,hdr.ctn.off2});m.in_rt=hash_in_status.get({hdr.cstatus.status});')
    src = once(src, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_ct;', '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_status;\n    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_ct;')
    src = once(src, 'if (hdr.ctn.crc1 != (m.in_ct[7:0] ++ m.in_ct[15:8])) { m.cbadt = 1; }',
               'if (hdr.ctn.crc1 != (m.in_ct[7:0] ++ m.in_ct[15:8]) || hdr.cstatus.crc != (m.in_rt[7:0] ++ m.in_rt[15:8])) { m.cbadt = 1; }')
    src = once(src, '(0, 1, _) : set_ina(61);', '(0, 1, _) : set_ina(60);')
    src = once(src, '8w0 &&& 8w0x07, 37, _, 1,', '8w0 &&& 8w0x07, 49, _, 1,')
    src = once(src, 'action fwd_prep_ctl() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + 32w0xffffffc3; m.t = m.q + 32w61; }',
               'action fwd_prep_ctl() { m.y = m.q + m.leff; m.z = m.p + m.leff; m.pm = m.p + 32w0xffffffc4; m.t = m.q + 32w60; }')
    src = once(src, '(_, _, 32w0xffffffdb, 0, 32w0, _, _, _, _, _, _, _, _, _, _, _): out_zero_img_61();',
               '(_, _, 32w0xffffffcf, 0, 32w0, _, _, _, _, _, _, _, _, _, _, _): out_zero_img_60();')
    src = once(src, '    action out_zero_img_61()', '    action out_zero_img_60() { m.qx = 32w0xffffffc4; m.result = r_OUT_ZERO; m.changed = 1; }\n    action out_zero_img_61()')
    src = once(src, 'out_zero_img_61;out_zero_img_141;', 'out_zero_img_60;out_zero_img_61;out_zero_img_141;')
    # Replace only SBO's committed boundary; the virtual handshake61 remains unchanged.
    start = src.index('    table classify_rev {'); end = src.index('    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;', start)
    body = src[start:end]
    body, count = re.subn(r'            \(32w0x[0-9a-f]+ &&& 32w0x[0-9a-f]+, 8w37\) : rev_withhold_open\(\);\n', '', body)
    newrows = ''.join('            (32w0x%08x &&& 32w0x%08x, 8w49) : rev_withhold_open();\n' % row for row in rev_ternary_window(60))
    body = body.replace('            (32w0 &&& 32w0x80000000, _) : rev_translate();', '            (32w0 &&& 32w0x80000000, _) : rev_translate();\n' + newrows)
    body = re.sub(r'size = (\d+);', lambda m: 'size = %d;' % (int(m[1]) - count + len(rev_ternary_window(60))), body, count=1)
    src = src[:start] + body + src[end:]
    src = once(src, '    action out_reset_front_37() { m.qx = m.q - 32w37; m.result = r_OUT_RESET_FRONT; m.changed = 1; }\n', '')
    src = src.replace('out_reset_front_37; ', '')
    src = once(src, '(32w37, _, _, _, _, _, _, _, _, _, _, _, _, _, _, 8w0x04 &&& 8w0x04): out_reset_front_37();', '')
    # second frame's transport sequence is the next one and FIN, wrapping at 63.
    src = re.sub(r'action ctl_sequences\(bit<8> second, bit<8> third\)\{[^}]*\}',
                 'action ctl_sequences(bit<8> second, bit<8> third){hdr.cs2.tpctrl=second|8w0x80;}', src)
    src = replace_action(src, 'crc_ctl_tail2', 'm.ctcrc2=hash_ctl_tail2.get({hdr.cs2.tpctrl,hdr.ctn.off,hdr.ctn.status,hdr.ctn.index2,hdr.ctn.code2,hdr.ctn.count2,hdr.ctn.on2,hdr.ctn.off2[31:8]});')
    src = replace_action(src, 'crc_ctl_tail3', 'm.ctcrc3=hash_ctl_tail3.get({hdr.ctn.off2[7:0],hdr.cstatus.status});')
    # CRC deltas change only length, independent of live link addresses/control.
    base = bytes.fromhex('0564264401000000')
    def delta(length):
        return int.from_bytes(struct.pack('<H', crc(base) ^ crc(base[:2] + bytes([length]) + base[3:])), 'big')
    src = replace_action(src, 'ctl_eligible',
        'hdr.cb0.tpctrl=hdr.cb0.tpctrl&8w0x7f;hdr.cb0.crc0=hdr.cb0.crc0^16w0x0c37;'
        'hdr.cd2.setValid();hdr.cd2.start=hdr.dl.start;hdr.cd2.len=8w23;hdr.cd2.ctrl=hdr.dl.ctrl;'
        'hdr.cd2.dst=hdr.dl.dst;hdr.cd2.src=hdr.dl.src;hdr.cd2.crc=hdr.dl.crc^16w0x%04x;'
        'hdr.cs2.setValid();hdr.cs2.off=hdr.ctn.off;hdr.cs2.status=hdr.ctn.status;'
        'hdr.cs2.index2=hdr.ctn.index2;hdr.cs2.code2=hdr.ctn.code2;hdr.cs2.count2=hdr.ctn.count2;'
        'hdr.cs2.on2=hdr.ctn.on2;hdr.cs2.off_hi=hdr.ctn.off2[31:8];hdr.cs2.crc=m.ctcrc2[7:0]++m.ctcrc2[15:8];'
        'hdr.cs3.setValid();hdr.cs3.off_lo=hdr.ctn.off2[7:0];hdr.cs3.status=hdr.cstatus.status;'
        'hdr.cs3.crc=m.ctcrc3[7:0]++m.ctcrc3[15:8];'
        'hdr.ctn.off=0;hdr.ctn.status=0;hdr.ctn.index2=0;hdr.ctn.code2=0;hdr.ctn.count2=0;hdr.ctn.on2=0;hdr.ctn.off2=0;hdr.ctn.crc1=0;'
        'hdr.cstatus.status=0;hdr.cstatus.crc=0;hdr.ctn.setInvalid();hdr.cstatus.setInvalid();'
        'hdr.dl.len=8w21;hdr.dl.crc=hdr.dl.crc^16w0x%04x;hdr.ip.len=hdr.ip.len+16w11;m.len_delta=16w11;' % (delta(23), delta(21)))
    # Recompute incremental TCP checksum with exactly the parsed native and emitted encoded fields.
    src = src.replace('hdr.ctn.on_lo, hdr.ctn.off, hdr.ctn.status, hdr.ctn.crc1, 8w0,',
                      'hdr.ctn.off, hdr.ctn.status, hdr.ctn.index2, hdr.ctn.code2, hdr.ctn.count2, hdr.ctn.on2, hdr.ctn.off2, hdr.ctn.crc1, hdr.cstatus.status, hdr.cstatus.crc, 8w0,')
    src = src.replace('hdr.cs2.tpctrl, hdr.cs2.on_lo, hdr.cs2.off, hdr.cs2.crc,',
                      'hdr.cs2.tpctrl, hdr.cs2.off, hdr.cs2.status, hdr.cs2.index2, hdr.cs2.code2, hdr.cs2.count2, hdr.cs2.on2, hdr.cs2.off_hi, hdr.cs2.crc,')
    src = src.replace('hdr.cs3.tpctrl, hdr.cs3.status, hdr.cs3.crc, 8w0,', 'hdr.cs3.off_lo, hdr.cs3.status, hdr.cs3.crc,')
    src = once(src, '                hdr.cd3.start, hdr.cd3.len, hdr.cd3.ctrl, hdr.cd3.dst, hdr.cd3.src, hdr.cd3.crc,\n', '')
    src = src.replace('pkt.emit(hdr.cb0); pkt.emit(hdr.ctn);', 'pkt.emit(hdr.cb0); pkt.emit(hdr.ctn); pkt.emit(hdr.cstatus);')
    # c32 allocator: 17 mutually constrained wide mapper values compete for16
    # egress wide containers. Subtract the arriving ACK in the parser, exactly
    # where seq/window/checksum are already subtracted, eliminating the 32-bit
    # inverted ACK carried solely to perform that subtraction in the deparser.
    src = once(src, 'tcp_old.subtract({hdr.tcp.seq, hdr.tcp.window, hdr.tcp.checksum});',
               'tcp_old.subtract({hdr.tcp.seq, hdr.tcp.ack, hdr.tcp.window, hdr.tcp.checksum});')
    src, count = re.subn(r'    bit<32> ack_inv;[^\n]*\n', '', src)
    assert count == 1
    src = once(src, '@pa_no_overlay("egress", "m.ack_inv")\n', '')
    assert src.count('m.ack_inv = ~hdr.tcp.ack;') == 3
    src = src.replace(' m.ack_inv = ~hdr.tcp.ack;', '')
    assert src.count('m.ack_inv, ') == 2
    src = src.replace('m.ack_inv, ', '')
    return src


def transform_status_lookup(src):
    """c34: exact tiny-block CRC lookups replace three custom hash operations.

    Every8bitstatus has one accepted native CRC; no other16bitCRC is accepted.
    The admitted guarded CROB has off2=0, so its final encoded block is[0,status].
    Dynamic16octet tail hashes and every native CRC check remain in place.
    """
    src = once(src, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_status;\n', '')
    src = replace_action(src, 'response_crct',
        'm.tcrc=hash_response_tail.get({hdr.rtail.off,hdr.rtail.status,hdr.rtail.index2,hdr.rtail.code2,hdr.rtail.count2,hdr.rtail.on2,hdr.rtail.off2,hdr.rtail.crc});')
    valid_rows = ''.join('(8w%d,16w0x%04x):response_status_good();' %
        (status, int.from_bytes(struct.pack('<H', crc(bytes([status]))), 'big')) for status in range(256))
    status_table = ('action response_status_good(){m.crc1=16w0x993a;}\n'
        'action response_status_bad(){m.crc1=16w0;}\n'
        'table response_status_crc_t{key={hdr.cstatus.status:exact;hdr.cstatus.crc:exact;}'
        'actions={response_status_good;response_status_bad;}size=256;const default_action=response_status_bad();'
        'const entries={' + valid_rows + '}}\n')
    src = once(src, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_tail;',
               status_table + 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_tail;')
    src = once(src, 'if((bit<8>)m.response==8w1){response_crct_t.apply();}else{input_tail_t.apply();}',
               'if((bit<8>)m.response==8w1){response_crct_t.apply();response_status_crc_t.apply();}else{input_tail_t.apply();}')
    src = once(src, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_status;\n', '')
    src = replace_action(src, 'in_ct',
        'm.in_ct=hash_in_ct.get({hdr.ctn.off,hdr.ctn.status,hdr.ctn.index2,hdr.ctn.code2,hdr.ctn.count2,hdr.ctn.on2,hdr.ctn.off2});')
    src = once(src, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail3;\n', '')
    src = replace_action(src, 'crc_ctl_tail3', '')
    src = once(src, 'action crc_ctl_tail3(){}', '')
    src = replace_table(src, 'crc_ctl_tail3_t', '')
    e_rows = ''.join('8w%d:status_crc(16w%d,16w%d);' %
        (status, crc(bytes([status])), crc(bytes([0, status]))) for status in range(256))
    e_table = ('action status_crc(bit<16> expected,bit<16> encoded){m.in_rt=expected;m.ctcrc3=encoded;}\n'
        'table status_crc_t{key={hdr.cstatus.status:exact;}actions={status_crc;NoAction;}size=256;'
        'const default_action=NoAction();const entries={' + e_rows + '}}\n')
    src = once(src, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_ct;',
               e_table + '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_ct;')
    # Outputlookup assumes off_lo=0. N already enforces full off2=0; retain
    # this condition in E's independent shape predicate as well.
    start = src.index('table ctl_profile{'); end = src.index('\n', start)
    profile = src[start:end]
    profile = once(profile, 'hdr.cb0.g_count:exact;}', 'hdr.cb0.g_count:exact;hdr.ctn.off2[7:0]:exact;}')
    profile = once(profile, '8w0x17,8w2):ctl_shape();', '8w0x17,8w2,8w0):ctl_shape();')
    src = src[:start] + profile + src[end:]
    src = once(src, 'if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); }',
        'if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); status_crc_t.apply(); ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); }')
    src = once(src, '                if ((bit<8>)m.mode == 1 && m.ctl_shape == 1) { ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); crc_ctl_tail3_t.apply(); }\n', '')
    return src


def transform_profile_crc(src):
    """c38: factor fixed-profile tail CRCs into exact, bounded lookups.

    N's existing profile is a required guard conjunct and checks every fixed
    tail byte. E repeats those checks independently before encoding. The only
    variable native tail byte is status1; encoded block2 also varies in its
    transport octet. CRC is affine: CRC(sequence,status) is its sequence/zero
    baseline XOR the status contribution. No CRC or profile check is removed.
    """
    req_tail = bytes(3) + bytes([3, 1, 1]) + bytes.fromhex('c800000000000000') + bytes(1)
    def response_tail(status):
        return bytes(4) + bytes([status, 3, 1, 1]) + bytes.fromhex('c800000000000000')
    def wire_crc(data):
        return int.from_bytes(struct.pack('<H', crc(data)), 'big')

    src = once(src, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_tail;\n', '')
    src = replace_action(src, 'input_tail', 'm.tcrc=16w0x993a;')
    src = once(src, 'action input_tail(){m.tcrc=16w0x993a;}',
               'action input_tail(){m.tcrc=16w0x993a;}\naction tail_crc_bad(){m.tcrc=16w0;}')
    src = replace_table(src, 'input_tail_t',
        'table input_tail_t{key={hdr.tail.crc:exact;}actions={input_tail;tail_crc_bad;}size=1;'
        'const default_action=tail_crc_bad();const entries={16w0x%04x:input_tail();}}' % wire_crc(req_tail))
    src = once(src, 'Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_response_tail;\n', '')
    src = replace_action(src, 'response_crct', 'm.tcrc=16w0x993a;')
    rows = ''.join('(8w%d,16w0x%04x):response_crct();' % (status, wire_crc(response_tail(status)))
                   for status in range(256))
    src = replace_table(src, 'response_crct_t',
        'table response_crct_t{key={hdr.rtail.status:exact;hdr.rtail.crc:exact;}'
        'actions={response_crct;tail_crc_bad;}size=256;const default_action=tail_crc_bad();'
        'const entries={' + rows + '}}')

    # The affine lookup is valid only for this fully checked command profile.
    start = src.index('table ctl_profile{'); end = src.index('\n', start)
    profile = src[start:end]
    profile = once(profile, 'hdr.ctn.off2[7:0]:exact;}',
        'hdr.cb0.index:exact;hdr.cb0.crob_code:exact;hdr.cb0.crob_count:exact;hdr.cb0.on_hi:exact;'
        'hdr.ctn.off:exact;hdr.ctn.index2:exact;hdr.ctn.code2:exact;hdr.ctn.count2:exact;'
        'hdr.ctn.on2:exact;hdr.ctn.off2:exact;}')
    profile = once(profile, '8w0x17,8w2,8w0):ctl_shape();',
        '8w0x17,8w2,8w1,8w1,8w1,32w0xc8000000,32w0,8w3,8w1,8w1,32w0xc8000000,32w0):ctl_shape();')
    src = src[:start] + profile + src[end:]

    src = once(src, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_ct;\n', '')
    src = replace_action(src, 'in_ct', '')
    src = once(src, 'action in_ct(){}',
        'action tail_status_crc(bit<16> native,bit<16> contribution){m.in_ct=native;m.ctcrc2=contribution;}')
    zero_block = bytes([0x80]) + response_tail(0)[:-1]
    status_rows = ''.join('8w%d:tail_status_crc(16w%d,16w%d);' %
        (status, crc(response_tail(status)), crc(bytes([0x80]) + response_tail(status)[:-1]) ^ crc(zero_block))
        for status in range(256))
    src = replace_table(src, 'in_ct_t',
        'table in_ct_t{key={hdr.ctn.status:exact;}actions={tail_status_crc;NoAction;}size=256;'
        'const default_action=NoAction();const entries={' + status_rows + '}}')
    src = replace_table(src, 'ctl_sequences_t', '')
    src = re.sub(r'action ctl_sequences\(bit<8> second, bit<8> third\)\{[^}]*\}', '', src)
    src = once(src, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail2;\n', '')
    src = replace_action(src, 'crc_ctl_tail2', '')
    src = once(src, 'action crc_ctl_tail2(){}',
        'action tail_sequence_crc(bit<8> transport,bit<16> baseline){hdr.cs2.tpctrl=transport;m.ctcrc2=m.ctcrc2^baseline;}')
    seq_rows = ''.join('8w%d:tail_sequence_crc(8w%d,16w%d);' %
        (0xc0 | seq, 0x80 | ((seq + 1) & 63), crc(bytes([0x80 | ((seq + 1) & 63)]) + response_tail(0)[:-1]))
        for seq in range(64))
    src = replace_table(src, 'crc_ctl_tail2_t',
        'table crc_ctl_tail2_t{key={hdr.cb0.tpctrl:exact;}actions={tail_sequence_crc;NoAction;}size=64;'
        'const default_action=NoAction();const entries={' + seq_rows + '}}')
    src = once(src, ' ctl_sequences_t.apply(); crc_ctl_tail2_t.apply();', ' crc_ctl_tail2_t.apply();')
    return src


def separate_checksum_conditions(src):
    # c38 H55 packed the synthesized IPv4/TCP checksum-selection bits together.
    # The allocator then serialized their independent writes: placement log
    # advanced TCP's condition from stage10 to11 solely for this PHV dependency.
    # c39 moved updated-IP into B21, but the newly materialized original-IP
    # selector remained in H55 with the TCP selectors. Separate both IP bits.
    # SDK9.13.2 pa_no_pack separates those fields without changing either
    # checksum predicate, field list, or the reverse window's arithmetic.
    fields = ('hdr.tcp.checksum.$deparse_original_csum',
              'hdr.tcp.checksum.$deparse_updated_csum_0',
              'hdr.tcp.checksum.$deparse_updated_csum_1')
    # TCP's three selection bits may still share a container with one another.
    annotation = ''.join('@pa_no_pack("egress","hdr.ip.checksum.%s","%s")\n' % (ip, field)
                         for ip in ('$deparse_original_csum', '$deparse_updated_csum_0') for field in fields)
    return once(src, 'control r_Egress(inout r_headers_t hdr,',
                annotation + 'control r_Egress(inout r_headers_t hdr,')
