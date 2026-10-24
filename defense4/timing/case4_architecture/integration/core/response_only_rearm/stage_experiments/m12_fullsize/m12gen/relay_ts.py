"""Observed SEL-751 TCP timestamp profile and removal of stored CROB constants.

The native capture uses TCP40/44 on SYN/SYNACK and TCP32 on every data/ACK.
Both CROBs remain fully validated by the fixed request/response profile before
the tuple/link/application/generation and native-boundary authority is consulted.
"""
import re

from .common import combined, neg, once
from .relay_sbo import replace_table


def transform(src):
    src = constants_are_profiles(src)
    src = normalizer_ts(src)
    src = defer_shallow_checksum(src)
    src = handshake_checksum_deposits(src)
    src = handshake_mss_first(src)
    src = early_shallow_checksum(src)
    src = stream_read_timestamp_prefix(src)
    src = stream_handshake_options(src)
    src = mapper_ts(src)
    src = early_egress_lengths(src)
    return padder_crc_placement(padder_ts(src))


def padder_crc_placement(src):
    # c46 split input CRC's low8 bits into W27 with conn_ok/p1_res, creating
    # a false p1_conn->CRC dependency. The delayed profile then encountered
    # stage3's16-table capacity and pushed prefixes/checksum selectors to4/5.
    # c30 kept this CRC alone; restore that constraint without packet changes.
    return once(src, 'control x_Egress(inout x_headers_t hdr,',
                '@pa_solitary("egress","m.in_rb0")\ncontrol x_Egress(inout x_headers_t hdr,')


def defer_shallow_checksum(src):
    """Avoid constant and checksum-engine writes to the same parser container.

    The inherited shallow READ response supplies the same constant in its
    existing admission action, before network/guard consumes it. Full checks
    on requests, controls and handshakes still use the parser checksum result.
    c42 confirmed that this removes the SDK's clear-on-write warning while
    leaving a separate handshake deposit-lowering failure to diagnose.
    """
    src = once(src, 'state finish_shallow{m.tcp_sum=16w0xffeb;', 'state finish_shallow{')
    return once(src, 'action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;}',
                'action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;m.tcp_sum=16w0xffeb;}')


def handshake_checksum_deposits(src):
    """Keep SYN checksum deposits out of zero-extract option-check suffixes.

    c42 parser.log ends inside RemoveNegativeDeposits' shift of ts_syn_echo,
    after repairing a negative terminal deposit through earlier option
    lookbacks. Avoid that repair by computing after the last option
    extraction/subtraction instead (20/24 bytes into those states). Every
    exact option/MSS check still precedes parsed/shape acceptance. E, ACKs,
    controls and the inherited shallow READ policy are unchanged.
    """
    for last in ('oa', 'ob'):
        src = once(src, 'tc.subtract(hdr.%s);m.packet_kind=' % last,
                   'tc.subtract(hdr.%s);m.tcp_sum=tc.get();m.packet_kind=' % last)
    src = once(src, '(8w2,8w4,16w1460):finish;default:accept;',
               '(8w2,8w4,16w1460):finish_handshake;default:accept;')
    return once(src, ' state finish{',
        ' state finish_handshake{m.parsed=(bit<1>)(8w1);m.shape_valid=(bit<1>)(8w1);transition accept;}\n state finish{')


def handshake_mss_first(src):
    """Release MSS match-register lifetimes before checking timestamp words.

    c43 passed negative-deposit lowering but exhausted the parser's match
    registers keeping MSS until after three32bit option checks. The same
    conjunction is now checked MSS-first, with per-role continuations.
    """
    for role, kind in (('syn', 1), ('synack', 2)):
        src = once(src, 'm.packet_kind=8w%d;transition ts_%s_profile;' % (kind, role),
                   'm.packet_kind=8w%d;transition ts_%s_mss;' % (kind, role))
    src = once(src, '32w0x01030307:mss_check;', '32w0x01030307:finish_handshake;')
    src = once(src, '32w0x0101080a:mss_check;', '32w0x0101080a:finish_handshake;')
    states = ''.join(' state ts_%s_mss{transition select(hdr.mss.kind,hdr.mss.len,hdr.mss.value){'
                     '(8w2,8w4,16w1460):ts_%s_profile;default:accept;}}\n' % (role, role)
                     for role in ('syn', 'synack'))
    return once(src, ' state mss_check{', states + ' state mss_check{')


def early_shallow_checksum(src):
    """Set only READ-response kind11's inherited constant in existing crc_t.

    c42's later assignment introduced a read_shallow_admit->network match
    dependency. crc_t already selects kind11 at stage1; its otherwise identical
    header/first-block CRC action can publish the same constant a stage earlier.
    No parser write, new table/key/field or full-checksum path is introduced.
    """
    match = re.search(r'action crc_head_first\(\)\{([^\n]+)\}', src)
    assert match
    clone = 'action crc_head_first_shallow(){' + match[1] + 'm.tcp_sum=16w0xffeb;}'
    src = once(src, match[0], match[0] + '\n' + clone)
    src = once(src, 'actions={crc_head;crc_head_first;NoAction;}',
               'actions={crc_head;crc_head_first;crc_head_first_shallow;NoAction;}')
    src = once(src, '8w11:crc_head_first();', '8w11:crc_head_first_shallow();')
    return once(src, 'action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;m.tcp_sum=16w0xffeb;}',
                'action read_shallow_admit(){m.crc1=m.bcrc;m.tcrc=m.bcrc;}')


def stream_read_timestamp_prefix(src):
    """Bound N's two READ timestamp checks to16bit parser matches.

    c44 held IP.len16 through the READ IP/DNP3 length correlation, leaving
    insufficient match registers for the32bit timestamp prefix. Consume and
    check its two16bit words separately, then extract the opaque8byte body.
    All pieces have even length and are subtracted in their extraction state.
    Struct emission keeps their12 bytes contiguous; other TS paths keep tso.
    Parsed-header PHV/POV cost still requires fresh target measurement.
    """
    old = combined.segment(src, 'N')
    n = once(old, 'header n_opt4_h{bit<32> v;}',
             'header n_opt4_h{bit<32> v;}\nheader n_ts_word_h{bit<16> v;}\n'
             'header n_ts_body_h{bit<32> value;bit<32> echo;}')
    n = once(n, 'n_opt4_h ob;n_dl_h dl;',
             'n_opt4_h ob;n_ts_word_h rts0;n_ts_word_h rts1;n_ts_body_h rts;n_dl_h dl;')
    for root, destination in (('rx_tcp_ts', 'rx_dl'), ('rx_response_tcp_ts', 'rx_response_dl')):
        before = (' state ' + root + '{pkt.extract(hdr.tso);tc.subtract(hdr.tso);'
                  'transition select(hdr.tso.a){32w0x0101080a:' + destination + ';default:accept;}}')
        after = (' state ' + root + '{pkt.extract(hdr.rts0);tc.subtract(hdr.rts0);'
                 'transition select(hdr.rts0.v){16w0x0101:' + root + '_kind;default:accept;}}\n'
                 ' state ' + root + '_kind{pkt.extract(hdr.rts1);tc.subtract(hdr.rts1);'
                 'transition select(hdr.rts1.v){16w0x080a:' + root + '_body;default:accept;}}\n'
                 ' state ' + root + '_body{pkt.extract(hdr.rts);tc.subtract(hdr.rts);transition ' + destination + ';}')
        n = once(n, before, after)
    return once(src, old, n)


def stream_handshake_options(src):
    """Keep handshake residual end positions inside their final consumed words.

    c46's backend shortened ts_syn's shift to12 to retain later option
    lookbacks, while its checksum residual ended at19. Stream each option
    word and check fixed words immediately. The final SYN WS word and SYNACK
    value/echo state consume4/8 bytes, deposit after their last subtraction,
    and reach only metadata/acceptance states afterwards.
    """
    old = combined.segment(src, 'N')
    n = once(old, 'n_opt12_h tso;n_opt4_h oa;',
             'n_opt12_h tso;n_opt4_h hs0;n_opt4_h hs1;n_opt4_h hs2;n_opt4_h oa;')
    def state(name, body):
        nonlocal n
        matches = list(re.finditer(r' state ' + name + r'\{[^\n]*\}', n))
        assert len(matches) == 1, name
        n = once(n, matches[0][0], ' state ' + name + '{' + body + '}')
    for role, kind in (('syn', 1), ('synack', 2)):
        state('ts_' + role, 'pkt.extract(hdr.mss);tc.subtract(hdr.mss);m.packet_kind=8w%d;transition ts_%s_mss;' % (kind, role))
    def word(name, header, literal, destination, deposit=False):
        state(name, 'pkt.extract(hdr.%s);tc.subtract(hdr.%s);' % (header, header) +
              ('m.tcp_sum=tc.get();' if deposit else '') +
              'transition select(hdr.%s.v){%s:%s;default:accept;}' % (header, literal, destination))
    word('ts_syn_profile', 'hs0', '32w0x0402080a', 'ts_syn_value')
    word('ts_syn_echo', 'hs2', '32w0', 'ts_syn_ws')
    word('ts_syn_ws', 'oa', '32w0x01030307', 'finish_handshake', deposit=True)
    word('ts_synack_profile', 'hs0', '32w0x01030300', 'ts_synack_sack')
    word('ts_synack_sack', 'hs1', '32w0x01010402', 'ts_synack_ts')
    word('ts_synack_ts', 'hs2', '32w0x0101080a', 'ts_synack_values')
    n = once(n, ' state finish_handshake{',
        ' state ts_syn_value{pkt.extract(hdr.hs1);tc.subtract(hdr.hs1);transition ts_syn_echo;}\n'
        ' state ts_synack_values{pkt.extract(hdr.oa);tc.subtract(hdr.oa);pkt.extract(hdr.ob);tc.subtract(hdr.ob);'
        'm.tcp_sum=tc.get();transition finish_handshake;}\n state finish_handshake{')
    return once(src, old, n)


def early_egress_lengths(src):
    """Consume E's77/89 IP length predicates before its32bit TS prefix match.

    c45's remaining parser allocator failure reached E's ts12 state. IP.len
    was still live for both dl_len>=77 and dl's small control-frame guard.
    Three preselected bands retain both checks and every DL destination:
    short packets still parse/check all12 option bytes, and77..88 differs
    from>=89 only for the original guarded control DL value0x26.
    No header, metadata, MAU or checksum/deparser expression changes.
    """
    old = combined.segment(src, 'E')
    e = once(old, '4w8: ts12;', '4w8: dl_len;')
    start = e.index('    state dl_len {'); end = e.index('\n', start)
    length = e[start:end]
    length = once(length, 'default: accept;', 'default: ts12_short;')
    assert ': dl;' in length
    length = length.replace(': dl;', ': ctl_len;')
    e = e[:start] + length + e[end:]

    pattern = r'    state dl \{\s*pkt.extract\(hdr.dl\);\s*transition select\(hdr.dl.len, hdr.ip.len\) \{(.*?)\n        \}\n    \}'
    match = re.search(pattern, e, re.S)
    assert match
    body = re.sub(r'//[^\n]*', '', match[1])
    entry_pattern = r'\(([^()]*)\)\s*:\s*(\w+);'
    guards, rows = [], []
    for key, destination in re.findall(entry_pattern, body):
        dl, ip = [part.strip() for part in key.split(',')]
        if ip == '_':
            rows.append((dl, destination))
        else:
            assert dl == '8w0x26' and destination == 'accept'
            guards.append(ip)
    default = re.search(r'default:\s*(\w+);', body)
    assert len(guards) == 4 and rows and default
    residue = re.sub(entry_pattern, '', body)
    residue = re.sub(r'default:\s*\w+;', '', residue)
    assert not residue.strip()
    def dl_state(name, mid=False):
        entries = ''.join('%s:%s;' % (dl, 'accept' if mid and dl == '8w0x26' else destination)
                          for dl, destination in rows)
        return ('    state ' + name + ' { pkt.extract(hdr.dl); transition select(hdr.dl.len) { ' +
                entries + 'default:' + default[1] + '; } }')
    classification = ('    state ctl_len { transition select(hdr.ip.len) { ' +
                      ''.join(guard + ':ts12_mid;' for guard in guards) + 'default:ts12; } }\n')
    e = once(e, match[0], classification + dl_state('dl') + '\n' + dl_state('dl_mid', mid=True))
    before = '    state ts12 { pkt.extract(hdr.tso); transition select(hdr.tso.a) { 32w0x0101080a: dl_len; default: tcp_odd; } }'
    states = '\n'.join('    state %s { pkt.extract(hdr.tso); transition select(hdr.tso.a) { 32w0x0101080a: %s; default: tcp_odd; } }' %
                       (name, destination) for name, destination in
                       (('ts12', 'dl'), ('ts12_mid', 'dl_mid'), ('ts12_short', 'accept')))
    e = once(e, before, states)
    return once(src, old, e)


def constants_are_profiles(src):
    old = combined.segment(src, 'N')
    n = old
    start = n.index('Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_object_real_on;')
    end = n.index('Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_off_native_start;', start)
    n = n[:start] + n[end:]
    n = once(n, 'Register<n_object_pair_t,bit<1>>(1,{0,0}) pair_real_off_native_start;',
             'Register<bit<32>,bit<1>>(1,0) pair_real_off_native_start;')
    n = n.replace('RegisterAction<n_object_pair_t,bit<1>,bit<32>>(pair_real_off_native_start)',
                  'RegisterAction<bit<32>,bit<1>,bit<32>>(pair_real_off_native_start)')
    n, signatures = re.subn(
        r'(RegisterAction<bit<32>,bit<1>,bit<32>>\(pair_real_off_native_start\) \w+=\{void apply\(inout )n_object_pair_t( v,)',
        r'\1bit<32>\2', n)
    assert signatures == 2
    n = once(n, 'v.first=m.compare_real_off;v.second=m.compare_native_start;r=32w0;',
             'v=m.compare_native_start;r=32w0;')
    n = once(n, 'v.first!=m.compare_real_off||v.second!=m.compare_native_start', 'v!=m.compare_native_start')
    n = once(n, 'real_object_t.apply();', '')
    n = re.sub(r'm.compare_real_(?:object|on|off)\s*=[^;]+;', '', n)
    for field in ('compare_real_object', 'diff_real_object', 'compare_real_on', 'compare_real_off'):
        n = once(n, 'bit<32> ' + field + ';', '')
    start = n.index('table object_match{')
    end = n.index('\n', start)
    table = n[start:end]
    table = once(table, 'm.diff_real_object:exact;', '')
    def remove_constant(match):
        values = match[1].split(',')
        assert len(values) == 7
        return '(' + ','.join(values[:3] + values[4:]) + '):matched();'
    table = re.sub(r'\(([^()]*)\):matched\(\);', remove_constant, table)
    n = n[:start] + table + n[end:]
    return once(src, old, n)


def normalizer_ts(src):
    old = combined.segment(src, 'N')
    n = old
    # The selectedprofile has exactly two READs. Their former range49 siblings
    # have no accepted protocolshape; removing these live parser paths also
    # removes their unrelated CRC hash/table dependencies before N's guard.
    n = once(n, '(4w5,4w0,16w0,8w16):read_dl;(4w5,4w0,16w0,8w24):read_dl;', '')
    n = once(n, '24w0x0c0117:rtail37;default:read_response_second;', '24w0x0c0117:rtail37;default:accept;')
    n = once(n,
        'if(m.packet_kind==8w9){if(hdr.rd_req.isValid()){read_request_profile.apply();rd_request_crc_t.apply();}else{if(hdr.rd_req_full.isValid()){read_request_full_profile.apply();}else{read_request_mx_profile.apply();}rd_request_two_crc_t.apply();}}else{read_response_profile.apply();if(hdr.second.isValid()){rd_second_crc_t.apply();rd_tail_crc_t.apply();}else{read_shallow_admit_t.apply();}}',
        'if(m.packet_kind==8w9){if(hdr.rd_req_full.isValid()){read_request_full_profile.apply();}else{read_request_mx_profile.apply();}rd_request_two_crc_t.apply();}else{read_response_profile.apply();read_shallow_admit_t.apply();}')
    # Existing timestamp handshake and pure ACK parsers preserve their opaque
    # options. Only the current captured packet lengths are admitted here.
    replacements = {
        '(4w4,4w5,8w6,16w40):ip_flags;': '',
        '(4w4,4w5,8w6,16w44):ip_flags;': '',
        '(4w4,4w5,8w6,16w85):native_ip_flags;': '(4w4,4w5,8w6,16w97):native_ip_flags;',
        '(4w4,4w5,8w6,16w77):response_ip_flags;': '',
        '(4w4,4w5,8w6,16w65):rx_ip_flags;': '(4w4,4w5,8w6,16w77):rx_ip_flags;',
        '(4w4,4w5,8w6,16w67):rx_ip_flags;': '(4w4,4w5,8w6,16w79):rx_ip_flags;',
        '(4w4,4w5,8w6,16w89):read_response_ip_flags;': '',
        '(4w4,4w5,8w6,16w131):rx_response_ip_flags;': '(4w4,4w5,8w6,16w143):rx_response_ip_flags;',
        '(4w4,4w5,8w6,16w174):rx_response_ip_flags;': '(4w4,4w5,8w6,16w186):rx_response_ip_flags;',
        '(4w4,4w5,8w6,16w72):ts_read_ip_flags;': '',
        '(8w0x14,16w67):read_request_full;': '(8w0x14,16w79):read_request_full;',
        '(8w0x12,16w65):read_request_mx;': '(8w0x12,16w77):read_request_mx;',
        '(8w0x4c,16w131):read_response_fb;': '(8w0x4c,16w143):read_response_fb;',
        '(8w0x73,16w174):read_response_fb;': '(8w0x73,16w186):read_response_fb;',
    }
    for before, after in replacements.items():
        n = once(n, before, after)
    for state, dest in (('native_tcp', 'native_dl'), ('rx_tcp', 'rx_dl'), ('rx_response_tcp', 'rx_response_dl')):
        start = n.index(' state ' + state + '{')
        end = n.index('\n', start)
        body = n[start:end]
        body = body.replace('4w5,', '4w8,')
        body = body.replace(':' + dest + ';', ':' + state + '_ts;')
        opt = ('\n state ' + state + '_ts{pkt.extract(hdr.tso);tc.subtract(hdr.tso);'
               'transition select(hdr.tso.a){32w0x0101080a:' + dest + ';default:accept;}}')
        n = n[:start] + body + opt + n[end:]
    assert n.count('16w57..16w65535') == 3
    n = n.replace('16w57..16w65535', '16w1460')
    for state, profile in (('ts_syn', 'ts_syn_profile'), ('ts_synack', 'ts_synack_profile')):
        start = n.index(' state ' + state + '{'); end = n.index('\n', start)
        body = once(n[start:end], 'transition mss_check;', 'transition ' + profile + ';')
        n = n[:start] + body + n[end:]
    n = once(n, ' state mss_check{',
        ' state ts_syn_profile{transition select(hdr.tso.a){32w0x0402080a:ts_syn_echo;default:accept;}}\n'
        ' state ts_syn_echo{transition select(hdr.tso.c){32w0:ts_syn_ws;default:accept;}}\n'
        ' state ts_syn_ws{transition select(hdr.oa.v){32w0x01030307:mss_check;default:accept;}}\n'
        ' state ts_synack_profile{transition select(hdr.tso.a){32w0x01030300:ts_synack_sack;default:accept;}}\n'
        ' state ts_synack_sack{transition select(hdr.tso.b){32w0x01010402:ts_synack_ts;default:accept;}}\n'
        ' state ts_synack_ts{transition select(hdr.tso.c){32w0x0101080a:mss_check;default:accept;}}\n'
        ' state mss_check{')
    # Normal data/ACK timestamp prefix is exactly NOP,NOP,kind8,len10.
    n = once(n, '(4w8,8w20):ts_close;', '(4w8,8w20):ts_close;(4w8,8w4):ts_close;')
    return once(src, old, n)


def mapper_ts(src):
    old = combined.segment(src, 'E')
    e = old
    e = once(e, 'struct r_headers_t {',
             'header r_ts12_h{bit<32> a;bit<32> b;bit<32> c;}\nheader r_opt4_h{bit<32> v;}\nstruct r_headers_t {')
    e = once(e, 'r_mss_h mss;', 'r_mss_h mss; r_ts12_h tso; r_opt4_h oa; r_opt4_h ob;')
    e = once(e, 'transition select(hdr.tcp.offset) { 4w5: dl_len; 4w6: mss; default: tcp_odd; }',
             'transition select(hdr.tcp.offset) { 4w8: ts12; 4w10: syn_ts; 4w11: synack_ts; default: tcp_odd; }')
    e = once(e, '    state tcp_odd {',
             '    state ts12 { pkt.extract(hdr.tso); transition select(hdr.tso.a) { 32w0x0101080a: dl_len; default: tcp_odd; } }\n'
             '    state syn_ts { pkt.extract(hdr.mss); pkt.extract(hdr.tso); pkt.extract(hdr.oa); m.has_mss=1w1; transition syn_profile; }\n'
             '    state syn_profile { transition select(hdr.mss.kind,hdr.mss.len,hdr.mss.mss) { (8w2,8w4,16w1460): syn_word; default: tcp_odd; } }\n'
             '    state syn_word { transition select(hdr.tso.a) { 32w0x0402080a: syn_echo; default: tcp_odd; } }\n'
             '    state syn_echo { transition select(hdr.tso.c) { 32w0: syn_ws; default: tcp_odd; } }\n'
             '    state syn_ws { transition select(hdr.oa.v) { 32w0x01030307: accept; default: tcp_odd; } }\n'
             '    state synack_ts { pkt.extract(hdr.mss); pkt.extract(hdr.tso); pkt.extract(hdr.oa); pkt.extract(hdr.ob); m.has_mss=1w1; transition synack_profile; }\n'
             '    state synack_profile { transition select(hdr.mss.kind,hdr.mss.len,hdr.mss.mss) { (8w2,8w4,16w1460): synack_word0; default: tcp_odd; } }\n'
             '    state synack_word0 { transition select(hdr.tso.a) { 32w0x01030300: synack_word1; default: tcp_odd; } }\n'
             '    state synack_word1 { transition select(hdr.tso.b) { 32w0x01010402: synack_word2; default: tcp_odd; } }\n'
             '    state synack_word2 { transition select(hdr.tso.c) { 32w0x0101080a: accept; default: tcp_odd; } }\n'
             '    state tcp_odd {')
    # Add the current TCP header length to the existing native-size accounting.
    # Handshakes have no application payload despite their longer option lists.
    start = e.index('    table leff_t {')
    end = e.index('    /* SALU operand', start)
    leff = e[start:end]
    leff = once(leff, 'hdr.robj.g_qual : ternary; }', 'hdr.robj.g_qual : ternary; hdr.tcp.offset : exact; }')
    def adjust(match):
        fields, literal = match[1], match[2]
        value = int(literal, 16)
        return '(' + fields + ', 4w8) : leff_off(32w0x%08x);' % ((value - 12) & 0xffffffff)
    leff = re.sub(r'\(([^()]*)\)\s*: leff_off\(32w0x([0-9a-fA-F]+)\);', adjust, leff)
    leff = once(leff, 'size = 6;', 'size = 8;')
    leff = once(leff, 'const entries = {',
                'const entries = { (_,_,_,_,_,_,_,4w10):leff_off(%s);(_,_,_,_,_,_,_,4w11):leff_off(%s);' % (neg(60), neg(64)))
    e = e[:start] + leff + e[end:]
    # Captured masterWS7/relayWS0 negotiation fixes reverse window units.
    # Work in byte coordinates, then conservatively round the translated edge
    # down to128byte units. SYN windows are never scaled or rewritten.
    assert e.count('widen_win.get({hdr.tcp.window})') == 1
    assert e.count('widen_win_d.get({hdr.tcp.window})') == 1
    e = e.replace('widen_win.get({hdr.tcp.window})', 'widen_win.get({hdr.tcp.window,7w0})')
    e = e.replace('widen_win_d.get({hdr.tcp.window})', 'widen_win_d.get({hdr.tcp.window,7w0})')
    e = once(e, 'narrow_win.get({m.wnd[15:0]})', 'narrow_win.get({m.wnd[22:7]})')
    e = once(e, '32w0 &&& 32w0xFFFF0000, _) : window_exact();',
             '32w0 &&& 32w0xFF800000, _) : window_exact();')
    # Every option octet parsed after subtract_all_and_deposit must be restored
    # to the incremental checksum sum;12 bytes preserve all byte parities.
    e = e.replace('hdr.tcp.window, m.len_delta,',
                  'hdr.tcp.window, m.len_delta, hdr.tso.a, hdr.tso.b, hdr.tso.c,')
    e = once(e, 'pkt.emit(hdr.tcp); pkt.emit(hdr.mss); pkt.emit(hdr.dl);',
             'pkt.emit(hdr.tcp); pkt.emit(hdr.mss); pkt.emit(hdr.tso); pkt.emit(hdr.oa); pkt.emit(hdr.ob); pkt.emit(hdr.dl);')
    return once(src, old, e)


def padder_ts(src):
    start = src.index('/* ==== pipe-1 egress:')
    end = src.index('Pipeline(n_IgParser', start)
    old = src[start:end]
    x = old
    x = once(x, 'struct x_headers_t {',
             'header x_ts12_h{bit<32> a;bit<32> b;bit<32> c;}\nstruct x_headers_t {')
    x = once(x, 'x_tcp_h tcp;', 'x_tcp_h tcp; x_ts12_h tso;')
    x = once(x, '16w131: ip_frag; 16w174: ip_frag;', '16w143: ip_frag; 16w186: ip_frag;')
    x = once(x, 'transition select(hdr.tcp.offset) { 4w5: dl; default: accept; }',
             'transition select(hdr.tcp.offset) { 4w8: ts12; default: accept; }')
    x = once(x, '    state dl {',
             '    state ts12 { pkt.extract(hdr.tso); transition select(hdr.tso.a) { 32w0x0101080a: dl; default: accept; } }\n    state dl {')
    x = x.replace('(16w131,', '(16w143,').replace('(16w174,', '(16w186,')
    x = once(x, 'hdr.ip.len = 16w181;', 'hdr.ip.len = 16w193;')
    x = once(x, 'hdr.ip.len = 16w198;', 'hdr.ip.len = 16w210;')
    # BothREAD checksum arms begin with the pseudoheader length adjustment.
    x = x.replace('.update({m.len_delta,', '.update({m.len_delta, hdr.tso.a, hdr.tso.b, hdr.tso.c,')
    x = once(x, 'pkt.emit(hdr.ip); pkt.emit(hdr.tcp);', 'pkt.emit(hdr.ip); pkt.emit(hdr.tcp); pkt.emit(hdr.tso);')
    return once(src, old, x)
