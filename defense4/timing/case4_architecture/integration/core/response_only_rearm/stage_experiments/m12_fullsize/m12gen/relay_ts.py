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
    src = mapper_ts(src)
    return padder_ts(src)


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
