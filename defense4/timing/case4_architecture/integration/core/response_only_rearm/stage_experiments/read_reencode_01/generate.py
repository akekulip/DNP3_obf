"""E edit: replace the READ filler with the two-range G10V2 re-encoding (reencode.py is the oracle).

The status octets keep their order; only object headers and CRCs change. So the parser splits the
native READ response at every boundary the two layouts need, and padding moves no data:

  native  dl | rh robj p03 p45 c0 | p612 p1321 c1 | p22 c2                  (18+18+3 octets)
  padded  dl | rh ra   p03 ca    | rbh p45 p612 cb | p1321 p22 c2           (18+18+12 octets)

rh = transport, app control, function, IIN (5); robj = `0a 02 00 00 16`; p03/p45/p612/p1321/p22 =
P0-3/P4-5/P6-12/P13-21/P22; ra/rbh = the constant headers `0a 02 01 00 00 03 00` / `0a 02 01 04 00 16 00`;
ca/cb = their blocks' CRCs; c2 is rewritten with the third block's CRC. robj, c0 and c1 become invalid.
Net +9 octets, so IMAGE_LEN, len_delta, ip.len, accounting and the reverse partition are unchanged.
Input CRC validation (in_rb0/in_rb1/in_rt) keeps checking the native blocks.

The padded-case TCP checksum list names exactly the emitted headers in emit order: absent headers add
whatever shares their containers (see the PIN note in the source), so robj, c0 and c1 are not listed.

Input: retx_passthrough_01's composite (rearm_56r). Only E changes; N and T are asserted identical.
  python3 generate.py OUT_DIR [--late] [--strict]
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'retx_passthrough_01/evidence/full_01/response_only.p4'
SOURCE_SHA256 = 'ec0dd7af81b7f8667f6a00277230ececcd1f351ebc3c1d5bbf87cd1a92ead199'
spec = importlib.util.spec_from_file_location('reencode_combined', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)

HDR_A, HDR_B = '56w0x0a020100000300', '56w0x0a020104001600'
NATIVE_FIELDS = ('hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, '
                 'hdr.robj.g_qual,\n                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
                 '                hdr.p612.d, hdr.p1321.d, hdr.c1.crc,\n'
                 '                hdr.p22.d, hdr.c2.crc, 8w0,\n')
PADDED_FIELDS = ('hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.ra.v, hdr.p03.d, hdr.ca.crc,\n'
                 '                hdr.rbh.v, hdr.p45.d, hdr.p612.d, hdr.cb.crc,\n'
                 '                hdr.p1321.d, hdr.p22.d, hdr.c2.crc,\n')
OLD_NATIVE = ('hdr.rb0.tpctrl, hdr.rb0.appctrl, hdr.rb0.func, hdr.rb0.iin, hdr.rb0.g_group, hdr.rb0.g_var, hdr.rb0.g_qual,\n'
              '                hdr.rb0.g_start, hdr.rb0.g_stop, hdr.rb0.data_mid, hdr.rb0.crc0,\n'
              '                hdr.rb1.data, hdr.rb1.crc1,\n'
              '                hdr.rtn.data_last, hdr.rtn.crc2, 8w0,\n')
OLD_PADDED = OLD_NATIVE + '                hdr.rtp.data_last, hdr.rtp.filler, hdr.rtp.crc2,\n'

OLD_PINS = ''.join('@pa_no_overlay("egress", "hdr.%s")\n' % f for f in (
    'rb0.tpctrl', 'rb0.appctrl', 'rb0.func', 'rb0.iin', 'rb0.g_group', 'rb0.g_var', 'rb0.g_qual', 'rb0.g_start',
    'rb0.g_stop', 'rb0.data_mid', 'rb0.crc0', 'rb1.data', 'rb1.crc1', 'rtn.data_last', 'rtn.crc2',
    'rtp.data_last', 'rtp.filler', 'rtp.crc2'))
NEW_PINS = ''.join('@pa_no_overlay("egress", "hdr.%s")\n' % f for f in (
    'rh.tpctrl', 'rh.appctrl', 'rh.func', 'rh.iin', 'robj.g_group', 'robj.g_var', 'robj.g_qual', 'robj.g_start',
    'robj.g_stop', 'p03.d', 'p45.d', 'c0.crc', 'p612.d', 'p1321.d', 'c1.crc', 'p22.d', 'c2.crc',
    'ra.v', 'ca.crc', 'rbh.v', 'cb.crc'))

EDITS = (
    # header types
    ('header r_read_b0_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<8> g_start;bit<8> g_stop;bit<48> data_mid;bit<16> crc0;}\n'
     'header r_read_b1_h{bit<128> data;bit<16> crc1;}\n'
     'header r_read_tail_n_h{bit<8> data_last;bit<16> crc2;}\n'
     'header r_read_tail_p_h{bit<8> data_last;bit<72> filler;bit<16> crc2;}\n',
     '/* READ response split at every boundary of the native and re-encoded layouts (read_reencode_01). */\n'
     'header r_read_h_h{bit<8> tpctrl;bit<8> appctrl;bit<8> func;bit<16> iin;}\n'
     'header r_read_obj_h{bit<8> g_group;bit<8> g_var;bit<8> g_qual;bit<8> g_start;bit<8> g_stop;}\n'
     'header r_read_crc_h{bit<16> crc;}\n'
     'header r_read_d8_h{bit<8> d;}\n'
     'header r_read_d16_h{bit<16> d;}\n'
     'header r_read_d32_h{bit<32> d;}\n'
     'header r_read_d56_h{bit<56> d;}\n'
     'header r_read_d72_h{bit<72> d;}\n'
     'header r_read_hdr_h{bit<56> v;}\n'),
    # header struct: one declaration order that serves both layouts
    ('r_dl_h dl; r_read_b0_h rb0; r_read_b1_h rb1; r_read_tail_n_h rtn;\n'
     '                   r_read_tail_p_h rtp; r_ctl_b0_h cb0;',
     'r_dl_h dl; r_read_h_h rh; r_read_obj_h robj; r_read_hdr_h ra; r_read_d32_h p03; r_read_crc_h ca;\n'
     '                   r_read_hdr_h rbh; r_read_d16_h p45; r_read_crc_h c0; r_read_d56_h p612; r_read_crc_h cb;\n'
     '                   r_read_d72_h p1321; r_read_crc_h c1; r_read_d8_h p22; r_read_crc_h c2; r_ctl_b0_h cb0;'),
    ('    bit<16> rtcrc; bit<16> ctcrc1;', '    bit<16> rtcrc; bit<16> rtcrc_a; bit<16> rtcrc_b; bit<16> ctcrc1;'),
    (OLD_PINS, NEW_PINS),
    # parser
    ('state read_b0 { pkt.extract(hdr.rb0); pkt.extract(hdr.rb1); pkt.extract(hdr.rtn); transition accept; }',
     'state read_b0 { pkt.extract(hdr.rh); pkt.extract(hdr.robj); pkt.extract(hdr.p03); pkt.extract(hdr.p45); '
     'pkt.extract(hdr.c0);\n        pkt.extract(hdr.p612); pkt.extract(hdr.p1321); pkt.extract(hdr.c1); '
     'pkt.extract(hdr.p22); pkt.extract(hdr.c2); transition accept; }'),
    # profile
    ('hdr.rb0.tpctrl:ternary;hdr.rb0.appctrl:ternary;hdr.rb0.func:exact;hdr.rb0.g_group:exact;hdr.rb0.g_var:exact;'
     'hdr.rb0.g_qual:exact;hdr.rb0.g_start:exact;hdr.rb0.g_stop:exact;}',
     'hdr.rh.tpctrl:ternary;hdr.rh.appctrl:ternary;hdr.rh.func:exact;hdr.robj.g_group:exact;hdr.robj.g_var:exact;'
     'hdr.robj.g_qual:exact;hdr.robj.g_start:exact;hdr.robj.g_stop:exact;}'),
    # input CRCs over the native blocks
    ('m.in_rb0=hash_in_rb0.get({hdr.rb0.tpctrl,hdr.rb0.appctrl,hdr.rb0.func,hdr.rb0.iin,hdr.rb0.g_group,hdr.rb0.g_var,'
     'hdr.rb0.g_qual,hdr.rb0.g_start,hdr.rb0.g_stop,hdr.rb0.data_mid});',
     'm.in_rb0=hash_in_rb0.get({hdr.rh.tpctrl,hdr.rh.appctrl,hdr.rh.func,hdr.rh.iin,hdr.robj.g_group,hdr.robj.g_var,'
     'hdr.robj.g_qual,hdr.robj.g_start,hdr.robj.g_stop,hdr.p03.d,hdr.p45.d});'),
    ('m.in_rb1=hash_in_rb1.get({hdr.rb1.data});', 'm.in_rb1=hash_in_rb1.get({hdr.p612.d,hdr.p1321.d});'),
    ('m.in_rt=hash_in_rt.get({hdr.rtn.data_last});', 'm.in_rt=hash_in_rt.get({hdr.p22.d});'),
    # output CRCs of the three re-encoded blocks, hashed early from native fields and constants
    ('    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.rtn.data_last,8w0x29,64w0x0106290206290306});}\n'
     '    table crc_read_tail_t{actions={crc_read_tail;}size=1;const default_action=crc_read_tail();}\n',
     '    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1321.d,hdr.p22.d});}\n'
     '    table crc_read_tail_t{actions={crc_read_tail;}size=1;const default_action=crc_read_tail();}\n'
     '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_read_a;\n'
     '    action crc_read_a(){m.rtcrc_a=hash_read_a.get({hdr.rh.tpctrl,hdr.rh.appctrl,hdr.rh.func,hdr.rh.iin,%s,hdr.p03.d});}\n'
     '    table crc_read_a_t{actions={crc_read_a;}size=1;const default_action=crc_read_a();}\n'
     '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_read_b;\n'
     '    action crc_read_b(){m.rtcrc_b=hash_read_b.get({%s,hdr.p45.d,hdr.p612.d});}\n'
     '    table crc_read_b_t{actions={crc_read_b;}size=1;const default_action=crc_read_b();}\n' % (HDR_A, HDR_B)),
    ('in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); }',
     'in_rb1_t.apply(); in_rt_t.apply(); crc_read_tail_t.apply(); crc_read_a_t.apply(); crc_read_b_t.apply(); }'),
    ('if (hdr.rb0.isValid()) { read_profile.apply();', 'if (hdr.rh.isValid()) { read_profile.apply();'),
    # native CRC verdicts
    ('if (hdr.rb0.crc0 != (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { m.rbad0 = 1; }',
     'if (hdr.c0.crc != (m.in_rb0[7:0] ++ m.in_rb0[15:8])) { m.rbad0 = 1; }'),
    ('if (hdr.rb1.crc1 != (m.in_rb1[7:0] ++ m.in_rb1[15:8])) { m.rbad1 = 1; }',
     'if (hdr.c1.crc != (m.in_rb1[7:0] ++ m.in_rb1[15:8])) { m.rbad1 = 1; }'),
    ('if (hdr.rtn.crc2 != (m.in_rt[7:0] ++ m.in_rt[15:8])) { m.rbadt = 1; }',
     'if (hdr.c2.crc != (m.in_rt[7:0] ++ m.in_rt[15:8])) { m.rbadt = 1; }'),
    # pad action: validate the constant headers and new CRCs, drop the native object header and CRCs
    ('action read_eligible(){hdr.rtp.setValid();hdr.rtp.data_last=hdr.rtn.data_last;hdr.rtp.filler=72w0x290106290206290306;'
     'hdr.rtp.crc2=m.rtcrc[7:0]++m.rtcrc[15:8];hdr.rtn.data_last=0;hdr.rtn.crc2=0;hdr.rtn.setInvalid();',
     'action read_eligible(){hdr.ra.setValid();hdr.ra.v=%s;hdr.ca.setValid();hdr.ca.crc=m.rtcrc_a[7:0]++m.rtcrc_a[15:8];'
     'hdr.rbh.setValid();hdr.rbh.v=%s;hdr.cb.setValid();hdr.cb.crc=m.rtcrc_b[7:0]++m.rtcrc_b[15:8];'
     'hdr.c2.crc=m.rtcrc[7:0]++m.rtcrc[15:8];hdr.robj.setInvalid();hdr.c0.setInvalid();hdr.c1.setInvalid();'
     % (HDR_A, HDR_B)),
    # deparser
    ('        if (hdr.rtp.isValid()) {\n', '        if (hdr.ra.isValid()) {\n'),
    ('pkt.emit(hdr.rb0); pkt.emit(hdr.rb1); pkt.emit(hdr.rtn); pkt.emit(hdr.rtp);',
     'pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.ra); pkt.emit(hdr.p03); pkt.emit(hdr.ca);\n'
     '        pkt.emit(hdr.rbh); pkt.emit(hdr.p45); pkt.emit(hdr.c0); pkt.emit(hdr.p612); pkt.emit(hdr.cb);\n'
     '        pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);'),
)


def frozen():
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'rearm_56r input changed'
    return raw.decode()


def once(text, old, new):
    assert text.count(old) == 1, ('anchor not found exactly once', old[:90], text.count(old))
    return text.replace(old, new, 1)


# full_01 applies the two new block-CRC hashes in E's stage-0 block, next to the input CRCs. That compile
# moved pipe-0 ingress (N, byte-identical) from 11 to 12 stages. LATE applies them after derive_t instead,
# still before the pad action that reads them.
LATE = ('crc_read_tail_t.apply(); crc_read_a_t.apply(); crc_read_b_t.apply(); }',
        'crc_read_tail_t.apply(); }',
        '        derive_t.apply();\n',
        '        derive_t.apply();\n        if (hdr.rh.isValid()) { crc_read_a_t.apply(); crc_read_b_t.apply(); }\n')


# STRICT: the strict-response policy (READ re-encoded to 58, SELECT/OPERATE responses native). The control profile
# never matches, so a control response is never committed or padded; the mapper accounts it at its native length
# (acct_grow) and only translates its sequence. This does NOT meet the equal-size target.
STRICT = ('8w0x81,8w0x0c,8w0x01,8w0x28,16w0x0100,8w0x00):ctl_shape();}}',
          '8w0x81,8w0x0c,8w0x01,8w0x28,16w0x0100,8w0x00):NoAction();}}')


def transform(e, late=False, strict=False):
    # The padded checksum list must be replaced before the native one (it contains it).
    e = once(e, OLD_PADDED, PADDED_FIELDS)
    assert e.count(OLD_NATIVE) == 2, 'expected the native READ fields in tcp_plain and tcp_ctl'
    e = e.replace(OLD_NATIVE, NATIVE_FIELDS)
    for old, new in EDITS:
        e = once(e, old, new)
    if late:
        e = once(e, LATE[0], LATE[1])
        e = once(e, LATE[2], LATE[3])
    if strict:
        e = once(e, *STRICT)
    for gone in ('hdr.rb0', 'hdr.rb1', 'hdr.rtn', 'hdr.rtp'):
        assert gone not in e, gone
    return e


def full_source(late=False, strict=False):
    base = frozen()
    old_e = combined.segment(base, 'E')
    source = base.replace(old_e, transform(old_e, late, strict), 1)
    assert combined.segment(source, 'N') == combined.segment(base, 'N')
    assert combined.segment(source, 'T') == combined.segment(base, 'T')
    return source


def write(directory, late=False, strict=False):
    directory = Path(directory)
    text = full_source(late, strict)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='read_reencode_01', late_block_crc=late, strict_controls_native=strict, source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    rearm_56r_source={'path': str(SOURCE), 'sha256': SOURCE_SHA256},
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    segment_sha256={name: hashlib.sha256(combined.segment(text, name).encode()).hexdigest()
                                    for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1], late='--late' in sys.argv[2:], strict='--strict' in sys.argv[2:])
