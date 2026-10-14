"""Generate the E-only 61-octet candidate from strict dup_hold_01.

The input is the qualified strict composite. N and T are preserved byte for
byte; only E is edited. The generator records the exact role hashes and asserts
that replacing the new E with the original E reconstructs the input source.
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'dup_hold_01/evidence/full_02_strict/response_only.p4'
SOURCE_SHA256 = '2ad71761399e023b0d3b6b72f9fb71257da012499ffe30ac4758b395fc1bd97c'

spec = importlib.util.spec_from_file_location('seg61_02_combined', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)

READ_A = '40w0x0a02000005'
READ_B = '40w0x0a02000609'
READ_C = '56w0x0a02010a001600'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def frozen():
    raw = SOURCE.read_bytes()
    assert digest(raw) == SOURCE_SHA256, 'strict input changed'
    return raw.decode()


def once(text, old, new):
    count = text.count(old)
    assert count == 1, ('anchor not found exactly once', count, old[:120])
    return text.replace(old, new, 1)


def reverse_entries(limit=61):
    rows = ['            (32w0 &&& 32w0x80000000, _) : rev_translate();']
    for n in range(1, limit + 1):
        value = (1 << 32) - n
        rows.append('            (32w0x%08x, 16w0 .. 16w%d) : rev_withhold_zero();' % (value, n - 1))
        rows.append('            (32w0x%08x, 16w%d .. 16w65535) : rev_withhold_open();' % (value, n))
    return '\n'.join(rows)


READ_TCP_NATIVE = (
    'hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.robj.g_group, hdr.robj.g_var, hdr.robj.g_qual,\n'
    '                hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n'
    '                hdr.p612.d, hdr.p1321.d, hdr.c1.crc,\n'
    '                hdr.p22.d, hdr.c2.crc, 8w0,\n'
)

READ_TCP_61 = (
    'hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.ra.v, hdr.p03.d, hdr.p45.d, hdr.ca.crc,\n'
    '                hdr.rbh.v, hdr.p69.d, hdr.rc.v, hdr.cb.crc,\n'
    '                hdr.p1012.d, hdr.p1321.d, hdr.p22.d, hdr.c2.crc, 8w0,\n'
)

READ_TCP_58 = (
    'hdr.rh.tpctrl, hdr.rh.appctrl, hdr.rh.func, hdr.rh.iin, hdr.ra.v, hdr.p03.d, hdr.ca.crc,\n'
    '                hdr.rbh.v, hdr.p45.d, hdr.p612.d, hdr.cb.crc,\n'
    '                hdr.p1321.d, hdr.p22.d, hdr.c2.crc,\n'
)

CTL_TCP_NATIVE = (
    'hdr.cb0.tpctrl, hdr.cb0.appctrl, hdr.cb0.func, hdr.cb0.iin, hdr.cb0.g_group, hdr.cb0.g_var, hdr.cb0.g_qual,\n'
    '                hdr.cb0.g_count, hdr.cb0.index, hdr.cb0.crob_code, hdr.cb0.crob_count, hdr.cb0.on_hi, hdr.cb0.crc0,\n'
    '                hdr.ctn.on_lo, hdr.ctn.off, hdr.ctn.status, hdr.ctn.crc1, 8w0,\n'
)

CTL_TCP_61 = (
    'hdr.cb0.tpctrl, hdr.cb0.appctrl, hdr.cb0.func, hdr.cb0.iin, hdr.cb0.g_group, hdr.cb0.g_var, hdr.cb0.g_qual,\n'
    '                hdr.cb0.g_count, hdr.cb0.index, hdr.cb0.crob_code, hdr.cb0.crob_count, hdr.cb0.on_hi, hdr.cb0.crc0,\n'
    '                hdr.cd2.start, hdr.cd2.len, hdr.cd2.ctrl, hdr.cd2.dst, hdr.cd2.src, hdr.cd2.crc,\n'
    '                hdr.cs2.tpctrl, hdr.cs2.on_lo, hdr.cs2.off, hdr.cs2.crc,\n'
    '                hdr.cd3.start, hdr.cd3.len, hdr.cd3.ctrl, hdr.cd3.dst, hdr.cd3.src, hdr.cd3.crc,\n'
    '                hdr.cs3.tpctrl, hdr.cs3.status, hdr.cs3.crc, 8w0,\n'
)


def transform_e(e):
    e = once(e, 'const bit<32> r_IMAGE_LEN = 58;', 'const bit<32> r_IMAGE_LEN = 61;')
    e = once(e, 'header r_read_hdr_h{bit<56> v;}',
             'header r_read_hdr40_h{bit<40> v;}\nheader r_read_hdr_h{bit<56> v;}\nheader r_ctl_dl_h{bit<16> start;bit<8> len;bit<8> ctrl;bit<16> dst;bit<16> src;bit<16> crc;}\nheader r_ctl_seg2_h{bit<8> tpctrl;bit<16> on_lo;bit<32> off;bit<16> crc;}\nheader r_ctl_seg3_h{bit<8> tpctrl;bit<8> status;bit<16> crc;}')
    e = once(e, 'r_read_hdr_h ra;', 'r_read_hdr40_h ra;')
    e = once(e, 'r_read_d56_h p612;', 'r_read_d32_h p69; r_read_d24_h p1012;')
    e = once(e, 'r_read_hdr_h rbh;', 'r_read_hdr40_h rbh;')
    e = once(e, 'r_read_d72_h p1321; r_read_crc_h c1; r_read_d8_h p22; r_read_crc_h c2; r_ctl_b0_h cb0; r_ctl_tail_n_h ctn; r_ctl_tail_p1_h ctp1; r_ctl_tail_p2_h ctp2;',
             'r_read_hdr_h rc; r_read_d72_h p1321; r_read_crc_h c1; r_read_d8_h p22; r_read_crc_h c2; r_ctl_b0_h cb0; r_ctl_tail_n_h ctn; r_ctl_dl_h cd2; r_ctl_seg2_h cs2; r_ctl_dl_h cd3; r_ctl_seg3_h cs3;')
    e = once(e, 'header r_read_d16_h{bit<16> d;}', 'header r_read_d16_h{bit<16> d;}\nheader r_read_d24_h{bit<24> d;}')
    e = once(e, '    bit<16> rtcrc; bit<16> rtcrc_a; bit<16> rtcrc_b; bit<16> ctcrc1;',
             '    bit<16> rtcrc; bit<16> rtcrc_a; bit<16> rtcrc_b; bit<16> ctcrc1; bit<16> ctcrc2; bit<16> ctcrc3;')
    e = once(e, '@pa_no_overlay("egress", "hdr.p612.d")\n',
             '@pa_no_overlay("egress", "hdr.p69.d")\n@pa_no_overlay("egress", "hdr.p1012.d")\n@pa_no_overlay("egress", "hdr.rc.v")\n')
    e = once(e, '@pa_no_overlay("egress", "hdr.ctp1.on_lo")\n@pa_no_overlay("egress", "hdr.ctp1.off")\n@pa_no_overlay("egress", "hdr.ctp1.status")\n@pa_no_overlay("egress", "hdr.ctp1.filler_a")\n@pa_no_overlay("egress", "hdr.ctp1.crc1")\n@pa_no_overlay("egress", "hdr.ctp2.filler_b")\n@pa_no_overlay("egress", "hdr.ctp2.crc2")\n',
             '@pa_no_overlay("egress", "hdr.cd2.start")\n@pa_no_overlay("egress", "hdr.cd2.len")\n@pa_no_overlay("egress", "hdr.cd2.ctrl")\n@pa_no_overlay("egress", "hdr.cd2.dst")\n@pa_no_overlay("egress", "hdr.cd2.src")\n@pa_no_overlay("egress", "hdr.cd2.crc")\n@pa_no_overlay("egress", "hdr.cs2.tpctrl")\n@pa_no_overlay("egress", "hdr.cs2.on_lo")\n@pa_no_overlay("egress", "hdr.cs2.off")\n@pa_no_overlay("egress", "hdr.cs2.crc")\n@pa_no_overlay("egress", "hdr.cd3.start")\n@pa_no_overlay("egress", "hdr.cd3.len")\n@pa_no_overlay("egress", "hdr.cd3.ctrl")\n@pa_no_overlay("egress", "hdr.cd3.dst")\n@pa_no_overlay("egress", "hdr.cd3.src")\n@pa_no_overlay("egress", "hdr.cd3.crc")\n@pa_no_overlay("egress", "hdr.cs3.tpctrl")\n@pa_no_overlay("egress", "hdr.cs3.status")\n@pa_no_overlay("egress", "hdr.cs3.crc")\n')
    e = once(e, 'pkt.extract(hdr.p612); pkt.extract(hdr.p1321); pkt.extract(hdr.c1); pkt.extract(hdr.p22); pkt.extract(hdr.c2); transition accept;',
             'pkt.extract(hdr.p69); pkt.extract(hdr.p1012); pkt.extract(hdr.p1321); pkt.extract(hdr.c1); pkt.extract(hdr.p22); pkt.extract(hdr.c2); transition accept;')
    e = once(e, 'm.in_rb1=hash_in_rb1.get({hdr.p612.d,hdr.p1321.d});',
             'm.in_rb1=hash_in_rb1.get({hdr.p69.d,hdr.p1012.d,hdr.p1321.d});')
    e = once(e, 'm.in_ct=hash_in_ct.get({hdr.ctn.on_lo,hdr.ctn.off,hdr.ctn.status});',
             'm.in_ct=hash_in_ct.get({hdr.ctn.on_lo,hdr.ctn.off,hdr.ctn.status});')
    e = once(e, '    RegisterAction<bit<32>, r_slot_t, bit<32>>(img_start) start_arm = {     // virtual image: ISN+1-58\n        void apply(inout bit<32> v) { v = hdr.tcp.seq + 32w0xFFFFFFC7; } };',
             '    RegisterAction<bit<32>, r_slot_t, bit<32>>(img_start) start_arm = {     // virtual image: ISN+1-61\n        void apply(inout bit<32> v) { v = hdr.tcp.seq + 32w0xFFFFFFC4; } };')
    e = once(e, 'm.pm = m.p + 32w0xFFFFFFC6;', 'm.pm = m.p + 32w0xFFFFFFC3;')
    start = e.index('    table classify_rev {')
    end = e.index('\n    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) narrow_win;', start)
    e = e[:start] + '''    table classify_rev {
        key = { m.r : ternary; hdr.tcp.window : range; }
        actions = { rev_translate; rev_withhold_zero; rev_withhold_open; rev_drop; }
        size = 124; const default_action = rev_drop();
        const entries = {
%s
        }
    }
''' % reverse_entries() + e[end:]
    e = once(e, 'hdr.ra.v=56w0x0a020100000300;', 'hdr.ra.v=%s;' % READ_A)
    e = once(e, 'hdr.rbh.v=56w0x0a020104001600;', 'hdr.rbh.v=%s;' % READ_B)
    e = once(e, 'hdr.cb.setValid();hdr.cb.crc=m.rtcrc_b[7:0]++m.rtcrc_b[15:8];',
             'hdr.rc.setValid();hdr.rc.v=%s;hdr.cb.setValid();hdr.cb.crc=m.rtcrc_b[7:0]++m.rtcrc_b[15:8];' % READ_C)
    e = once(e, 'hdr.dl.len=8w0x2f;hdr.dl.crc=hdr.dl.crc^16w0x3b2f;hdr.ip.len=hdr.ip.len+16w9;m.len_delta=16w9;',
             'hdr.dl.len=8w0x32;hdr.dl.crc=hdr.dl.crc^16w0xaf35;hdr.ip.len=hdr.ip.len+16w12;m.len_delta=16w12;')
    e = once(e, 'm.rtcrc=hash_read_tail.get({hdr.p1321.d,hdr.p22.d});',
             'm.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});')
    e = once(e, 'm.rtcrc_a=hash_read_a.get({hdr.rh.tpctrl,hdr.rh.appctrl,hdr.rh.func,hdr.rh.iin,56w0x0a020100000300,hdr.p03.d});',
             'm.rtcrc_a=hash_read_a.get({hdr.rh.tpctrl,hdr.rh.appctrl,hdr.rh.func,hdr.rh.iin,%s,hdr.p03.d,hdr.p45.d});' % READ_A)
    e = once(e, 'm.rtcrc_b=hash_read_b.get({56w0x0a020104001600,hdr.p45.d,hdr.p612.d});',
             'm.rtcrc_b=hash_read_b.get({%s,hdr.p69.d,%s});' % (READ_B, READ_C))
    e = once(e, 'action ctl_eligible(){hdr.ctp1.setValid();hdr.ctp1.on_lo=hdr.ctn.on_lo;hdr.ctp1.off=hdr.ctn.off;hdr.ctp1.status=hdr.ctn.status;hdr.ctp1.filler_a=72w0x29032802002d010000;hdr.ctp1.crc1=m.ctcrc1[7:0]++m.ctcrc1[15:8];hdr.ctp2.setValid();hdr.ctp2.filler_b=80w0x2041002e010000a04100;hdr.ctp2.crc2=16w0xf995;hdr.ctn.on_lo=0;hdr.ctn.off=0;hdr.ctn.status=0;hdr.ctn.crc1=0;hdr.ctn.setInvalid();hdr.dl.len=8w0x2f;hdr.dl.crc=hdr.dl.crc^16w0x131a;hdr.ip.len=hdr.ip.len+16w21;m.len_delta=16w21;}',
             'action ctl_eligible(){hdr.cb0.tpctrl=hdr.cb0.tpctrl&8w0x7f;hdr.cb0.crc0=hdr.cb0.crc0^16w0x0c37;hdr.cd2.setValid();hdr.cd2.start=hdr.dl.start;hdr.cd2.len=8w0x0c;hdr.cd2.ctrl=hdr.dl.ctrl;hdr.cd2.dst=hdr.dl.dst;hdr.cd2.src=hdr.dl.src;hdr.cd2.crc=hdr.dl.crc^16w0xc178;hdr.cs2.setValid();hdr.cs2.on_lo=hdr.ctn.on_lo;hdr.cs2.off=hdr.ctn.off;hdr.cs2.crc=m.ctcrc2[7:0]++m.ctcrc2[15:8];hdr.cd3.setValid();hdr.cd3.start=hdr.dl.start;hdr.cd3.len=8w0x07;hdr.cd3.ctrl=hdr.dl.ctrl;hdr.cd3.dst=hdr.dl.dst;hdr.cd3.src=hdr.dl.src;hdr.cd3.crc=hdr.dl.crc^16w0x4d71;hdr.cs3.setValid();hdr.cs3.status=hdr.ctn.status;hdr.cs3.crc=m.ctcrc3[7:0]++m.ctcrc3[15:8];hdr.ctn.on_lo=0;hdr.ctn.off=0;hdr.ctn.status=0;hdr.ctn.crc1=0;hdr.ctn.setInvalid();hdr.dl.len=8w0x15;hdr.dl.crc=hdr.dl.crc^16w0x3b2f;hdr.ip.len=hdr.ip.len+16w24;m.len_delta=16w24;}')
    e = once(e, 'm.ctcrc1=hash_ctl_tail1.get({hdr.ctn.on_lo,hdr.ctn.off,hdr.ctn.status,8w0x29,64w0x032802002d010000});',
             'm.ctcrc1=hash_ctl_tail1.get({hdr.ctn.on_lo,hdr.ctn.off,hdr.ctn.status});')
    sequence_table = '    action ctl_sequences(bit<8> second, bit<8> third){hdr.cs2.tpctrl=second;hdr.cs3.tpctrl=third;}\n'
    sequence_table += '    table ctl_sequences_t{key={hdr.cb0.tpctrl:exact;}actions={ctl_sequences;NoAction;}size=64;const default_action=NoAction();const entries={\n'
    sequence_table += ''.join('        8w%d:ctl_sequences(8w%d,8w%d);\n' %
                              (192 + seq, (seq + 1) % 64, 128 | ((seq + 2) % 64)) for seq in range(64))
    sequence_table += '    }}\n'
    e = once(e, '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail1;\n',
             sequence_table + '    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail1;\n')
    e = once(e, '    table crc_ctl_tail1_t{actions={crc_ctl_tail1;}size=1;const default_action=crc_ctl_tail1();}\n',
             '    table crc_ctl_tail1_t{actions={crc_ctl_tail1;}size=1;const default_action=crc_ctl_tail1();}\n    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail2;\n    action crc_ctl_tail2(){m.ctcrc2=hash_ctl_tail2.get({hdr.cs2.tpctrl,hdr.ctn.on_lo,hdr.ctn.off});}\n    table crc_ctl_tail2_t{actions={crc_ctl_tail2;}size=1;const default_action=crc_ctl_tail2();}\n    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_ctl_tail3;\n    action crc_ctl_tail3(){m.ctcrc3=hash_ctl_tail3.get({hdr.cs3.tpctrl,hdr.ctn.status});}\n    table crc_ctl_tail3_t{actions={crc_ctl_tail3;}size=1;const default_action=crc_ctl_tail3();}\n')
    e = once(e, 'if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); crc_ctl_tail1_t.apply(); }',
             'if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); crc_ctl_tail1_t.apply(); ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); crc_ctl_tail3_t.apply(); }')
    e = once(e, '8w0x81,8w0x0c,8w0x01,8w0x28,16w0x0100,8w0x00):NoAction();}}',
             '8w0x81,8w0x0c,8w0x01,8w0x28,16w0x0100,8w0x00):ctl_shape();}}')
    assert e.count(READ_TCP_58) == 1
    e = once(e, READ_TCP_58, READ_TCP_61)
    assert e.count(CTL_TCP_NATIVE) == 3
    # Only the padded control branch changes. Native and READ branches retain
    # their original native control-tail fields; invalid-header gating is intact.
    before, native, after = e.rpartition(CTL_TCP_NATIVE)
    assert native == CTL_TCP_NATIVE
    e = before + CTL_TCP_61 + after
    assert e.count('hdr.p612.d, hdr.p1321.d') == 2
    e = e.replace('hdr.p612.d, hdr.p1321.d', 'hdr.p69.d, hdr.p1012.d, hdr.p1321.d')
    e = once(e, 'pkt.emit(hdr.ra); pkt.emit(hdr.p03); pkt.emit(hdr.ca);',
             'pkt.emit(hdr.ra); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0); pkt.emit(hdr.ca);')
    e = once(e, '                hdr.ctp1.on_lo, hdr.ctp1.off, hdr.ctp1.status, hdr.ctp1.filler_a, hdr.ctp1.crc1,\n                hdr.ctp2.filler_b, hdr.ctp2.crc2,\n', '')
    e = once(e, '        if (hdr.ctp1.isValid()) {', '        if (hdr.cd2.isValid()) {')
    e = once(e, 'pkt.emit(hdr.rbh); pkt.emit(hdr.p45); pkt.emit(hdr.c0); pkt.emit(hdr.p612); pkt.emit(hdr.cb);\n        pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);\n        pkt.emit(hdr.cb0); pkt.emit(hdr.ctn); pkt.emit(hdr.ctp1); pkt.emit(hdr.ctp2);',
             'pkt.emit(hdr.rbh); pkt.emit(hdr.p69); pkt.emit(hdr.rc); pkt.emit(hdr.cb);\n        pkt.emit(hdr.p1012); pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);\n        pkt.emit(hdr.cb0); pkt.emit(hdr.ctn); pkt.emit(hdr.cd2); pkt.emit(hdr.cs2); pkt.emit(hdr.cd3); pkt.emit(hdr.cs3);')
    for gone in ('56w0x0a020100000300', '56w0x0a020104001600',
                 'hdr.p612.d,hdr.p1321.d', 'hdr.ip.len+16w9', 'hdr.ip.len+16w21'):
        assert gone not in e, gone
    return e


def full_source():
    base = frozen()
    old_e = combined.segment(base, 'E')
    new_e = transform_e(old_e)
    text = base.replace(old_e, new_e, 1)
    assert combined.segment(text, 'N') == combined.segment(base, 'N')
    assert combined.segment(text, 'T') == combined.segment(base, 'T')
    assert text.replace(new_e, old_e, 1) == base
    return text


def write(directory):
    directory = Path(directory)
    text = full_source()
    directory.mkdir(parents=True, exist_ok=False)
    out = directory / 'response_only.p4'
    out.write_text(text)
    (directory / 'generate.py').write_bytes(Path(__file__).read_bytes())
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='seg61_02',
                    source_sha256=digest(text.encode()),
                    strict_source={'path': str(SOURCE), 'sha256': SOURCE_SHA256},
                    generator_sha256=digest(Path(__file__).read_bytes()),
                    image_len=61,
                    profile='candidate61',
                    control_policy='segmented61',
                    strict_controls_native=False,
                    read_growth=12,
                    control_growth=24,
                    native_lengths={'READ': 49, 'SELECT_OPERATE': 37},
                    output_lengths={'READ': 61, 'SELECT_OPERATE': 61},
                    changed_role='E',
                    segment_sha256={name: digest(combined.segment(text, name).encode())
                                    for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: generate.py OUT_DIR')
    write(sys.argv[1])
