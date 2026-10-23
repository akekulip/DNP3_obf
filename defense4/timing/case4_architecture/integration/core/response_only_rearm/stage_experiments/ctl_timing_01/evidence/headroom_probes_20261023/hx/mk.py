#!/usr/bin/env python3
"""Build headroom variants of c26 (all.p4) from anchored old->new edits.  usage: mk.py NAME E1 E2 E3 ..."""
import re, sys, json
from pathlib import Path
D = Path('/home/philip/Projects/DNP3/.scratch_p4')
BASE = (D / 'all.p4').read_text()

def once(src, old, new):
    n = src.count(old)
    assert n == 1, (n, old[:120])
    return src.replace(old, new)

def split_top(s):
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch == '(' : depth += 1
        if ch == ')' : depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur); cur = ''
        else:
            cur += ch
    out.append(cur); return out

def drop_cols(entries_text, drop):
    """entries_text: '(k0, k1, ...): act(...);(...): act();' -> remove key columns in drop."""
    res, i = '', 0
    while i < len(entries_text):
        if entries_text[i] == '(':
            depth, j = 0, i
            while True:
                if entries_text[j] == '(': depth += 1
                if entries_text[j] == ')':
                    depth -= 1
                    if depth == 0: break
                j += 1
            inner = entries_text[i+1:j]
            cols = split_top(inner)
            cols = [c for k, c in enumerate(cols) if k not in drop]
            res += '(' + ','.join(cols) + ')'
            # copy up to next ';'
            k = entries_text.index(';', j)
            res += entries_text[j+1:k+1]; i = k + 1
        else:
            res += entries_text[i]; i += 1
    return res

EDITS = {}
# ---- E1: CRC-tail precompute (ctl_sequences_t, crc_ctl_tail2_t, crc_ctl_tail3_t) only on the control-pad branch
EDITS['E1'] = [
 ("if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); crc_ctl_tail3_t.apply(); }",
  "if (hdr.cb0.isValid()) { ctl_profile.apply(); in_cb0_t.apply(); in_ct_t.apply(); }"),
 ("if (m.read_shape == 1) { read_pad_t.apply(); } else { ctl_pad_t.apply(); }",
  "if (m.read_shape == 1) { read_pad_t.apply(); } else { ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); crc_ctl_tail3_t.apply(); ctl_pad_t.apply(); }"),
]
# ---- E1b: same three tables, applied in the forward-classification branch that decides the pad (mode==1), before classify_fwd
EDITS['E1b'] = [
 EDITS['E1'][0],
 ("if ((bit<8>)m.mode == 1) { classify_fwd.apply(); }",
  "if ((bit<8>)m.mode == 1) { if (m.ctl_shape == 1) { ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); crc_ctl_tail3_t.apply(); } classify_fwd.apply(); }"),
]
# ---- E1c: same three tables, applied right after mode_t under (mode==1 && ctl_shape==1), a superset of the control-pad path
EDITS['E1c'] = [
 EDITS['E1'][0],
 ("                mode_t.apply();\n",
  "                mode_t.apply();\n                if ((bit<8>)m.mode == 1 && m.ctl_shape == 1) { ctl_sequences_t.apply(); crc_ctl_tail2_t.apply(); crc_ctl_tail3_t.apply(); }\n"),
]
# ---- X4 (exploratory, outside the three experiments): same-width identity-hash copy in prep_t -> plain move (frees 2 hash-dist units)
EDITS['X4'] = [
 ("action qualified_wire_ack() { m.ina = wire_ack_input.get({hdr.prov.wgen}); m.qx = hdr.tcp.ack; m.ack_inv = ~hdr.tcp.ack; }",
  "action qualified_wire_ack() { m.ina = hdr.prov.wgen; m.qx = hdr.tcp.ack; m.ack_inv = ~hdr.tcp.ack; }"),
]
# ---- N1: N pins on the instantiated n_Ingress (container 74: owner_op/matched; container 65: sequence_valid/drop_ctl)
EDITS['N1'] = [
 ('@pa_solitary("ingress", "m.expected_work_phase")\n',
  '@pa_solitary("ingress", "m.expected_work_phase")\n@pa_solitary("ingress", "m.owner_op") @pa_solitary("ingress", "m.matched") @pa_solitary("ingress", "m.sequence_valid")\n'),
]
EDITS['N2'] = [
 ('@pa_solitary("ingress", "m.sequence_valid")\n',
  '@pa_solitary("ingress", "m.sequence_valid")\n@pa_solitary("ingress", "m.badh") @pa_solitary("ingress", "m.network_valid") @pa_solitary("ingress", "m.compare_read_app")\n'),
]
# ---- E2: isolate CRC-tail metadata; pragma attached to the instantiated egress control (r_IgParser is never instantiated)
EDITS['E2'] = [
 ("control r_Egress(inout r_headers_t hdr,",
  "@pa_solitary(\"egress\",\"m.ctcrc2\") @pa_solitary(\"egress\",\"m.ctcrc3\")\ncontrol r_Egress(inout r_headers_t hdr,"),
]
EDITS['E2a'] = EDITS['E2']
EDITS['E2'] = [
 ("control r_Egress(inout r_headers_t hdr,",
  "/* attached to the instantiated egress control: pragmas on r_IgParser (never instantiated) are silently dropped */\n"
  "@pa_solitary(\"egress\",\"m.ctcrc2\") @pa_solitary(\"egress\",\"m.ctcrc3\")\n"
  "@pa_solitary(\"egress\",\"m.badh\") @pa_solitary(\"egress\",\"m.cbad0\") @pa_solitary(\"egress\",\"m.cbadt\")\n"
  "@pa_solitary(\"egress\",\"m.read_shape\") @pa_solitary(\"egress\",\"m.ctl_shape\")\n"
  "control r_Egress(inout r_headers_t hdr,"),
]
# ---- E2b (diagnostic): move the whole existing egress pragma block onto r_EgParser (instantiated)
def e2b(src):
    a = src.index('/* Same reason as in case4_pad58b_wire.p4')
    b = src.index('/* ------------------------------------------------------------------ ingress: port forwarding only */')
    block = src[a:b]
    src = src[:a] + src[b:]
    return once(src, '/* ------------------------------------------------------------------ egress parser */\n',
                '/* ------------------------------------------------------------------ egress parser */\n' + block)
# ---- E3: remove unreachable read_b0 pieces
EDITS['E3'] = [
 ("r_read_hdr40_h rbh; r_read_d16_h p45; r_read_crc_h c0; r_read_d32_h p69; r_read_d24_h p1012; r_read_crc_h cb;\n                   r_read_hdr_h rc; r_read_d72_h p1321; r_read_crc_h c1; r_read_d8_h p22; r_read_crc_h c2; r_ctl_b0_h cb0;",
  "r_read_hdr40_h rbh; r_read_crc_h cb;\n                   r_read_hdr_h rc; r_ctl_b0_h cb0;"),
 ("r_read_obj_h robj; r_read_hdr40_h ra; r_read_d32_h p03; r_read_crc_h ca;", "r_read_obj_h robj; r_read_hdr40_h ra; r_read_crc_h ca;"),
 ("bit<16> in_dl; bit<16> in_rb0; bit<16> in_rb1; bit<16> in_rt; bit<16> in_cb0; bit<16> in_ct;", "bit<16> in_dl; bit<16> in_cb0; bit<16> in_ct;"),
 ("bit<1> badh; bit<1> rbad0; bit<1> rbad1; bit<1> rbadt; bit<1> cbad0; bit<1> cbadt;", "bit<1> badh; bit<1> cbad0; bit<1> cbadt;"),
 ('@pa_solitary("egress","m.badh") @pa_solitary("egress","m.rbad0") @pa_solitary("egress","m.rbad1")\n@pa_solitary("egress","m.rbadt") @pa_solitary("egress","m.cbad0") @pa_solitary("egress","m.cbadt")',
  '@pa_solitary("egress","m.badh") @pa_solitary("egress","m.cbad0") @pa_solitary("egress","m.cbadt")'),
 ('@pa_no_overlay("egress", "hdr.p03.d")\n@pa_no_overlay("egress", "hdr.p45.d")\n@pa_no_overlay("egress", "hdr.c0.crc")\n@pa_no_overlay("egress", "hdr.p69.d")\n@pa_no_overlay("egress", "hdr.p1012.d")\n@pa_no_overlay("egress", "hdr.p1321.d")\n@pa_no_overlay("egress", "hdr.c1.crc")\n@pa_no_overlay("egress", "hdr.p22.d")\n@pa_no_overlay("egress", "hdr.c2.crc")\n', ''),
 ("m.badh = 0; m.rbad0 = 0; m.rbad1 = 0; m.rbadt = 0; m.cbad0 = 0; m.cbadt = 0;", "m.badh = 0; m.cbad0 = 0; m.cbadt = 0;"),
 ("    state read_b0 { pkt.extract(hdr.rh); pkt.extract(hdr.robj); pkt.extract(hdr.p03); pkt.extract(hdr.p45); pkt.extract(hdr.c0);\n        pkt.extract(hdr.p69); pkt.extract(hdr.p1012); pkt.extract(hdr.p1321); pkt.extract(hdr.c1); pkt.extract(hdr.p22); pkt.extract(hdr.c2); transition accept; }\n", ""),
 ("    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rb0;\n    action in_rb0(){m.in_rb0=hash_in_rb0.get({hdr.rh.tpctrl,hdr.rh.appctrl,hdr.rh.func,hdr.rh.iin,hdr.robj.g_group,hdr.robj.g_var,hdr.robj.g_qual,hdr.robj.g_start,hdr.robj.g_stop,hdr.p03.d,hdr.p45.d});}\n    table in_rb0_t{actions={in_rb0;}size=1;const default_action=in_rb0();}\n    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rb1;\n    action in_rb1(){m.in_rb1=hash_in_rb1.get({hdr.p69.d,hdr.p1012.d,hdr.p1321.d});}\n    table in_rb1_t{actions={in_rb1;}size=1;const default_action=in_rb1();}\n    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_in_rt;\n    action in_rt(){m.in_rt=hash_in_rt.get({hdr.p22.d});}\n    table in_rt_t{actions={in_rt;}size=1;const default_action=in_rt();}\n", ""),
 ("    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_read_tail;\n    action crc_read_tail(){m.rtcrc=hash_read_tail.get({hdr.p1012.d,hdr.p1321.d,hdr.p22.d});}\n    table crc_read_tail_t{actions={crc_read_tail;}size=1;const default_action=crc_read_tail();}\n    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,poly) hash_read_b;\n    action crc_read_b(){m.rtcrc_b=hash_read_b.get({40w0x0a02000609,hdr.p69.d,56w0x0a02010a001600});}\n    table crc_read_b_t{actions={crc_read_b;}size=1;const default_action=crc_read_b();}\n", ""),
 ("pkt.emit(hdr.rh); pkt.emit(hdr.robj); pkt.emit(hdr.p03); pkt.emit(hdr.p45); pkt.emit(hdr.c0);\n        pkt.emit(hdr.p69);\n        pkt.emit(hdr.p1012); pkt.emit(hdr.p1321); pkt.emit(hdr.c1); pkt.emit(hdr.p22); pkt.emit(hdr.c2);\n",
  "pkt.emit(hdr.rh); pkt.emit(hdr.robj);\n"),
 ("m.r_residual});\n", None),  # placeholder, handled below
]
CSUM_OLD = "hdr.robj.g_start, hdr.robj.g_stop, hdr.p03.d, hdr.p45.d, hdr.c0.crc,\n                hdr.p69.d, hdr.p1012.d, hdr.p1321.d, hdr.c1.crc,\n                hdr.p22.d, hdr.c2.crc, 8w0,\n"
CSUM_NEW = "hdr.robj.g_start, hdr.robj.g_stop,\n"
ACCT_KEY_OLD = "m.leff : ternary; m.read_shape : ternary; m.ctl_shape : ternary; m.badh : ternary;\n                m.rbad0 : ternary; m.rbad1 : ternary; m.rbadt : ternary; m.cbad0 : ternary; m.cbadt : ternary; }"
ACCT_KEY_NEW = "m.leff : ternary; m.read_shape : ternary; m.ctl_shape : ternary; m.badh : ternary;\n                m.cbad0 : ternary; m.cbadt : ternary; }"
CF_KEY_OLD = "m.read_shape : ternary; m.ctl_shape : ternary; m.badh : ternary;\n                m.rbad0 : ternary; m.rbad1 : ternary; m.rbadt : ternary; m.cbad0 : ternary; m.cbadt : ternary;\n                hdr.tcp.flags : ternary; }"
CF_KEY_NEW = "m.read_shape : ternary; m.ctl_shape : ternary; m.badh : ternary;\n                m.cbad0 : ternary; m.cbadt : ternary;\n                hdr.tcp.flags : ternary; }"

def table_entries(src, tname):
    a = src.index('table ' + tname + ' {')
    e = src.index('const entries = {', a) + len('const entries = {')
    z = src.index('}\n    }', e)
    return e, z

def apply_e3(src, log):
    for old, new in EDITS['E3']:
        if new is None: continue
        src = once(src, old, new); log.append((old, new))
    assert src.count(CSUM_OLD) == 2; src = src.replace(CSUM_OLD, CSUM_NEW); log.append((CSUM_OLD + ' [x2]', CSUM_NEW))
    for tname, ko, kn in (('acct_t', ACCT_KEY_OLD, ACCT_KEY_NEW), ('classify_fwd', CF_KEY_OLD, CF_KEY_NEW)):
        src = once(src, ko, kn); log.append((ko, kn))
        e, z = table_entries(src, tname)
        old = src[e:z]; new = drop_cols(old, {10, 11, 12})
        src = src[:e] + new + src[z:]; log.append((old, new))
    return src

if __name__ == '__main__':
    name, sel = sys.argv[1], sys.argv[2:]
    src, log = BASE, []
    for s in sel:
        if s == 'E3': src = apply_e3(src, log)
        elif s == 'E2b': src = e2b(src); log.append(('<egress pragma block before r_IgParser>', '<same block before r_EgParser>'))
        else:
            for old, new in EDITS[s]:
                src = once(src, old, new); log.append((old, new))
    (D / (name + '.p4')).write_text(src)
    (D / 'hx' / (name + '.edits.json')).write_text(json.dumps(log, indent=1))
    print(name, sel, len(log), 'edits')
