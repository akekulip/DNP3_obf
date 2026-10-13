"""Minimal safe real-relay profile: only the exact clean handshake maps; every option-bearing segment is native.

Input: dup_hold_01/evidence/full_02_strict/response_only.p4 (rearm_57s, strict control policy), sha256-pinned.
realrelay_01 showed on the model that a TS/WS/SACK handshake opens N's owner on the TS SYN, N then drops the
offset-11 SYN-ACK and the tuple wedges; on a mapped flow offset-8 TS segments hit E's drop_odd; E has no native
pass on a configured tuple; the relay's FIN|PSH|ACK (0x19) is not admitted.

N (pipe 0 ingress):
  * The TS shape parser (ts_* states: TS SYN offset 10, TS SYN-ACK offset 11, TS ACK/FIN offset 8, TS READ
    request/response) is removed, so no option-bearing segment can open, arm or advance anything.
  * Every IPv4 (IHL 5) TCP segment now has its TCP header extracted. A segment whose data offset is not 5 and
    that no template parses (offset 7..15, or offset 6 on a non-SYN) ends in the new parser state `foreign`:
    packet_kind 20, network_valid 1. No checksum residue is computed for it; it is never rewritten, so its own
    checksums travel unchanged. An offset-6 SYN/SYN-ACK whose option fails the MSS template stays unparsed
    exactly as before (mss_syn has already set packet_kind, which Tofino's parser cannot re-assign).
  * guard: (stage 0, packet_kind 20, dir 1|2) -> go_native (go only: no work claim, no generation).
    Every table on the go path is then a read for this packet (work read, epoch load, client/server load,
    owner read; owner_command has no stage-0 row).
  * option_native_t (after owner_t, in the stage-0 branch, exclusive with first_event/busy_t): owner phase 0x0000
    (never opened), 0x010f (both FINs and ACKs) or 0x0200 (qualified RST) -> native_pass: event 0xe800, the
    route the `ports` table already chose. Any other phase (a live clean connection) -> NoAction, which is
    today's path (E drops it).
  * FIN|PSH|ACK (0x19, offset 5, no payload) parses as a close exactly like FIN|ACK (0x11): the parser takes
    it to `close`, and every hdr.tcp.flags == 8w17 entry of network, sequence_diff, close_phase_t and
    first_event (all ternary keys) is masked 8w17&&&8w0xf7 (PSH ignored). Entry counts are unchanged.
E (pipe 0 egress):
  * provenance kind 0xe8 on a configured tuple: lifecycle_access already rejects it (catch-all), so it never
    enters the mapper branch; in the rejected branch it is now pass_native() (strip provenance, outcome 16)
    instead of drop_lifetime(). No register is touched and nothing is rewritten (changed == pad == 0).
  * settle_t gains key m.normalize (1 only on N's 0xe0 master lap): (dir 2, SH_ODD, mode 1, normalize 1) ->
    NoAction, so an option-bearing master segment is no longer dropped on the lap by a stale mode 1 left by an
    earlier mapped connection; N decides on its return. Departures keep drop_odd.
T: byte-identical.

  python3 generate.py OUT_DIR
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'dup_hold_01/evidence/full_02_strict/response_only.p4'
SOURCE_SHA256 = '2ad71761399e023b0d3b6b72f9fb71257da012499ffe30ac4758b395fc1bd97c'
spec = importlib.util.spec_from_file_location('realrelay_native_combined', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)

FOREIGN_KIND = 20          # N packet_kind of an option-bearing segment (unused in N)
NATIVE_EVENT = 0xe800      # N event -> E provenance kind 0xe8 (unused in N, E and T)
E_NATIVE_PASS = 16         # E outcome counter index (0..15 used, counter has 32 cells)
NATIVE_PHASES = (0x0000, 0x010f, 0x0200)

TS_STATES = (
    ' state ts_ip_flags{', ' state ts_tcp{', ' state ts_ack{', ' state ts_close{', ' state ts_syn{',
    ' state ts_synack_ip_flags{', ' state ts_synack_tcp{', ' state ts_synack{', ' state ts_read_ip_flags{',
    ' state ts_read_tcp{', ' state ts_read_opt{', ' state ts_read_response_ip_flags{',
    ' state ts_read_response_tcp{', ' state ts_read_response_opt{')
NEW_STATES = (
    ' state option_ip_flags{transition select(hdr.ip.frag,hdr.ip.flags){(13w0,3w0):option_tcp;(13w0,3w2):option_tcp;'
    'default:accept;}}\n'
    ' /* realrelay_native_01: a segment no template parsed is native unless its data offset is 5. */\n'
    ' state option_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset){4w5:accept;'
    'default:foreign;}}\n'
    ' state foreign{m.packet_kind=8w%d;m.network_valid=(bit<1>)(8w1);transition accept;}\n' % FOREIGN_KIND)

N_EDITS = (
    # ip: the four TS lengths go to the generic option path, as does every other IHL-5 TCP length
    ('(4w4,4w5,8w6,16w52):ts_ip_flags;(4w4,4w5,8w6,16w64):ts_synack_ip_flags;(4w4,4w5,8w6,16w72):ts_read_ip_flags;'
     '(4w4,4w5,8w6,16w101):ts_read_response_ip_flags;default:accept;}}',
     '(4w4,4w5,8w6,_):option_ip_flags;default:accept;}}'),
    # every TCP-extracting state: unparsed with data offset 5 stays unparsed (as before); any other offset is
    # foreign. The test sits in each state's own select: a separate state ran out of parser match registers.
    ('(4w5,16w40,8w17):close;(4w5,16w40,8w20):close;(4w5,16w40,8w4):close;default:accept;}}',
     '(4w5,16w40,8w17):close;(4w5,16w40,8w25):close;(4w5,16w40,8w20):close;(4w5,16w40,8w4):close;'
     '(4w5,_,_):accept;default:foreign;}}'),
    ('8w0x04&&&8w0x04):native_command_reject;default:accept;}}',
     '8w0x04&&&8w0x04):native_command_reject;(4w5,_,_,_):accept;default:foreign;}}'),
    ('(4w5,4w0,16w0,8w24):response_dl;default:accept;}}',
     '(4w5,4w0,16w0,8w24):response_dl;(4w5,_,_,_):accept;default:foreign;}}'),
    ('(4w5,4w0,16w0,8w24):read_dl;(4w10,4w0,16w0,8w2):ts_syn;default:accept;}}',
     '(4w5,4w0,16w0,8w24):read_dl;(4w5,_,_,_):accept;default:foreign;}}'),
    ('(4w5,4w0,16w0,8w24):read_response_dl;default:accept;}}',
     '(4w5,4w0,16w0,8w24):read_response_dl;(4w5,_,_,_):accept;default:foreign;}}'),
    ('state replay_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,'
     'hdr.tcp.urgent,hdr.tcp.flags){default:accept;}}',
     'state replay_tcp{pkt.extract(hdr.tcp);tc.subtract(hdr.tcp);transition select(hdr.tcp.offset,hdr.tcp.reserved,'
     'hdr.tcp.urgent,hdr.tcp.flags){(4w5,_,_,_):accept;default:foreign;}}'),
    # 0x19 admitted as FIN|ACK (single-occurrence flag rows; the two large tables are masked in transform_n)
    ('(1w1,8w4,8w17,false,', '(1w1,8w4,8w17&&&8w0xf7,false,'),
    ('(_,2w1,8w17):diff_forward();', '(_,2w1,8w17&&&8w0xf7):diff_forward();'),
    ('(_,2w2,8w17):diff_reverse();', '(_,2w2,8w17&&&8w0xf7):diff_reverse();'),
    # guard: an option-bearing segment with a direction goes, without claiming work (44 of 48)
    ('actions={go_new;go_keep;go_ret_work;go_ret_nowork;go_ret_abort;refuse_n_ack_return;NoAction;}size=48;',
     'actions={go_new;go_keep;go_ret_work;go_ret_nowork;go_ret_abort;refuse_n_ack_return;go_native;NoAction;}size=48;'),
    ('(2w0,8w12,8w0,2w1,1w1,_,_,_,_,_,_,_,_):go_new(8w12);',
     '(2w0,8w12,8w0,2w1,1w1,_,_,_,_,_,_,_,_):go_new(8w12);'
     '(2w0,8w20,8w0,2w1,_,_,_,_,_,_,_,_,_):go_native();(2w0,8w20,8w0,2w2,_,_,_,_,_,_,_,_,_):go_native();'),
    ('\naction refuse_n_ack_return(){md.drop_ctl=3w1;}',
     '\naction refuse_n_ack_return(){md.drop_ctl=3w1;}\n'
     ' action go_native(){m.go=(bit<1>)(8w1);}\n'
     ' /* realrelay_native_01: an option-bearing segment on a tuple with no live clean connection leaves native. */\n'
     ' action native_pass(){hdr.event.event=16w0x%04x;}\n'
     ' table option_native_t{key={m.observed:ternary;}actions={native_pass;NoAction;}size=3;const entries={%s}'
     'const default_action=NoAction();}'
     % (NATIVE_EVENT, ''.join('32w0x%08x&&&32w0xffff0000:native_pass();' % (p << 16) for p in NATIVE_PHASES))),
    ('}else if(m.work_op==8w1){busy_t.apply();}else if(m.kind==8w4){deny();}',
     '}else if(m.work_op==8w1){busy_t.apply();}else if(m.kind==8w4){deny();}'
     'else if(m.packet_kind==8w20){option_native_t.apply();}'),
)

E_EDITS = (
    ('const bit<8> r_OUT_DROP_MERGED = 15;',
     'const bit<8> r_OUT_DROP_MERGED = 15;\n'
     '// realrelay_native_01: an option-bearing segment N passed native (provenance kind 0xe8)\n'
     'const bit<8> r_OUT_NATIVE_PASS = %d;' % E_NATIVE_PASS),
    ('    action strip_provenance() { hdr.prov.setInvalid(); }\n',
     '    action strip_provenance() { hdr.prov.setInvalid(); }\n'
     '    action pass_native() { hdr.prov.setInvalid(); m.result = r_OUT_NATIVE_PASS; }\n'),
    # the rejected-lifetime branch of a configured TCP segment (inner else of `dir != 0 && tcp.isValid()`)
    ('            } else { drop_lifetime(); }\n        } else {\n',
     '            } else if (hdr.prov.kind == 8w0xe8) { pass_native(); } else { drop_lifetime(); }\n        } else {\n'),
    ('        key = { m.dir : ternary; m.shape : ternary; m.mode : ternary; }',
     '        key = { m.dir : ternary; m.shape : ternary; m.mode : ternary; m.normalize : ternary; }'),
    ('const entries = {(0, _, _): NoAction();(1, (bit<3>)r_SH_SYNACK_OK, _): armed_map();(1, (bit<3>)r_SH_SYN, _): '
     'armed_nat();(_, (bit<3>)r_SH_ODD, 1): drop_odd();(_, _, 0): native();}',
     'const entries = {(0, _, _, _): NoAction();(1, (bit<3>)r_SH_SYNACK_OK, _, _): armed_map();(1, (bit<3>)r_SH_SYN, _, _): '
     'armed_nat();(2, (bit<3>)r_SH_ODD, 1, 1): NoAction();(_, (bit<3>)r_SH_ODD, 1, _): drop_odd();(_, _, 0, _): native();}'),
)

# (table start, table end marker, old, new, expected count) for the two large ternary flag tables
MASKED = (
    ('table close_phase_t{', 'const default_action=NoAction();}', '(8w17,', '(8w17&&&8w0xf7,', 48),
    ('table first_event{', ' action next_stage()', ',2w1,8w17,', ',2w1,8w17&&&8w0xf7,', 23),
    ('table first_event{', ' action next_stage()', ',2w2,8w17,', ',2w2,8w17&&&8w0xf7,', 23),
)


def frozen():
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'dup_hold_01 full_02_strict input changed'
    return raw.decode()


def once(text, old, new):
    assert text.count(old) == 1, ('anchor not found exactly once', old[:90], text.count(old))
    return text.replace(old, new, 1)


def fresh(text, tokens):
    for token in tokens:
        assert token not in text, ('value already in use', token)


def transform_n(text):
    fresh(text, ('packet_kind==8w20', 'packet_kind=8w20', '(2w0,8w20', '0xe8', 'go_native', 'option_native_t',
                 'native_pass', 'foreign', 'option_tcp', '16w40,8w25', '&&&8w0xf7'))
    # remove the TS shape states: one contiguous block that ends at `finish`
    start = text.index(TS_STATES[0])
    end = text.index(' state finish{')
    block = text[start:end]
    assert text.count(TS_STATES[0]) == 1 and all(block.count(s) == 1 for s in TS_STATES), 'TS block shape'
    assert block.count(' state ') == len(TS_STATES), 'unexpected state inside the TS block'
    text = text[:start] + NEW_STATES + text[end:]
    for old, new in N_EDITS:
        text = once(text, old, new)
    for first, last, old, new, count in MASKED:
        i = text.index(first)
        assert text.count(first) == 1
        j = text.index(last, i)
        body = text[i:j]
        assert body.count(old) == count, (first, old, body.count(old))
        text = text[:i] + body.replace(old, new) + text[j:]
    parser = text[text.index('parser n_IgParser'):text.index('control n_Ingress')]
    for token in (':ts_', ' ts_', 'hdr.tso', 'hdr.oa', 'hdr.ob'):
        assert token not in parser, ('TS parse remains', token)
    return text


def transform_e(text):
    fresh(text, ('0xe8', 'r_OUT_NATIVE_PASS', 'pass_native', 'm.normalize : ternary'))
    for old, new in E_EDITS:
        text = once(text, old, new)
    return text


def full_source():
    base = frozen()
    old_n, old_e, old_t = (combined.segment(base, name) for name in ('N', 'E', 'T'))
    new_n, new_e = transform_n(old_n), transform_e(old_e)
    source = base.replace(old_n, new_n, 1).replace(old_e, new_e, 1)
    assert combined.segment(source, 'T') == old_t, 'T must be byte-identical'
    assert combined.segment(source, 'N') == new_n and combined.segment(source, 'E') == new_e
    assert source.replace(new_n, old_n, 1).replace(new_e, old_e, 1) == base, 'only N and E may differ'
    return source, (old_n, old_e, old_t)


def write(directory):
    directory = Path(directory)
    text, old = full_source()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='realrelay_native_01', source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    dup_hold_source={'path': str(SOURCE), 'sha256': SOURCE_SHA256},
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    native_profile={'n_foreign_packet_kind': FOREIGN_KIND, 'n_native_event': '0x%04x' % NATIVE_EVENT,
                                    'e_native_prov_kind': '0x%02x' % (NATIVE_EVENT >> 8),
                                    'e_outcome_native_pass': E_NATIVE_PASS,
                                    'native_owner_phases': ['0x%04x' % p for p in NATIVE_PHASES],
                                    'fin_psh_ack_0x19': 'admitted as FIN|ACK (flags 8w17 masked 8w0xf7)'},
                    segment_sha256={name: hashlib.sha256(combined.segment(text, name).encode()).hexdigest()
                                    for name in ('N', 'E', 'T')},
                    input_segment_sha256={name: hashlib.sha256(seg.encode()).hexdigest()
                                          for name, seg in zip(('N', 'E', 'T'), old)})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1])
