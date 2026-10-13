"""Hold an identical OPERATE copy in T while its original is still held; forward it after release.

In rearm_56r + read_reencode_01 (input below) a retransmitted OPERATE (packet_kind 7, sequence_valid 3,
owner phase 0xc) takes first_event's forward_original row: event 0x0108 (N kind 8), guard go_ret_work,
no read_terminal_t row for kind 8, so terminal_ack/terminal_strip put it on the wire ~0.1 s after it
was sent, before T released the held original (read_reencode_01/evidence/dup_model_01, _02).

This experiment routes that one first_event row to a new N event 0x0118 (N kind 24, unused in N),
threads kind 24 through N's laps exactly as kind 8 (parser, network, guard, owner check), and hands
it to T at the terminal lap as T kind 15 (t_KIND_OPERATE_DUP, unused in T and E) through the same
commit_before_t / E 0xe5 lap / committed_t path the original OPERATE (T kind 12) takes. In T:
  enabled == 0                 -> forward to the relay as an OPERATE passthrough (tev.kind rewritten to
                                  12: E's lifecycle_access rejects any provenance kind it does not
                                  know, and E is not edited)
  e_bad != 0                   -> tin_verdict's default drop_old_epoch (unchanged)
  op_done ^ op_gen == 0        -> forward to the relay as above (original already released: recovery)
  otherwise                    -> drop, counted at the new outcomes index 16 (t_OUT_OP_DUP_DROP)
op_done is only read (the existing read_op_done / op_done_read); op_gen comes from the existing
default peek_operate_generation. No other kind's rows change; E is byte-identical to the input.

  python3 generate.py OUT_DIR
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# read_reencode_01 full_01 (block-CRC hashes in E's stage 0). full_02 (--late) drops SYN-ACKs on the model
# (read_reencode_01/evidence/model_diag_02, model_retx_02), so it is not used. N and T are identical in the two.
# Input composites from read_reencode_01: full_01 = all-58 profile (READ re-encoded, control G41 padding),
# full_04 = strict policy (READ re-encoded, SELECT/OPERATE responses native). Both pinned by sha256.
INPUTS = {
    'all58': (HERE.parent / 'read_reencode_01/evidence/full_01/response_only.p4',
              '3bab2181a7b42955bfb0cade94391d509bbb8549f25726d37397f4c69acaf43b'),
    'strict': (HERE.parent / 'read_reencode_01/evidence/full_04/response_only.p4',
               '4d143d8607e897f46d5945d6de5cd1779a5de759f28cd3300e177a1ab404f845'),
}
SOURCE, SOURCE_SHA256 = INPUTS['all58']
spec = importlib.util.spec_from_file_location('dup_hold_combined', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)

N_KIND, N_EVENT = 24, 0x0118        # N-side kind / first-lap event of the duplicate (0x0118, 0x0218, 0x0318)
T_KIND = 15                         # T tev.kind (t_KIND_OPERATE_DUP); N committed event 0xe60f -> 0x0f00
OUT_INDEX = 16                      # outcomes index (t_OUT_OP_DUP_DROP); 16..22 were unused
CRC_ROW = '_,_,1w1,8w1,1w0,16w0x993a,16w0x993a,_,16w0x993a,_'

N_EDITS = (
    # parser: the three laps of the duplicate carry the t0 header exactly as kind 7's laps do
    ('16w0x0108:origin;', '16w0x0108:origin;16w0x0118:read_t0;'),
    ('16w0x0208:origin;', '16w0x0208:origin;16w0x0218:read_t0;'),
    ('16w0x0308:origin;', '16w0x0308:origin;16w0x0318:read_t0;'),
    # committed_t: the E-returned commit of T kind 15 (size == entry count, 2 -> 3)
    ('table committed_t{key={hdr.event.event:exact;}actions={committed_to_t;deny;}size=2;'
     'const entries={16w0xe609:committed_to_t(16w0x0900);16w0xe60c:committed_to_t(16w0x0c00);}',
     'table committed_t{key={hdr.event.event:exact;}actions={committed_to_t;deny;}size=3;'
     'const entries={16w0xe609:committed_to_t(16w0x0900);16w0xe60c:committed_to_t(16w0x0c00);'
     '16w0xe60f:committed_to_t(16w0x0f00);}'),
    # network: the duplicate's return laps carry OPERATE's TCP flags (16 / 24), as kind 7 does
    ('(1w1,8w7,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();',
     '(1w1,8w7,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'
     '(1w1,8w24,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'
     '(1w1,8w24,8w24,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'),
    # first_event: new action, and the OPERATE duplicate row (kind 7, seq 3, owner 0xc) uses it
    (' action forward_original(){hdr.event.event=16w0x0108;}',
     ' action forward_original(){hdr.event.event=16w0x0108;}\n'
     ' action first_operate_dup(){hdr.event.event=16w0x0118;hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;}'),
    ('count_refused;count_resent;count_replay_refused;forward_original;close_forward;NoAction;}size=163;',
     'count_refused;count_resent;count_replay_refused;forward_original;first_operate_dup;close_forward;NoAction;}size=163;'),
    ('(8w7,3w3,_,32w0xc0000&&&32w0xffff0000,_,_,_,_,_,_):forward_original();',
     '(8w7,3w3,_,32w0xc0000&&&32w0xffff0000,_,_,_,_,_,_):first_operate_dup();'),
    # stages 1-2: the owner check kind 8 gets
    ('else if(m.kind==8w8||m.kind==8w10||', 'else if(m.kind==8w8||m.kind==8w24||m.kind==8w10||'),
    # stage 3: commit to T as kind 15 (size 10 == entry count after the row)
    ('(8w7,32w0,32w0,_):commit_before_t(8w12);',
     '(8w7,32w0,32w0,_):commit_before_t(8w12);(8w24,32w0,32w0,_):commit_before_t(8w15);'),
    # guard: the duplicate's return laps, same qualification as the kind-8 OPERATE row
    ('(_,8w7,8w8,%s):go_ret_work();' % CRC_ROW,
     '(_,8w7,8w8,%s):go_ret_work();(_,8w7,8w24,%s):go_ret_work();' % (CRC_ROW, CRC_ROW)),
)

T_EDITS = (
    ('const bit<8> t_KIND_OPERATE = 12; const bit<8> t_KIND_RESET = 13; const bit<8> t_KIND_OPEN = 14;\n',
     'const bit<8> t_KIND_OPERATE = 12; const bit<8> t_KIND_RESET = 13; const bit<8> t_KIND_OPEN = 14;\n'
     '// An identical OPERATE copy (dup_hold_01): held-time drop, post-release forward. Never cloned or held.\n'
     'const bit<8> t_KIND_OPERATE_DUP = 15;\n'),
    ('const bit<32> t_OUT_OLD_EPOCH_DROP = 14; const bit<32> t_OUT_GEN_EXHAUSTED = 15;\n',
     'const bit<32> t_OUT_OLD_EPOCH_DROP = 14; const bit<32> t_OUT_GEN_EXHAUSTED = 15;\n'
     'const bit<32> t_OUT_OP_DUP_DROP = 16;\n'),
    ('            (12, 0) : opaque_ethernet;\n            (t_KIND_RESET, 0) : opaque_ethernet;\n',
     '            (12, 0) : opaque_ethernet;\n            (t_KIND_OPERATE_DUP, 0) : opaque_ethernet;\n'
     '            (t_KIND_RESET, 0) : opaque_ethernet;\n'),
    ('14 : bump(14); 15 : bump(15); 23 : bump(23);', '14 : bump(14); 15 : bump(15); 16 : bump(16); 23 : bump(23);'),
    ('    action drop_old_epoch() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_OLD_EPOCH_DROP); }\n',
     '    action drop_old_epoch() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_OLD_EPOCH_DROP); }\n'
     '    // The duplicate leaves as an OPERATE passthrough: E accepts only provenance kinds it knows.\n'
     '    action passthrough_operate_dup() { hdr.tev.kind = t_KIND_OPERATE; ig_tm_md.ucast_egress_port = t_RELAY_PORT; }\n'
     '    action drop_operate_dup() { ig_dprsr_md.drop_ctl = 1; count(t_OUT_OP_DUP_DROP); }\n'),
    ('hold_ack; drop_duplicate_response; admit_response; hold_operate; unmatched; drop_old_epoch; drop_exhausted; }',
     'hold_ack; drop_duplicate_response; admit_response; hold_operate; unmatched; drop_old_epoch; drop_exhausted;\n'
     '                    passthrough_operate_dup; drop_operate_dup; }'),
    ('            (t_KIND_OPERATE, 0, 0, _, _, _, _, _) : passthrough_tev_relay();\n',
     '            (t_KIND_OPERATE, 0, 0, _, _, _, _, _) : passthrough_tev_relay();\n'
     '            (t_KIND_OPERATE_DUP, 0, 0, _, _, _, _, _) : passthrough_operate_dup();\n'),
    ('            (t_KIND_OPERATE, _, 0, _, _, _, _, _) : hold_operate();\n',
     '            (t_KIND_OPERATE, _, 0, _, _, _, _, _) : hold_operate();\n'
     '            // done_diff = op_done ^ op_gen (read_op_done): 0 = the current OPERATE was already released.\n'
     '            (t_KIND_OPERATE_DUP, _, 0, 0, _, _, _, _) : passthrough_operate_dup();\n'
     '            (t_KIND_OPERATE_DUP, _, 0, _, _, _, _, _) : drop_operate_dup();\n'),
    ('        default_action = drop_old_epoch(); size = 19;', '        default_action = drop_old_epoch(); size = 22;'),
    # First in the t_T_IN branch: bf-p4c places a gateway with the first table it guards and a later gateway
    # cannot precede an earlier one, so after read_resp_done's gateway (stage 8) this read pulled op_done_reg
    # to stage 9 and T to 12 stages (evidence/on_full02_build_01). op_done_reg's own stage is 7.
    ('        } else if (ig_intr_md.ingress_port == t_T_IN) {\n',
     '        } else if (ig_intr_md.ingress_port == t_T_IN) {\n'
     '            // Read only: no op_done write, no op_gen bump, no op_t0 arm, no clone (dup_hold_01).\n'
     '            if (md.event_kind == t_KIND_OPERATE_DUP && md.e_bad == 0 && md.enabled != 0) { read_op_done(); }\n'),
)


def frozen(profile='all58'):
    path, digest = INPUTS[profile]
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, ('read_reencode_01 input changed', profile)
    return raw.decode()


def once(text, old, new):
    assert text.count(old) == 1, ('anchor not found exactly once', old[:90], text.count(old))
    return text.replace(old, new, 1)


def transform(text, edits, fresh):
    for token in fresh:
        assert token not in text, ('value already in use', token)
    for old, new in edits:
        text = once(text, old, new)
    return text


def full_source(profile='all58'):
    base = frozen(profile)
    old_n, old_e, old_t = (combined.segment(base, name) for name in ('N', 'E', 'T'))
    new_n = transform(old_n, N_EDITS, ('0x0118', '0x0218', '0x0318', '0xe60f', '8w24,8w', ',8w24,_', '(8w24,'))
    new_t = transform(old_t, T_EDITS, ('t_KIND_OPERATE_DUP', 'OUT_OP_DUP', '(15, 0)', '16 : bump'))
    source = base.replace(old_n, new_n, 1).replace(old_t, new_t, 1)
    assert combined.segment(source, 'E') == old_e, 'E must be byte-identical'
    assert combined.segment(source, 'N') == new_n and combined.segment(source, 'T') == new_t
    assert source.replace(new_n, old_n, 1).replace(new_t, old_t, 1) == base
    return source


def write(directory, profile='all58'):
    directory = Path(directory)
    text = full_source(profile)
    source, source_sha256 = INPUTS[profile]
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(source.with_suffix('.inputs.json').read_text())
    layout = dict(metadata['outcome_layout'])
    layout.update(op_dup_drop=OUT_INDEX, unused=[i for i in layout['unused'] if i != OUT_INDEX])
    metadata.update(experiment='dup_hold_01', source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    control_policy=profile,
                    read_reencode_source={'path': str(source), 'sha256': source_sha256},
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    dup_kinds={'n_kind': N_KIND, 'n_event': '0x%04x' % N_EVENT, 't_kind': T_KIND,
                               'n_committed_event': '0xe6%02x' % T_KIND},
                    outcome_layout=layout,
                    segment_sha256={name: hashlib.sha256(combined.segment(text, name).encode()).hexdigest()
                                    for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1], 'strict' if '--strict' in sys.argv[2:] else 'all58')
