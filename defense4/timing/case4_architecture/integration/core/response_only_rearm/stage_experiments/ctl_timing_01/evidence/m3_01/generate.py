"""Generate the control-timing candidate from the qualified candidate61 source (Gate 3; see DESIGN.md).

Milestone 1 (this generator's `m1`): the SELECT transaction joins T's READ lane. N only:
  - read_terminal_t: SELECT (kind 5) commits to T as a REQUEST (commit_before_t(9)) instead of leaving through
    terminal_ack; the control response in owner state 9 (kind 6) is emitted to T as a RESPONSE (0x0b00).
  - first_event: the outstation's bare ACK in owner state 9 is a lane ACK (first_read_ack) instead of
    forward_original.
  - no t0 stamp for SELECT/response events (the loop parser reads them without hdr.t0; T ignores t0q).
The OPERATE transaction (owner state 0xc) is untouched in m1. E and T are byte-identical; the generator asserts
both, and that putting the original N back reconstructs the input.
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'seg61_02/evidence/full_04/response_only.p4'
SOURCE_SHA256 = '1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa'

spec = importlib.util.spec_from_file_location('ctl_timing_combined', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def frozen():
    raw = SOURCE.read_bytes()
    assert digest(raw) == SOURCE_SHA256, 'qualified candidate61 input changed'
    return raw.decode()


def once(text, old, new):
    count = text.count(old)
    assert count == 1, ('anchor not found exactly once', count, old[:120])
    return text.replace(old, new, 1)


def transform_n_m1(n):
    # No t0 stamp on first_select/first_response: N's loop parser (envelope_event) reads events 0x0105/0x0106
    # without hdr.t0, so stamping it shifts the loop packet (model_control_timing_m1_01_02: SELECT reparsed as
    # packet_kind 0 and lost). T never reads t0q, so commit_before_t/emit_tev may carry an unset value.
    n = once(n, '(8w10,3w1,_,32w0x90000&&&32w0xffff0000,_,_,_,_,_,_):forward_original();',
             '(8w10,3w1,_,32w0x90000&&&32w0xffff0000,_,_,_,_,_,_):first_read_ack();')
    # read_terminal_t: SELECT before the direction-1 terminal_ack row, the state-9 response before terminal_strip.
    n = once(n, 'actions={terminal_open;terminal_synack;terminal_ack;commit_before_t;emit_tev;terminal_strip;'
                'terminal_abort;}size=10;',
             'actions={terminal_open;terminal_synack;terminal_ack;commit_before_t;emit_tev;terminal_strip;'
             'terminal_abort;}size=12;')
    n = once(n, '(8w11,32w0,32w0,_):emit_tev(16w0x0b00);',
             '(8w11,32w0,32w0,_):emit_tev(16w0x0b00);(8w5,32w0,32w0,_):commit_before_t(8w9);'
             '(8w6,32w0,32w0,_):emit_tev(16w0x0b00);')
    return n


def transform_n_m2(n):
    """m1, plus the OPERATE transaction: ACK in owner state 0xc is a lane ACK; its response (kind 16) is a RESPONSE."""
    n = transform_n_m1(n)
    n = once(n, '(8w10,3w1,_,32w0xc0000&&&32w0xffff0000,_,_,_,_,_,_):forward_original();',
             '(8w10,3w1,_,32w0xc0000&&&32w0xffff0000,_,_,_,_,_,_):first_read_ack();')
    n = once(n, 'terminal_abort;}size=12;', 'terminal_abort;}size=13;')
    n = once(n, '(8w6,32w0,32w0,_):emit_tev(16w0x0b00);',
             '(8w6,32w0,32w0,_):emit_tev(16w0x0b00);(8w16,32w0,32w0,_):emit_tev(16w0x0b00);')
    return n


def transform_t_m2(t):
    """An admitted OPERATE also opens a READ-lane generation and t0 (its J hold rows are unchanged). Kind 15
    (OPERATE duplicate) gets no lane rows. No READ-lane blocker clone for OPERATE (DESIGN.md, change 4)."""
    t = once(t, """            (t_T_IN, t_KIND_REQUEST, _, _, 0) : live_admit_gen();
            (_, _, _, _, 0) : live_gen();
        }
        default_action = bad_gen(); size = 9;""", """            (t_T_IN, t_KIND_REQUEST, _, _, 0) : live_admit_gen();
            (t_T_IN, t_KIND_OPERATE, 0, _, 0) : live_gen();
            (t_T_IN, t_KIND_OPERATE, _, _, 0) : live_admit_gen();
            (_, _, _, _, 0) : live_gen();
        }
        default_action = bad_gen(); size = 11;""")
    t = once(t, """            (t_T_IN, t_KIND_REQUEST, _, _) : admit_t0();
        }
        default_action = read_t0(); size = 3;""", """            (t_T_IN, t_KIND_REQUEST, _, _) : admit_t0();
            (t_T_IN, t_KIND_OPERATE, _, 32w0xffff) : read_t0();
            (t_T_IN, t_KIND_OPERATE, 0, _) : read_t0();
            (t_T_IN, t_KIND_OPERATE, _, _) : admit_t0();
        }
        default_action = read_t0(); size = 6;""")
    return t


def transform_t_m3(t):
    """m2, plus a per-response piggyback bound (DESIGN.md, change 5 as revised): ack_seen_reg records the lane
    generation of the last standalone ACK; a held response whose generation saw no ACK (piggybacked) may go at
    t0 + pb. Separate-ACK responses keep a_commit + gap and the readiness fallback. pb is set_params' last
    argument; its default equals the readiness default, so an unset pb changes nothing."""
    t = transform_t_m2(t)
    t = once(t, """    action set_params(bit<32> da, bit<32> readiness, bit<32> cap, bit<32> gap, bit<32> op_j,
                      bit<32> budget, bit<32> enabled) {
        md.da = da; md.readiness = readiness; md.gap = gap; md.op_j = op_j;
        md.budget_cap = budget; md.enabled = enabled;
    }""", """    action set_params(bit<32> da, bit<32> readiness, bit<32> cap, bit<32> gap, bit<32> op_j,
                      bit<32> budget, bit<32> enabled, bit<32> pb) {
        md.da = da; md.readiness = readiness; md.gap = gap; md.op_j = op_j;
        md.budget_cap = budget; md.enabled = enabled; md.pb_bound = pb;
    }""")
    t = once(t, "default_action = set_params(2000000, 12000000, 16000000, 800000, 2400000, 240000, 1); size = 1;",
             "default_action = set_params(2000000, 12000000, 16000000, 800000, 2400000, 240000, 1, 12000000); size = 1;")
    t = once(t, "    bit<32> now_m_readiness; bit<32> readiness_delta;",
             "    bit<32> now_m_readiness; bit<32> readiness_delta;\n"
             "    bit<32> pb_bound; bit<32> now_m_pb; bit<32> pb_delta; bit<32> ack_seen_diff;")
    t = once(t, "        md.now_m_da = md.now - md.da; md.now_m_readiness = md.now - md.readiness; md.now_m_gap = md.now - md.gap;\n    }",
             "        md.now_m_da = md.now - md.da; md.now_m_readiness = md.now - md.readiness; md.now_m_gap = md.now - md.gap;\n"
             "        md.now_m_pb = md.now - md.pb_bound;\n    }\n"
             "    action compute_pb_delta() { md.pb_delta = md.now_m_pb - md.t0_v; }")
    t = once(t, """    table child_seen0_access {""", """    // Piggyback detection: the last lane generation a standalone ACK was seen in. A response held in a
    // generation with no ACK (TCP piggybacked the ACK on it) reads a non-zero diff.
    Register<bit<32>, bit<1>>(1, 0xffffffff) ack_seen_reg;
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_seen_reg) ack_seen_mark = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = 0; value = md.cur_gen; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(ack_seen_reg) ack_seen_read = {
        void apply(inout bit<32> value, out bit<32> out_value) { out_value = value ^ md.cur_gen; }
    };
    action mark_ack_seen() { md.ack_seen_diff = ack_seen_mark.execute(0); }
    action read_ack_seen() { md.ack_seen_diff = ack_seen_read.execute(0); }
    table ack_seen_access {
        key = { ig_intr_md.ingress_port : ternary; md.event_kind : ternary; hdr.ladder.role : ternary;
                md.e_bad : ternary; }
        actions = { mark_ack_seen; read_ack_seen; NoAction; }
        const entries = {
            (t_T_IN, t_KIND_ACK, _, 0) : mark_ack_seen();
            (t_HELD_RETURN, _, t_ROLE_RESP_HELD, _) : read_ack_seen();
        }
        default_action = NoAction(); size = 2;
    }
    table child_seen0_access {""")
    t = once(t, """        key = { md.e_bad : ternary; md.enabled : ternary; md.lgen_diff : ternary; md.readiness_delta : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; }
        actions = { set_resp_go; }
        const entries = {
            (0, 0, _, _, _, _) : set_resp_go(0);
            (0, _, 0, 32w0 &&& 32w0x80000000, _, _) : set_resp_go(1);
            (0, _, 0, _, 32w0 &&& 32w0x80000000, 0) : set_resp_go(1);
        }
        default_action = set_resp_go(0); size = 3;""", """        key = { md.e_bad : ternary; md.enabled : ternary; md.lgen_diff : ternary; md.readiness_delta : ternary;
                md.gap_delta : ternary; md.commit_diff : ternary; md.ack_seen_diff : ternary; md.pb_delta : ternary; }
        actions = { set_resp_go; }
        const entries = {
            (0, 0, _, _, _, _, _, _) : set_resp_go(0);
            (0, _, 0, 32w0 &&& 32w0x80000000, _, _, _, _) : set_resp_go(1);
            (0, _, 0, _, 32w0 &&& 32w0x80000000, 0, _, _) : set_resp_go(1);
            (0, _, 0, _, _, _, 0, _) : set_resp_go(0);                          // a standalone ACK was seen
            (0, _, 0, _, _, _, _, 32w0 &&& 32w0x80000000) : set_resp_go(1);     // piggybacked: t0 + pb passed
        }
        default_action = set_resp_go(0); size = 5;""")
    t = once(t, "        child_seen0_access.apply(); child_seen1_access.apply(); child_seen2_access.apply();\n",
             "        child_seen0_access.apply(); child_seen1_access.apply(); child_seen2_access.apply();\n"
             "        ack_seen_access.apply();\n")
    t = once(t, "            compute_da_delta(); compute_readiness_delta(); read_lgen_diff();",
             "            compute_da_delta(); compute_readiness_delta(); compute_pb_delta(); read_lgen_diff();")
    return t


def full_source(milestone='m1'):
    base = frozen()
    old_n, old_t = combined.segment(base, 'N'), combined.segment(base, 'T')
    new_n = {'m1': transform_n_m1, 'm2': transform_n_m2, 'm3': transform_n_m2}[milestone](old_n)
    new_t = {'m1': lambda t: t, 'm2': transform_t_m2, 'm3': transform_t_m3}[milestone](old_t)
    text = base.replace(old_n, new_n, 1).replace(old_t, new_t, 1)
    assert combined.segment(text, 'E') == combined.segment(base, 'E')
    assert text.replace(new_n, old_n, 1).replace(new_t, old_t, 1) == base
    return text


def write(directory, milestone='m1'):
    directory = Path(directory)
    text = full_source(milestone)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    (directory / 'generate.py').write_bytes(Path(__file__).read_bytes())
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='ctl_timing_01', milestone=milestone,
                    source_sha256=digest(text.encode()),
                    candidate61_source={'path': str(SOURCE), 'sha256': SOURCE_SHA256},
                    generator_sha256=digest(Path(__file__).read_bytes()),
                    changed_roles=['N'] if milestone == 'm1' else ['N', 'T'],
                    segment_sha256={name: digest(combined.segment(text, name).encode()) for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps({'source_sha256': metadata['source_sha256'], 'segments': metadata['segment_sha256']}, indent=1))


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        raise SystemExit('usage: generate.py OUT_DIR [m1|m2|m3]')
    write(sys.argv[1], *(sys.argv[2:]))
