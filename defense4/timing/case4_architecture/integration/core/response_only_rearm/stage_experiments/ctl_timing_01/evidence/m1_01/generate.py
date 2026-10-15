"""Generate the control-timing candidate from the qualified candidate61 source (Gate 3; see DESIGN.md).

Milestone 1 (this generator's `m1`): the SELECT transaction joins T's READ lane. N only:
  - read_terminal_t: SELECT (kind 5) commits to T as a REQUEST (commit_before_t(9)) instead of leaving through
    terminal_ack; the control response in owner state 9 (kind 6) is emitted to T as a RESPONSE (0x0b00).
  - first_event: the outstation's bare ACK in owner state 9 is a lane ACK (first_read_ack) instead of
    forward_original.
  - first_select and first_response stamp hdr.t0 as the READ actions do (deterministic bytes; T ignores t0q).
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
T0 = 'hdr.t0.setValid();hdr.t0.t0q=p.global_tstamp[31:8]++8w0;'

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
    n = once(n, 'action first_select(){hdr.event.event=16w0x0105;}',
             'action first_select(){hdr.event.event=16w0x0105;' + T0 + '}')
    n = once(n, 'action first_response(){hdr.event.event=16w0x0106;}',
             'action first_response(){hdr.event.event=16w0x0106;' + T0 + '}')
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


def full_source(milestone='m1'):
    base = frozen()
    old_n = combined.segment(base, 'N')
    new_n = {'m1': transform_n_m1}[milestone](old_n)
    text = base.replace(old_n, new_n, 1)
    for role in ('E', 'T'):
        assert combined.segment(text, role) == combined.segment(base, role), role
    assert text.replace(new_n, old_n, 1) == base
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
        raise SystemExit('usage: generate.py OUT_DIR [m1]')
    write(sys.argv[1], *(sys.argv[2:]))
