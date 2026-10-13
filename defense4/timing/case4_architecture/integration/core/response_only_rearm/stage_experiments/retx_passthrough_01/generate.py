"""Forward retransmitted copies of already-forwarded segments instead of refusing them.

Candidate56 (combined_nt_diag_01) lets N refuse a retransmitted READ request, READ response,
SELECT response, SELECT or OPERATE copy: `sequence_guard` has no row for it, `first_event` takes a
count_* row, the packet recirculates as kind 255 and `read_terminal_t` drops it. A copy lost
downstream of the switch therefore cannot be repaired by TCP. This experiment adds table rows
only (no register, SALU or stage) that route such a copy through the existing `forward_original`
mechanism, which already carries kind 10. E and T are byte-identical to candidate56.
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'combined_nt_diag_01/evidence/full_01/response_only.p4'
SOURCE_SHA256 = '13b21e3c3407'  # prefix; the full hash is checked against the retained qualification record
spec = importlib.util.spec_from_file_location('retx_diag_generator', HERE.parent / 'combined_nt_01/generate.py')
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)
spec = importlib.util.spec_from_file_location('retx_diag_t', HERE.parent / 'combined_nt_diag_01/generate.py')
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)
NEG = '32w0x80000000&&&32w0x80000000'
RESPONSE_KINDS = ((6, 0xdb), (11, 0xcf))  # kind -> low byte of the negative server_diff (-37, -49)


def frozen():
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest().startswith(SOURCE_SHA256), 'candidate56 input changed'
    return raw.decode()


def once(text, old, new):
    assert text.count(old) == 1, ('anchor moved', old[:80], text.count(old))
    return text.replace(old, new, 1)


def edit_network(n):
    old = '(1w1,8w8,8w16,false,16w0xffeb,8w1..8w255,4w0,16w0):network_accept();'
    return once(n, old, old + old.replace('8w16,false', '8w24,false'))


def edit_guard(n):
    start = n.index('table guard{')
    end = n.index('apply{', start)
    table = n[start:end]
    abort = '(2w1,_,_,2w0,_,_,_,_,_,_,_,_,_):go_ret_abort();'
    assert table.count(abort) == 1
    rows = ''
    for kind in (5, 6, 7, 9, 11):
        found = re.findall(r'\(_,8w%d,8w%d,(_,_,1w1,8w1,1w0,16w0x993a,16w0x993a,[^)]*)\):go_ret_work\(\);' % (kind, kind), table)
        assert len(found) == 1, ('return row for kind', kind, len(found))
        rows += '(_,8w%d,8w8,%s):go_ret_work();' % (kind, found[0])
    return n[:start] + table.replace(abort, rows + abort, 1) + n[end:]


def edit_sequence_guard(n):
    n = once(n, 'action seq_resent(){', 'action seq_retx(){m.sequence_valid=(bit<3>)(8w2);}\n action seq_resent(){')
    n = once(n, 'table sequence_guard{key={m.client_diff:exact;m.server_diff:ternary;}actions={seq_ok;seq_fresh;seq_forward_fresh;seq_resent;',
             'table sequence_guard{key={m.client_diff:ternary;m.server_diff:ternary;}actions={seq_ok;seq_fresh;seq_forward_fresh;seq_retx;seq_resent;')
    rows = ''.join('(32w0,32w0xffffff%02x):seq_retx();(%s,32w0xffffff%02x):seq_retx();' % (low, NEG, low)
                   for _, low in RESPONSE_KINDS)
    rows += '(32w0xffffffec,32w0):seq_retx();(32w0xffffffec,%s):seq_retx();' % NEG
    n = once(n, '(32w0,32w0&&&32w0x80000000):seq_forward_fresh();}const default_action=seq_fresh();',
             '(32w0,32w0&&&32w0x80000000):seq_forward_fresh();' + rows + '}const default_action=seq_fresh();')
    return once(n, 'seq_replay;seq_fin;NoAction;}size=8;', 'seq_replay;seq_fin;NoAction;}size=16;')


def edit_first_event(n):
    def row(kind, seq, owner, client='_', server='_'):
        return '(8w%d,3w%d,_,32w0x%x&&&32w0xffff0000,%s,%s,_,_,_,_):forward_original();' % (kind, seq, owner, client, server)
    rows = (row(9, 2, 0xe0000, '32w0xffffffec') + row(9, 2, 0x50000, '32w0xffffffec') +
            row(11, 2, 0xe0000, '_', '32w0xffffffcf') + row(11, 2, 0x50000, '_', '32w0xffffffcf') +
            row(6, 2, 0xa0000, '_', '32w0xffffffdb') + row(6, 2, 0xc0000, '_', '32w0xffffffdb') +
            row(6, 2, 0x50000, '_', '32w0xffffffdb') +
            row(5, 3, 0x90000) + row(7, 3, 0xc0000))
    return once(n, '(8w5,3w3,_,_,_,_,_,_,_,_):count_resent();', rows + '(8w5,3w3,_,_,_,_,_,_,_,_):count_resent();')


def transform(n):
    for edit in (edit_network, edit_guard, edit_sequence_guard, edit_first_event):
        n = edit(n)
    return n


def full_source():
    base = frozen()
    old_n = combined.segment(base, 'N')
    new_n = transform(old_n)
    source = base.replace(old_n, new_n, 1)
    assert combined.segment(source, 'E') == combined.segment(base, 'E')
    assert combined.segment(source, 'T') == combined.segment(base, 'T')
    assert source.replace(new_n, old_n, 1) == base
    return source


def source_role(name):
    frozen()
    source = diag.source_role(name)
    return transform(source) if name == 'N' else source


def write(directory):
    directory = Path(directory)
    text = full_source()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'response_only.p4').write_text(text)
    metadata = json.loads(SOURCE.with_suffix('.inputs.json').read_text())
    metadata.update(experiment='retx_passthrough_01', source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    candidate56_source={'path': str(SOURCE), 'sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest()},
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    segment_sha256={name: hashlib.sha256(combined.segment(text, name).encode()).hexdigest()
                                    for name in ('N', 'E', 'T')})
    (directory / 'response_only.inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    write(sys.argv[1])
