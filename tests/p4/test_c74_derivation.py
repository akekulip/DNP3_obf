"""c74 = c72 + const-entry rows only (results/builds/c74/derive_c74.py). Static checks on the two sources."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C72 = ROOT / 'results/builds/c72/response_only.p4'
C74 = ROOT / 'results/builds/c74/response_only.p4'
DERIVE = ROOT / 'results/builds/c74/derive_c74.py'


def table(text, head):
    start = text.index(head)
    body = text.index('const entries={', start) + len('const entries={')
    depth, end = 1, body
    while depth:
        depth += {'{': 1, '}': -1}.get(text[end], 0)
        end += 1
    rows = re.findall(r'\(([^()]*)\):(\w+)\(([^)]*)\);', text[body:end - 1])
    size = int(re.search(r'size=(\d+);', text[start:body]).group(1))
    return [(tuple(k.strip() for k in key.split(',')), act, arg) for key, act, arg in rows], size


def test_derivation_reproduces_c74_byte_for_byte(tmp_path):
    out, manifest = tmp_path / 'c74.p4', tmp_path / 'manifest.json'
    subprocess.run([sys.executable, str(DERIVE), str(C72), str(out), str(manifest)], check=True, capture_output=True)
    assert out.read_bytes() == C74.read_bytes()


def test_only_four_lines_change_and_line_numbers_are_kept():
    a, b = C72.read_text().split('\n'), C74.read_text().split('\n')
    assert len(a) == len(b)
    changed = [i + 1 for i, (x, y) in enumerate(zip(a, b)) if x != y]
    assert changed == [404, 405, 519, 529]          # first_event size, first_event entries, busy_t, guard


def test_busy_t_requests_retry_like_the_master_ack():
    old, old_size = table(C72.read_text(), 'table busy_t{')
    new, new_size = table(C74.read_text(), 'table busy_t{')
    assert (old_size, new_size) == (22, 28) and len(new) == 28
    by_kind = {}
    for key, act, _ in new:
        by_kind.setdefault(key[0], []).append((key[1:], act))
    ack_rows = [(k, a) for k, a in by_kind['8w3']]
    for kind in ('8w5', '8w7', '8w9'):
        assert by_kind[kind] == ack_rows == [(('2w0', '_'), 'busy_retry_ack'), (('2w1', '6w1'), 'busy_exhausted'),
                                             (('2w1', '_'), 'busy_retry_rst_next')]
    assert new[0] == (('_', '2w2', '_'), 'retry_stale', '')               # a stale retry still drops first
    assert [k[0] for k, a, _ in new if a == 'busy_drop'] == ['8w1', '8w2', '8w12']   # SYN, SYN-ACK, replay
    assert [r for r in old if r[0][0] not in ('8w5', '8w7', '8w9')] == [r for r in new if r[0][0] not in ('8w5', '8w7', '8w9')]


def test_guard_retry_rows_copy_each_go_new_row_and_precede_go_stale():
    old, _ = table(C72.read_text(), 'table guard{')
    new, size = table(C74.read_text(), 'table guard{')
    assert size == 57 and len(new) == 57
    added = [row for row in new if row not in old]
    assert [(r[1], r[2]) for r in added] == [('go_retry', '8w9'), ('go_retry', '8w5'), ('go_retry', '8w7')]
    stale = next(i for i, r in enumerate(new) if r[1] == 'go_stale')
    for key, act, arg in added:
        assert new.index((key, act, arg)) < stale and key[-1] == '2w1'
        native = next(r for r in new if r[1] == 'go_new' and r[2] == arg)
        assert native[0][:-1] == key[:-1] and native[0][-1] == '_'
    assert [r for r in new if r not in added] == old


def test_first_event_adds_exactly_the_four_late_handshake_ack_rows():
    old, old_size = table(C72.read_text(), '@stage(9) table first_event{')
    new, size = table(C74.read_text(), '@stage(9) table first_event{')
    assert (old_size, size, len(new)) == (401, 405, 405)
    added = [row for row in new if row not in old]
    assert [r for r in new if r not in added] == old
    assert len(added) == 4 and {r[1] for r in added} == {'forward_original'}
    want = set()
    for client_diff in ('32w0xffffffe7', '32w0xffffffe5'):          # -25 (mixed READ), -27 (integrity READ)
        for owner in ('32w0xd0000&&&32w0xffff0000', '32w0xe0000&&&32w0xffff0000'):
            want.add(('8w3', '1w0', owner, client_diff, '32w0x00000000', '2w1', '8w0x10', '_', '1w0', '_', '_', '_',
                      '_', '_', '_', '_'))
    assert {r[0] for r in added} == want
    # no other kind-3 row can match owner 0xd/0xe, so placement does not shadow or get shadowed
    others = [r for r in old if r[0][0] == '8w3' and r[0][2].split('&&&')[0] in ('32w0xd0000', '32w0xe0000')]
    assert others == []


def test_no_action_or_declaration_outside_const_entries_changes():
    strip = re.compile(r'const entries=\{.*?\}\s*(?:const default_action|\})', re.S)
    a = re.sub(r'size=\d+;', '', strip.sub('', C72.read_text()))
    b = re.sub(r'size=\d+;', '', strip.sub('', C74.read_text()))
    b = b.replace(' /* c74: READ/SELECT/OPERATE retry through n_RETRY_BUDGET like kind 3; SYN, SYN-ACK, replay drop */', '')
    assert a == b
