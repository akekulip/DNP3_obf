"""c75 = c72 + the request retries (H1) only (results/builds/c75/derive_c75.py). Static checks on the sources.

c75 is c74 without the four late-handshake-ACK first_event rows (H2): c74 with lines 404-405 taken from c72.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDS = ROOT / 'results/builds'
C72 = BUILDS / 'c72/response_only.p4'
C74 = BUILDS / 'c74/response_only.p4'
C75 = BUILDS / 'c75/response_only.p4'
DERIVE = BUILDS / 'c75/derive_c75.py'
ROWS = BUILDS / 'c75/c72_to_c75_rows.json'
H2_ROW = re.compile(r'\(8w3,1w0,32w0x[de]0000&&&32w0xffff0000,32w0xffffffe[57],32w0x00000000,2w1,8w0x10,_,1w0,'
                    r'_,_,_,_,_,_,_\):forward_original\(\);')


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


def changed(a, b):
    x, y = a.read_text().split('\n'), b.read_text().split('\n')
    assert len(x) == len(y)
    return [i + 1 for i, (p, q) in enumerate(zip(x, y)) if p != q]


def test_derivation_reproduces_c75_byte_for_byte(tmp_path):
    out, manifest = tmp_path / 'c75.p4', tmp_path / 'manifest.json'
    subprocess.run([sys.executable, str(DERIVE), str(C72), str(out), str(manifest)], check=True, capture_output=True)
    assert out.read_bytes() == C75.read_bytes()
    record = json.loads(manifest.read_text())
    assert record['changed_c72_lines'] == [519, 529]
    assert not any('first_event' in edit['edit'] or 'H2' in edit['edit'] for edit in record['edits'])


def test_only_the_retry_lines_change_against_c72():
    assert changed(C72, C75) == [519, 529]          # busy_t, guard


def test_c75_is_c74_with_lines_404_405_from_c72():
    assert changed(C74, C75) == [404, 405]          # first_event size, first_event entries
    c72, c75 = C72.read_text().split('\n'), C75.read_text().split('\n')
    assert c75[403:405] == c72[403:405]


def test_the_four_late_ack_forward_original_rows_are_absent():
    text = C75.read_text()
    assert H2_ROW.findall(C74.read_text()) and len(H2_ROW.findall(C74.read_text())) == 4   # the pattern has teeth
    assert H2_ROW.findall(text) == []
    assert '/* c74: the late handshake ACK' not in text
    assert table(text, '@stage(9) table first_event{') == table(C72.read_text(), '@stage(9) table first_event{')


def test_retry_tables_equal_c74s():
    for head in ('table busy_t{', 'table guard{'):
        assert table(C75.read_text(), head) == table(C74.read_text(), head)
    rows, size = table(C75.read_text(), 'table busy_t{')
    assert size == 28 and [k[0] for k, a, _ in rows if a == 'busy_drop'] == ['8w1', '8w2', '8w12']
    _, size = table(C75.read_text(), 'table guard{')
    assert size == 57


def test_no_action_or_declaration_outside_const_entries_changes():
    strip = re.compile(r'const entries=\{.*?\}\s*(?:const default_action|\})', re.S)
    a = re.sub(r'size=\d+;', '', strip.sub('', C72.read_text()))
    b = re.sub(r'size=\d+;', '', strip.sub('', C75.read_text()))
    b = b.replace(' /* c74: READ/SELECT/OPERATE retry through n_RETRY_BUDGET like kind 3; SYN, SYN-ACK, replay drop */', '')
    assert a == b


def test_row_record_matches_the_sources():
    record = json.loads(ROWS.read_text())
    assert set(record) >= {'busy_t', 'guard', 'c72_source_sha256', 'c75_source_sha256'}
    assert 'first_event' not in record
    import hashlib
    assert record['c72_source_sha256'] == hashlib.sha256(C72.read_bytes()).hexdigest()
    assert record['c75_source_sha256'] == hashlib.sha256(C75.read_bytes()).hexdigest()
    c74 = json.loads((BUILDS / 'c74/c72_to_c74_rows.json').read_text())
    assert record['busy_t'] == c74['busy_t'] and record['guard'] == c74['guard']
