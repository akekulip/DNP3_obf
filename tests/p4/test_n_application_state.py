"""Bounded application/READ identity packing versus independent two-cell semantics.

Only currently qualified identity domains are compared. This does not establish SDK
execution or replace the model campaign's stale/abort/duplicate packet checks.
"""
from functools import lru_cache
import itertools
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'p4/response_only.p4').read_text()
N = SOURCE.split('control n_Ingress(')[1].split('control n_IgDeparser(')[0]
CONTROL = tuple((function << 8) | app for function in (3, 4) for app in range(0xc0, 0xd0))
READ = tuple(shape | seq for shape in (0x100, 0x200) for seq in range(16))
CLASSES = (0, 0x300, 0x400, 0xfffffeff, 0xffffff0f)


@lru_cache(maxsize=64)
def block(text, pattern):
    match = re.search(pattern, text)
    assert match, pattern
    start = text.index('{', match.start())
    depth, end = 1, start
    while depth:
        end += 1
        depth += (text[end] == '{') - (text[end] == '}')
    return text[start + 1:end]


def salu(name):
    return block(block(N, r'\b' + name + r'\s*=\s*\{'), r'\bvoid\s+apply\(')


def table_rows(name):
    entries = block(block(N, r'\btable\s+' + name + r'\b'), r'\bconst\s+entries\s*=')
    return [(tuple(part.strip() for part in key.split(',')), action)
            for key, action in re.findall(r'\(([^()]*)\)\s*:\s*(\w+)\([^()]*\);', entries)]


def number(text):
    return int(text.split('w')[-1], 0)


def lookup(values):
    for key, action in table_rows('application_state_t'):
        if all(token == '_' or number(token) == value for token, value in zip(key, values)):
            return action
    return 'NoAction'


@lru_cache(maxsize=4)
def writes(name):
    return tuple(re.findall(r'v\.(crob|read_identity)\s*=(?!=)\s*([^;]+);', salu(name)))


def packed_write(name, cell, control=0, read=0):
    inputs = {'compare_application': control, 'compare_read_app': read}
    # Logical coordinates only: the source's two named16-bit fields remain authoritative.
    for field, expression in writes(name):
        high, low = {'crob': (15, 0), 'read_identity': (31, 16)}[field]
        match = re.fullmatch(r'm\.(\w+)\[(\d+):(\d+)\]', expression.strip())
        if match:
            field, src_high, src_low = match.groups()
            value = (inputs[field] >> int(src_low)) & ((1 << (int(src_high) - int(src_low) + 1)) - 1)
        else:
            value = number(expression.strip())
        mask = ((1 << (high - low + 1)) - 1) << low
        cell = (cell & ~mask) | ((value << low) & mask)
    return cell


def test_profiles_and_input_extractors_bound_all_packed_identity_bits():
    for name, expected in (('profile', {0xc0c0030c, 0xc0c0040c}),
                           ('response_profile', {0xc0c08100})):
        table = block(N, r'\btable\s+' + name + r'\b')
        keys = re.findall(r'([\w.]+)\s*:\s*(?:exact|ternary)', block(table, r'\bkey\s*='))
        column = keys.index('hdr.first.w0')
        patterns = {key[column] for key, action in table_rows(name) if action == 'eligible'}
        assert {number(pattern.split('&&&')[0]) for pattern in patterns} == expected
        masks = {number(pattern.split('&&&')[1]) for pattern in patterns}
        assert masks == ({0xc0f0ffff} if name == 'profile' else {0xc0f0ff00})
    compact = re.sub(r'\s+', '', N)
    assert 'm.compare_application=(bit<32>)(hdr.first.w0[15:8]++hdr.first.w0[23:16]);' in compact
    assert 'm.compare_application=(bit<32>)(hdr.first.w0[23:16]);' in compact
    assert 'm.compare_read_app=32w0x100|(bit<32>)(hdr.rd_req_full.app[3:0]);' in compact
    assert 'm.compare_read_app=32w0x200|(bit<32>)(hdr.rd_req_mx.app[3:0]);' in compact
    assert 'm.compare_read_app=shape|(bit<32>)(hdr.first.w0[19:16]);' in compact
    rows = table_rows('read_input_t')
    assert {key[3] for key, action in rows if action == 'read_response_input'} == {'8w0x4c', '8w0x73'}
    assert all(identity < 0x10000 for identity in CONTROL + READ)
    assert 0xffff not in READ


def test_table_domains_and_defaults_preserve_owned_update_paths():
    expected = {
        (1, 5, 1, 0): 'store_control_state', (1, 7, 1, 0): 'store_control_state',
        (0, 5, 4, 0): 'compare_control_state', (0, 7, 4, 0): 'compare_control_state',
        (0, 6, 4, 0): 'compare_control_state', (1, 9, 1, 0): 'store_read_state',
        (0, 9, 4, 0): 'compare_read_state', (0, 11, 4, 0): 'compare_read_state',
    }
    for values, action in expected.items():
        assert lookup(values) == action
    for stage, kind, phase, epoch in itertools.product(range(4), (0, 5, 6, 7, 9, 11, 255), range(5), (0, 1)):
        action = lookup((stage, kind, phase, epoch))
        if action.startswith('store_'):
            assert stage == phase == 1 and epoch == 0 and kind in (5, 7, 9)
    assert 'constdefault_action=NoAction();' in re.sub(r'\s+', '', block(N, r'\btable\s+application_state_t\b'))
    assert N.count('application_state_t.apply();') == 1


def test_source_update_masks_and_read_only_actions():
    assert writes('write_control_state') == (('crob', 'm.compare_application[15:0]'),
                                             ('read_identity', '16w0xffff'))
    assert writes('write_read_state') == (('read_identity', 'm.compare_read_app[15:0]'),)
    assert not writes('check_control_state') and not writes('check_read_state')
    assert 'r=v.crob;' in re.sub(r'\s+', '', salu('check_control_state'))
    assert 'if(v.read_identity==m.compare_read_app[15:0])' in re.sub(r'\s+', '', salu('check_read_state'))
    delta = block(N, r'\baction\s+control_state_delta\(')
    assert re.sub(r'\s+', '', delta) == 'm.diff_application=m.diff_application-m.compare_application[15:0];'
    compact = re.sub(r'\s+', '', N)
    assert 'if(m.stage==2w0&&m.work_phase==32w4&&(m.kind==8w5||m.kind==8w6||m.kind==8w7)){control_state_delta_t.apply();}' in compact
    apply = compact[compact.rindex('apply{'):]
    assert apply.index('application_state_t.apply();') < apply.index('control_state_delta_t.apply();') < apply.index('first_event.apply();')
    assert re.search(r'bit<16>\s+diff_application\b', SOURCE)
    cell = block(SOURCE, r'\bstruct\s+n_application_state_t\b')
    assert re.findall(r'bit<(\d+)>\s+(\w+)', cell) == [('16', 'crob'), ('16', 'read_identity')]
    assert 'Register<n_application_state_t,bit<1>>(1,{0,0}) application_state;' in N
    assert not re.search(r'\)\s+(?:application|read_app)\s*;', N)


def test_low16_control_delta_preserves_every_consumed_predicate():
    first_event = block(N, r'\btable\s+first_event\b')
    keys = re.findall(r'([\w.]+)\s*:\s*(?:exact|ternary)', block(first_event, r'\bkey\s*='))
    column = keys.index('m.diff_application')
    consumed = {key[column] for key, _ in table_rows('first_event')} - {'_'}
    assert consumed == {f'16w0x{value & 0xffff:x}&&&16w0xffff' for value in CLASSES}
    for stored, query in itertools.product((0,) + CONTROL, CONTROL + tuple(range(0xc0, 0xd0))):
        delta = stored - query
        assert -0x4cf <= delta <= 0x4cf
        for expected in CLASSES:
            assert ((delta & 0xffffffff) == expected) == ((delta & 0xffff) == (expected & 0xffff))


def test_read_identity_and_invalid_sentinel_preserve_matching():
    # A legacy short request has a four-bit identity too; it cannot collide with FFFF.
    queries = READ + tuple(range(16))
    for old, query in itertools.product((0, 0xffffffff) + queries, queries):
        new = old & 0xffff
        assert (old == query) == (new == (query & 0xffff))
    for low, read in itertools.product((0,) + CONTROL, READ):
        cell = packed_write('write_read_state', 0xffff0000 | low, read=read)
        assert cell == (read << 16) | low
        cell = packed_write('write_control_state', cell, control=0x3c0)
        assert cell == 0xffff03c0


def test_mixed_read_select_operate_and_duplicate_history_matches_two_cells():
    old_control, old_read, cell = 0, 0, 0
    rng = random.Random(0x6908)
    for _ in range(20000):
        operation = rng.choice(('read', 'control', 'read_compare', 'control_compare'))
        if operation == 'read':
            old_read = rng.choice(READ)
            cell = packed_write('write_read_state', cell, read=old_read)
            # The former app-forget(kind9) row was not invoked for packet_kind9.
            assert cell & 0xffff == old_control
        elif operation == 'control':
            old_control, old_read = rng.choice(CONTROL), 0xffffffff
            cell = packed_write('write_control_state', cell, control=old_control)
        elif operation == 'read_compare':
            query = rng.choice(READ)
            assert (old_read == query) == ((cell >> 16) == query)
        else:
            query = rng.choice(CONTROL + tuple(range(0xc0, 0xd0)))
            for expected in CLASSES:
                assert (((old_control - query) & 0xffffffff) == expected) == (
                    (((cell & 0xffff) - query) & 0xffff) == (expected & 0xffff))
        assert cell & 0xffff == old_control
        assert cell >> 16 == old_read & 0xffff
