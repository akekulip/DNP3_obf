"""Source-bound regressions for the early E img_wend operation.

The independent reference is the previous 32-bit operation: return old_wend + qx,
then add t to stored wend only on a commit. These checks do not replace SDK/model
or hardware validation. They use only the current P4 and no retained build files.
"""
import ast
import itertools
from pathlib import Path
import random
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'p4/response_only.p4').read_text()
PARSER = SOURCE.split('parser r_EgParser(')[1].split('control r_Egress(')[0]
EGRESS = SOURCE.split('control r_Egress(')[1].split('control r_EgDeparser(')[0]
MASK = 0xffffffff
EDGES = (0, 1, 2, 49, 60, 61, 91, 134, 141, 158,
         0x7fffffff, 0x80000000, 0xffffffc4, MASK)


def block(text, pattern):
    match = re.search(pattern, text)
    assert match, pattern
    start = text.index('{', match.start())
    depth = 1
    end = start
    while depth:
        end += 1
        depth += (text[end] == '{') - (text[end] == '}')
    return text[start + 1:end]


def rows(name):
    table = block(EGRESS, r'\btable\s+' + name + r'\b')
    entries = block(table, r'\bconst\s+entries\s*=')
    entries = re.sub(r'\(bit<\d+>\)', '', entries)
    return [(tuple(k.strip() for k in key.split(',')), action)
            for key, action in re.findall(r'\(([^()]*)\)\s*:\s*(\w+)\([^()]*\);', entries)]


def number(token):
    if token == 'r_SH_SYNACK_OK':
        return 1
    if token == 'r_SH_ACK':
        return 4
    return int(token.split('w')[-1], 0)


def lookup(table, values):
    for key, action in table:
        assert len(key) == len(values)
        matches = []
        for token, value in zip(key, values):
            if token == '_':
                matches.append(True)
            elif '&&&' in token:
                expected, mask = (number(part.strip()) for part in token.split('&&&'))
                matches.append(value & mask == expected & mask)
            else:
                matches.append(value == number(token))
        if all(matches):
            return action
    return 'NoAction'


def assignments(body):
    return [(target.replace('.', '_'), ast.parse(expr.replace('.', '_'), mode='eval').body)
            for target, expr in re.findall(r'([\w.]+)\s*=\s*([^;]+);', body)]


def evaluate(node, values):
    if isinstance(node, ast.Name):
        return values[node.id]
    assert isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub))
    left, right = evaluate(node.left, values), evaluate(node.right, values)
    return left + right if isinstance(node.op, ast.Add) else left - right


def execute(program, **values):
    for target, expression in program:
        values[target] = evaluate(expression, values) & MASK
    return values


def salu(name):
    outer = block(EGRESS, r'\b' + name + r'\s*=\s*\{')
    return assignments(block(outer, r'\bvoid\s+apply\('))


def test_grant_implies_zero_frontier_from_its_actual_writers():
    assert len(re.findall(r'm\.grant\s*=', PARSER + EGRESS)) == 2
    assert re.search(r'm\.grant\s*=\s*\(bit<1>\)\(0\)', PARSER)
    assert re.search(r'm\.grant\s*=\s*\(bit<1>\)\(acct_try\.execute\(m.idx\)\)', EGRESS)
    table = block(EGRESS, r'\btable\s+acct_t\b')
    keys = re.findall(r'([\w.]+)\s*:\s*(?:exact|ternary)', block(table, r'\bkey\s*='))
    frontier = keys.index('m.front_ret')
    grants = [key for key, action in rows('acct_t') if action == 'do_acct_try']
    assert len(grants) == 3
    assert all(key[frontier] == '0' for key in grants)
    assert len(re.findall(r'm\.front_ret\s*=', EGRESS)) == 1
    apply = EGRESS[EGRESS.rindex('    apply {'):]
    assert apply.index('front_t.apply();') < apply.index('acct_t.apply();') < apply.index('img_wend_t.apply();')


def test_early_commit_selection_matches_previous_classifier_priority():
    classifier, wend = rows('classify_fwd'), rows('img_wend_t')
    assert sum(action == 'out_commit' for _, action in classifier) == 1
    for front, grant in itertools.product(EDGES, (0, 1)):
        if grant and front:
            continue  # Excluded by the checked writer invariant above.
        values = [front, grant] + [0] * 14
        old_commit = lookup(classifier, values) == 'out_commit'
        new_commit = lookup(wend, (0, 1, 4, grant)) == 'do_wend_commit'
        assert new_commit == old_commit


def test_handshake_ack_and_noack_table_domains_are_preserved():
    table = rows('img_wend_t')
    for first, direction, shape, grant in itertools.product(range(2), range(4), range(8), range(2)):
        if first and direction == 1 and shape == 1:
            expected = 'do_wend_arm'
        elif direction == 1 and shape == 4:
            expected = 'do_wend_commit' if grant else 'do_wend_fwd'
        elif direction == 2 and shape == 4:
            expected = 'do_wend_rev'
        else:
            expected = 'NoAction'
        assert lookup(table, (first, direction, shape, grant)) == expected


def test_forward_sequence_finish_is_ack_only_after_the_classifier():
    assert EGRESS.count('finish_forward_sequence_t.apply();') == 1
    compact = re.sub(r'\s+', '', EGRESS)
    qualification = ('if((bit<8>)m.dir==1&&((bit<8>)m.shape==r_SH_ACK||'
                     '(bit<8>)m.shape==r_SH_NOACK)&&(bit<8>)m.mode==1)')
    qualified = block(compact, re.escape(qualification))
    assert 'classify_fwd.apply();' in qualified
    assert 'finish_forward_sequence_t.apply();' in qualified
    guard = block(EGRESS, r'if\s*\(\(bit<8>\)m.shape\s*==\s*r_SH_ACK\)\s*\{')
    assert guard.strip() == 'finish_forward_sequence_t.apply();'
    apply = EGRESS[EGRESS.rindex('    apply {'):]
    assert apply.index('img_wend_t.apply();') < apply.index('classify_fwd.apply();') < apply.index('finish_forward_sequence_t.apply();')
    assert 'm.r = wend_commit.execute(m.idx);' in EGRESS
    assert 'm.r = wend_fwd.execute(m.idx);' in EGRESS


@pytest.mark.parametrize('commit', (False, True), ids=('retransmission', 'commit'))
def test_forward_32bit_arithmetic_matches_previous_atomic_operation(commit):
    operation = salu('wend_commit' if commit else 'wend_fwd')
    finish = assignments(block(EGRESS, r'\baction\s+finish_forward_sequence\('))
    rng = random.Random(0x69)
    samples = list(itertools.product(EDGES, repeat=3))
    samples += [tuple(rng.getrandbits(32) for _ in range(3)) for _ in range(4096)]
    for stored, qx, increment in samples:
        expected_stored = (stored + increment) & MASK if commit else stored
        expected_sequence = (stored + qx) & MASK
        after = execute(operation, v=stored, m_qx=qx, m_t=increment)
        emitted = execute(finish, m_r=after['rv'], m_qx=qx)
        assert (after['v'], emitted['hdr_tcp_seq']) == (expected_stored, expected_sequence)


def test_reverse_and_handshake_32bit_operations_are_unchanged():
    assert 'm.r = wend_rev.execute(m.idx);' in EGRESS
    reverse, arm = salu('wend_rev'), salu('wend_arm')
    for stored, qx in itertools.product(EDGES, repeat=2):
        after = execute(reverse, v=stored, m_qx=qx)
        assert (after['v'], after['rv']) == (stored, (qx - stored) & MASK)
        assert execute(arm, v=stored, m_qx=qx)['v'] == qx
