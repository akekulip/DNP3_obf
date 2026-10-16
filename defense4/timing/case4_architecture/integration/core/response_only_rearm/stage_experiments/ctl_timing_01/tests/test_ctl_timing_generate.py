"""ctl_timing_01 generator: E is never touched; m1 changes N only; m2 changes N and T; retained sources reproduce;
the routing rows sit ahead of the catch-all rows that would otherwise take them."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('ctl_generate', HERE / 'generate.py')
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
seg = gen.combined.segment


@pytest.mark.parametrize('milestone, changed', [('m1', {'N'}), ('m2', {'N', 'T'}), ('m3', {'N', 'T'}), ('m4', {'N', 'T'})])
def test_only_the_intended_roles_change(milestone, changed):
    base, text = gen.frozen(), gen.full_source(milestone)
    for role in ('N', 'E', 'T'):
        assert (seg(text, role) != seg(base, role)) == (role in changed), role


def test_retained_m1_source_reproduces():
    retained = HERE / 'evidence/m1_02/response_only.p4'
    if not retained.is_file():
        pytest.skip('retained m1 source absent')
    assert hashlib.sha256(gen.full_source('m1').encode()).hexdigest() == \
        hashlib.sha256(retained.read_bytes()).hexdigest()


def test_routing_rows_precede_catch_alls():
    text = gen.full_source('m2')
    terminal = text[text.index('table read_terminal_t'):]
    terminal = terminal[:terminal.index('const default_action')]
    for row in ('(8w5,32w0,32w0,_):commit_before_t(8w9)', '(8w6,32w0,32w0,_):emit_tev(16w0x0b00)',
                '(8w16,32w0,32w0,_):emit_tev(16w0x0b00)'):
        assert terminal.index(row) < terminal.index('(_,32w0,32w0,2w1):terminal_ack()'), row
    assert 'size=13' in terminal and terminal.count('):') == 13
    gen_access = text[text.index('table gen_access'):]
    gen_access = gen_access[:gen_access.index('default_action')]
    assert gen_access.index('t_KIND_OPERATE, _, _, 0) : live_admit_gen') < gen_access.index('(_, _, _, _, 0) : live_gen')
    assert 't_KIND_OPERATE_DUP' not in gen_access


def test_no_t0_stamp_on_events_the_loop_parser_reads_without_t0():
    text = gen.full_source('m2')
    for action in ('action first_select(){hdr.event.event=16w0x0105;}', 'action first_response(){hdr.event.event=16w0x0106;}',
                   'action first_response_op(){hdr.event.event=16w0x0110;}'):
        assert action in text


@pytest.mark.parametrize('milestone, directory', [('m2', 'm2_01'), ('m3', 'm3_01'), ('m4', 'm4_01')])
def test_retained_sources_reproduce_with_e_unchanged(milestone, directory):
    retained = HERE / 'evidence' / directory / 'response_only.p4'
    if not retained.is_file():
        pytest.skip('retained %s source absent' % milestone)
    text = gen.full_source(milestone)
    assert text == retained.read_text()
    assert hashlib.sha256(seg(text, 'E').encode()).hexdigest() == \
        'a144cd30b21c01c1f1242b10817691a3a5b2df123deccc005c3763339c5c1a10'


def test_m4_table_4_9_rows_precede_the_refusals_and_exhaustion_drops_operate():
    n = seg(gen.full_source('m4'), 'N')
    first = n[n.index('table first_event'):]
    first = first[:first.index('}}')]
    read = '(8w9,3w1,1w0,32w0xa0000&&&32w0xffff0000,_,_,_,_,_,_):first_read_request();'
    select = '(8w5,3w1,1w0,32w0xa0000&&&32w0xffff0000,_,_,_,_,_,_):first_select();'
    assert first.index(read) < first.index('(8w9,_,_,_,_,_,_,_,_,_):count_refused();')
    assert first.index(select) < first.index('(8w5,_,_,_,_,_,_,_,_,_):count_refused();')
    # state 9 (SELECT response outstanding) stays refused for READ; no OPERATE row is added
    assert '(8w9,3w1,1w0,32w0x90000' not in first and first.count('first_operate();') == 1
    m3 = seg(gen.full_source('m3'), 'N')
    m3_first = m3[m3.index('table first_event'):]
    m3_first = m3_first[:m3_first.index('}}')]
    assert first.count('):') == m3_first.count('):') + 2 <= 163      # two rows; the table is declared size=163
    t = seg(gen.full_source('m4'), 'T')
    verdict = t[t.index('table tin_verdict'):]
    verdict = verdict[:verdict.index('size = ')]
    assert '(t_KIND_OPERATE, _, 0, _, _, _, 32w0xffff, _) : drop_exhausted();' in verdict
    assert 'size = 23;' in t[t.index('table tin_verdict'):t.index('table token_verdict')]


def test_m5_changes_n_only_relative_to_m4():
    m4, m5 = gen.full_source('m4'), gen.full_source('m5')
    assert seg(m5, 'N') != seg(m4, 'N')
    assert seg(m5, 'E') == seg(m4, 'E') and seg(m5, 'T') == seg(m4, 'T')
    assert m5.replace(seg(m5, 'N'), seg(m4, 'N'), 1) == m4


def test_m5_retry_rows_precede_the_native_rows_and_requests_keep_busy_drop():
    n = seg(gen.full_source('m5'), 'N')
    guard = n[n.index('table guard{'):]
    guard = guard[guard.index('const entries={'):guard.index('}}')]
    rows = guard[len('const entries={'):].split(';')
    assert [r.split(':')[-1] for r in rows[:4]] == ['go_retry(8w6)', 'go_retry(8w11)', 'go_stale()', 'go_stale()']
    assert all(r.endswith(',2w1)') or r.endswith(',2w2)') for r in (x.split(':')[0] for x in rows[:4]))
    assert all(',_):' in r for r in rows[4:] if r)                  # every native row wildcards m.retry
    busy = n[n.index('table busy_t{'):]
    busy = busy[:busy.index('}const default_action')]
    for kind in (1, 2, 5, 7, 9, 12):
        assert '(8w%d,_,_):busy_drop();' % kind in busy
    assert 'allocate' not in n[n.index('action go_retry'):n.index('action go_stale')]
    retained = HERE / 'evidence/m5_10/response_only.p4'
    if retained.is_file():
        assert gen.full_source('m5') == retained.read_text()


def test_m6_changes_n_only_relative_to_m5():
    m5, m6 = gen.full_source('m5'), gen.full_source('m6')
    assert seg(m6, 'N') != seg(m5, 'N')
    assert seg(m6, 'E') == seg(m5, 'E') and seg(m6, 'T') == seg(m5, 'T')
    assert m6.replace(seg(m6, 'N'), seg(m5, 'N'), 1) == m5
    retained = HERE / 'evidence/m6_07/response_only.p4'   # the m6 successor; m6_01-m6_06 are retained attempts
    if retained.is_file():
        assert gen.full_source('m6') == retained.read_text()
