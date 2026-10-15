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
