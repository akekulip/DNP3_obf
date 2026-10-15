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


@pytest.mark.parametrize('milestone, changed', [('m1', {'N'}), ('m2', {'N', 'T'})])
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
