"""c74 connection-start correction regressions (labelled, outside the model gate): case table, verdict rule, pass
history and request checks. Pure functions only; the model run is scripts/model/run_connection_fix.py."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/model'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import model_connection_fix as cf  # noqa: E402
import model_connection_start as cs  # noqa: E402
from test_connection_start import PREFIX_48, cell, frame, ingress  # noqa: E402

READ = dict(direction='m2r', seq=101, flags=0x18, payload_len=25)


def test_every_per_class_scenario_runs_for_both_read_classes_and_singles_once():
    names = [c['case'] for c in cf.CASES]
    assert len(names) == len(set(names)) == 2 * len(cf.PER_CLASS_ORDER) + len(cf.SINGLE_ORDER)
    for scenario in cf.PER_CLASS_ORDER:
        assert {c['read_class'] for c in cf.CASES if c['scenario'] == scenario} == {'mixed', 'integrity'}
    for scenario in cf.SINGLE_ORDER:
        assert [c['read_class'] for c in cf.CASES if c['scenario'] == scenario] == [None]
    assert set(cf.SCENARIOS) == set(cf.CASE_FUNCTIONS) == set(cf.PER_CLASS_ORDER + cf.SINGLE_ORDER)
    for case in cf.CASES:
        if case['read_class']:
            assert case['read_length'] == {'mixed': 25, 'integrity': 27}[case['read_class']]


def test_the_required_scenarios_are_present_and_forced_cases_are_labelled():
    required = {'H1', 'H2', 'H2r', 'collision', 'collision_causal', 'H1prime', 'exhaust', 'stale_retry', 'dup_during_retry',
                'dup_after_admit', 'stale_ack', 'reconnect', 'rst_at_start', 'fin_at_start', 'rst_read_outstanding',
                'fin_after_exchange', 'operate_without_select', 'operate_retry_before_select_response',
                'operate_mismatched_crob', 'H1_sbo'}
    assert required <= set(cf.SCENARIOS)
    forced = {s for s, v in cf.SCENARIOS.items() if v[0] == 'forced_register'}
    assert forced == {'H1prime', 'exhaust', 'stale_retry', 'dup_during_retry', 'operate_retry_before_select_response',
                      'syn_busy'}
    assert {s for s, v in cf.SCENARIOS.items() if v[1] == 'residual'} == {'residual_class_mismatch',
                                                                           'residual_later_read'}


def test_verdict_never_passes_an_unreached_state_or_a_failed_check():
    assert cf.verdict(True, True) == 'pass'
    assert cf.verdict(None, True) == 'pass'
    assert cf.verdict(True, False) == 'fail'
    assert cf.verdict(None, False) == 'fail'
    assert cf.verdict(False, True) == 'state_not_reached'
    assert cf.Checks().ok() is False                    # a case with no checks never passes


def test_exhaustion_sequence_is_the_compiled_budget():
    budget = int(re.search(r'n_RETRY_BUDGET=(\d+);', (ROOT / 'results/builds/c74/response_only.p4').read_text()).group(1))
    assert budget == cf.RETRY_BUDGET == 32
    assert cf.EXHAUSTION.count('busy_retry_ack') == 1 and cf.EXHAUSTION.count('busy_exhausted') == 1
    assert cf.EXHAUSTION.count('busy_retry_rst_next') == budget - 1 and len(cf.EXHAUSTION) == budget + 1


def claim(pid, port, before, after, extra):
    return ingress(pid, port, frame(101, 901, 0x18, b'x' * 25, prefix=PREFIX_48),
                   [(4, 'n_Ingress.work.dispatch', 'hit', 'n_Ingress.work.claim_work', False, before, after)] + extra)


def busy(name):
    return [(7, 'n_Ingress.busy_t', 'hit', 'n_Ingress.' + name, False, None, None)]


def first(name, default=False):
    return [(9, 'n_Ingress.first_event', 'hit', ('n_Ingress.' + name) if name != 'NoAction' else name, default,
             None, None)]


def lap(pid, port, name):
    return ingress(pid, port, frame(101, 901, 0x18, b'x' * 25, prefix=PREFIX_48),
                   [(9, 'n_Ingress.continuation_t', 'hit', 'n_Ingress.' + name, False, None, None)])


def test_history_reads_retries_admission_laps_and_t_ingress():
    lines = (claim('0x40', 48, cell(1, 9), cell(1, 9), busy('busy_retry_ack'))
             + claim('0x41', 68, cell(2, 9), cell(2, 9), busy('busy_retry_rst_next'))
             + claim('0x42', 68, cell(4, 9), cell(1, 10), first('first_read_request'))
             + lap('0x43', 68, 'next_stage') + lap('0x44', 68, 'commit_before_t') + lap('0x45', 180, 'next_stage'))
    hist = cf.history(cs.parse_passes(lines), READ)
    assert [h['busy'] for h in hist] == ['busy_retry_ack', 'busy_retry_rst_next', None, None, None, None]
    assert [h['claim'] for h in hist] == [True, True, True, False, False, False]
    summary = cf.summarize(hist, 180)
    assert summary == dict(busy=['busy_retry_ack', 'busy_retry_rst_next'], first_event=['first_read_request'],
                           loss=[], aborts=0, terminal_ack=0, t_ingress=1, passes=6)
    checks = cf.Checks()
    cf.request_checks(checks, 'READ', summary, 'first_read_request')
    assert checks.ok(), [r for r in checks.rows if not r['ok']]


def test_request_checks_fail_on_the_c72_busy_drop_and_on_two_admissions():
    dropped = cf.summarize(cf.history(cs.parse_passes(claim('0x50', 48, cell(1, 9), cell(1, 9), busy('busy_drop'))),
                                      READ), 180)
    checks = cf.Checks()
    cf.request_checks(checks, 'READ', dropped, 'first_read_request')
    failed = {r['name'] for r in checks.rows if not r['ok']}
    assert {'READ_first_claim_busy_retry_ack', 'READ_only_retry_busy_actions', 'READ_no_loss_action',
            'READ_admitted_once_by_first_read_request', 'READ_T_ingress_once'} <= failed
    twice = dict(busy=[], first_event=['first_read_request', 'first_read_request'], loss=[], aborts=0,
                 terminal_ack=0, t_ingress=2, passes=2)
    checks = cf.Checks()
    cf.request_checks(checks, 'READ', twice, 'first_read_request', retried=False)
    assert {r['name'] for r in checks.rows if not r['ok']} == {'READ_admitted_once_by_first_read_request',
                                                               'READ_T_ingress_once'}


def test_exhaustion_and_stale_actions_count_as_loss():
    for name in ('busy_exhausted', 'retry_stale', 'busy_drop'):
        summary = cf.summarize(cf.history(cs.parse_passes(claim('0x60', 68, cell(1, 9), cell(1, 9), busy(name))),
                                          READ), 180)
        assert summary['loss'] == [name]


def test_core_registers_reads_the_bfrt_layout():
    regs = {'owner': {'f1': 0xe0002, 'action_name': None}, 'client': {'f1': 126}, 'server': {'f1': 901},
            'epoch': {'f1': 6}, 'work.work': {'generation': 9, 'phase': 4}}
    assert cf.core_registers(regs) == dict(owner=0xe0002, client=126, server=901, epoch=6, work_phase=4)
