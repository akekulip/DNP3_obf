"""reset_application_check.py: the revised reset contract (Philip, 2026-10-17), with the attribution and count
cross-check the code review required."""
import importlib.util
import sys
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CT))
spec = importlib.util.spec_from_file_location('reset_application_check', CT / 'reset_application_check.py')
rac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rac)
EV = CT / 'evidence'
APPLY = ['t_Ingress.close_epoch', 't_Ingress.live_reset_gen']


def rec(wall, *actions):
    return dict(wall='12:00:%06.3f' % wall, pipe=1, frame='', actions=['t_Ingress.%s' % a for a in actions])


def test_release_before_application_with_matching_counts_passes():
    v = rac.classify([rec(1.0, 'release_response_counted'), dict(rec(2.0), actions=APPLY)], 1, 1)
    assert v['verdict'] == 'PASS'


def test_release_after_application_fails():
    v = rac.classify([dict(rec(2.0), actions=APPLY), rec(3.0, 'release_response_counted')], 1, 1)
    assert v['verdict'] == 'FAIL'


def test_a_release_in_the_application_pass_counts_as_after():
    v = rac.classify([dict(rec(2.0), actions=APPLY + ['t_Ingress.release_response_counted'])], 1, 1)
    assert v['verdict'] == 'FAIL'


def test_a_lost_release_is_unattributed_not_a_pass():
    """Code review B: T counted a release the log attribution did not find."""
    v = rac.classify([dict(rec(2.0), actions=APPLY)], 1, 0)
    assert v['verdict'] == 'unattributed'


def test_a_master_copy_without_a_release_before_the_reset_is_unattributed():
    v = rac.classify([dict(rec(2.0), actions=APPLY)], 0, 1)
    assert v['verdict'] == 'unattributed'


def test_missing_counts_are_unattributed():
    v = rac.classify([rec(1.0, 'release_response_counted'), dict(rec(2.0), actions=APPLY)], None, None)
    assert v['verdict'] == 'unattributed'


def test_no_application_is_never_a_pass():
    assert rac.classify([rec(1.0, 'release_response_counted')], 1, 1)['verdict'] == 'no reset applied'


LOG = """\
:10-17 12:45:20.857841:    :0xd7c:-:<0,0,->:---- Mirroring session 1003 : ingress  ----
:10-17 12:45:20.857867:    :0xd7d:0xd7c:<0,1,0>:========== Ingress Pkt from port 182 (103 bytes)  ==========
:10-17 12:45:20.857879:    :0xd7d:0xd7c:<0,1,0>:Packet :
:10-17 12:45:20.857888:        :0xd7d:0xd7c:<0,1,0>:0f 00 00 a9 00 08 77 f9 00 11
:10-17 12:45:20.857948:    :0xd7d:0xd7c:<0,1,0>:========== Egress Pkt from TM to port 180 (tm 80, real 80 bytes) ==========
:10-17 12:45:20.857956:    :0xd7d:0xd7c:<0,1,0>:Packet :
:10-17 12:45:20.857964:        :0xd7d:0xd7c:<0,1,0>:00 00 01 55 0d 01 00 00
:10-17 12:45:20.858100:    :0xd7d:0xd7c:<0,1,0>:Execute Action: t_Ingress.release_response_counted
:10-17 12:45:20.858200:    :0xd7d:0xd7c:<0,1,0>:Execute Action: r_Egress.do_start_commit
"""


def test_an_interleaved_egress_header_does_not_steal_the_ingress_action():
    """Code review B: the release belongs to the ingress packet (frame with the pattern), not the egress record
    whose header and dump came between."""
    records = rac.ingress_records(LOG.splitlines(True))
    assert len(records) == 1 and '000877f9' in records[0]['frame']
    assert records[0]['actions'] == ['t_Ingress.release_response_counted']


@pytest.mark.skipif(not list((EV / 'model_contention_m10_03_02').glob('model_*.log')),
                    reason='the model log is over 50 MiB and untracked (UNTRACKED_LARGE_LOGS.sha256), so a clean '
                           'checkout lacks it; the synthetic tests above still run')
def test_the_recorded_attempt_02_run_cannot_be_verified_under_the_revised_contract():
    """The historical failure keeps its original result. Its restart points did not record T's release count, so
    the revised contract can only report 'unattributed', even though the one release found preceded the reset."""
    sel = rac.check(EV / 'model_contention_m10_03_02')['restart_SELECT']
    assert sel['verdict'] == 'unattributed' and len(sel['released_before']) == 1 and sel['released_after'] == []


TSTAMP_LOG = """\
:10-17 12:45:20.857867:    :0xd7d:0xd7c:<0,1,0>:========== Ingress Pkt from port 182 (103 bytes)  ==========
:10-17 12:45:20.857870:        :0xd7d:-:<0,1,->:Ingress Parser state '$entry_point.start': extracted 0x0268d564, updating PHV word   0 to value 0x0268d564 I [ig_intr_md_from_prsr.global_tstamp[39:8]]
:10-17 12:45:20.857880:        :0xd7d:0xd7c:<0,1,0>:	ig_intr_md_from_prsr.global_tstamp[39:8] = 0x9999999
:10-17 12:45:20.858100:    :0xd7d:0xd7c:<0,1,0>:Execute Action: t_Ingress.admit_response
"""


def test_each_ingress_record_carries_t_clock_from_its_own_parser():
    """committed_precondition_check reads T's clock per pass: the parser's extracted value, not a later dump line."""
    records = rac.ingress_records(TSTAMP_LOG.splitlines(True))
    assert records[0]['t_units'] == 0x0268d564 and records[0]['actions'] == ['t_Ingress.admit_response']


def test_default_tags_are_every_recorded_restart_point_ordinary_and_targeted():
    results = {'meta': {'points': [dict(tag='restart_READ', restarts=0), dict(tag='restart_READ_new_READ'),
                                   dict(tag='restart_targeted_READ_1', restarts=0),
                                   dict(tag='restart_targeted_READ_2', restarts=1), dict(tag='sweep_READ_000ms')]}}
    assert rac.restart_tags(results) == ('restart_READ', 'restart_targeted_READ_1', 'restart_targeted_READ_2')


@pytest.fixture
def completed_restart():
    run = EV / 'model_contention_m10_03_07'
    results = __import__('json').loads((run / 'contention_results.json').read_text())
    report = __import__('json').loads((run / 'reset_application.json').read_text())
    return results, report


def test_complete_recorded_reset_coverage_is_accepted(completed_restart):
    results, report = completed_restart
    assert rac.coverage_problems(results, report) == []


@pytest.mark.parametrize('mutation', ('missing_report', 'invented_report', 'missing_point', 'duplicate_point',
    'skip_attempt', 'missing_case', 'duplicate_case', 'failed_case', 'missing_witness', 'partial_sections',
    'bad_summary', 'bad_release_count', 'wrong_sequence', 'missing_application', 'bad_copies', 'invented_case',
    'truncated_synack', 'inconsistent_counter', 'missing_ordinary_aggregate'))
def test_reset_coverage_rejects_incomplete_or_inconsistent_evidence(completed_restart, mutation):
    results, report = completed_restart
    if mutation == 'missing_report':
        report.pop('restart_SELECT')
    elif mutation == 'invented_report':
        report['invented'] = dict(verdict='PASS')
    elif mutation == 'missing_point':
        results['meta']['points'] = [p for p in results['meta']['points'] if p['tag'] != 'restart_SELECT']
    elif mutation == 'duplicate_point':
        results['meta']['points'].append(dict(next(p for p in results['meta']['points'] if p['tag'] == 'restart_SELECT')))
    elif mutation == 'skip_attempt':
        next(p for p in results['meta']['points'] if p['tag'] == 'restart_targeted_READ_1')['tag'] = 'restart_targeted_READ_2'
    elif mutation == 'missing_case':
        results['cases'] = [c for c in results['cases'] if c['name'] != 'restart_READ_new_READ_request_relayed']
    elif mutation == 'duplicate_case':
        results['cases'].append(dict(results['cases'][0]))
    elif mutation == 'failed_case':
        next(c for c in results['cases'] if c['name'] == 'restart_READ_SYNACK')['ok'] = False
    elif mutation == 'missing_witness':
        next(p for p in results['meta']['points'] if p['tag'] == 'restart_targeted_READ_1')['restarts'] = 0
    elif mutation == 'partial_sections':
        results['meta']['sections'] = ['abort']
    elif mutation == 'bad_summary':
        results['summary']['total'] -= 1
    elif mutation == 'bad_release_count':
        report['restart_READ']['t_release_count'] += 1
    elif mutation == 'wrong_sequence':
        report['restart_READ']['server_seq'] = '01234567'
    elif mutation == 'missing_application':
        report['restart_READ'].pop('applied_at')
    elif mutation == 'invented_case':
        results['cases'].append(dict(name='restart_invented_SYN', ok=True))
        results['summary']['total'] += 1
        results['summary']['passed'] += 1
    elif mutation == 'truncated_synack':
        next(c for c in results['cases'] if c['name'] == 'restart_READ_SYNACK')['received'] = {'9': ['00']}
    elif mutation == 'inconsistent_counter':
        next(p for p in results['meta']['points'] if p['tag'] == 'restart_READ')['count_busy_delta'][5] = 1
    elif mutation == 'missing_ordinary_aggregate':
        results['meta'].pop('ordinary_restart_by_kind')
    else:
        report['restart_READ']['copies_to_master'] = 2
    assert rac.coverage_problems(results, report)
