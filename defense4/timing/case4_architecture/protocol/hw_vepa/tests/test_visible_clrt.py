"""Host-observed CLRT is reported per exchange/function, never compared against D or any threshold (Philip,
2026-10-25). Software OPERATE hold, fixture identity, application and switch gates remain enforced."""
import json

import pytest

from test_campaign_bindings import cfg_for
from test_campaign_run import FakeRunner
from test_checks import EXP, evidence
import campaign as cp
import checks


def rows(values, kind='READ'):
    return {'exchanges': [{'kind': kind, 'complete': True, 'piggyback': False,
                           'attempts': 1, 'clrt_us': value, 't_req': i} for i, value in enumerate(values)]}


def test_visible_clrt_reports_n_min_median_max_and_values_per_function():
    t = rows([800, 650, 54104])
    t['exchanges'] += [dict(t['exchanges'][0], complete=False), dict(t['exchanges'][0], piggyback=True),
                       dict(t['exchanges'][0], clrt_us=None), {'kind': 'SELECT', 'complete': True, 'clrt_us': 5000}]
    out = checks.visible_clrt(t)
    assert set(out) == {'READ', 'SELECT', 'OPERATE'}
    assert out['READ'] == dict(n=3, piggyback=1, min_us=650, median_us=800, max_us=54104, values_us=[650, 800, 54104])
    assert out['SELECT']['values_us'] == [5000]
    assert out['OPERATE'] == dict(n=0, piggyback=0, min_us=None, median_us=None, max_us=None, values_us=[])


@pytest.mark.parametrize('clrt', [800, 650, 54104])
def test_clrt_far_from_the_gap_is_reported_and_never_fails(clrt):
    ev = evidence(reads=20)
    ev['timing'].update(rows([clrt] * 20))
    fails, obs = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'separate_ack', 20, ev)
    assert not any('precision' in f.lower() or 'clrt' in f.lower() for f in fails), fails
    assert obs['visible_clrt']['READ']['values_us'] == [clrt] * 20
    assert 'read_precision' not in obs


def test_piggyback_fraction_rejects_wrong_fixture_identity():
    ev = evidence()          # separate-ACK evidence evaluated as the piggyback fixture: fraction 0, outside [0.95, 1]
    fails, obs = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'piggyback', 10, ev, mirror_k=2)
    assert obs['piggyback_fraction'] == 0.0
    assert any('piggyback fraction' in f for f in fails), fails


def test_piggyback_uses_response_fallback_and_still_generates_each_read():
    ev = evidence(fixture='piggyback')
    before, after = ev['before']['outcomes'], ev['after']['outcomes']
    after['OUT_ACK_COMMIT'] = before['OUT_ACK_COMMIT']
    after['OUT_RESP_RELEASE'] = before['OUT_RESP_RELEASE']
    after['OUT_RESP_FALLBACK'] = before['OUT_RESP_FALLBACK'] + 10
    fails, observed = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'piggyback', 10, ev, mirror_k=2)
    assert not fails, fails
    assert observed['pktgen']['READ'] == {'triggers': 10, 'pkts': 40}


def test_piggyback_ack_fallback_is_never_allowed():
    ev = evidence(fixture='piggyback')
    ev['after']['outcomes']['OUT_ACK_FALLBACK'] += 1
    fails, _ = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'piggyback', 10, ev)
    assert any('OUT_ACK_FALLBACK' in f for f in fails)


def test_read_only_profile_requires_zero_operate_release():
    ev = evidence()
    ev['outstation'].update(select_real=0, operate_real=0)
    for kind in ('SELECT', 'OPERATE'):
        ev['timing']['summary'].pop(kind)
    ev['timing']['exchanges'] = [row for row in ev['timing']['exchanges'] if row['kind'] == 'READ']
    fails, _ = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'separate_ack', 10, ev, run_sbo=False)
    assert any('OUT_OP_RELEASE' in f for f in fails)


def test_gate_ok_is_strict_ok_without_an_invalid_host_diagnostic():
    assert cp.gate_ok({'ok': True})
    assert not cp.gate_ok({'ok': False})
    assert not cp.gate_ok({'ok': True, 'host_diagnostic_invalid': True})
    # a former "reported, not gated" marker never excuses a failed block
    assert not cp.gate_ok({'ok': False, 'host_precision_reported_not_gated': True})


# ---- whole campaign over the fake runner -----------------------------------------------------------------------

class Timing(FakeRunner):
    def __init__(self, clrt_us=1101, fault=None):
        super().__init__()
        self.clrt_us, self.fault = clrt_us, fault

    def evidence(self, text):
        ev = super().evidence(text)
        for row in ev['timing']['exchanges']:
            if row['kind'] == 'READ':
                row['clrt_us'] = self.clrt_us
        if self.fault == 'application':
            ev['master']['reads'][0]['matches_seed'] = False
        elif self.fault == 'short_hold':
            ev['hold']['operates'][0].update(transit_us=100.0, observed=True)
        elif self.fault == 'unobserved_operate':
            ev['hold']['operates'][0].update(transit_us=None, observed=False)
        return ev


RETIRED = {'purpose': 'timing_precision_characterization', 'read_precision': True, 'host_precision_gated': False}


def execute(tmp_path, runner, evaluation=None):
    cfg = cfg_for(tmp_path / 'build', 'match')
    cfg['evidence_dir'] = str(tmp_path / 'evidence')
    cfg['fixture']['modes'] = ['separate_ack']
    cfg['trials'] = {'reads_per_trial': 50, 'trials_per_arm': 3}
    cfg['timing_params_ns']['gap'] = 950000
    cfg['evaluation'] = dict(RETIRED if evaluation is None else evaluation)
    c = cp.Campaign(cfg, runner, 'c1', arms=['combined'])
    rc = c.execute()
    return rc, json.loads((tmp_path / 'evidence/c1/campaign_run.json').read_text())


@pytest.mark.parametrize('evaluation', [None, {}])
def test_clrt_tail_passes_and_old_threshold_keys_are_ignored_and_not_reported(tmp_path, evaluation):
    rc, record = execute(tmp_path, Timing(clrt_us=1101), evaluation)    # 151 us from the configured 950 us gap
    assert rc == 0 and record['ok'] is True and record['gate_ok'] is True
    assert not record.get('soft_failures') and 'host_precision_reported_not_gated' not in record
    assert not set(RETIRED) & set(record['effective']['evaluation'])
    trials = record['arms'][0]['trials']
    assert len(trials) == 3
    for trial in trials:
        assert trial['ok'] is True and trial['failures'] == []
        assert 'continuation' not in trial and 'qualification' not in trial
        assert set(trial['observed']['visible_clrt']['READ']['values_us']) == {1101}


def test_software_operate_transit_below_op_j_fails_the_campaign(tmp_path):
    rc, record = execute(tmp_path, Timing(clrt_us=950, fault='short_hold'))
    assert rc == 1 and record['ok'] is False
    for trial in record['arms'][0]['trials']:
        assert trial['observed']['operate_hold']['min_transit_us'] == 100.0
        assert trial['observed']['operate_hold']['below_op_j']
        assert any(f.startswith('OPERATE hold:') for f in trial['failures'])


@pytest.mark.parametrize('fault, prefix', [('unobserved_operate', 'OPERATE hold:'), ('application', 'READ')])
def test_correctness_failures_stay_hard(tmp_path, fault, prefix):
    rc, record = execute(tmp_path, Timing(fault=fault))
    assert rc == 1 and record['ok'] is False and record['failure']
    trials = record['arms'][0]['trials']
    assert len(trials) == 1 and not record.get('soft_failures')
    assert any(f.startswith(prefix) for f in trials[0]['failures']), trials[0]['failures']
