"""Timing characterization continues only after an isolated numeric precision threshold failure."""
import hashlib
import json

import pytest

from test_campaign_bindings import cfg_for
import campaign as cp
from test_campaign_run import FakeRunner


class TimingTail(FakeRunner):
    def __init__(self, fault=None):
        super().__init__()
        self.fault = fault

    def evidence(self, text):
        ev = super().evidence(text)
        for row in ev['timing']['exchanges']:
            if row['kind'] == 'READ':
                row['clrt_us'] = 1101  # 151us from the configured 950us target
        if self.fault == 'stale' or (self.fault == 'late_stale' and '_t1' in text):
            ev['after']['outcomes']['OUT_TOKEN_STALE'] += 1
        elif self.fault == 'application':
            ev['master']['reads'][0]['matches_seed'] = False
        elif self.fault == 'structural':
            ev['before'] = None
        elif self.fault == 'extractor':
            self.wire_rc = 1
        return ev


def config(tmp_path, purpose='timing_precision_characterization', reads=50):
    cfg = cfg_for(tmp_path / 'build', 'match')
    cfg['evidence_dir'] = str(tmp_path / 'evidence')
    cfg['fixture']['modes'] = ['separate_ack']
    cfg['trials'] = {'reads_per_trial': reads, 'trials_per_arm': 3}
    cfg['timing_params_ns']['gap'] = 950000
    cfg['evaluation'] = {'purpose': purpose, 'read_precision': True}
    return cfg


def execute(tmp_path, fault=None, purpose='timing_precision_characterization', reads=50):
    cfg = config(tmp_path, purpose, reads)
    c = cp.Campaign(cfg, TimingTail(fault), 'c1', arms=['combined'])
    rc = c.execute()
    return cfg, rc, json.loads((tmp_path / 'evidence/c1/campaign_run.json').read_text())


def test_precision_only_failures_continue_and_retain_strict_failure_provenance(tmp_path):
    cfg, rc, record = execute(tmp_path)
    assert rc == 1 and record['ok'] is False
    assert record['failure'] is None
    trials = record['arms'][0]['trials']
    assert len(trials) == len(record['soft_failures']) == 3
    for trial in trials:
        assert trial['ok'] is False
        assert trial['continuation'] == {'purpose': 'timing_precision_characterization',
                                        'allowed': True, 'reason': 'READ p99 absolute error threshold only'}
        assert all(f.startswith('READ precision:') for f in trial['failures'])
        assert trial['observed']['read_precision']['eligible'] == 50
        assert trial['observed']['read_precision']['absolute_error_us']['p99'] == 151
    assert record['effective']['evaluation'] == cfg['evaluation']
    expected_sha = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert record['config_sha256'] == expected_sha
    assert record['effective']['max_token_stale'] == {cfg['arms'][0]['build']: 0}


@pytest.mark.parametrize('fault', ['stale', 'application', 'structural', 'extractor'])
def test_precision_characterization_hard_stops_on_other_failures(tmp_path, fault):
    _, rc, record = execute(tmp_path, fault)
    assert rc == 1 and record['ok'] is False
    assert len(record['arms'][0]['trials']) == 1
    assert not record.get('soft_failures')
    assert record['failure']


def test_precision_characterization_does_not_waive_minimum_denominator(tmp_path):
    _, rc, record = execute(tmp_path, reads=10)
    assert rc == 1
    assert len(record['arms'][0]['trials']) == 1
    assert not record.get('soft_failures')


def test_qualification_still_stops_on_first_precision_threshold_failure(tmp_path):
    _, rc, record = execute(tmp_path, purpose='qualification')
    assert rc == 1
    assert len(record['arms'][0]['trials']) == 1
    assert not record.get('soft_failures')


def test_precision_characterization_is_a_valid_explicit_purpose(tmp_path):
    cp.validate_profile(config(tmp_path))


def test_precision_characterization_cannot_disable_precision_gate(tmp_path):
    cfg = config(tmp_path)
    cfg['evaluation']['read_precision'] = False
    with pytest.raises(ValueError, match='disable READ precision'):
        cp.validate_profile(cfg)


def test_unknown_evaluation_purpose_is_rejected(tmp_path):
    with pytest.raises(ValueError, match='evaluation.purpose'):
        cp.validate_profile(config(tmp_path, purpose='precision_loosened'))


def test_other_failure_after_precision_only_block_stops_and_keeps_prior_failure(tmp_path):
    _, rc, record = execute(tmp_path, fault='late_stale')
    assert rc == 1 and record['failure']
    trials = record['arms'][0]['trials']
    assert len(trials) == 2
    assert record['soft_failures'] == [trials[0]['label']]
    assert trials[0]['continuation']['allowed'] is True
    assert trials[1]['continuation']['allowed'] is False
    assert any('OUT_TOKEN_STALE' in f for f in trials[1]['failures'])


def test_effective_precision_gate_default_is_recorded_for_characterization(tmp_path):
    cfg = config(tmp_path)
    cfg['evaluation'].pop('read_precision')
    cp.validate_profile(cfg)
    c = cp.Campaign(cfg, TimingTail(), 'c1', arms=['combined'])
    assert c.execute() == 1
    record = json.loads((tmp_path / 'evidence/c1/campaign_run.json').read_text())
    assert record['effective']['evaluation'] == {'purpose': 'timing_precision_characterization', 'read_precision': True}
    assert len(record['soft_failures']) == 3
