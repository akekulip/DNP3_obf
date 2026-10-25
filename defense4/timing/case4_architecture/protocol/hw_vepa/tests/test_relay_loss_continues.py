"""A physical relay loss trial that fails recovery is RECORDED and the block runs its remaining presets
(rc01_hw_c51_20261024_03 stopped after preset 4 of 7); only an infrastructure failure stops the block."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402
import relay_loss  # noqa: E402


class Fake:
    verdict_loss = cp.Campaign.verdict_loss

    def __init__(self):
        self.cfg = dict(endpoint_profile='sel751')
        self.rn = SimpleNamespace(dry=False)
        self.soft_failures = []

    def relay_verdict(self, trial, *args, **kwargs):
        app = trial.get('application', True)
        trial.update(failures=[] if app else ['master transaction failed: OPERATE'], ok=app, observed={},
                     dimension_verdicts=dict(application=app))


def run(tmp_path, monkeypatch, rc, application=True, target_failures=()):
    (tmp_path / 'result.json').write_text(json.dumps(dict(loss={'class': 'select_resp_padded'})))
    (tmp_path / 'relay_wire.json').write_text('{}')
    monkeypatch.setattr(relay_loss, 'target_checks', lambda *args: list(target_failures))
    fake, trial = Fake(), dict(application=application)
    fake.verdict_loss(trial, {}, 'label_t3', str(tmp_path), SimpleNamespace(rc=rc), {}, 'physical_relay', {}, 59410)
    return fake, json.loads((tmp_path / 'trial.json').read_text())


def test_application_failure_is_recorded_and_does_not_stop(tmp_path, monkeypatch):
    fake, trial = run(tmp_path, monkeypatch, rc=1, application=False)
    assert fake.soft_failures == ['label_t3']
    assert trial['ok'] is False and trial['dimension_verdicts']['application'] is False


def test_target_failure_is_recorded_and_does_not_stop(tmp_path, monkeypatch):
    fake, trial = run(tmp_path, monkeypatch, rc=0, target_failures=['drop not observed'])
    assert fake.soft_failures == ['label_t3']
    assert trial['ok'] is False and trial['dimension_verdicts']['loss_target'] is False


def test_clean_trial_records_nothing(tmp_path, monkeypatch):
    fake, trial = run(tmp_path, monkeypatch, rc=0)
    assert fake.soft_failures == [] and trial['ok'] is True


def test_infrastructure_failure_still_stops(tmp_path, monkeypatch):
    with pytest.raises(cp.StepFailed):
        run(tmp_path, monkeypatch, rc=255)
