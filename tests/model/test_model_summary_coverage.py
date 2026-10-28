"""The model summary must say which stimulus each driver ran, so a timing-off pass is not read as timing-on coverage
(audit 2026-10-28, section 4.6)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/model'))
import model_summary  # noqa: E402


def launch(root, run, environment):
    (root / run).mkdir(parents=True)
    (root / run / 'launch_command.json').write_text(json.dumps(dict(stimulus_environment=environment)))


def test_timing_off_abandon_is_reported_as_not_covering_timing_enabled_abandon(tmp_path, monkeypatch):
    monkeypatch.setattr(model_summary, 'model_root', lambda build: tmp_path)
    launch(tmp_path, 'model_abandon_x_02', {'ABANDON_T': '0'})
    launch(tmp_path, 'model_smoke_x_01', {})
    base = dict(latest_by_driver={'abandon': 'model_abandon_x_02', 'smoke': 'model_smoke_x_01'})
    coverage = model_summary.stimulus_coverage('x', base)
    assert coverage['stimulus_by_driver']['abandon'] == {'ABANDON_T': '0'}
    assert coverage['stimulus_by_driver']['smoke'] == {}
    assert [c['driver'] for c in coverage['coverage_not_established']] == ['abandon']
    assert 'timing enabled' in coverage['coverage_not_established'][0]['scenario']


def test_timing_enabled_abandon_run_closes_that_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(model_summary, 'model_root', lambda build: tmp_path)
    launch(tmp_path, 'model_abandon_x_03', {'ABANDON_T': '1'})
    coverage = model_summary.stimulus_coverage('x', dict(latest_by_driver={'abandon': 'model_abandon_x_03'}))
    assert coverage['coverage_not_established'] == []


def test_missing_launch_record_is_reported_not_assumed(tmp_path, monkeypatch):
    monkeypatch.setattr(model_summary, 'model_root', lambda build: tmp_path)
    coverage = model_summary.stimulus_coverage('x', dict(latest_by_driver={'abandon': 'model_abandon_x_09'}))
    assert coverage['stimulus_by_driver']['abandon'] is None
    assert [c['driver'] for c in coverage['coverage_not_established']] == ['abandon']
