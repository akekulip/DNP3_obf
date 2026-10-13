"""Fresh endpoint directories work; retained run labels remain exclusive."""
import importlib.util
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('name', ['vision_candidate', 'vision_isolation', 'vision_replay'])
def test_scenario_creates_fresh_runs_parent_but_refuses_reuse(tmp_path, monkeypatch, name):
    spec = importlib.util.spec_from_file_location('fresh_' + name, HW / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    vc = module if name == 'vision_candidate' else module.vc
    runs = tmp_path / 'new_endpoint' / 'runs'
    monkeypatch.setattr(vc.vr, 'RUNS', runs)
    monkeypatch.setattr(vc, 'guard', lambda *a, **kw: None)

    def stop_before_traffic(*args):
        raise RuntimeError('test stops before traffic')
    monkeypatch.setattr(vc, 'preflight', stop_before_traffic)
    args = ('fresh_run', 59400, 'rst', 1) if name == 'vision_candidate' else ('fresh_run', 59400, 1)
    result = module.scenario(*args, apply=True)
    assert result['ok'] is False
    assert result['error'] == 'test stops before traffic'
    assert (runs / 'fresh_run' / 'scenario.json').is_file()
    with pytest.raises(FileExistsError):
        module.scenario(*args, apply=True)
