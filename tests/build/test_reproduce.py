import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]


def test_reproduction_refuses_a_stale_candidate_before_compiling(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('current_reproduce', ROOT / 'scripts/reproduce.py')
    reproduce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reproduce)
    monkeypatch.setattr(reproduce, 'ROOT', tmp_path)
    build = tmp_path / 'results/builds/selected'
    output = tmp_path / 'report.json'
    package = SimpleNamespace(verify_package=lambda selected: {'source_matches': True},
        sha=lambda path: 'canonical' if path == tmp_path / 'p4/response_only.p4' else 'stale')
    monkeypatch.setattr(reproduce, 'load', lambda name, path: package if 'package' in name else object())
    monkeypatch.setattr(sys, 'argv', ['reproduce.py', str(build), '--output', str(output)])
    assert reproduce.main() == 1
    report = json.loads(output.read_text())
    assert report['error'] == 'selected build is not the canonical current P4'
    assert report['hardware_contact'] is False
    assert 'fresh_build' not in report
