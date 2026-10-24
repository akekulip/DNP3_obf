"""Retained non-reset model logs restore only with exact archive and byte pins."""
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('retained_logs', Path(__file__).resolve().parents[1] / 'restore_retained_logs.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.mark.parametrize('tamper', (False, True))
@pytest.mark.parametrize('name', ('model_capture.log', 'model.out'))
def test_nonreset_retained_log_requires_archive_pin(tmp_path, monkeypatch, tamper, name):
    evidence = tmp_path / 'evidence'
    run = evidence / 'model_packets_m12p_c30_sdk9132_01'
    run.mkdir(parents=True)
    (run / 'dependency_closure.json').write_text('{}')
    log = run / name
    archive = log.with_suffix(log.suffix + '.xz')
    data = b'original model trace\n'
    archive.write_bytes(lzma.compress(data))
    record = {'sha256': hashlib.sha256(data).hexdigest(),
              'archive': str(archive.relative_to(tmp_path)),
              'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
    manifest = tmp_path / 'retention.json'
    manifest.write_text(json.dumps({'logs': {str(log.relative_to(tmp_path)): record}}))
    if tamper:
        archive.write_bytes(lzma.compress(b'changed trace\n'))
    monkeypatch.setattr(module, 'EVIDENCE', evidence)
    monkeypatch.setattr(module, 'REPO', tmp_path)
    monkeypatch.setattr(module, 'RETENTION', manifest)
    assert module.main() == int(tamper)
    assert log.exists() is not tamper
    if not tamper:
        assert log.read_bytes() == data
