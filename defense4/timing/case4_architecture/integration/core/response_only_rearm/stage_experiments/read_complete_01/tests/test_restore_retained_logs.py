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


def retained_run(tmp_path, label, data=b'original model trace\n'):
    run = tmp_path / 'ctl_evidence' / ('model_smoke_m12p_%s_sdk9132_01' % label)
    run.mkdir(parents=True)
    (run / 'dependency_closure.json').write_text('{}')
    log = run / 'model_capture.log'
    archive = log.with_suffix('.log.xz')
    archive.write_bytes(lzma.compress(data))
    record = {'sha256': module.sha(data), 'archive': str(archive.relative_to(tmp_path)),
              'archive_sha256': module.sha(archive.read_bytes()),
              'archive_bytes': archive.stat().st_size, 'raw_bytes': len(data)}
    manifest = tmp_path / 'rc_evidence' / ('%s_dependency_retention_20261024' % label) / 'manifest.json'
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({'logs': {str(log.relative_to(tmp_path)): record}}))
    return log, archive, record, manifest


def bind_retention(monkeypatch, tmp_path, manifest):
    monkeypatch.setattr(module, 'EVIDENCE', tmp_path / 'ctl_evidence')
    monkeypatch.setattr(module, 'REPO', tmp_path)
    monkeypatch.setattr(module, 'RETENTION', manifest)


def test_second_retention_manifest_restores_its_own_pinned_log(tmp_path, monkeypatch):
    first, _, _, manifest = retained_run(tmp_path, 'c30', b'c30 trace\n')
    second, _, _, _ = retained_run(tmp_path, 'c48', b'selected relay trace\n')
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 0
    assert first.read_bytes() == b'c30 trace\n'
    assert second.read_bytes() == b'selected relay trace\n'


@pytest.mark.parametrize('field', ('sha256', 'archive', 'archive_sha256', 'archive_bytes', 'raw_bytes'))
def test_conflicting_duplicate_log_pins_fail_before_restoring_any_log(tmp_path, monkeypatch, capsys, field):
    log, _, record, manifest = retained_run(tmp_path, 'c30')
    other, _, _, second = retained_run(tmp_path, 'c48')
    duplicate = dict(record)
    duplicate[field] = 'conflicting pin'
    second.write_text(json.dumps({'logs': {str(log.relative_to(tmp_path)): duplicate}}))
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 1
    assert 'conflicting retained log pins' in capsys.readouterr().out.lower()
    assert not log.exists()
    assert not other.exists()


def test_identical_duplicate_log_pins_are_allowed(tmp_path, monkeypatch):
    log, _, record, manifest = retained_run(tmp_path, 'c30')
    other, _, other_record, second = retained_run(tmp_path, 'c48')
    second.write_text(json.dumps({'logs': {str(log.relative_to(tmp_path)): dict(record),
                                          str(other.relative_to(tmp_path)): other_record}}))
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 0
    assert log.read_bytes() == b'original model trace\n'
    assert other.read_bytes() == b'original model trace\n'


@pytest.mark.parametrize('tamper', ('archive', 'decompressed'))
def test_second_manifest_archive_and_decompressed_bytes_are_both_pinned(tmp_path, monkeypatch, capsys, tamper):
    _, _, _, manifest = retained_run(tmp_path, 'c30')
    log, archive, record, second = retained_run(tmp_path, 'c48')
    archive.write_bytes(lzma.compress(b'tampered selected run\n'))
    if tamper == 'decompressed':
        record['archive_sha256'] = module.sha(archive.read_bytes())
        record['archive_bytes'] = archive.stat().st_size
        second.write_text(json.dumps({'logs': {str(log.relative_to(tmp_path)): record}}))
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 1
    expected = 'retained archive pin mismatch' if tamper == 'archive' else 'does not decompress to the pinned'
    assert expected in capsys.readouterr().out
    assert not log.exists()


def test_second_manifest_does_not_override_reset_closure_pin(tmp_path, monkeypatch, capsys):
    _, _, _, manifest = retained_run(tmp_path, 'c30')
    log, _, _, _ = retained_run(tmp_path, 'c48')
    (log.parent / 'dependency_closure.json').write_text(json.dumps({
        'postchecks': {'reset_application': {'input_sha256': {log.name: module.sha(b'other reset trace')}}}}))
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 1
    assert 'retained archive pin mismatch' in capsys.readouterr().out
    assert not log.exists()


@pytest.mark.parametrize('existing', (b'original model trace\n', b'different existing bytes\n'))
def test_existing_log_bytes_are_never_overwritten(tmp_path, monkeypatch, existing):
    _, _, _, manifest = retained_run(tmp_path, 'c30')
    log, _, _, _ = retained_run(tmp_path, 'c48')
    log.write_bytes(existing)
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == int(existing != b'original model trace\n')
    assert log.read_bytes() == existing


def test_log_created_during_restore_is_never_overwritten(tmp_path, monkeypatch):
    log, _, _, manifest = retained_run(tmp_path, 'c30')
    bind_retention(monkeypatch, tmp_path, manifest)
    original_open = Path.open

    def race(path, mode='r', *args, **kwargs):
        if path == log and mode in ('wb', 'xb') and not log.exists():
            with original_open(log, 'wb') as output:
                output.write(b'concurrent trace\n')
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', race)
    assert module.main() == 1
    assert log.read_bytes() == b'concurrent trace\n'


@pytest.mark.parametrize('raw_present', (False, True))
def test_missing_manifest_archive_fails_even_when_other_archives_exist(tmp_path, monkeypatch, capsys, raw_present):
    _, _, _, manifest = retained_run(tmp_path, 'c30')
    log, archive, _, _ = retained_run(tmp_path, 'c68')
    archive.unlink()
    if raw_present:
        log.write_bytes(b'original model trace\n')
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 1
    assert 'missing retained archive' in capsys.readouterr().out
    assert log.exists() is raw_present


def test_manifest_archive_outside_discovery_glob_is_restored(tmp_path, monkeypatch):
    log, archive, record, manifest = retained_run(tmp_path, 'c68')
    (log.parent / 'dependency_closure.json').unlink()
    alternate = tmp_path / 'ctl_evidence' / 'aborted_attempt'
    alternate.mkdir()
    moved_archive = alternate / archive.name
    archive.rename(moved_archive)
    moved_log = moved_archive.with_suffix('')
    record['archive'] = str(moved_archive.relative_to(tmp_path))
    manifest.write_text(json.dumps({'logs': {str(moved_log.relative_to(tmp_path)): record}}))
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 0
    assert moved_log.read_bytes() == b'original model trace\n'
    assert not (alternate / 'dependency_closure.json').exists()


def test_manifest_only_aborted_attempt_restores_without_creating_closure(tmp_path, monkeypatch):
    log, _, _, manifest = retained_run(tmp_path, 'c68')
    closure = log.parent / 'dependency_closure.json'
    closure.unlink()
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 0
    assert log.read_bytes() == b'original model trace\n'
    assert not closure.exists()


def test_unpinned_discovered_archive_is_refused_without_closure(tmp_path, monkeypatch, capsys):
    _, _, _, manifest = retained_run(tmp_path, 'c30')
    log, _, _, second = retained_run(tmp_path, 'c68')
    second.unlink()
    (log.parent / 'dependency_closure.json').unlink()
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 1
    assert 'not pinned' in capsys.readouterr().out
    assert not log.exists()


@pytest.mark.parametrize('field', ('archive_bytes', 'raw_bytes'))
def test_manifest_size_mismatch_prevents_restoration(tmp_path, monkeypatch, capsys, field):
    log, _, record, manifest = retained_run(tmp_path, 'c68')
    record[field] += 1
    manifest.write_text(json.dumps({'logs': {str(log.relative_to(tmp_path)): record}}))
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 1
    assert 'mismatch' in capsys.readouterr().out
    assert not log.exists()


def test_corrupt_xz_with_matching_archive_pin_fails_without_partial_log(tmp_path, monkeypatch, capsys):
    log, archive, record, manifest = retained_run(tmp_path, 'c68')
    archive.write_bytes(archive.read_bytes()[:-10])
    record['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
    record['archive_bytes'] = archive.stat().st_size
    manifest.write_text(json.dumps({'logs': {str(log.relative_to(tmp_path)): record}}))
    bind_retention(monkeypatch, tmp_path, manifest)
    assert module.main() == 1
    assert 'FAIL' in capsys.readouterr().out
    assert not log.exists()
