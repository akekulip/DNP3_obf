import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def module():
    spec = importlib.util.spec_from_file_location('retained_logs', ROOT / 'scripts/model/retained_logs.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_archive_round_trip_preserves_log_identity_and_discards_redundant_stdout(tmp_path):
    retained = module()
    content = b'model ingress and exact action execution\n' * 1000
    log = tmp_path / 'model_20261026.log'
    log.write_bytes(content)
    (tmp_path / 'model.out').write_bytes(content)
    record = retained.archive_run(tmp_path)
    assert record['raw_sha256'] == hashlib.sha256(content).hexdigest()
    assert not (tmp_path / 'model.out').exists()
    log.unlink()
    assert retained.restore_run(tmp_path) == log
    assert log.read_bytes() == content


@pytest.mark.parametrize('startup, name', [(False, 'model_stdout.txt'), (True, 'startup_stdout.txt')])
def test_distinct_stdout_is_preserved_not_discarded(tmp_path, startup, name):
    retained = module()
    (tmp_path / 'model_test.log').write_bytes(b'model log\n')
    stdout = b'model log\nplus stdout-only startup lines\n'
    (tmp_path / 'model.out').write_bytes(stdout)
    retained.archive_run(tmp_path, preserve_startup_stdout=startup)
    assert not (tmp_path / 'model.out').exists()
    assert (tmp_path / (name + '.xz')).is_file() and not (tmp_path / name).exists()
    assert retained.restore_stdout(tmp_path) == [tmp_path / name]
    assert (tmp_path / name).read_bytes() == stdout


def test_stdout_already_preserved_with_same_bytes_is_dropped_and_different_bytes_refused(tmp_path):
    retained = module()
    (tmp_path / 'model_test.log').write_bytes(b'model log\n')
    (tmp_path / 'model_stdout.txt').write_bytes(b'stdout\n')
    (tmp_path / 'model.out').write_bytes(b'stdout\n')
    retained.archive_run(tmp_path)
    assert not (tmp_path / 'model.out').exists()
    (tmp_path / 'model.out').write_bytes(b'other stdout\n')
    with pytest.raises(ValueError, match='distinct model stdout'):
        retained.archive_run(tmp_path)
    assert (tmp_path / 'model.out').read_bytes() == b'other stdout\n'
    assert retained.restore_stdout(tmp_path) and (tmp_path / 'model_stdout.txt').read_bytes() == b'stdout\n'


def test_attempt_without_model_log_raises_and_keeps_stdout(tmp_path):
    retained = module()
    (tmp_path / 'model.out').write_bytes(b'startup refusal\n')
    with pytest.raises(ValueError, match='exactly one model log'):
        retained.archive_run(tmp_path)
    assert (tmp_path / 'model.out').read_bytes() == b'startup refusal\n'


def test_archive_and_restored_log_tampering_each_fail(tmp_path):
    retained = module()
    log = tmp_path / 'model_test.log'
    log.write_bytes(b'actual model log\n')
    record = retained.archive_run(tmp_path)
    log.write_bytes(b'wrong bytes\n')
    with pytest.raises(ValueError, match='restored log hash differs'):
        retained.restore_run(tmp_path)
    log.unlink()
    (tmp_path / record['archive']).write_bytes(b'corrupted archive')
    with pytest.raises(ValueError, match='archive hash differs'):
        retained.restore_run(tmp_path)
    assert not log.exists()


def test_retention_manifest_cannot_restore_outside_selected_run(tmp_path):
    retained = module()
    log = tmp_path / 'model_test.log'
    log.write_bytes(b'log\n')
    retained.archive_run(tmp_path)
    path = tmp_path / 'model_log_retention.json'
    data = json.loads(path.read_text())
    data['raw'] = '../model_escape.log'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='invalid retained log name'):
        retained.restore_run(tmp_path)


def test_restore_visits_only_latest_attempt_of_explicit_build(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(ROOT / 'scripts/model'))
    import model_summary
    retained = module()
    monkeypatch.setattr(model_summary, 'model_root', lambda build: tmp_path / 'models' / Path(build).name)
    selected, historical = tmp_path / 'builds/selected', tmp_path / 'builds/historical'
    paths = []
    for build, attempt in ((selected, 1), (selected, 2), (historical, 1)):
        run = tmp_path / 'models' / build.name / ('model_smoke_%s_%02d' % (build.name, attempt))
        run.mkdir(parents=True)
        (run / 'launch_command.json').write_text(json.dumps({'source_sha256': build.name}))
        (run / 'smoke_results.json').write_text(json.dumps({'summary': {'passed': 1, 'total': 1, 'failed': []}}))
        log = run / 'model_test.log'
        log.write_bytes((build.name + str(attempt)).encode())
        retained.archive_run(run)
        log.unlink()
        paths.append(log)
    assert retained.restore_selected(selected) == []
    assert [path.exists() for path in paths] == [False, True, False]


def test_distinct_stdout_is_kept_as_verified_xz_and_restores_byte_exact(tmp_path):
    retained = module()
    (tmp_path / 'model_test.log').write_bytes(b'model log\n')
    stdout = b'model log\nstdout-only startup lines\n' * 1000
    (tmp_path / 'model.out').write_bytes(stdout)
    retained.archive_run(tmp_path)
    assert not (tmp_path / 'model_stdout.txt').exists() and (tmp_path / 'model_stdout.txt.xz').is_file()
    record = json.loads((tmp_path / 'model_stdout_retention.json').read_text())['files']['model_stdout.txt']
    assert record['raw_sha256'] == hashlib.sha256(stdout).hexdigest() and record['raw_bytes'] == len(stdout)
    assert retained.restore_stdout(tmp_path) == [tmp_path / 'model_stdout.txt']
    assert (tmp_path / 'model_stdout.txt').read_bytes() == stdout
    assert retained.restore_stdout(tmp_path) == []          # idempotent once restored


def test_existing_raw_preserved_stdout_migrates_and_tampering_is_refused(tmp_path):
    retained = module()
    raw = tmp_path / 'model_stdout.txt'
    raw.write_bytes(b'already preserved raw stdout\n')
    retained.compress_stdout(tmp_path)
    assert not raw.exists()
    (tmp_path / 'model_stdout.txt.xz').write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='archive hash differs'):
        retained.restore_stdout(tmp_path)


def test_freeze_inventory_lists_the_xz_and_manifest_not_the_raw_stdout(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(ROOT / 'scripts/model'))
    import model_summary
    retained = module()
    monkeypatch.setattr(model_summary, 'model_root', lambda build: tmp_path / 'models' / Path(build).name)
    run = tmp_path / 'models/b/model_smoke_b_01'
    run.mkdir(parents=True)
    (run / 'launch_command.json').write_text(json.dumps({'source_sha256': 'b'}))
    (run / 'smoke_results.json').write_text(json.dumps({'summary': {'passed': 1, 'total': 1, 'failed': []}}))
    (run / 'model_test.log').write_bytes(b'log\n')
    (run / 'model.out').write_bytes(b'different stdout\n')
    retained.archive_run(run)
    names = {p.name for p in retained.retained_files(tmp_path / 'builds/b')}
    assert {'model_stdout.txt.xz', 'model_stdout_retention.json'} <= names and 'model_stdout.txt' not in names
