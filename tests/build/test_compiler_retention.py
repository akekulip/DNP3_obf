import importlib.util
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]


def fixture(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('compile_retention', ROOT / 'scripts/build.py')
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    compile_dir = tmp_path / 'compile_local'
    files = {'source/response_only.p4': b'original source', 'out/response_only.p4pp': b'original preprocessing',
             'out/bfrt.json': b'original BFRT', 'out/p0/context.json': b'original context',
             'out/p0/logs/mau.resources.log': b'original resources', 'compile.log': b'original compile log'}
    for name, content in files.items():
        path = compile_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    manifest = dict(source='/original/response_only.p4', source_sha256=compiler.sha(compile_dir / 'source/response_only.p4'),
        source_files={'response_only.p4': compiler.sha(compile_dir / 'source/response_only.p4')},
        artifact_sha256={name[4:]: compiler.sha(compile_dir / name) for name in ('out/bfrt.json', 'out/p0/context.json')},
        resources={'report_sha256': {'p0/logs/mau.resources.log': compiler.sha(compile_dir / 'out/p0/logs/mau.resources.log')}},
        compile_log_sha256=compiler.sha(compile_dir / 'compile.log'))
    (compile_dir / 'manifest.json').write_text(json.dumps(manifest))
    # Compiler verification has its own tests. These tests exercise retention of
    # its approved byte inventory, without requiring an SDK process in unit QA.
    monkeypatch.setattr(compiler, 'verify_evidence', lambda *args, **kwargs: {'compiled_artifacts_verified': True})
    return compiler, compile_dir, files


def test_restore_exact_original_out_source_and_log(tmp_path, monkeypatch):
    compiler, directory, files = fixture(tmp_path, monkeypatch)
    compiler.retain_evidence(directory)
    shutil.rmtree(directory / 'out')
    shutil.rmtree(directory / 'source')
    (directory / 'compile.log').unlink()
    assert compiler.restore_evidence(directory)['compiled_artifacts_verified'] is True
    assert {name: (directory / name).read_bytes() for name in files} == files


def test_tampered_archive_cannot_be_restored(tmp_path, monkeypatch):
    compiler, directory, _ = fixture(tmp_path, monkeypatch)
    retained = compiler.retain_evidence(directory)
    (directory / retained['archive']).write_bytes(b'wrong archive')
    with pytest.raises(ValueError, match='archive hash differs'):
        compiler.restore_evidence(directory)


def test_existing_changed_artifact_is_rejected_instead_of_overwritten(tmp_path, monkeypatch):
    compiler, directory, _ = fixture(tmp_path, monkeypatch)
    compiler.retain_evidence(directory)
    changed = directory / 'out/bfrt.json'
    changed.write_bytes(b'changed artifact')
    with pytest.raises(ValueError, match='existing compiler evidence hash differs'):
        compiler.restore_evidence(directory)
    assert changed.read_bytes() == b'changed artifact'
