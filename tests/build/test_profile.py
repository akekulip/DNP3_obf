import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def module():
    spec = importlib.util.spec_from_file_location('current_profile', ROOT / 'scripts/profile.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_package_binds_actual_source_and_identical_profiles(tmp_path):
    profile = module()
    canonical = tmp_path / 'canonical.p4'
    canonical.write_text((ROOT / 'p4/response_only.p4').read_text())
    first = profile.package(tmp_path / 'build_a', source=canonical)
    canonical.write_text(canonical.read_text() + '\n// identity probe\n')
    second = profile.package(tmp_path / 'build_b', source=canonical)
    assert first['source_sha256'] != second['source_sha256']
    assert second['supported_profile'] == json.loads((tmp_path / 'build_b/supported_profile.json').read_text())
    assert second['supported_profile']['candidate']['artifact_sha256'] == {}
    assert 'transforms_applied' not in second
    assert profile.verify_package(tmp_path / 'build_b')['source_matches'] is True


def test_changed_source_rejects_stale_compile_before_artifact_pinning(tmp_path):
    profile = module()
    build = tmp_path / 'build'
    profile.package(build)
    (build / 'compile_local').mkdir()
    (build / 'compile_local/manifest.json').write_text(json.dumps({'source_sha256': 'stale', 'exit_code': 0}))
    with pytest.raises(ValueError, match='successful compile of this source'):
        profile.record_artifacts(build)


def test_source_tampering_and_packaging_input_tampering_rejected(tmp_path):
    profile = module()
    build = tmp_path / 'build'
    profile.package(build)
    (build / 'response_only.p4').write_text('stale')
    assert profile.verify_package(build)['source_matches'] is False


def test_cli_accepts_repository_relative_entry_path(tmp_path):
    result = subprocess.run([sys.executable, 'scripts/profile.py', str(tmp_path / 'cli_build')],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
