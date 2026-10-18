"""Record exact build artifacts only after both supported compiler results validate."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CT))
import efficiency_candidates as gen

ARTIFACTS = ('manifest.json', 'bfrt.json', 'p0/context.json', 'p0/response_only.bfa', 'p0/tofino.bin',
             'p1/context.json', 'p1/response_only.bfa', 'p1/tofino.bin', 'response_only.conf')


@pytest.fixture
def compiled(tmp_path):
    build = tmp_path / 'candidate'
    inputs = gen.generate(build, ('t_single_child',))
    for name, version in (('compile_local', '9.13.1'), ('compile_switch_9132', '9.13.2')):
        out = build / name / 'out'
        hashes = {}
        for artifact in ARTIFACTS + ('response_only.p4pp',):
            path = out / artifact
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(version + ':' + artifact)
            if artifact != 'response_only.p4pp':
                hashes[artifact] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest = dict(exit_code=0, source_sha256=inputs['source_sha256'], compiler='p4c ' + version + ' (SHA: fixture)',
                        artifact_sha256=hashes)
        (build / name / 'manifest.json').write_text(json.dumps(manifest))
    return build


def test_recorded_artifact_pins_bind_both_compilers_and_preprocessed_source(compiled):
    source = (compiled / 'response_only.p4').read_bytes()
    before = {str(p.relative_to(compiled)): p.read_bytes() for p in compiled.rglob('*') if p.is_file()}
    result = gen.record_artifacts(compiled)
    assert (compiled / 'response_only.p4').read_bytes() == source
    assert result['supported_profile'] == json.loads((compiled / 'supported_profile.json').read_text())
    pins = result['supported_profile']['candidate']['artifact_sha256']
    assert set(pins) == {'compile_local', 'compile_switch_9132'}
    for name, artifacts in pins.items():
        assert set(artifacts) == set(ARTIFACTS) | {'response_only.p4pp'}
        for artifact, sha in artifacts.items():
            assert sha == hashlib.sha256((compiled / name / 'out' / artifact).read_bytes()).hexdigest()
    for path, value in before.items():
        if path not in ('response_only.inputs.json', 'supported_profile.json'):
            assert (compiled / path).read_bytes() == value


@pytest.mark.parametrize('mutation', ('candidate_hash', 'inputs_hash', 'profile_disagrees', 'compiler_version',
    'compile_failed', 'compiled_source', 'missing_manifest', 'missing_artifact', 'wrong_artifact_hash', 'missing_p4pp'))
def test_invalid_compile_or_profile_cannot_refresh_artifact_pins(compiled, mutation):
    inputs_path = compiled / 'response_only.inputs.json'
    profile_path = compiled / 'supported_profile.json'
    manifest_path = compiled / 'compile_switch_9132/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    inputs = json.loads(inputs_path.read_text())
    if mutation == 'candidate_hash':
        inputs['supported_profile']['candidate']['source_sha256'] = '0' * 64
        inputs_path.write_text(json.dumps(inputs))
        profile_path.write_text(json.dumps(inputs['supported_profile']))
    elif mutation == 'inputs_hash':
        inputs['source_sha256'] = '0' * 64
        inputs_path.write_text(json.dumps(inputs))
    elif mutation == 'profile_disagrees':
        profile_path.write_text('{}')
    elif mutation == 'compiler_version':
        manifest['compiler'] = 'p4c 9.13.1 (wrong compiler)'
    elif mutation == 'compile_failed':
        manifest['exit_code'] = 1
    elif mutation == 'compiled_source':
        manifest['source_sha256'] = '0' * 64
    elif mutation == 'missing_manifest':
        manifest_path.unlink()
    elif mutation == 'missing_artifact':
        (compiled / 'compile_switch_9132/out/p1/tofino.bin').unlink()
    elif mutation == 'wrong_artifact_hash':
        manifest['artifact_sha256']['p1/tofino.bin'] = '0' * 64
    else:
        (compiled / 'compile_switch_9132/out/response_only.p4pp').unlink()
    if mutation in ('compiler_version', 'compile_failed', 'compiled_source', 'wrong_artifact_hash'):
        manifest_path.write_text(json.dumps(manifest))
    before = inputs_path.read_bytes(), profile_path.read_bytes()
    with pytest.raises((ValueError, OSError)):
        gen.record_artifacts(compiled)
    assert (inputs_path.read_bytes(), profile_path.read_bytes()) == before
