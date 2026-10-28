import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
C72_OUT = ROOT / 'results/builds/c72/compile_local/out'

STUB_COMPILER = '''
import hashlib, json
from pathlib import Path
def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def verify_evidence(output, source_root=None):
    return {'compiled_artifacts_verified': json.loads((Path(output) / 'stub.json').read_text())['verified']}
def pipeline_contexts(out):
    pipes = json.loads((Path(out).parent / 'stub.json').read_text())['pipes']
    return {name: Path(path) for name, path in pipes.items()}
'''


def module(root=None, monkeypatch=None):
    spec = importlib.util.spec_from_file_location('model_config', ROOT / 'scripts/model/model_config.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    if root is not None:
        monkeypatch.setattr(result, 'ROOT', root)
    return result


def fixture(tmp_path, verified=True, inventory=('p0', 'p1'), conf_pipes=('p0', 'p1')):
    """Stub compiler root plus one compiled out/ with a single original .conf."""
    root = tmp_path / 'repo'
    (root / 'scripts').mkdir(parents=True)
    (root / 'scripts/build.py').write_text(STUB_COMPILER)
    compiled = tmp_path / 'build/compile_local'
    out = compiled / 'out'
    out.mkdir(parents=True)
    config = {'p4_devices': [{'device-id': 0, 'agent0': 'lib/libpltfm_mgr.so', 'p4_programs': [{
        'program-name': 'response_only', 'bfrt-config': '/moved/historical/bfrt.json',
        'p4_pipelines': [{'p4_pipeline_name': name, 'context': '/moved/%s/context.json' % name,
                          'config': '/moved/%s/tofino.bin' % name, 'path': '/moved'} for name in conf_pipes]}]}]}
    conf = out / 'response_only.conf'
    conf.write_text(json.dumps(config, indent=2))
    (compiled / 'stub.json').write_text(json.dumps({
        'verified': verified, 'pipes': {name: '%s/pipe/context.json' % name for name in inventory}}))
    (compiled / 'manifest.json').write_text(json.dumps({
        'source_sha256': 'a' * 64, 'artifact_sha256': {'response_only.conf': hashlib.sha256(conf.read_bytes()).hexdigest()}}))
    return root, out, conf


def test_unverified_compiler_artifacts_are_refused(tmp_path, monkeypatch):
    root, out, _ = fixture(tmp_path, verified=False)
    with pytest.raises(ValueError, match='verified original compiler artifacts'):
        module(root, monkeypatch).prepare(out, tmp_path / 'noagent.conf')
    assert not (tmp_path / 'noagent.conf').exists()


def test_derived_config_is_rebased_and_original_bytes_are_unchanged(tmp_path, monkeypatch):
    root, out, conf = fixture(tmp_path)
    before = conf.read_bytes()
    destination = tmp_path / 'run/noagent.conf'
    destination.parent.mkdir()
    binding = module(root, monkeypatch).prepare(out, destination)
    assert conf.read_bytes() == before
    device = json.loads(destination.read_text())['p4_devices'][0]
    assert 'agent0' not in device
    program = device['p4_programs'][0]
    assert program['bfrt-config'] == str(out / 'bfrt.json')
    for pipe in program['p4_pipelines']:
        name = pipe['p4_pipeline_name']
        assert pipe['context'] == str(out / name / 'pipe/context.json')
        assert pipe['config'] == str(out / name / 'pipe/tofino.bin')
        assert pipe['path'] == str(out)
    recorded = json.loads((destination.parent / 'model_config_binding.json').read_text())
    assert recorded == binding
    assert recorded['original_config_sha256'] == hashlib.sha256(before).hexdigest()
    assert recorded['derived_config_sha256'] == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert recorded['selected_out'] == str(out.resolve())


@pytest.mark.parametrize('inventory, conf_pipes', [
    (('p0', 'p1'), ('p0',)),          # config omits a verified pipeline
    (('p0',), ('p0', 'p1')),          # config names a pipeline the compiler did not produce
    (('p0', 'p1'), ('p0', 'p0', 'p1')),  # duplicate pipeline
])
def test_pipeline_mismatch_with_verified_inventory_is_refused(tmp_path, monkeypatch, inventory, conf_pipes):
    root, out, _ = fixture(tmp_path, inventory=inventory, conf_pipes=conf_pipes)
    with pytest.raises(ValueError, match='pipeline'):
        module(root, monkeypatch).prepare(out, tmp_path / 'noagent.conf')


def test_tampered_original_config_is_refused(tmp_path, monkeypatch):
    root, out, conf = fixture(tmp_path)
    conf.write_text(conf.read_text() + ' ')
    with pytest.raises(ValueError, match='hash differs'):
        module(root, monkeypatch).prepare(out, tmp_path / 'noagent.conf')


@pytest.mark.skipif(not C72_OUT.is_dir(), reason='selected c72 package not present')
def test_selected_c72_package_derives_a_private_config_without_writing_the_build(tmp_path):
    original = C72_OUT / 'response_only.conf'
    before = original.read_bytes()
    destination = tmp_path / 'noagent.conf'
    binding = module().prepare(C72_OUT, destination)
    assert original.read_bytes() == before
    assert binding['original_config_sha256'] == hashlib.sha256(before).hexdigest()
    for pipe in json.loads(destination.read_text())['p4_devices'][0]['p4_programs'][0]['p4_pipelines']:
        assert Path(pipe['context']).is_file() and Path(pipe['config']).is_file()
