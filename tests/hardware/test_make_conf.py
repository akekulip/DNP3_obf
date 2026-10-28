"""Hardware configuration requires the configured switch's PCI identity."""
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('current_make_conf', ROOT/'scripts/hardware/make_conf.py')
make_conf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(make_conf)


@pytest.fixture
def compiled(tmp_path):
    out = tmp_path/'out'
    out.mkdir()
    config = {
        'chip_list': [{'pcie_sysfs_prefix': 'compiler-default'}],
        'p4_devices': [{'p4_programs': [{
            'program-name': 'response_only',
            'model_json_path': 'model-only.json',
            'p4_pipelines': [dict(p4_pipeline_name=n, pipe_scope=[i,i+2])
                             for i,n in enumerate(('p0','p1'))],
        }]}],
    }
    (out/'response_only.conf').write_text(json.dumps(config))
    (out/'bfrt.json').write_text('{}')
    for name in ('p0','p1'):
        (out/name).mkdir()
        (out/name/'context.json').write_text('{}')
        (out/name/'tofino.bin').write_bytes(b'compiled')
    (out/'p1/response_only.bfa').write_text('compiled mirror guard input')
    target = tmp_path/'hardware.conf'
    arguments = [str(out), '--remote-dir', '/selected/out', '--pcie', make_conf.PCIE_LOADED,
                 '-o', str(target)]
    return target, arguments


def vendor_identity(monkeypatch, value):
    vendor = Path('/sys/bus/pci/devices')/make_conf.PCIE_LOADED/'vendor'
    original_exists, original_read = Path.is_file, Path.read_text
    monkeypatch.setattr(Path, 'is_file', lambda p: value is not None if p == vendor else original_exists(p))
    def read(p, *args, **kwargs):
        return value if p == vendor else original_read(p, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)


@pytest.mark.parametrize('value', [None, '0xffff\n'])
def test_unverified_switch_identity_writes_no_config(compiled, monkeypatch, value):
    target, arguments = compiled
    vendor_identity(monkeypatch, value)
    assert make_conf.main(arguments) == 1
    assert not target.exists()


def test_offline_cannot_bypass_switch_identity(compiled, monkeypatch):
    target, arguments = compiled
    vendor_identity(monkeypatch, None)
    with pytest.raises(SystemExit) as error:
        make_conf.main(arguments + ['--offline'])
    assert error.value.code == 2
    assert not target.exists()


def test_verified_switch_generates_two_pipe_config(compiled, monkeypatch):
    target, arguments = compiled
    vendor_identity(monkeypatch, '0x1d1c\n')
    assert make_conf.main(arguments) == 0
    conf = json.loads(target.read_text())
    program = conf['p4_devices'][0]['p4_programs'][0]
    assert [p['pipe_scope'] for p in program['p4_pipelines']] == [[0],[1]]
    assert program['bfrt-config'] == '/selected/out/bfrt.json'
    assert 'model_json_path' not in program
