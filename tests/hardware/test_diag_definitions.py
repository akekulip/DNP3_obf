"""D3/E2 diagnostic-mirror campaign definitions (offline; no socket, SSH or BFRT client is opened).

Each registered block (results/analysis/diag_mirror_d3/DESIGN.json) is its own one-block definition, so a failed block
cannot leave the others unexecuted. prepare() with the declared c72_diag_mirror build writes the diagnostic contract
into each config; every other definition's prepared output is byte-for-byte what it was. These c72 definitions are
historical since c74 became canonical: c72_diag_mirror is admitted only in the c72-canonical context
(tests/hardware/historical_c72.py), which these tests reinstate."""
import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import campaign_base
import diag_mirror_sessions
import freeze_gate
import matrix
sys.path.insert(0, str(Path(__file__).resolve().parent))
import historical_c72  # noqa: E402

DESIGN = json.loads((ROOT / 'results/analysis/diag_mirror_d3/DESIGN.json').read_text())
DIAG = ROOT / 'results/builds/c72_diag_mirror'
C72 = ROOT / 'results/builds/c72'
NATIVE = ROOT / 'results/hardware/native/c72_native_20261027_01/relay_wire.json'
DIAG_DEFINITIONS = {'diag_d3_on': 'd3_mirror_on_d20', 'diag_d3_off': 'd3_mirror_off_d20',
                    'diag_e2_first': 'e2_first_request_d20'}
EXCHANGES = {'diag_d3_on': 4 * 2 * (65 + 2 * 64), 'diag_d3_off': 4 * 2 * (65 + 2 * 64), 'diag_e2_first': 1 * 32 * 8}
NATIVE_PROBE_PORTS = {59411, 59412}  # c72_native_20261027_01/_02 master ports (out.pcap)
PINNED = 'f2c32cf2a'                 # matrix.py before the diagnostic definitions
NON_DIAGNOSTIC = ('qualification', 'evaluation', 'recovery', 'recovery_r1', 'recovery_r2', 'recovery_r3')
needs_diag = pytest.mark.skipif(not (DIAG / 'compile_local/out/response_only.p4pp').is_file(),
                                reason='compiled c72_diag_mirror outputs not restored')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


DIAG_SOURCE = sha(DIAG / 'response_only.p4')
LAB = json.loads((matrix.HERE / 'lab.json').read_text())
TEMPLATE = next(block for block in LAB['blocks'] if block['id'] == '02_d5_reference')


def design(block_id):
    return next(block for block in DESIGN['blocks'] if block['id'] == block_id)


def definition_ports(name):
    """{block id: master ports a definition's block can open, including any reconnect port}."""
    out = {}
    for block in matrix.load_definition(name)[0]['blocks']:
        span = block['traffic']['master_port_range']
        ports = set(range(span['first'], span['last'] + 1))
        for scenario in block['config'].get('scenarios', {}).values():
            ports |= {port + scenario['reconnect_port_offset'] for port in ports}
        out[block['id']] = ports
    return out


def snapshot(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in sorted(Path(directory).rglob('*')) if p.is_file()}


def configs_of(manifest):
    return [Path(step['argv'][4]) for step in manifest['steps']]


@pytest.mark.parametrize('name', sorted(DIAG_DEFINITIONS))
def test_diag_definition_is_one_registered_block_with_its_arms_trials_and_d(name):
    definition, spec = matrix.load_definition(name)
    registered = design(DIAG_DEFINITIONS[name])
    assert [block['id'] for block in definition['blocks']] == [registered['id']]
    assert definition['common'] == LAB['common'] and definition['common']['trial_mode'] == 'per_trial_cold'
    block = definition['blocks'][0]
    assert block['tool'] == 'campaign' and block['arguments'] == []
    assert block['arms'] == [next(a for a in TEMPLATE['arms'] if a['name'] == arm) for arm in registered['arms']]
    assert block['diag_mirror'] == registered['diag_mirror'].split()[0] in ('on', 'off')
    cfg, traffic = block['config'], block['traffic']
    assert cfg['timing_params_ns'] == dict(TEMPLATE['config']['timing_params_ns'],
                                           gap=DESIGN['common_workload']['d_ms'] * 1000000)
    assert cfg['timing_params_ns']['gap'] == 20000000
    reads = registered.get('reads_per_trial', TEMPLATE['config']['trials']['reads_per_trial'])
    assert cfg['trials'] == dict(reads_per_trial=reads, trials_per_arm=registered['trials_per_arm'])
    if registered.get('run_sbo') is False:
        assert traffic['run_sbo'] is False and 'sbo_cycles' not in traffic
        sbo = 0
    else:
        assert traffic['run_sbo'] is True and traffic['sbo_cycles'] == TEMPLATE['traffic']['sbo_cycles'] == 64
        sbo = traffic['sbo_cycles']
    # everything else is the template reference block
    assert {k: v for k, v in cfg.items() if k not in ('trials', 'timing_params_ns')} == \
        {k: v for k, v in TEMPLATE['config'].items() if k not in ('trials', 'timing_params_ns')}
    assert {k: v for k, v in traffic.items() if k not in ('master_port_range', 'run_sbo', 'sbo_cycles')} == \
        {k: v for k, v in TEMPLATE['traffic'].items() if k not in ('master_port_range', 'run_sbo', 'sbo_cycles')}
    connections = len(block['arms']) * registered['trials_per_arm']
    assert connections == registered['fresh_connections']
    assert spec == dict(file='lab_diag.json', blocks=1, exchanges=connections * (reads + 2 * sbo), diagnostic=True)
    assert spec['exchanges'] == EXCHANGES[name]


def test_every_registered_diag_block_has_exactly_one_definition():
    assert sorted(DIAG_DEFINITIONS.values()) == sorted(block['id'] for block in DESIGN['blocks'])
    # every diagnostic definition is registered by a design: the D3/E2 design's three blocks, plus the definitions
    # that later design files register themselves (the combined-arm connection-start baseline)
    later_blocks = {json.loads((ROOT / 'results/analysis/diag_mirror_d3' / name).read_text())['block']['id']
                    for name in ('DESIGN_e2_combined.json',)}
    # and the c74 confirmation design's diagnostic blocks (on c74_diag_mirror)
    later_blocks |= {block['id'] for block in json.loads((ROOT / 'results/analysis/c74_confirmation/DESIGN.json')
                                                         .read_text())['blocks'] if block['diagnostic']}
    later = {n for n, block_id in matrix.DIAG_BLOCKS.items() if block_id in later_blocks}
    assert len(later) == len(later_blocks)
    assert sorted(n for n, spec in matrix.DEFINITIONS.items() if spec.get('diagnostic')) == \
        sorted(set(DIAG_DEFINITIONS) | later)


def test_diag_master_ports_are_disjoint_from_each_other_and_every_existing_definition():
    diag = {name: definition_ports(name)[block_id] for name, block_id in DIAG_DEFINITIONS.items()}
    for name, ports in diag.items():
        assert len(ports) == design(DIAG_DEFINITIONS[name])['fresh_connections']
    blocks = list(diag.values())
    assert all(not (a & b) for index, a in enumerate(blocks) for b in blocks[index + 1:])
    existing = set(NATIVE_PROBE_PORTS)
    for name in matrix.DEFINITIONS:
        if name not in DIAG_DEFINITIONS:
            existing |= set().union(*definition_ports(name).values())
    assert not set().union(*blocks) & existing


@pytest.fixture(scope='module')
def prepared_diag(tmp_path_factory):
    root = tmp_path_factory.mktemp('diag_matrix')
    with pytest.MonkeyPatch.context() as mp:
        historical_c72.use_c72_context(mp, root)
        return {name: json.loads(matrix.prepare(DIAG, NATIVE, root / name, 'offline_' + name, definition=name)
                                 .read_text()) for name in DIAG_DEFINITIONS}


@needs_diag
@pytest.mark.parametrize('name', sorted(DIAG_DEFINITIONS))
def test_prepare_writes_the_diagnostic_contract_into_each_diag_config(prepared_diag, name):
    manifest = prepared_diag[name]
    assert manifest['expected_exchanges'] == EXCHANGES[name] == manifest['steps'][0]['expected_exchanges']
    (path,) = configs_of(manifest)
    cfg = campaign_base.load_config(path)
    copy_port = diag_mirror_sessions.load(DIAG)['copy_port']
    assert copy_port == DESIGN['capture']['copy_port'] == 10
    assert cfg['purpose'] == 'diagnostic'
    assert cfg['diag_mirror'] == dict(state=design(DIAG_DEFINITIONS[name])['diag_mirror'].split()[0],
                                      copy_port=copy_port, capture_interface='enp59s0f1np1',
                                      build_label='c72_diag_mirror', source_sha256=DIAG_SOURCE)
    assert list(cfg['diag_mirror']) == ['state', 'copy_port', 'capture_interface', 'build_label', 'source_sha256']
    assert cfg['ports_map'] == dict(LAB['common']['ports_map'], stat_ports='9,64,10')
    assert cfg['builds']['current']['source_sha256'] == DIAG_SOURCE == cfg['ctl_timing_identity']['source_sha256']
    assert cfg['builds']['current']['out_dir'] == 'results/builds/c72_diag_mirror/compile_local/out'


def test_prepare_of_a_diag_definition_refuses_a_non_diagnostic_build(tmp_path):
    with pytest.raises(ValueError, match='diagnostic'):
        matrix.prepare(C72, NATIVE, tmp_path / 'out', 'refused', definition='diag_d3_on')
    assert not (tmp_path / 'out').exists()


def test_prepare_of_a_diag_definition_refuses_a_build_failing_admission(tmp_path, monkeypatch):
    monkeypatch.setattr(freeze_gate, 'diagnostic_problems', lambda build, source: ['derived source tampered'])
    with pytest.raises(ValueError, match='derived source tampered'):
        matrix.prepare(DIAG, NATIVE, tmp_path / 'out', 'refused', definition='diag_e2_first')
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('where', ['config_purpose', 'config_diag_mirror', 'block_diag_mirror'])
def test_non_diagnostic_definition_cannot_carry_the_diagnostic_contract(tmp_path, monkeypatch, where):
    source = tmp_path / 'hw'
    source.mkdir()
    lab = json.loads((matrix.HERE / 'lab.json').read_text())
    block = lab['blocks'][1]
    if where == 'config_purpose':
        block['config']['purpose'] = 'diagnostic'
    elif where == 'config_diag_mirror':
        block['config']['diag_mirror'] = dict(state='on')
    else:
        block['diag_mirror'] = 'on'
    (source / 'lab.json').write_text(json.dumps(lab))
    monkeypatch.setattr(matrix, 'HERE', source)
    with pytest.raises(ValueError, match='diagnostic'):
        matrix.prepare(C72, NATIVE, tmp_path / 'out', 'refused')


@pytest.fixture(scope='module')
def pinned_matrix(tmp_path_factory):
    """matrix.py at the commit before the diagnostic definitions, run with the current HERE and ROOT."""
    source = subprocess.run(['git', '-C', str(ROOT), 'show', PINNED + ':scripts/hardware/matrix.py'],
                            capture_output=True, check=True).stdout
    path = tmp_path_factory.mktemp('pinned_matrix') / 'matrix_pinned.py'
    path.write_bytes(source)
    spec = importlib.util.spec_from_file_location('matrix_pinned', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE, module.ROOT = matrix.HERE, matrix.ROOT
    return module


@pytest.mark.parametrize('name', NON_DIAGNOSTIC)
def test_non_diagnostic_prepare_is_byte_for_byte_unchanged(pinned_matrix, tmp_path, name):
    output = tmp_path / 'matrix'
    pinned_matrix.prepare(C72, NATIVE, output, 'offline_' + name, definition=name)
    before = snapshot(output)
    blocks = sorted(block['id'] for block in matrix.load_definition(name)[0]['blocks'])
    assert sorted(before) == ['configs/' + block + '.json' for block in blocks] + ['manifest.json']
    assert len(before) == matrix.DEFINITIONS[name]['blocks'] + 1
    shutil.rmtree(output)
    manifest = matrix.prepare(C72, NATIVE, output, 'offline_' + name, definition=name)
    assert snapshot(output) == before
    for path in configs_of(json.loads(manifest.read_text())):
        cfg = json.loads(path.read_text())
        assert 'purpose' not in cfg and 'diag_mirror' not in cfg and cfg['ports_map']['stat_ports'] == '9,64'


def controlled_files(mp):
    """write() over a fixed file set (collect()'s repository-wide set is edited concurrently by other work)."""
    def collect(build, configs):
        return sorted({freeze_gate.rel(Path(build) / 'response_only.p4'),
                       freeze_gate.rel(Path(build) / 'compile_local/manifest.json')}
                      | {freeze_gate.rel(c) for c in configs})
    mp.setattr(freeze_gate, 'collect', collect)


def outside_paths(mp):
    original = freeze_gate.rel

    def rel(path):
        try:
            return original(path)
        except ValueError:
            return str(Path(path).resolve())
    mp.setattr(freeze_gate, 'rel', rel)


@needs_diag
def test_prepared_diag_configs_freeze_and_bind_to_the_diag_build_but_never_qualify(prepared_diag, tmp_path,
                                                                                    monkeypatch):
    historical_c72.use_c72_context(monkeypatch, tmp_path)
    outside_paths(monkeypatch)
    controlled_files(monkeypatch)
    configs = [path for manifest in prepared_diag.values() for path in configs_of(manifest)]
    with contextlib.redirect_stdout(io.StringIO()):
        freeze_gate.write(SimpleNamespace(build=str(DIAG), output=str(tmp_path / 'freeze.json'), regen=None,
                                          configs=[str(c) for c in configs], diagnostic_exception=None))
    frozen = json.loads((tmp_path / 'freeze.json').read_text())
    assert frozen['candidate']['diagnostic'] is True and frozen['candidate']['qualifies'] is False
    for path in configs:
        assert freeze_gate.candidate_binding(frozen, path) == []
        with contextlib.redirect_stdout(io.StringIO()):
            code = freeze_gate.check(SimpleNamespace(freeze=str(tmp_path / 'freeze.json'), config=str(path),
                                                     record=str(tmp_path / (path.stem + '_check.json'))))
        record = json.loads((tmp_path / (path.stem + '_check.json')).read_text())
        assert code == 0 and record['ok'] is True and record['qualifies'] is False and record['diagnostic'] is True
