"""E4b SELECT-without-OPERATE campaign definition (offline; no socket, SSH or BFRT client is opened).

The single registered block (results/analysis/e4b_select_only/DESIGN.json) is qualification block 10 without its loss
preset, with six cold trials of 20 READs and four abandoned SELECTs each. Every existing definition's prepared output
stays byte-for-byte what matrix.py at ca0db02d1 produced."""
import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import campaign  # noqa: E402
import campaign_base  # noqa: E402
import checks  # noqa: E402
import matrix  # noqa: E402

DESIGN = json.loads((ROOT / 'results/analysis/e4b_select_only/DESIGN.json').read_text())
C72 = ROOT / 'results/builds/c72'
DIAG = ROOT / 'results/builds/c72_diag_mirror'
NATIVE = ROOT / 'results/hardware/native/c72_native_20261027_01/relay_wire.json'
NATIVE_PROBE_PORTS = {59411, 59412}  # c72_native_20261027_01/_02 master ports (out.pcap)
PINNED = 'ca0db02d1'                 # matrix.py before the E4b definition
NAME = 'e4b_select_only'
# definitions added after E4b (tests/hardware/test_strict_cycle_definition.py); not part of the E4b comparison
LATER = {'strict_cycle_c72_d20', 'strict_cycle_c72_d5', 'diag_e2_combined'}
LAB = json.loads((matrix.HERE / 'lab.json').read_text())
TEMPLATE = next(block for block in LAB['blocks'] if block['id'] == '10_d20_loss_full')
REGISTERED = DESIGN['block']


def snapshot(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in sorted(Path(directory).rglob('*')) if p.is_file()}


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


def test_design_registers_observable_mechanism_falsifier_and_trial_count():
    assert DESIGN['schema'] == 'c72-e4b-select-only-design-v1'
    assert DESIGN['build'] == 'results/builds/c72' and DESIGN['source_sha256'] == \
        hashlib.sha256((C72 / 'response_only.p4').read_bytes()).hexdigest()
    assert set(DESIGN['observable']) == {'select', 'read_after_select', 'no_operate', 'switch_state_after_trial',
                                         'restoration'}
    assert 'IEEE 1815' in DESIGN['mechanism']['relay']
    assert 'response_ready_ack_d_no_j_v3' in DESIGN['mechanism']['switch']
    assert any('failed restoration' in item for item in DESIGN['falsifier'])
    assert any('READ after an abandoned SELECT' in item for item in DESIGN['falsifier'])
    assert REGISTERED['trials_per_arm'] == REGISTERED['fresh_connections'] == DESIGN['fixed_denominators']['trials']
    model = DESIGN['model_counterpart']
    assert hashlib.sha256((ROOT / model['result']).read_bytes()).hexdigest() == model['result_sha256']


def test_e4b_definition_is_block_10_without_loss_with_the_registered_select_only_workload():
    definition, spec = matrix.load_definition(NAME)
    assert [block['id'] for block in definition['blocks']] == [REGISTERED['id']]
    assert definition['common'] == LAB['common'] and definition['common']['trial_mode'] == 'per_trial_cold'
    block = definition['blocks'][0]
    assert block['tool'] == 'campaign' and block['arguments'] == []           # plain trials, no --loss
    assert block['arms'] == [dict(name=REGISTERED['arm'], T=REGISTERED['T'], padding=REGISTERED['padding'])]
    cfg, traffic = block['config'], block['traffic']
    assert cfg['timing_params_ns'] == dict(TEMPLATE['config']['timing_params_ns'], gap=REGISTERED['d_ms'] * 1000000)
    assert cfg['trials'] == dict(reads_per_trial=REGISTERED['reads_per_trial'],
                                 trials_per_arm=REGISTERED['trials_per_arm'])
    assert cfg['loss'] == dict(TEMPLATE['config']['loss'], presets={})
    assert {k: v for k, v in cfg.items() if k not in ('trials', 'loss')} == \
        {k: v for k, v in TEMPLATE['config'].items() if k not in ('trials', 'loss')}
    assert traffic == dict(TEMPLATE['traffic'], sbo_cycles=REGISTERED['sbo_cycles'], sbo_select_only=True,
                           master_port_range=dict(first=REGISTERED['master_port_range'][0],
                                                  last=REGISTERED['master_port_range'][1]))
    assert traffic['read_schedule'] == REGISTERED['read_schedule'] and traffic['run_sbo'] is True
    assert checks.planned_controls(traffic) == dict(SELECT=4, OPERATE=0)
    per_trial = REGISTERED['reads_per_trial'] + REGISTERED['sbo_cycles']
    assert spec == dict(file='lab_e4b.json', blocks=1, exchanges=REGISTERED['trials_per_arm'] * per_trial)
    assert spec['exchanges'] == DESIGN['fixed_denominators']['exchanges'] == 144


def test_e4b_master_ports_are_disjoint_from_every_existing_definition():
    (ports,) = definition_ports(NAME).values()
    span = REGISTERED['master_port_range']
    assert ports == set(range(span[0], span[1] + 1)) and len(ports) == REGISTERED['fresh_connections']
    existing = set(NATIVE_PROBE_PORTS)
    for name in matrix.DEFINITIONS:
        if name != NAME:
            existing |= set().union(*definition_ports(name).values())
    for path in ('lab.json', 'lab_eval.json', 'lab_recovery.json', 'lab_diag.json'):
        assert (matrix.HERE / path).is_file()
    assert not ports & existing


@pytest.fixture(scope='module')
def prepared(tmp_path_factory):
    root = tmp_path_factory.mktemp('e4b_matrix')
    manifest = json.loads(matrix.prepare(C72, NATIVE, root / 'out', 'offline_e4b', definition=NAME).read_text())
    return manifest


def test_prepare_writes_one_select_only_config_the_campaign_accepts(prepared):
    assert prepared['expected_exchanges'] == 144 == prepared['steps'][0]['expected_exchanges']
    (step,) = prepared['steps']
    assert step['argv'][3] == 'campaign' and step['argv'][6:] == []
    cfg = campaign_base.load_config(step['argv'][4])
    assert cfg['traffic']['sbo_select_only'] is True and cfg['traffic']['sbo_cycles'] == 4
    assert 'purpose' not in cfg and 'diag_mirror' not in cfg and cfg['ports_map']['stat_ports'] == '9,64'
    assert cfg['builds']['current']['source_sha256'] == DESIGN['source_sha256']
    engine = campaign.CandidateCampaign(cfg, campaign_base.DryRunner(), 'offline_e4b', config_path=step['argv'][4])
    units = engine.units()
    assert len(units) == 6 and [unit['reads'] for unit in units] == [20] * 6
    assert engine.ports()[:6] == list(range(60160, 60166))
    assert engine.endpoint_control_args().endswith(' --sbo-cycles 4 --sbo-select-only 1 --read-schedule full')


def test_dry_plan_runs_six_plain_trials_with_the_select_only_endpoint(prepared):
    (step,) = prepared['steps']
    cfg = campaign_base.load_config(step['argv'][4])
    rn = campaign_base.DryRunner()
    engine = campaign.CandidateCampaign(cfg, rn, 'offline_e4b_plan', config_path=step['argv'][4])
    engine.root = str(Path(prepared['steps'][0]['run_root']).parent / 'never_written')
    engine.bound = {'current': dict(cfg['builds']['current']['hashes'])}
    for unit, port in zip(engine.units(), engine.ports()):
        with contextlib.redirect_stdout(io.StringIO()):
            engine.run_unit(unit, port)
    vision = [cmd for where, cmd in rn.calls if where == 'vision' and 'vision_run.py run ' in cmd]
    assert len(vision) == 6
    assert all(' --reads 20 ' in cmd and ' --sbo-cycles 4 --sbo-select-only 1 ' in cmd for cmd in vision)
    assert not any(' --drop ' in cmd or ' --scenario ' in cmd for cmd in vision)
    assert [int(cmd.split(' --master-port ')[1].split()[0]) for cmd in vision] == list(range(60160, 60166))


@pytest.fixture(scope='module')
def pinned_matrix(tmp_path_factory):
    """matrix.py at the commit before the E4b definition, run with the current HERE and ROOT."""
    source = subprocess.run(['git', '-C', str(ROOT), 'show', PINNED + ':scripts/hardware/matrix.py'],
                            capture_output=True, check=True).stdout
    path = tmp_path_factory.mktemp('pinned_matrix') / 'matrix_pinned_e4b.py'
    path.write_bytes(source)
    spec = importlib.util.spec_from_file_location('matrix_pinned_e4b', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE, module.ROOT = matrix.HERE, matrix.ROOT
    return module


@pytest.mark.parametrize('name', sorted(n for n in matrix.DEFINITIONS if n != NAME and n not in LATER))
def test_every_existing_definition_prepares_byte_for_byte_unchanged(pinned_matrix, tmp_path, name):
    diagnostic = matrix.DEFINITIONS[name].get('diagnostic')
    build = DIAG if diagnostic else C72
    if diagnostic and not (DIAG / 'compile_local/out/response_only.p4pp').is_file():
        pytest.skip('compiled c72_diag_mirror outputs not restored')
    assert name in pinned_matrix.DEFINITIONS and pinned_matrix.DEFINITIONS[name] == matrix.DEFINITIONS[name]
    output = tmp_path / 'matrix'
    pinned_matrix.prepare(build, NATIVE, output, 'offline_' + name, definition=name)
    before = snapshot(output)
    shutil.rmtree(output)
    matrix.prepare(build, NATIVE, output, 'offline_' + name, definition=name)
    assert snapshot(output) == before


def test_only_the_e4b_definition_was_added(pinned_matrix):
    assert sorted(n for n in matrix.DEFINITIONS if n not in LATER) == sorted(list(pinned_matrix.DEFINITIONS) + [NAME])
    assert all(matrix.DEFINITIONS[name] == spec for name, spec in pinned_matrix.DEFINITIONS.items())
