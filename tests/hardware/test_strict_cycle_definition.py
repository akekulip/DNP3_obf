"""Strict-cycle c72 baseline and combined-arm E2 diagnostic definitions (offline; no socket, SSH or BFRT client).

strict_cycle_c72_d20 / strict_cycle_c72_d5 (results/analysis/strict_cycle/DESIGN.json): qualification block
05_d20_reference_rest on the combined arm, at D = 20 ms and its D = 5 ms counterpart through the gap, 4 cold trials of
32 strict cycles each. diag_e2_combined (results/analysis/diag_mirror_d3/DESIGN_e2_combined.json): the
e2_first_request_d20 shape with the combined arm instead of off. Ports are disjoint from every other definition."""
import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import campaign  # noqa: E402
import campaign_base  # noqa: E402
import checks  # noqa: E402
import matrix  # noqa: E402


def load(relative):
    """A registered design; absent (before registration) it is empty and every test that reads it fails."""
    path = ROOT / relative
    return json.loads(path.read_text()) if path.is_file() else {}


STRICT_DESIGN = load('results/analysis/strict_cycle/DESIGN.json')
E2_DESIGN = load('results/analysis/diag_mirror_d3/DESIGN_e2_combined.json')
C72 = ROOT / 'results/builds/c72'
DIAG = ROOT / 'results/builds/c72_diag_mirror'
NATIVE = ROOT / 'results/hardware/native/c72_native_20261027_01/relay_wire.json'
NATIVE_PROBE_PORTS = {59411, 59412}  # c72_native_20261027_01/_02 master ports (out.pcap)
STRICT_NAMES = {'strict_cycle_c72_d20': 20, 'strict_cycle_c72_d5': 5}
NEW = set(STRICT_NAMES) | {'diag_e2_combined'}
LAB = json.loads((matrix.HERE / 'lab.json').read_text())
TEMPLATE = next(block for block in LAB['blocks'] if block['id'] == '05_d20_reference_rest')
LAB_DIAG = json.loads((matrix.HERE / 'lab_diag.json').read_text())
E2_OFF = next(block for block in matrix.expand_diag(LAB_DIAG)['blocks'] if block['id'] == 'e2_first_request_d20')
needs_diag = pytest.mark.skipif(not (DIAG / 'compile_local/out/response_only.p4pp').is_file(),
                                reason='compiled c72_diag_mirror outputs not restored')


def registered(name):
    return next(block for block in STRICT_DESIGN['blocks'] if block['definition'] == name)


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


def test_designs_register_observable_mechanism_falsifier_and_trial_count():
    for design in (STRICT_DESIGN, E2_DESIGN):
        assert design['registered_before_traffic'] == '2026-10-29'
        assert design['observable'] and design['mechanism'] and design['falsifier']
    assert STRICT_DESIGN['schema'] == 'c72-strict-cycle-design-v1'
    assert STRICT_DESIGN['source_sha256'] == hashlib.sha256((C72 / 'response_only.p4').read_bytes()).hexdigest()
    counts = ('trials', 'cycles_per_trial', 'exchanges_per_trial', 'exchanges')   # the design may also carry a note
    assert {key: STRICT_DESIGN['fixed_denominators'][key] for key in counts} == \
        dict(trials=8, cycles_per_trial=32, exchanges_per_trial=128, exchanges=1024)
    assert E2_DESIGN['schema'] == 'c72-diag-e2-combined-design-v1'
    assert E2_DESIGN['build']['source_sha256'] == hashlib.sha256((DIAG / 'response_only.p4').read_bytes()).hexdigest()
    assert E2_DESIGN['block']['fresh_connections'] == E2_DESIGN['fixed_denominators']['trials'] == 32


@pytest.mark.parametrize('name', sorted(STRICT_NAMES))
def test_strict_definition_is_block_05_on_the_combined_arm_with_the_strict_workload(name):
    design = registered(name)
    definition, spec = matrix.load_definition(name)
    assert [block['id'] for block in definition['blocks']] == [design['id']]
    assert definition['common'] == LAB['common'] and definition['common']['trial_mode'] == 'per_trial_cold'
    block = definition['blocks'][0]
    assert block['tool'] == 'campaign' and block['arguments'] == []
    assert block['arms'] == [dict(name='combined', T=1, padding=1)] and design['arm'] == 'combined'
    cfg, traffic = block['config'], block['traffic']
    assert design['d_ms'] == STRICT_NAMES[name]
    assert cfg['timing_params_ns'] == dict(TEMPLATE['config']['timing_params_ns'], gap=design['d_ms'] * 1000000)
    assert cfg['trials'] == dict(reads_per_trial=64, trials_per_arm=4) == \
        dict(reads_per_trial=design['reads_per_trial'], trials_per_arm=design['trials_per_arm'])
    assert {k: v for k, v in cfg.items() if k not in ('trials', 'timing_params_ns')} == \
        {k: v for k, v in TEMPLATE['config'].items() if k not in ('trials', 'timing_params_ns')}
    assert traffic == dict(TEMPLATE['traffic'], sbo_cycles=32, sbo_strict_cycle=True,
                           master_port_range=dict(first=design['master_port_range'][0],
                                                  last=design['master_port_range'][1]))
    assert checks.sbo_strict_cycle(traffic) is True and checks.planned_controls(traffic) == dict(SELECT=32, OPERATE=32)
    assert spec == dict(file='lab_strict_cycle.json', blocks=1, exchanges=4 * (64 + 2 * 32))
    assert spec['exchanges'] * 2 == STRICT_DESIGN['fixed_denominators']['exchanges']


def test_diag_e2_combined_is_the_e2_shape_with_the_combined_arm():
    definition, spec = matrix.load_definition('diag_e2_combined')
    (block,) = definition['blocks']
    assert block['id'] == E2_DESIGN['block']['id'] and definition['diag'] == matrix.expand_diag(LAB_DIAG)['diag']
    assert block['arms'] == [dict(name='combined', T=1, padding=1)]
    same = ('tool', 'arguments', 'config', 'diag_mirror')
    assert {k: block[k] for k in same} == {k: E2_OFF[k] for k in same}
    assert block['diag_mirror'] == 'on' and block['config']['timing_params_ns']['gap'] == 20000000
    assert block['config']['trials'] == dict(E2_OFF['config']['trials'], trials_per_arm=32, reads_per_trial=8)
    assert block['traffic'] == dict(E2_OFF['traffic'], master_port_range=dict(
        first=E2_DESIGN['block']['master_port_range'][0], last=E2_DESIGN['block']['master_port_range'][1]))
    assert block['traffic']['run_sbo'] is False and 'sbo_cycles' not in block['traffic']
    assert spec == dict(file='lab_diag.json', blocks=1, exchanges=32 * 8, diagnostic=True)
    assert matrix.DIAG_BLOCKS['diag_e2_combined'] == E2_DESIGN['block']['id']


def test_new_master_ports_are_disjoint_from_each_other_and_every_other_definition():
    new = {name: set().union(*definition_ports(name).values()) for name in NEW}
    assert new['strict_cycle_c72_d20'] == set(range(60170, 60174))
    assert new['strict_cycle_c72_d5'] == set(range(60174, 60178))
    assert new['diag_e2_combined'] == set(range(60180, 60212))
    blocks = list(new.values())
    assert all(not (a & b) for index, a in enumerate(blocks) for b in blocks[index + 1:])
    existing = set(NATIVE_PROBE_PORTS)
    for name in matrix.DEFINITIONS:
        if name not in NEW:
            existing |= set().union(*definition_ports(name).values())
    assert not set().union(*blocks) & existing and min(set().union(*blocks)) >= 60170


@pytest.fixture(scope='module')
def prepared(tmp_path_factory):
    root = tmp_path_factory.mktemp('strict_matrix')
    return {name: json.loads(matrix.prepare(C72, NATIVE, root / name, 'offline_' + name, definition=name).read_text())
            for name in STRICT_NAMES}


@pytest.mark.parametrize('name', sorted(STRICT_NAMES))
def test_prepare_writes_one_strict_config_the_campaign_accepts(prepared, name):
    manifest = prepared[name]
    assert manifest['expected_exchanges'] == 512 == manifest['steps'][0]['expected_exchanges']
    (step,) = manifest['steps']
    cfg = campaign_base.load_config(step['argv'][4])
    assert cfg['traffic']['sbo_strict_cycle'] is True and cfg['traffic']['sbo_cycles'] == 32
    assert 'purpose' not in cfg and 'diag_mirror' not in cfg
    engine = campaign.CandidateCampaign(cfg, campaign_base.DryRunner(), 'offline_' + name, config_path=step['argv'][4])
    assert [unit['reads'] for unit in engine.units()] == [64] * 4
    assert engine.ports()[:4] == list(range(*{20: (60170, 60174), 5: (60174, 60178)}[STRICT_NAMES[name]]))
    assert engine.endpoint_control_args().endswith(' --sbo-cycles 32 --sbo-strict-cycle 1 --read-schedule mixed_full')


def test_dry_plan_runs_four_plain_strict_trials(prepared):
    (step,) = prepared['strict_cycle_c72_d20']['steps']
    cfg = campaign_base.load_config(step['argv'][4])
    rn = campaign_base.DryRunner()
    engine = campaign.CandidateCampaign(cfg, rn, 'offline_strict_plan', config_path=step['argv'][4])
    engine.root = str(Path(step['run_root']).parent / 'never_written')
    engine.bound = {'current': dict(cfg['builds']['current']['hashes'])}
    for unit, port in zip(engine.units(), engine.ports()):
        with contextlib.redirect_stdout(io.StringIO()):
            engine.run_unit(unit, port)
    vision = [cmd for where, cmd in rn.calls if where == 'vision' and 'vision_run.py run ' in cmd]
    assert len(vision) == 4
    assert all(' --reads 64 ' in cmd and ' --sbo-cycles 32 --sbo-strict-cycle 1 ' in cmd for cmd in vision)
    assert not any(' --drop ' in cmd or ' --scenario ' in cmd for cmd in vision)


@needs_diag
def test_prepare_writes_the_diagnostic_contract_into_the_e2_combined_config(tmp_path):
    manifest = json.loads(matrix.prepare(DIAG, NATIVE, tmp_path / 'm', 'offline_e2c', definition='diag_e2_combined')
                          .read_text())
    assert manifest['expected_exchanges'] == 256
    (step,) = manifest['steps']
    cfg = campaign_base.load_config(step['argv'][4])
    assert cfg['purpose'] == 'diagnostic' and cfg['diag_mirror']['state'] == 'on'
    assert cfg['diag_mirror']['build_label'] == 'c72_diag_mirror' and cfg['arms'] == [
        dict(name='combined', T=1, padding=1, build='current')]
    assert cfg['traffic']['run_sbo'] is False and cfg['trials'] == dict(reads_per_trial=8, trials_per_arm=32)


def test_strict_definitions_refuse_the_c72_diag_build_contract_and_e2_combined_refuses_c72(tmp_path):
    with pytest.raises(ValueError, match='diagnostic'):
        matrix.prepare(C72, NATIVE, tmp_path / 'e2', 'offline_e2c', definition='diag_e2_combined')
