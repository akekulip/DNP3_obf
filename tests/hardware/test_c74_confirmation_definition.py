"""c74 focused-confirmation definitions (offline; no socket, SSH or BFRT client is opened).

results/analysis/c74_confirmation/DESIGN.json registers eight one-block definitions that repeat c72 blocks on c74:
strict_cycle_c74_d20/_d5, diag_e2_combined_c74/diag_e2_off_c74 (on c74_diag_mirror), recovery_c74_r1/r2/r3 and
e4b_select_only_c74. Each is its c72 counterpart unchanged except the block id and the master ports; ports are disjoint
from every other definition. The non-diagnostic ones freeze and qualify only on the canonical build; the diagnostic
ones are admitted only with c74_diag_mirror and never qualify. These definitions are historical since c75 became
canonical: c74 and c74_diag_mirror are admitted only in the c74-canonical context (tests/hardware/historical_c74.py),
which the admission tests reinstate."""
import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import campaign_base  # noqa: E402
import freeze_gate  # noqa: E402
import matrix  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
import historical_c74  # noqa: E402

DESIGN = json.loads((ROOT / 'results/analysis/c74_confirmation/DESIGN.json').read_text())
CURRENT = json.loads((ROOT / 'results/analysis/stage_cut/current_build.json').read_text())
C74 = ROOT / 'results/builds/c74'
C74_DIAG = ROOT / 'results/builds/c74_diag_mirror'
C72_DIAG = ROOT / 'results/builds/c72_diag_mirror'
NATIVE = ROOT / 'results/hardware/native/c72_native_20261027_01/relay_wire.json'
NATIVE_PROBE_PORTS = {59411, 59412}
# c74 definition -> (c72 counterpart definition, c74 master ports)
COUNTERPART = {'strict_cycle_c74_d20': ('strict_cycle_c72_d20', range(60300, 60304)),
               'strict_cycle_c74_d5': ('strict_cycle_c72_d5', range(60304, 60308)),
               'diag_e2_combined_c74': ('diag_e2_combined', range(60310, 60342)),
               'diag_e2_off_c74': ('diag_e2_first', range(60350, 60382)),
               'recovery_c74_r1': ('recovery_r1', range(60390, 60396)),
               'recovery_c74_r2': ('recovery_r2', range(60396, 60402)),
               'recovery_c74_r3': ('recovery_r3', range(60402, 60408)),
               'e4b_select_only_c74': ('e4b_select_only', range(60410, 60416))}
DIAGNOSTIC = {'diag_e2_combined_c74', 'diag_e2_off_c74'}
needs_c74 = pytest.mark.skipif(not (C74 / 'compile_local/out/response_only.p4pp').is_file(),
                               reason='compiled c74 outputs not restored')
needs_diag = pytest.mark.skipif(not (C74_DIAG / 'compile_local/out/response_only.p4pp').is_file(),
                                reason='compiled c74_diag_mirror outputs not restored')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ports(name):
    out = set()
    for block in matrix.load_definition(name)[0]['blocks']:
        span = block['traffic']['master_port_range']
        block_ports = set(range(span['first'], span['last'] + 1))
        for scenario in block['config'].get('scenarios', {}).values():
            block_ports |= {port + scenario['reconnect_port_offset'] for port in block_ports}
        out |= block_ports
    return out


def test_the_design_binds_both_c74_builds_and_c74_is_no_longer_canonical():
    assert CURRENT['candidate'] != 'c74' and sha(ROOT / 'p4/response_only.p4') != sha(C74 / 'response_only.p4')
    assert DESIGN['schema'] == 'c74-confirmation-design-v1' and DESIGN['registered_before_traffic'] == '2026-10-30'
    assert DESIGN['build']['source_sha256'] == sha(C74 / 'response_only.p4')
    assert DESIGN['diag_build']['source_sha256'] == sha(C74_DIAG / 'response_only.p4')
    assert json.loads((C74_DIAG / 'diag_mirror.json').read_text())['base_build'] == 'results/builds/c74'


def test_design_registers_every_c74_definition_with_observable_mechanism_falsifier_and_denominators():
    blocks = {block['definition']: block for block in DESIGN['blocks']}
    assert set(blocks) == set(COUNTERPART)
    for name, block in blocks.items():
        assert block['observable'] and block['mechanism'] and block['falsifier']
        spec = matrix.DEFINITIONS[name]
        assert block['planned_exchanges'] == spec['exchanges'] == block['planned_denominators']['exchanges']
        assert block['diagnostic'] is bool(spec.get('diagnostic')) is (name in DIAGNOSTIC)
        assert block['build'] == ('results/builds/c74_diag_mirror' if name in DIAGNOSTIC else 'results/builds/c74')
        assert block['master_port_range'] == [min(COUNTERPART[name][1]), max(COUNTERPART[name][1])]
    assert any('first failure' in rule for rule in DESIGN['stop_rules'])
    assert DESIGN['fixed_denominators']['exchanges'] == sum(matrix.DEFINITIONS[n]['exchanges'] for n in COUNTERPART)
    assert {path: sha(ROOT / path) for path in DESIGN['inherits']} == DESIGN['inherits']


@pytest.mark.parametrize('name', sorted(COUNTERPART))
def test_c74_definition_is_its_c72_counterpart_except_the_block_id_and_master_ports(name):
    counterpart, _ports = COUNTERPART[name]
    (block,), (reference,) = matrix.load_definition(name)[0]['blocks'], matrix.load_definition(counterpart)[0]['blocks']
    assert block['id'] == reference['id'] + '_c74' or (name == 'diag_e2_off_c74' and
                                                      block['id'] == 'e2_off_first_request_d20_c74')
    strip = lambda b: dict(b, id=None, traffic=dict(b['traffic'], master_port_range=None))
    assert strip(block) == strip(reference)
    spec, ref_spec = matrix.DEFINITIONS[name], matrix.DEFINITIONS[counterpart]
    assert (spec['blocks'], spec['exchanges'], spec.get('diagnostic')) == \
        (ref_spec['blocks'], ref_spec['exchanges'], ref_spec.get('diagnostic'))
    definition = matrix.load_definition(name)[0]
    assert definition['common'] == matrix.load_definition(counterpart)[0]['common']
    if name in DIAGNOSTIC:
        assert definition['diag'] == dict(capture_interface='enp59s0f1np1', build_label='c74_diag_mirror')


def test_c74_master_ports_are_disjoint_from_each_other_and_every_other_definition():
    new = {name: ports(name) for name in COUNTERPART}
    for name, expected in COUNTERPART.items():
        assert new[name] == set(expected[1])
    values = list(new.values())
    assert all(not (a & b) for index, a in enumerate(values) for b in values[index + 1:])
    existing = set(NATIVE_PROBE_PORTS)
    for name in matrix.DEFINITIONS:
        if name not in COUNTERPART:
            existing |= ports(name)
    assert not set().union(*values) & existing


@needs_c74
@pytest.mark.parametrize('name', sorted(set(COUNTERPART) - DIAGNOSTIC))
def test_prepare_with_the_canonical_build_writes_configs_the_campaign_accepts(name, tmp_path):
    manifest = json.loads(matrix.prepare(C74, NATIVE, tmp_path / 'm', 'offline_' + name, definition=name).read_text())
    assert manifest['expected_exchanges'] == matrix.DEFINITIONS[name]['exchanges']
    (step,) = manifest['steps']
    cfg = campaign_base.load_config(step['argv'][4])
    assert cfg['builds']['current']['source_sha256'] == sha(C74 / 'response_only.p4')
    assert 'purpose' not in cfg and 'diag_mirror' not in cfg


@needs_diag
@pytest.mark.parametrize('name', sorted(DIAGNOSTIC))
def test_prepare_of_a_c74_diag_definition_writes_the_c74_diagnostic_contract(name, tmp_path, monkeypatch):
    historical_c74.use_c74_context(monkeypatch, tmp_path)
    manifest = json.loads(matrix.prepare(C74_DIAG, NATIVE, tmp_path / 'm', 'offline_' + name, definition=name)
                          .read_text())
    assert manifest['expected_exchanges'] == 256
    (step,) = manifest['steps']
    cfg = campaign_base.load_config(step['argv'][4])
    assert cfg['purpose'] == 'diagnostic'
    assert cfg['diag_mirror'] == dict(state='on', copy_port=10, capture_interface='enp59s0f1np1',
                                      build_label='c74_diag_mirror', source_sha256=sha(C74_DIAG / 'response_only.p4'))
    assert cfg['ports_map']['stat_ports'].split(',') == ['9', '64', '10']


@pytest.mark.parametrize('name', sorted(DIAGNOSTIC))
def test_c74_diag_definitions_refuse_the_canonical_build_and_the_historical_c72_diag_build(name, tmp_path):
    with pytest.raises(ValueError, match='diagnostic'):
        matrix.prepare(C74, NATIVE, tmp_path / 'a', 'refused', definition=name)
    with pytest.raises(ValueError, match='diagnostic build refused'):
        matrix.prepare(C72_DIAG, NATIVE, tmp_path / 'b', 'refused', definition=name)
    assert not (tmp_path / 'a').exists() and not (tmp_path / 'b').exists()


@needs_diag
def test_historical_c72_diag_definitions_refuse_the_c74_diag_build(tmp_path):
    with pytest.raises(ValueError, match='not the registered diagnostic build c72_diag_mirror'):
        matrix.prepare(C74_DIAG, NATIVE, tmp_path / 'm', 'refused', definition='diag_e2_combined')


def freeze(build, configs, output, mp):
    original = freeze_gate.rel

    def rel(path):
        try:
            return original(path)
        except ValueError:
            return str(Path(path).resolve())
    mp.setattr(freeze_gate, 'rel', rel)
    mp.setattr(freeze_gate, 'collect', lambda b, c: sorted(
        {rel(Path(b) / 'response_only.p4'), rel(Path(b) / 'compile_local/manifest.json')} | {rel(x) for x in c}))
    with contextlib.redirect_stdout(io.StringIO()):
        freeze_gate.write(SimpleNamespace(build=str(build), output=str(output), regen=None,
                                          configs=[str(c) for c in configs], diagnostic_exception=None))
    return json.loads(Path(output).read_text())


def check(frozen_path, config, record):
    with contextlib.redirect_stdout(io.StringIO()):
        code = freeze_gate.check(SimpleNamespace(freeze=str(frozen_path), config=str(config), record=str(record)))
    return code, json.loads(Path(record).read_text())


@needs_c74
def test_c74_no_longer_freezes_as_a_qualifying_candidate_now_that_c75_is_canonical(tmp_path, monkeypatch):
    # c74 was admitted and qualified while it was canonical (its retained freezes under results/hardware/campaigns/
    # rc01_hw_c74_*); its model runs bind the c74 observation library, so only the canonical c75 can qualify now
    assert 'candidate is not the canonical current P4 source' in freeze_gate.compile_problems(C74, sha(C74 / 'response_only.p4'))
    manifest = json.loads(matrix.prepare(C74, NATIVE, tmp_path / 'm', 'offline_sc', definition='strict_cycle_c74_d20')
                          .read_text())
    with pytest.raises(SystemExit, match='cannot freeze'):
        freeze(C74, [Path(manifest['steps'][0]['argv'][4])], tmp_path / 'freeze.json', monkeypatch)
    assert not (tmp_path / 'freeze.json').exists()


@needs_diag
def test_c74_diag_mirror_is_admitted_with_its_own_evidence_and_never_qualifies(tmp_path, monkeypatch):
    historical_c74.use_c74_context(monkeypatch, tmp_path)
    source = sha(C74_DIAG / 'response_only.p4')
    assert freeze_gate.diagnostic_problems(C74_DIAG, source) == []
    assert freeze_gate.compile_problems(C74_DIAG, source) == []
    assert freeze_gate.diag_evidence_names(C74_DIAG) == ('diag_mirror_fidelity_01.json', 'gate_vs_c74_01.json')
    assert freeze_gate.diagnostic_evidence_problems(C74_DIAG) == []
    manifest = json.loads(matrix.prepare(C74_DIAG, NATIVE, tmp_path / 'm', 'offline_e2', definition='diag_e2_off_c74')
                          .read_text())
    config = Path(manifest['steps'][0]['argv'][4])
    frozen = freeze(C74_DIAG, [config], tmp_path / 'freeze.json', monkeypatch)
    assert frozen['candidate']['diagnostic'] is True and frozen['candidate']['qualifies'] is False
    code, record = check(tmp_path / 'freeze.json', config, tmp_path / 'check.json')
    assert code == 0 and record['ok'] is True and record['qualifies'] is False and record['diagnostic'] is True
