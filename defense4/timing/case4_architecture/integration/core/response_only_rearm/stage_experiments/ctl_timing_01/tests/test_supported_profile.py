"""supported_profile.json: every pinned value equals its source (review af7bd434, section 6)."""
import hashlib
import importlib.util
import json
import re

import pytest
import sys
from pathlib import Path

CT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CT))
X = CT.parent
PROFILE = json.loads((CT / 'supported_profile.json').read_text())
CONFIGS = sorted((X / 'seg61_02/hw/config').glob('ctl_m10_*.json'))


def module(name, path):
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_candidate_identity_is_the_build_on_disk():
    cand = PROFILE['candidate']
    build = CT / 'evidence' / Path(cand['build']).name
    assert hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest() == cand['source_sha256']
    assert json.loads((build / 'response_only.inputs.json').read_text())['segment_sha256'] == cand['segment_sha256']
    for compile_dir, hashes in cand['artifact_sha256'].items():
        manifest = json.loads((build / compile_dir / 'manifest.json').read_text())
        assert manifest['source_sha256'] == cand['source_sha256'] and manifest['exit_code'] == 0
        assert {k: v for k, v in manifest['artifact_sha256'].items() if k != 'manifest.json'} == hashes


def _literals(path):
    """Module-level NAME = literal assignments of a source file."""
    import ast
    out = {}
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    return out


def test_encoding_matches_the_profile_checker_and_encoder():
    checker = _literals(X / 'read_reencode_01/profile_check.py')
    enc = PROFILE['encoding']
    assert checker['READ_RANGES'] == tuple(tuple(r) for r in enc['read_ranges'])
    assert checker['CONTROL_SPLIT'] == tuple(enc['control_application_partition'])
    assert checker['NATIVE_LEN'] == enc['native_input_octets']
    assert _literals(X / 'seg61_01/encode61.py')['CTL_PARTS'] == tuple(enc['control_application_partition'])
    assert sum(enc['control_application_partition']) == 22


def test_clock_and_retry_budget_match_the_generator():
    gen = module('profile_generate', CT / 'generate.py')
    clock = PROFILE['clock']
    assert gen.T_TIME_M7 == dict(unit_ns=clock['t_unit_ns'], grid_ns=clock['t_grid_ns'], source=clock['t_source'])
    assert gen.RETRY_BUDGET == PROFILE['n']['retry_budget_laps']
    assert 'count_busy_bump.execute(4w5)' in (CT / 'evidence/m10_03/response_only.p4').read_text()


def test_every_m10_config_pins_this_profile():
    assert sorted(p.name for p in CONFIGS) == sorted(
        'ctl_m10_%s.json' % n for n in ('persistence_graceful_950', 'persistence_rst_950', 'loss_core_950',
                                        'reconnect_950', 'held_operate_350', 'interleave_950'))
    timing, ports = PROFILE['timing_ns'], PROFILE['ports']
    for path in CONFIGS:
        cfg = json.loads(path.read_text())
        build = cfg['builds']['ctl_timing_m10_03']
        assert build['source_sha256'] == PROFILE['candidate']['source_sha256'] and build['image_len'] == 61
        assert cfg['expectations']['native_len'] == PROFILE['encoding']['native_input_octets']
        assert {k: v for k, v in cfg['ports_map'].items()} == {k: v for k, v in ports.items() if k != 'note'}
        want = dict(timing, **(timing['held_operate_overrides'] if 'held_operate' in path.name else {}))
        t = cfg['timing_params_ns']
        assert (t['gap'], t['op_j'], t['pb'], t['readiness'], t['da'], t['cap']) == (
            want['D_release_budget'], want['J_operate_hold'], want['pb_piggyback_bound'], want['readiness'],
            want['da'], want['cap'])


def test_child_count_is_the_number_of_t_child_registers():
    text = (CT / 'evidence/m10_03/response_only.p4').read_text()
    assert len(set(re.findall(r'child_seen(\d+)_reg;', text))) == PROFILE['t_child_count']


# ---- the compiled constants themselves (code review of m10_03, finding 5) ---------------------------------------
BUILD = CT / 'evidence' / Path(PROFILE['candidate']['build']).name
SOURCE = (BUILD / 'response_only.p4').read_text()
INPUTS = json.loads((BUILD / 'response_only.inputs.json').read_text())


def test_ports_match_the_p4_constants_and_the_build_port_map():
    ports = PROFILE['ports']
    for name, key in (('n_RETURN_PORT', 'recirc'), ('n_N_ACK_RETURN', 'n_ack_return'),
                      ('n_READ_HANDOFF_PORT', 't_in')):
        assert 'const PortId_t %s=9w%d;' % (name, ports[key]) in SOURCE
    pm = INPUTS['port_map']
    assert (pm['relay_port'], pm['n_ack_return'], pm['t_in'], pm['hb_return'], pm['held_return']) == (
        ports['relay_dev'], ports['n_ack_return'], ports['t_in'], ports['hb_return'], ports['held_return'])


def test_retry_budget_is_both_thirty_twos_in_the_source():
    budget = PROFILE['n']['retry_budget_laps']
    assert 'const bit<32> n_RETRY_BUDGET=%d;' % budget in SOURCE
    table = SOURCE[SOURCE.index('table reset_boundary{'):]
    table = table[:table.index('const default_action')]
    assert table.count('16w%d' % budget) == 2           # the wait abort row and the restart abort row


def test_output_octets_and_clock_match_the_build_record():
    for path in CONFIGS:
        assert json.loads(path.read_text())['builds']['ctl_timing_m10_03']['image_len'] == \
            PROFILE['encoding']['output_octets']
    clock = PROFILE['clock']
    assert INPUTS['t_time'] == dict(unit_ns=clock['t_unit_ns'], grid_ns=clock['t_grid_ns'], source=clock['t_source'])


@pytest.mark.skipif(not (BUILD / 'compile_local' / 'out').is_dir(),
                    reason='compiler outputs are untracked (freeze_gate marks them tracked: false), so a clean checkout '
                           'lacks them; the manifest cross-check above still runs')
def test_artifact_hashes_match_the_files():
    for compile_dir, hashes in PROFILE['candidate']['artifact_sha256'].items():
        for rel, want in hashes.items():
            assert hashlib.sha256((BUILD / compile_dir / 'out' / rel).read_bytes()).hexdigest() == want


@pytest.mark.parametrize('children', (1, 2, 3))
def test_successor_semantics_are_bound_to_source_instead_of_name(tmp_path, children):
    import model_profile
    source = tmp_path / 'response_only.p4'
    source.write_text('new successor source')
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    inputs = dict(source_sha256=sha, milestone='successor', supported_profile=dict(
        reset_restart_required=True, t_child_count=children, candidate=dict(source_sha256=sha)))
    got = model_profile.resolve(inputs, source, 'successor')
    assert got['milestone'] == 'm10' and got['reset_restart_required'] is True and got['t_child_count'] == children


@pytest.mark.parametrize('mutation', ('missing', 'wrong_hash', 'no_reset', 'bad_children', 'historical_name_bypass'))
def test_unknown_or_inconsistent_profile_cannot_select_old_expectations(tmp_path, mutation):
    import model_profile
    source = tmp_path / 'response_only.p4'
    source.write_text('new successor source')
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    inputs = dict(source_sha256=sha, milestone='successor', supported_profile=dict(
        reset_restart_required=True, t_child_count=1, candidate=dict(source_sha256=sha)))
    milestone = 'successor'
    if mutation == 'missing':
        inputs.pop('supported_profile')
    elif mutation == 'wrong_hash':
        inputs['supported_profile']['candidate']['source_sha256'] = '0' * 64
    elif mutation == 'no_reset':
        inputs['supported_profile']['reset_restart_required'] = False
    elif mutation == 'bad_children':
        inputs['supported_profile']['t_child_count'] = 4   # 1,2,3 are valid (2 = segmented second child); 4 is not
    else:
        inputs.pop('supported_profile')
        inputs['milestone'] = milestone = 'm9'
    with pytest.raises(ValueError):
        model_profile.resolve(inputs, source, milestone)


@pytest.mark.parametrize('probes, expected', (((), 3), (('t_single_child',), 1)))
def test_source_simulator_uses_declared_child_layout(tmp_path, probes, expected):
    import efficiency_candidates
    sys.path.insert(0, str(CT / 'tests'))
    import contention_source
    build = tmp_path / 'successor'
    efficiency_candidates.generate(build, probes)
    pipeline = contention_source.LapPipeline(build / 'response_only.p4')
    assert pipeline.t_child_count == expected
    assert sorted(name for role, name in pipeline.t.src.cells if name.startswith('child_seen')) == [
        'child_seen%d_reg' % n for n in range(expected)]
    pipeline.close()
