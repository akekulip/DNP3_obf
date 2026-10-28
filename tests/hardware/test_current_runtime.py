"""Offline current-runtime regression gates. No socket, SSH or BFRT client is opened."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks'),
               str(ROOT / 'scripts/hardware/active_harness'), str(ROOT / 'tests/checks')]
import campaign
import campaign_base
import guarded_block
import freeze_gate
import installer_base
import matrix
import persistence
import readback
import rows
import sbo_driver
import snapshot_counters
import vision_run
from fixtures import conversation
from scripts import profile
from scripts.checks import relay_check
from scripts.checks import replay


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    """A config-only fake compile; the real freeze verifier rejects these fake binaries."""
    build, native = fake_build(tmp_path, monkeypatch)
    manifest = matrix.prepare(build, native / 'relay_wire.json', tmp_path / 'matrix', 'offline_fixture')
    return json.loads(manifest.read_text()), manifest


@pytest.fixture
def prepared_evaluation(tmp_path, monkeypatch):
    build, native = fake_build(tmp_path, monkeypatch)
    manifest = matrix.prepare(build, native / 'relay_wire.json', tmp_path / 'evaluation', 'offline_eval',
                              definition='evaluation')
    return json.loads(manifest.read_text()), manifest


@pytest.fixture
def prepared_recovery(tmp_path, monkeypatch):
    """The recovery matrix and, from the same fake build, the qualification matrix it copies."""
    build, native = fake_build(tmp_path, monkeypatch)
    recovery = matrix.prepare(build, native / 'relay_wire.json', tmp_path / 'recovery', 'offline_recovery',
                              definition='recovery')
    qualification = matrix.prepare(build, native / 'relay_wire.json', tmp_path / 'matrix', 'offline_fixture')
    return json.loads(recovery.read_text()), recovery, json.loads(qualification.read_text())


def fake_build(tmp_path, monkeypatch):
    build = tmp_path / 'build'
    profile.package(build)
    compiled = build / 'compile_local'
    (compiled / 'out/p0').mkdir(parents=True)
    (compiled / 'out/p1').mkdir()
    pins = {}
    for name in campaign_base.BUILD_HASHED:
        path = compiled / 'out' / name
        path.write_bytes(('config-only fixture: ' + name).encode())
        pins[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (compiled / 'manifest.json').write_text(json.dumps(dict(artifact_sha256=pins, compiler='p4c 9.13.2')))
    native = tmp_path / 'native'
    conversation(native)
    wire = relay_check.analyze(native, 59410, dict(READ=0, SELECT=1, OPERATE=1), 'full')
    (native / 'relay_wire.json').write_text(json.dumps(wire))
    monkeypatch.setattr(matrix, 'ROOT', tmp_path)
    monkeypatch.setattr(campaign_base.endpoint_profiles, 'PROJECT_ROOT', tmp_path)
    monkeypatch.setattr(campaign_base, 'path_of', lambda value: str(Path(value) if Path(value).is_absolute()
                                                                   else tmp_path / value))
    return build, native


def test_fixed_matrix_preparation_does_not_make_a_freeze_or_contact_hardware(prepared):
    value, path = prepared
    assert len(value['steps']) == 10 and value['expected_exchanges'] == 2440
    assert sum(step['expected_exchanges'] for step in value['steps']) == 2440
    assert not (path.parent / 'freeze.json').exists()
    rst=value['steps'][6]['argv']
    assert rst[rst.index('--rst-grace-ms')+1]=='1000'


def test_all_ten_current_blocks_plan_with_one_binary_and_no_retired_hold(prepared):
    value, _ = prepared
    for step in value['steps']:
        config = step['argv'][4]
        cfg = campaign_base.load_config(config)
        options, kwargs = step['argv'][6:], {}
        for option, key in (('--loss', 'loss'), ('--scenario', 'scenario'), ('--close-mode', 'close_mode'), ('--rst-grace-ms','rst_grace_ms')):
            if option in options:
                kwargs[key] = int(options[options.index(option) + 1]) if key == 'rst_grace_ms' else options[options.index(option) + 1]
        cls = persistence.CandidateSeriesCampaign if step['argv'][3] == 'persistence' else campaign.CandidateCampaign
        with contextlib.redirect_stdout(io.StringIO()) as output:
            engine = cls(cfg, campaign_base.DryRunner(), step['argv'][5], config_path=config, **kwargs)
            assert engine.execute() == 0
        commands = output.getvalue()
        assert 'BLOCKED/UNBOUND' not in commands
        assert '--t-op-j' not in commands and '/integration/' not in commands
        assert 'vision_candidate.py' not in commands and 'clrt_check.py' not in commands
        assert '/scripts/hardware/bringup_composite.py' in commands
        assert len({arm['build'] for arm in cfg['arms']}) == 1


def test_evaluation_matrix_is_sixteen_four_arm_blocks_per_d_interleaved_and_counterbalanced(prepared_evaluation):
    value, path = prepared_evaluation
    assert len(value['steps']) == 64 and value['expected_exchanges'] == 49408
    assert all(step['expected_exchanges'] == 772 for step in value['steps'])
    assert not (path.parent / 'freeze.json').exists()
    configs = [json.loads(Path(step['argv'][4]).read_text()) for step in value['steps']]
    gaps = [cfg['timing_params_ns']['gap'] // 1000000 for cfg in configs]
    assert gaps == [5, 10, 15, 20] * 16  # D cycles block by block, so drift is not confounded with D
    for d in (5, 10, 15, 20):
        orders = [tuple(arm['name'] for arm in cfg['arms']) for cfg, gap in zip(configs, gaps) if gap == d]
        assert len(orders) == 16
        for position in range(4):  # each arm in each run position exactly 4 times per D
            column = [order[position] for order in orders]
            assert sorted(column.count(arm) for arm in set(column)) == [4, 4, 4, 4]
    for cfg in configs:
        assert {arm['name']: (arm['T'], arm['padding']) for arm in cfg['arms']} == {
            'off': (0, 0), 'timing_only': (1, 0), 'size_only': (0, 1), 'combined': (1, 1)}
        assert cfg['trials']['reads_per_trial'] == 65 and cfg['traffic']['sbo_cycles'] == 64
        assert cfg['loss']['inject'] is False and cfg['endpoint_profile'] == 'sel751'


def test_every_evaluation_block_plans_through_its_real_cli(prepared_evaluation):
    value, _ = prepared_evaluation
    for step in value['steps']:
        assert step['argv'][3] == 'campaign' and step['argv'][6:] == []
        with contextlib.redirect_stdout(io.StringIO()) as output:
            assert campaign_base.main(['plan', '--config', step['argv'][4], '--run-id', step['argv'][5]]) == 0
        assert 'BLOCKED/UNBOUND' not in output.getvalue()


def test_qualification_matrix_denominator_is_unchanged_by_the_evaluation_definition(prepared):
    value, _ = prepared
    assert len(value['steps']) == 10 and value['expected_exchanges'] == 2440


# E3 SELECT-loss recovery: qualification block 10 t3 (padded SELECT response dropped at the master host) per condition.
RECOVERY_ENTRY = {'class': 'select_resp_padded', 'n': 1, 'target': 'identity'}
RECOVERY_BLOCKS = {'r1_d20_combined': (20, 'combined', 1, 1),
                   'r2_d20_size_only': (20, 'size_only', 0, 1),
                   'r3_d5_combined': (5, 'combined', 1, 1)}
RECOVERY_TRIALS = 6
NATIVE_PROBE_PORTS = {59411, 59412}  # c72_native_20261027_01/_02 master ports (out.pcap)


def definition_ports(name):
    """{block id: master ports a matrix definition's block can open, including any reconnect port}."""
    out = {}
    for block in matrix.load_definition(name)[0]['blocks']:
        span = block['traffic']['master_port_range']
        ports = set(range(span['first'], span['last'] + 1))
        for scenario in block['config'].get('scenarios', {}).values():
            ports |= {port + scenario['reconnect_port_offset'] for port in ports}
        out[block['id']] = ports
    return out


def test_recovery_matrix_denominator_is_three_six_trial_select_response_loss_blocks(prepared_recovery):
    value, path, _ = prepared_recovery
    assert matrix.DEFINITIONS['recovery'] == dict(file='lab_recovery.json', blocks=3, exchanges=396)
    assert [step['id'] for step in value['steps']] == list(RECOVERY_BLOCKS)
    # Each trial is one block-10 connection: 20 READs plus one SELECT and one OPERATE.
    assert all(step['expected_exchanges'] == RECOVERY_TRIALS * (20 + 2) for step in value['steps'])
    assert value['expected_exchanges'] == 3 * RECOVERY_TRIALS * 22 == 396
    assert not (path.parent / 'freeze.json').exists()


def test_recovery_blocks_copy_qualification_block_10_except_d_arm_preset_and_ports(prepared_recovery):
    value, _, qualification = prepared_recovery
    reference_step = next(step for step in qualification['steps'] if step['id'] == '10_d20_loss_full')
    reference = json.loads(Path(reference_step['argv'][4]).read_text())
    assert reference_step['argv'][6:] == ['--loss', 'core_full']

    def masked(cfg):
        cfg = copy.deepcopy(cfg)
        for key in ('gap',):
            cfg['timing_params_ns'].pop(key)
        cfg['loss'].pop('presets')
        cfg['traffic'].pop('master_port_range')
        cfg.pop('arms')
        return cfg

    for step in value['steps']:
        d_ms, arm, timing, padding = RECOVERY_BLOCKS[step['id']]
        cfg = json.loads(Path(step['argv'][4]).read_text())
        assert step['argv'][3] == 'campaign' and step['argv'][6:7] == ['--loss'] and len(step['argv']) == 8
        preset = step['argv'][7]
        assert cfg['loss']['presets'] == {preset: [RECOVERY_ENTRY] * RECOVERY_TRIALS}
        assert cfg['timing_params_ns'] == dict(budget=240000, enabled=1, gap=d_ms * 1000000)
        assert cfg['arms'] == [dict(name=arm, T=timing, padding=padding, build='current')]
        assert masked(cfg) == masked(reference)
        assert cfg['endpoint']['points'] == [1, 3] == reference['endpoint']['points']
        assert cfg['trials']['reads_per_trial'] == 20 and cfg['traffic']['read_schedule'] == 'full'
        assert cfg['traffic']['run_sbo'] is True and 'sbo_cycles' not in cfg['traffic']
        assert cfg['loss']['inject'] is False and cfg['endpoint_profile'] == 'sel751'


def test_recovery_preset_repeats_plan_six_distinct_identity_trials_through_the_real_cli(prepared_recovery,
                                                                                      monkeypatch):
    """Repeated identical preset entries are six separate cold trials, each with its own label, seed and port."""
    value, _, _ = prepared_recovery
    seen = {}

    def recording(cls):
        class Recording(cls):
            def __init__(self, cfg, runner_, run_id, *args, **kwargs):
                super().__init__(cfg, runner_, run_id, *args, **kwargs)
                units = self.units()
                seen[run_id] = dict(fixtures=list(self.fixtures), ports=self.ports(),
                                    drops=[unit['drop'] for unit in units], trials=[unit['i'] for unit in units],
                                    labels={self.label(unit) for unit in units},
                                    seeds={unit['start_seed'] for unit in units},
                                    arms=[(unit['arm']['name'], unit['arm']['T'], unit['arm']['padding'])
                                          for unit in units])
        return Recording

    monkeypatch.setattr(campaign_base, 'Campaign', recording(campaign.CandidateCampaign))
    for step in value['steps']:
        config, run_id, options = step['argv'][4], step['argv'][5], step['argv'][6:]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            assert campaign_base.main(['plan', '--config', config, '--run-id', run_id] + options) == 0, step['id']
        text = output.getvalue()
        assert 'BLOCKED/UNBOUND' not in text
        _, arm, timing, padding = RECOVERY_BLOCKS[step['id']]
        record = seen[run_id]
        assert record['fixtures'] == ['physical_relay']
        assert record['drops'] == ['select_resp_padded:1:identity'] * RECOVERY_TRIALS
        assert record['trials'] == list(range(RECOVERY_TRIALS))
        assert len(record['labels']) == len(record['seeds']) == len(record['ports']) == RECOVERY_TRIALS
        assert record['arms'] == [(arm, timing, padding)] * RECOVERY_TRIALS
        planned = re.findall(r'traffic \+ capture on master port (\d+)', text)
        assert sorted(map(int, planned)) == record['ports']
        assert text.count('--drop select_resp_padded:1:identity') == RECOVERY_TRIALS


def test_recovery_master_ports_are_disjoint_from_each_other_and_earlier_matrices(prepared_recovery):
    value, _, _ = prepared_recovery
    recovery = definition_ports('recovery')
    for step in value['steps']:
        span = json.loads(Path(step['argv'][4]).read_text())['traffic']['master_port_range']
        assert set(range(span['first'], span['last'] + 1)) == recovery[step['id']]
    assert all(len(ports) == RECOVERY_TRIALS for ports in recovery.values())
    blocks = list(recovery.values())
    assert all(not (a & b) for index, a in enumerate(blocks) for b in blocks[index + 1:])
    earlier = set().union(*definition_ports('qualification').values(), *definition_ports('evaluation').values(),
                          NATIVE_PROBE_PORTS)
    assert not set().union(*blocks) & earlier


def test_each_block_argv_plans_through_its_real_cli_with_the_c69_command_parameters(prepared, monkeypatch):
    """The wrapper plans the manifest argv through each tool's CLI, so CLI defaults are part of the block."""
    value, _ = prepared
    seen = {}

    def recording(cls):
        class Recording(cls):
            def __init__(self, cfg, runner_, run_id, *args, **kwargs):
                super().__init__(cfg, runner_, run_id, *args, **kwargs)
                seen[run_id] = dict(fixtures=list(self.fixtures), reconnect_policy=self.reconnect_policy)
        return Recording

    monkeypatch.setattr(persistence, 'CandidateSeriesCampaign', recording(persistence.CandidateSeriesCampaign))
    monkeypatch.setattr(campaign_base, 'Campaign', recording(campaign.CandidateCampaign))
    for step in value['steps']:
        tool, config, run_id, options = step['argv'][3], step['argv'][4], step['argv'][5], step['argv'][6:]
        entry = persistence.main if tool == 'persistence' else campaign_base.main
        with contextlib.redirect_stdout(io.StringIO()):
            assert entry(['plan', '--config', config, '--run-id', run_id] + options) == 0, step['id']
        assert seen[run_id]['fixtures'] == ['physical_relay'], step['id']
        if '--scenario' in options:
            assert seen[run_id]['reconnect_policy'] == 'protected', step['id']


@pytest.mark.parametrize('change', ['software', 'old_timing', 'second_binary'])
def test_current_config_rejects_unsupported_profiles(prepared, tmp_path, change):
    value, _ = prepared
    cfg = json.loads(Path(value['steps'][1]['argv'][4]).read_text())
    if change == 'software':
        cfg['endpoint_profile'] = 'software'
    elif change == 'old_timing':
        cfg['timing_contract'] = 'response_ready_ack_d_v2'
    else:
        cfg['arms'][0]['build'] = 'other'
        cfg['builds']['other'] = copy.deepcopy(cfg['builds']['current'])
    path = tmp_path / 'bad.json'
    path.write_text(json.dumps(cfg))
    with pytest.raises(ValueError):
        campaign_base.load_config(path)


def test_matrix_block_cannot_override_the_ip_pair(prepared,tmp_path,monkeypatch):
    definition=json.loads((matrix.HERE/'lab.json').read_text())
    definition['blocks'][0]['config']['endpoints']={'master_ip':'192.168.10.2'}
    source=tmp_path/'lab';source.mkdir()
    (source/'lab.json').write_text(json.dumps(definition))
    monkeypatch.setattr(matrix,'HERE',source)
    with pytest.raises(ValueError,match='cannot override the fixed reciprocal'):
        matrix.prepare(tmp_path/'build',tmp_path/'native/relay_wire.json',tmp_path/'other_matrix','other')


@pytest.mark.parametrize('points', [[6], [1, 6], [], [0]])
def test_current_control_builder_retains_the_point_guard(points):
    with pytest.raises(PermissionError):
        sbo_driver.guarded(4, 0, points)


def test_installer_cannot_bind_a_different_ip_pair():
    with pytest.raises(ValueError, match='fixed reciprocal'):
        rows.endpoints('192.168.10.2',59410,9,'192.168.10.7',20000,64)


def test_current_data_connection_rows_are_exactly_one_reciprocal_ip_pair():
    master,relay=rows.endpoints('192.168.10.1',59410,9,'192.168.10.7',20000,64)
    operations=rows.build(master,relay,rows.VECTOR_DECOY,{'n_ack_return':48,'return_port':68})
    bindings=[dict((name,value)for name,value,_ in operation['key'])for operation in operations
              if operation['table']=='p0.n_Ingress.data_connection']
    assert len(bindings)==2
    assert {(row['hdr.ip.src'],row['hdr.ip.dst'],row['hdr.tcp.sport'],row['hdr.tcp.dport'])
            for row in bindings} == {(master.ip_int,relay.ip_int,59410,20000),
                                     (relay.ip_int,master.ip_int,20000,59410)}


def test_failed_select_does_not_build_or_send_operate():
    calls = []
    class Session:
        def transaction(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(ok=False, outcome='INVALID', problems=['TIMEOUT'])
    _, operate = sbo_driver.one_sbo(Session(), 0, 1, [1, 3], 500, False)
    assert [call['operation'] for call in calls] == ['SELECT']
    assert operate.outcome == 'NOT_ATTEMPTED'


def test_readback_reset_values_match_current_source_registers():
    source = (ROOT / 'p4/response_only.p4').read_text()
    registers = re.findall(r'Register<bit<32>,\s*bit<1>>\(1,\s*(0x[0-9a-f]+|[0-9]+)\)\s+(\w+_reg);', source)
    assert readback.T_REGISTER_INIT == {name: int(value, 0) for value, name in registers}


def test_installer_uses_only_the_current_parameter_abi(tmp_path):
    (tmp_path / 'response_only.p4pp').write_text((ROOT / 'p4/response_only.p4').read_text())
    args = SimpleNamespace(build_out=tmp_path, t_gap=5000000, t_budget=240000, t_enabled=1,
                           timing_contract='response_ready_ack_d_no_j_v3')
    assert installer_base.params(args) == dict(gap=5000000, budget=240000, enabled=1)


def test_guarded_run_never_clobbers_retained_evidence(tmp_path):
    root = tmp_path / 'retained'
    root.mkdir()
    with pytest.raises(ValueError, match='retained run path'):
        guarded_block.refuse_retained(root, tmp_path / 'record.json', 'offline_fixture')


def test_current_wrapper_cannot_skip_the_freeze_gate(tmp_path):
    with pytest.raises(ValueError, match='require the candidate freeze'):
        guarded_block.block('campaign', tmp_path / 'config.json', 'offline_fixture', [])


def test_physical_capture_always_records_offload_restoration_before_traffic(tmp_path, monkeypatch):
    class EnteredCaptureContext(Exception):
        pass
    @contextlib.contextmanager
    def context(*args, **kwargs):
        raise EnteredCaptureContext
        yield
    monkeypatch.setattr(vision_run, 'state', lambda: 'offline fixture')
    monkeypatch.setattr(vision_run, 'wait_relay_port_free', lambda _: {'result': 'offline_refusal'})
    monkeypatch.setattr(vision_run.capture_observation, 'offload_capture_context', context)
    with pytest.raises(EnteredCaptureContext):
        vision_run.run_relay_connection(str(tmp_path / 'capture'), 'fixture', 59410, 2, run_sbo=False)


def test_replay_missing_or_partial_matrix_is_never_pass(tmp_path):
    path = tmp_path / 'index.json'
    path.write_text(json.dumps(dict(schema=replay.SCHEMA, files={})))
    result = replay.replay_index(path)
    assert result['ok'] is False and result['hardware_contact'] is False
    assert result['exchanges'] == 0 and result['failures']


def test_native_preflight_plan_is_read_only_and_creates_no_evidence(tmp_path):
    output = tmp_path / 'native'
    with contextlib.redirect_stdout(io.StringIO()) as commands:
        result = matrix.native_probe(tmp_path / 'not_compiled', output, 'native_fixture', 59410)
    assert result == dict(status='dry-run', hardware_contact=False)
    assert '--run-sbo 0' in commands.getvalue()
    assert 'switch_swap.sh' not in commands.getvalue()
    assert not output.exists()


@pytest.mark.parametrize('pipe,gress,value', [('p0','ingress',11), ('p0','egress',11),
                                            ('p1','ingress',9), ('p1','egress',5)])
def test_hardware_freeze_requires_the_measured_stage_limits(tmp_path, monkeypatch, pipe, gress, value):
    (tmp_path / 'p4').mkdir()
    (tmp_path / 'p4/response_only.p4').write_text('current source')
    build = tmp_path / 'build'
    (build / 'compile_local').mkdir(parents=True)
    digest = hashlib.sha256(b'current source').hexdigest()
    pipes = {'p0': {'stages':dict(ingress=10,egress=10)}, 'p1': {'stages':dict(ingress=8,egress=4)}}
    pipes[pipe]['stages'][gress] = value
    (build/'compile_local/manifest.json').write_text(json.dumps(dict(source_sha256=digest,
        compiler='p4c 9.13.2',resources={'pipes':pipes})))
    monkeypatch.setattr(freeze_gate,'REPO',tmp_path)
    monkeypatch.setattr(freeze_gate,'compiler_module',lambda:SimpleNamespace(
        verify_evidence=lambda *args,**kwargs:{'compiled_artifacts_verified':True}))
    assert any(pipe+' '+gress+' stages' in error for error in freeze_gate.compile_problems(build,digest))


def test_hardware_index_resolves_only_within_the_current_checkout():
    assert replay.local('/old/checkout/results/hardware/run',Path('/old/checkout')) == ROOT/'results/hardware/run'
    with pytest.raises(ValueError):
        replay.local('/another/checkout/result',Path('/old/checkout'))


def test_n_snapshot_reads_current_structured_application_and_pair_fields():
    scalar=('owner','counter','epoch','retry_epoch','client','server')
    pairs=('pair_real_links_native_start','pair_real_tcp_dst_real_tcp_ports','pair_native_end_server_start')
    tables={'p0.n_Ingress.'+name for name in scalar+pairs+('application_state','work.work')}
    calls=[]
    class Switch:
        def register(self,name,*args):
            calls.append(name)
            assert name.rsplit('.',1)[-1] in scalar
            return [0]
        def must_get(self,name,*args):
            calls.append(name)
            if name.endswith('application_state'):
                return {'n_Ingress.application_state.crob':[7],
                        'n_Ingress.application_state.read_identity':[0x1234]}
            if name.endswith('work.work'):
                return {'n_Ingress.work.work.generation':[3],'n_Ingress.work.work.phase':[4]}
            return {'n_Ingress.'+name.rsplit('.',1)[-1]+'.first':[11],
                    'n_Ingress.'+name.rsplit('.',1)[-1]+'.second':[22]}
    observed=snapshot_counters.read_n_state(Switch(),0xffff,tables)
    assert observed['application_state']['n_Ingress.application_state.read_identity']==[0x1234]
    assert set(calls)==tables and len(calls)==len(tables)
    assert 'read_app' not in observed and 'count_first' not in observed


@pytest.mark.parametrize('name,block_id', [('recovery_r1', 'r1_d20_combined'), ('recovery_r2', 'r2_d20_size_only'),
                                           ('recovery_r3', 'r3_d5_combined')])
def test_single_block_recovery_definitions_equal_their_block_of_the_full_matrix(name, block_id):
    """One campaign per condition, so a recorded failure in one block cannot leave the others unexecuted."""
    single, spec = matrix.load_definition(name)
    full, _ = matrix.load_definition('recovery')
    assert spec == dict(file='lab_recovery.json', blocks=1, exchanges=132)
    assert [b['id'] for b in single['blocks']] == [block_id]
    assert single['blocks'][0] == next(b for b in full['blocks'] if b['id'] == block_id)
    assert single['common'] == full['common']
