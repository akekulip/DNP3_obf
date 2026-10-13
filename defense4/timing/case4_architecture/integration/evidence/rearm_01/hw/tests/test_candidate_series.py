import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

HW = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configured():
    module = load('candidate_series_test', HW / 'candidate_series.py')
    cfg = module.base.load_config(str(module.ARCH / 'protocol/hw_vepa/config/precision_5ms_gap800us_14892.json'))
    cfg['builds']['mirror_fix_01']['lifecycle_rearm'] = True
    cfg['trials'] = {'reads_per_trial': 20, 'trials_per_arm': 1}
    cfg['traffic']['master_port_range'] = {'first': 59420, 'last': 59420}
    cfg['evidence_dir'] = '/tmp/candidate_series_tests'
    return module, cfg


def test_constructor_refuses_any_shape_that_would_make_the_series_ambiguous():
    module, cfg = configured()
    campaign = module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_ok', arms=['combined'], fixtures=['separate_ack'])
    assert len(campaign.units()) == 1
    assert campaign.units()[0]['reads'] == 20
    assert campaign.scenario is None

    bad = json.loads(json.dumps(cfg))
    bad['trials']['reads_per_trial'] = 19
    with pytest.raises(ValueError, match='reads_per_trial must be 20'):
        module.CandidateSeriesCampaign(bad, module.base.DryRunner(), 'bad_reads', arms=['combined'], fixtures=['separate_ack'])

    bad = json.loads(json.dumps(cfg))
    bad['trials']['trials_per_arm'] = 2
    with pytest.raises(ValueError, match='exactly one cold trial'):
        module.CandidateSeriesCampaign(bad, module.base.DryRunner(), 'bad_trials', arms=['combined'], fixtures=['separate_ack'])

    bad = json.loads(json.dumps(cfg))
    bad['fixture']['modes'] = ['separate_ack', 'piggyback']
    with pytest.raises(ValueError, match='exactly one fixture'):
        module.CandidateSeriesCampaign(bad, module.base.DryRunner(), 'bad_fixture', arms=['combined'])

    bad = json.loads(json.dumps(cfg))
    bad['arms'][0]['name'] = 'other'
    with pytest.raises(ValueError, match='exactly one combined arm'):
        module.CandidateSeriesCampaign(bad, module.base.DryRunner(), 'bad_arm', arms=['other'], fixtures=['separate_ack'])


def test_candidate_series_uses_vision_candidate_once_and_does_not_append_endpoint_flags(monkeypatch):
    module, cfg = configured()
    calls = []
    campaign = module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_cmd', arms=['combined'],
                                              fixtures=['separate_ack'], close_mode='rst', rst_grace_ms=1000)

    def fake_run_unit(self, unit, port):
        calls.append(module.base.runner.vision_cmd(self.label(unit), port, unit['reads'], 8, 0, 0, 12345))

    monkeypatch.setattr(module.candidate_campaign.CandidateCampaign, 'run_unit', fake_run_unit)
    campaign.run_unit(campaign.units()[0], 59420)
    assert len(calls) == 1
    command = calls[0]
    assert 'vision_candidate.py' in command
    assert '--close-mode rst' in command
    assert '--rst-grace-ms 1000' in command
    assert '--reads 20' in command
    assert '--padding 1' in command
    assert '--read-pause-ms' not in command
    assert '--run-sbo' not in command
    assert 'vision_run.py run' not in command


def test_deploy_records_and_verifies_series_helpers(monkeypatch):
    module, cfg = configured()
    campaign = module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'series_deploy', arms=['combined'], fixtures=['separate_ack'])
    monkeypatch.setattr(module.candidate_campaign.CandidateCampaign, 'vision_identity', lambda self: None)
    monkeypatch.setattr(module.candidate_campaign.CandidateCampaign, 'deploy_switch', lambda self: None)
    campaign.vision_identity()
    campaign.deploy_switch()
    assert 'vision_candidate.py' in campaign.record['candidate_series_vision_identity']
    assert str(module.HERE / 'snapshot_lifecycle.py') in campaign.record['candidate_series_switch_identity']

    runner = module.base.DryRunner(); runner.dry = False
    campaign = module.CandidateSeriesCampaign(cfg, runner, 'series_deploy_fail', arms=['combined'], fixtures=['separate_ack'])
    monkeypatch.setattr(module.candidate_campaign.CandidateCampaign, 'vision_identity', lambda self: None)
    monkeypatch.setattr(campaign, 'step', lambda *args, **kwargs: module.base.Result(0, 'bad /wrong/path', ''))
    with pytest.raises(module.base.StepFailed, match='identity mismatch'):
        campaign.vision_identity()


def test_lifecycle_summary_reports_actual_names_and_requires_three_consistent_epochs_and_retired_work():
    module, _cfg = configured()
    snapshot = {'valid': True, 'errors': {}, 'software_read_fallbacks': [], 'registers': {
        'pipe0.N.work': {'work.generation': [503], 'work.phase': [4]},
        'pipe0.N.owner': {'owner': [(0x10f << 16) | 3]},
        'pipe0.N.epoch': {'epoch': [3]},
        'pipe0.E.epoch': {'epoch': [0x80000003]},
        'pipe1.T.cur_epoch_reg': {'cur_epoch_reg': [3]},
    }}
    failures, observed = module.lifecycle_gate(snapshot)
    assert failures == []
    assert observed['epochs']['values'] == {'N': 3, 'E': 3, 'T': 3}
    assert observed['epochs']['registers']['T'] == 'pipe1.T.cur_epoch_reg'
    assert observed['work']['phase'] == 4
    assert observed['work']['register'] == 'pipe0.N.work'
    assert observed['work']['generation'] == 503  # packet generation differs from connection epoch

    broken = json.loads(json.dumps(snapshot))
    broken['registers']['pipe0.E.epoch']['epoch'] = [2]
    failures, observed = module.lifecycle_gate(broken)
    assert any('N/E/T epochs' in f for f in failures)
    assert observed['epochs']['values']['E'] == 2

    broken = json.loads(json.dumps(snapshot))
    broken['registers']['pipe0.N.owner']['owner'] = [(9 << 16) | 3]
    assert any('owner must be retired' in f for f in module.lifecycle_gate(broken)[0])
    broken = json.loads(json.dumps(snapshot))
    broken['valid'] = False
    assert any('complete hardware read' in f for f in module.lifecycle_gate(broken)[0])


def test_pretty_json_from_actual_vision_helper_is_parsed():
    module, cfg = configured()
    campaign = module.CandidateSeriesCampaign(cfg, module.base.DryRunner(), 'pretty', arms=['combined'], fixtures=['separate_ack'])
    value = {'scenario': 'candidate_same_tuple', 'ok': True, 'connections': []}
    result = module.base.Result(0, 'status\n' + json.dumps(value, indent=2) + '\n', '')
    assert campaign._vision_json(result) == value


def sequence_fixture(module, client=10000, server=20000):
    flow = tuple(sorted((('192.168.10.61', 59420), ('192.168.10.62', 20000))))
    def packet(direction, flags, seq, ack, payload=b''):
        return {'flow': flow, 'dir': direction, 'flags': flags, 'seq': seq, 'ack': ack,
                'len': len(payload), 'payload': payload}
    read = bytearray(49); read[12] = 0x81; read[15:17] = b'\x0a\x02'
    sent = [packet('M->O', module.wc.SYN, client, 0),
            packet('O->M', module.wc.SYN | module.wc.ACK, server, client + 1),
            packet('M->O', module.wc.ACK, client + 1, server + 1),
            packet('O->M', module.wc.ACK | 8, server + 1, client + 1, bytes(read))]
    returned = [dict(p) for p in sent]
    returned[-1]['payload'] += bytes(9); returned[-1]['len'] += 9
    return sent, returned


def test_fresh_mapping_rejects_old_offsets_and_overlapping_isns():
    module, _ = configured()
    sent, returned = sequence_fixture(module)
    first = module.freshness_gate(sent, returned, 59420)
    next_sent, next_returned = sequence_fixture(module, 30000, 40000)
    assert module.freshness_gate(next_sent, next_returned, 59420, first)['client_isn'] == 30000
    with pytest.raises(ValueError, match='overlaps or precedes'):
        module.freshness_gate(sent, returned, 59420, first)
    returned[-1]['seq'] += 9
    with pytest.raises(ValueError, match='old mapping offset'):
        module.freshness_gate(sent, returned, 59420)


def test_series_switch_gate_uses_three_t_counts_but_last_leg_mapper_growth_only():
    module, cfg = configured()
    before = {'outcomes': {'OUT_ACK_COMMIT': 0, 'OUT_ACK_FALLBACK': 0, 'OUT_RESP_RELEASE': 0,
                           'OUT_RESP_FALLBACK': 0, 'OUT_OP_RELEASE': 0, 'OUT_TOKEN_STALE': 0},
              'pktgen': {'READ': {'trigger_counter': 0, 'pkt_counter': 0},
                         'OPERATE': {'trigger_counter': 0, 'pkt_counter': 0}},
              'loop_ports': {role: {'$OctetsReceived': 0, '$OctetsReceivedinGoodFrames': 0}
                             for role in module.checks.LOOP_ROLES},
              'regs': {'acct': {'acct.lo': [222], 'acct.hi': [0]}, 'front': {'front': [0]}}}
    after = json.loads(json.dumps(before))
    after['outcomes'].update(OUT_ACK_COMMIT=60, OUT_RESP_RELEASE=60, OUT_OP_RELEASE=3)
    after['pktgen']['READ'] = {'trigger_counter': 60, 'pkt_counter': 240}
    after['pktgen']['OPERATE'] = {'trigger_counter': 3, 'pkt_counter': 12}
    after['regs']['acct']['acct.lo'] = [222]
    lifecycle = actual_lifecycle()
    failures, observed = module.series_switch_gate(cfg, cfg['arms'][0], 20, {'before': before, 'after': after}, lifecycle)
    assert failures == []
    assert observed['external_growth_expected'] == 222
    assert observed['external_growth_bytes'] == 222

    lifecycle['registers']['p0.r_Egress.acct']['r_Egress.acct.lo'] = [1888]
    failures, _observed = module.series_switch_gate(cfg, cfg['arms'][0], 20, {'before': before, 'after': after}, lifecycle)
    assert any('last generation only' in f for f in failures)



def test_series_switch_gate_strict_build_expects_read_growth_only():
    module, cfg = configured()
    cfg['builds'][cfg['arms'][0]['build']]['control_padding'] = False
    before = {'outcomes': {'OUT_ACK_COMMIT': 0, 'OUT_ACK_FALLBACK': 0, 'OUT_RESP_RELEASE': 0,
                           'OUT_RESP_FALLBACK': 0, 'OUT_OP_RELEASE': 0, 'OUT_TOKEN_STALE': 0},
              'pktgen': {'READ': {'trigger_counter': 0, 'pkt_counter': 0},
                         'OPERATE': {'trigger_counter': 0, 'pkt_counter': 0}},
              'loop_ports': {role: {'$OctetsReceived': 0, '$OctetsReceivedinGoodFrames': 0}
                             for role in module.checks.LOOP_ROLES},
              'regs': {'acct': {'acct.lo': [180], 'acct.hi': [0]}, 'front': {'front': [0]}}}
    after = json.loads(json.dumps(before))
    after['outcomes'].update(OUT_ACK_COMMIT=60, OUT_RESP_RELEASE=60, OUT_OP_RELEASE=3)
    after['pktgen']['READ'] = {'trigger_counter': 60, 'pkt_counter': 240}
    after['pktgen']['OPERATE'] = {'trigger_counter': 3, 'pkt_counter': 12}
    lifecycle = actual_lifecycle()
    lifecycle['registers']['p0.r_Egress.acct']['r_Egress.acct.lo'] = [1180]
    failures, observed = module.series_switch_gate(cfg, cfg['arms'][0], 20, {'before': before, 'after': after}, lifecycle)
    assert observed['external_growth_expected'] == 180
    assert not any('last generation only' in f for f in failures), failures

def actual_lifecycle(epoch=145):
    return {'valid': True, 'errors': {}, 'software_read_fallbacks': [], 'registers': {
        'p0.n_Ingress.work.work': {'n_Ingress.work.work.generation': [216], 'n_Ingress.work.work.phase': [4]},
        'p0.n_Ingress.owner': {'n_Ingress.owner.f1': [(0x10f << 16) | 3]},
        'p0.n_Ingress.epoch': {'n_Ingress.epoch.f1': [epoch]},
        'p0.r_Egress.epoch': {'r_Egress.epoch.f1': [epoch | 0x80000000]},
        'p1.t_Ingress.cur_epoch_reg': {'t_Ingress.cur_epoch_reg.f1': [epoch]},
        'p0.r_Egress.acct': {'r_Egress.acct.lo': [1222], 'r_Egress.acct.hi': [0]},
        'p0.r_Egress.front': {'r_Egress.front.f1': [1000]},
    }}


def test_lifecycle_accepts_actual_schema_and_work_allocated_epoch():
    module, _ = configured()
    failures, observed = module.lifecycle_gate(actual_lifecycle())
    assert failures == []
    assert observed['epochs']['values'] == {'N': 145, 'E': 145, 'T': 145}
    assert observed['owner']['generation'] == 3


@pytest.mark.parametrize('epoch', [0, 0x7fffffff])
def test_lifecycle_rejects_unbounded_or_zero_work_allocated_epoch(epoch):
    module, _ = configured()
    assert module.lifecycle_gate(actual_lifecycle(epoch))[0]


def test_mapper_gate_reads_complete_lifecycle_banks_instead_of_missing_counter_regs(monkeypatch):
    module, cfg = configured()
    monkeypatch.setattr(module.checks, 'evaluate_switch', lambda *a, **kw: ([], {}))
    failures, observed = module.series_switch_gate(cfg, cfg['arms'][0], 20,
                                                 {'before': {}, 'after': {}}, actual_lifecycle())
    assert failures == []
    assert observed['external_growth_bytes'] == 222
    broken = actual_lifecycle()
    broken['software_read_fallbacks'] = ['p0.r_Egress.acct']
    assert module.series_switch_gate(cfg, cfg['arms'][0], 20,
                                    {'before': {}, 'after': {}}, broken)[0]


def test_sealed_epoch_profile_requires_retired_t_seal_and_decodes_generation():
    module, _cfg = configured()
    snap = {'valid': True, 'errors': {}, 'software_read_fallbacks': [],
            'T_epoch_sealed_encoding': True, 'registers': {
        'pipe0.N.work': {'work.generation': [216], 'work.phase': [4]},
        'pipe0.N.owner': {'owner': [(0x10f << 16) | 3]},
        'pipe0.N.epoch': {'epoch': [145]},
        'pipe0.E.epoch': {'epoch': [0x80000091]},
        'pipe1.T.cur_epoch_reg': {'cur_epoch_reg': [0x80000091]},
    }}
    errors, seen = module.lifecycle_gate(snap)
    assert errors == []
    assert seen['epochs']['T_sealed'] is True
    assert seen['epochs']['values'] == {'N': 145, 'E': 145, 'T': 145}
    snap['registers']['pipe1.T.cur_epoch_reg']['cur_epoch_reg'] = [145]
    assert any('T must be sealed' in error for error in module.lifecycle_gate(snap)[0])
    snap['registers']['pipe1.T.cur_epoch_reg']['cur_epoch_reg'] = [0xffffffff]
    assert module.lifecycle_gate(snap)[0]


def test_deployed_vision_helper_imports_from_only_its_pinned_files(tmp_path):
    import shutil
    import subprocess
    import sys
    module, _cfg = configured()
    for name, path in module.VISION_EXTRA.items():
        shutil.copyfile(path, tmp_path/name)
    for name in ('vision_run.py', 'loss.py'):
        shutil.copyfile(module.ARCH/'protocol/hw_vepa'/name, tmp_path/name)
    result = subprocess.run([sys.executable, '-I', '-c',
        "import sys,runpy;sys.path.insert(0,sys.argv[1]);sys.argv=['vision_candidate.py','--help'];runpy.run_path(sys.path[0]+'/vision_candidate.py',run_name='__main__')",
        str(tmp_path)], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert '--pre-read-grace-ms' in result.stdout
