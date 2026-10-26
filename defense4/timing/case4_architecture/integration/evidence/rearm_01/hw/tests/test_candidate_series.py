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


def test_fresh_mapping_recognises_two_read_classes_and_skips_crob_responses():
    module, _ = configured()
    for group in (b'\x01\x02', b'\x1e\x01', b'\x14\x01'):          # mixed (g1v2), analog g30v1, counter g20v1 first
        sent, returned = sequence_fixture(module)
        for packets in (sent, returned):
            packets[-1]['payload'] = packets[-1]['payload'][:15] + group + packets[-1]['payload'][17:]
        assert module.freshness_gate(sent, returned, 59420)['server_isn'] == 20000
    sent, returned = sequence_fixture(module)
    crob = bytearray(37); crob[12] = 0x81; crob[15:17] = b'\x0c\x01'
    for packets in (sent, returned):                     # a CROB echo at the image start is not taken as the READ
        packets[-1]['seq'] += 37
        packets.insert(3, dict(packets[-1], seq=20001, payload=bytes(crob), len=37))
    with pytest.raises(ValueError, match='old mapping offset'):
        module.freshness_gate(sent, returned, 59420)        # the first READ response no longer starts the image


def test_fresh_mapping_without_any_read_response_says_so():
    module, _ = configured()
    sent, returned = sequence_fixture(module)
    for packets in (sent, returned):
        packets[-1]['payload'] = packets[-1]['payload'][:15] + b'\x0c\x01' + packets[-1]['payload'][17:]
    with pytest.raises(ValueError, match='no native READ response found'):
        module.freshness_gate(sent, returned, 59420)


@pytest.mark.parametrize("timing_contract", [None, "response_ready_ack_d_v1"])
def test_series_switch_gate_uses_three_t_counts_but_last_leg_mapper_growth_only(timing_contract):
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
    if timing_contract:
        cfg['timing_contract'] = timing_contract
        for snapshot in (before, after):
            snapshot['outcomes']['OUT_WAIT_EXPIRED'] = snapshot['outcomes'].pop('OUT_ACK_FALLBACK')
            snapshot['outcomes']['OUT_EXPIRED_DROP'] = snapshot['outcomes'].pop('OUT_RESP_FALLBACK')
            snapshot['outcomes']['OUT_REQ_BYPASS'] = 0
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


def _dup_gate(module, cfg, dup_after, declared):
    cfg['traffic']['expect_held_operate_dup'] = declared
    before = {'outcomes': {'OUT_ACK_COMMIT': 0, 'OUT_ACK_FALLBACK': 0, 'OUT_RESP_RELEASE': 0, 'OUT_RESP_FALLBACK': 0,
                           'OUT_OP_RELEASE': 0, 'OUT_TOKEN_STALE': 0, 'OUT_OP_DUP_DROP': 0},
              'pktgen': {'READ': {'trigger_counter': 0, 'pkt_counter': 0},
                         'OPERATE': {'trigger_counter': 0, 'pkt_counter': 0}},
              'loop_ports': {role: {'$OctetsReceived': 0, '$OctetsReceivedinGoodFrames': 0}
                             for role in module.checks.LOOP_ROLES},
              'regs': {'acct': {'acct.lo': [222], 'acct.hi': [0]}, 'front': {'front': [0]}}}
    after = json.loads(json.dumps(before))
    after['outcomes'].update(OUT_ACK_COMMIT=60, OUT_RESP_RELEASE=60, OUT_OP_RELEASE=3, OUT_OP_DUP_DROP=dup_after)
    after['pktgen']['READ'] = {'trigger_counter': 60, 'pkt_counter': 240}
    after['pktgen']['OPERATE'] = {'trigger_counter': 3, 'pkt_counter': 12}
    lifecycle = actual_lifecycle()
    lifecycle['registers']['p0.r_Egress.acct']['r_Egress.acct.lo'] = [1222]
    return module.series_switch_gate(cfg, cfg['arms'][0], 20, {'before': before, 'after': after}, lifecycle)


def test_series_switch_gate_held_operate_duplicates():
    module, cfg = configured()
    failures, observed = _dup_gate(module, cfg, 3, True)
    assert observed['held_operate_dup_drops'] == 3 and not any('held-OPERATE' in f for f in failures), failures
    failures, _ = _dup_gate(module, cfg, 0, True)
    assert any('held-OPERATE duplicate expected' in f for f in failures)
    failures, _ = _dup_gate(module, cfg, 1, False)
    assert any('unexpected held-OPERATE duplicate' in f for f in failures)
    failures, _ = _dup_gate(module, cfg, 0, False)
    assert not any('held-OPERATE' in f for f in failures)


def test_series_switch_gate_image_61_growth():
    module, cfg = configured()
    cfg['builds'][cfg['arms'][0]['build']]['image_len'] = 61
    failures, observed = _dup_gate(module, cfg, 0, False)
    assert observed['external_growth_expected'] == 20 * 12 + 2 * 24

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


INJECTED = 'standards: packet_boundary: injected rejection'
PROFILE_INJECTED = 'profile: profile not conformant: attempt #3 (READ): injected rejection'


@pytest.mark.parametrize('rejection', [[], [INJECTED], [PROFILE_INJECTED]])
def test_verdict_fails_the_trial_when_the_standards_validator_rejects(monkeypatch, tmp_path, rejection):
    module, cfg = configured()
    runner = module.base.DryRunner(); runner.dry = False
    campaign = module.CandidateSeriesCampaign(cfg, runner, 'series_standards', arms=['combined'],
                                              fixtures=['separate_ack'], out=lambda *_: None)
    for cn in ('c1', 'c2', 'c3'):
        (tmp_path / cn).mkdir()
        (tmp_path / cn / 'verdict.json').write_text(json.dumps({'ok': True}))
    # Every other collaborator passes, so the standards wrapper is the only possible failure.
    monkeypatch.setattr(module.checks, 'application_checks', lambda *a, **kw: [])
    monkeypatch.setattr(module.wc, 'parse', lambda path: ([], []))
    monkeypatch.setattr(module, 'freshness_gate', lambda *a, **kw: {'server_isn': 1})
    monkeypatch.setattr(module, 'series_switch_gate', lambda *a, **kw: ([], {}))
    monkeypatch.setattr(module, 'lifecycle_gate', lambda *a, **kw: ([], {}))
    monkeypatch.setattr(campaign, 'run_standards_checker', lambda *a, **kw: {'ok': True})
    calls = []
    monkeypatch.setattr(campaign, 'validate_standards_file',
                        lambda *a, **kw: calls.append(kw['connection_id']) or list(rejection))
    vision = module.base.Result(0, json.dumps({'scenario': 'candidate_same_tuple', 'ok': True}), '')
    trial = {'reads': 20, 'master_port': 59420}
    arm = campaign.arms[0]
    if not rejection:
        campaign.verdict(trial, {}, 'series_standards', str(tmp_path), vision, arm, 'separate_ack')
        assert trial['ok'] is True and trial['failures'] == []
    else:
        with pytest.raises(module.base.StepFailed, match='injected rejection'):
            campaign.verdict(trial, {}, 'series_standards', str(tmp_path), vision, arm, 'separate_ack')
        assert trial['ok'] is False
        assert 'c1: ' + rejection[0] in trial['failures']
    assert calls == ['c1', 'c2', 'c3']


def test_control_timed_series_switch_gate_counts_each_connections_select_and_operate():
    """ctl_m4_persistence_{graceful,rst}_950_01 (silicon, 2026-10-15): 3 x (20 READ + 1 SBO) on m4. The gate first
    expected READ-only counts (60) and failed on the build's correct 66 commits/releases, 63 triggers and 6
    stranded SELECT tokens; with control_timed passed through, switch and lifecycle gates pass on that evidence."""
    module = load('candidate_series_m4_test', HW / 'candidate_series.py')
    base = module.ARCH / 'integration/core/response_only_rearm/stage_experiments/seg61_02'
    for mode in ('graceful', 'rst'):
        root = base / ('evidence/hw_campaigns/ctl_m4_persistence_%s_950_01/separate_ack/combined' % mode)
        if not root.is_dir():
            pytest.skip('retained m4 persistence evidence absent')
        d = next(root.iterdir())
        snap, label = d / 'snapshots', d.name
        cfg = json.loads((base / ('hw/config/ctl_m4_persistence_%s_950.json' % mode)).read_text())
        ev = module.checks.load_evidence_files(before=str(snap / ('%s_before.json' % label)),
                                               after=str(snap / ('%s_after.json' % label)))
        lifecycle = json.loads((snap / ('%s_after_lifecycle.json' % label)).read_text())
        reads = json.loads((d / 'trial.json').read_text())['reads']
        failures, observed = module.series_switch_gate(cfg, cfg['arms'][0], reads, ev, lifecycle)
        assert failures == [] and observed['outcomes']['OUT_ACK_COMMIT'] == 3 * reads + 6
        assert module.lifecycle_gate(lifecycle, mode)[0] == []
        cfg['builds'][cfg['arms'][0]['build']]['control_timed'] = False
        failures, _ = module.series_switch_gate(cfg, cfg['arms'][0], reads, ev, lifecycle)
        assert any('OUT_ACK_COMMIT' in f for f in failures)


def test_lifecycle_m5_retry_epoch_is_recorded_not_mistaken_for_n_epoch():
    module, _ = configured()
    snapshot = actual_lifecycle()
    snapshot['registers']['p0.n_Ingress.retry_epoch'] = {'n_Ingress.retry_epoch.f1': [145]}
    failures, observed = module.lifecycle_gate(snapshot)
    assert failures == [] and observed['epochs']['values'] == {'N': 145, 'E': 145, 'T': 145}
    assert observed['n_retry_epoch'] == 145


@pytest.mark.parametrize('emission_required', [False, True])
def test_physical_relay_series_gates_on_the_standards_dimension(monkeypatch, tmp_path, emission_required):
    """Retained c67 graceful persistence (three SEL-751 connections): the relay branch passes on its own evidence and
    raises when only the receiver-visible standards check fails (here an explicit emission-proof requirement)."""
    import shutil
    module = load('candidate_series_relay_test', HW / 'candidate_series.py')
    rc = module.ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01'
    source = next((rc / 'evidence/hw_blocks/rc01_hw_c67_20261025_07_persistence_graceful_950/physical_relay/combined')
                  .glob('*_t0'), None)
    if source is None or not (source / 'c1' / 'out.pcap').is_file():
        pytest.skip('retained c67 persistence captures absent')
    cfg = module.base.load_config(str(rc / 'hw/config/rc01_m12p_c67_sdk9132_sel751_d20_persistence_graceful_950.json'))
    if emission_required:
        cfg.setdefault('standards', {})['packet_boundary_required'] = True
    runner = module.base.DryRunner(); runner.dry = False
    campaign = module.CandidateSeriesCampaign(cfg, runner, 'rc01_hw_c67_20261025_07_persistence_graceful_950',
                                              arms=['combined'], fixtures=['physical_relay'], out=lambda *_: None)
    campaign.bound = {name: build.get('hashes') for name, build in cfg['builds'].items()}
    dest = tmp_path / 'trial'
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns('*.log', 'standards*.json'))
    monkeypatch.setattr(module.checks, 'evaluate_switch', lambda *a, **kw: ([], {}))
    monkeypatch.setattr(module, 'series_switch_gate', lambda *a, **kw: ([], {}))
    monkeypatch.setattr(module, 'lifecycle_gate', lambda *a, **kw: ([], {}))
    recorded = json.loads((dest / 'trial.json').read_text())
    trial = {k: recorded[k] for k in ('fixture', 'label', 'master_port', 'reads')}
    arm = campaign.arms[0]
    if emission_required:
        with pytest.raises(module.base.StepFailed, match='standards'):
            campaign.verdict(trial, {}, trial['label'], str(dest), SimpleNamespace(rc=0), arm, 'physical_relay')
        assert trial['dimension_verdicts']['standards'] is False
        assert trial['dimension_verdicts']['application'] is True
    else:
        campaign.verdict(trial, {}, trial['label'], str(dest), SimpleNamespace(rc=0), arm, 'physical_relay')
        assert trial['ok'] is True and trial['dimension_verdicts']['standards'] is True, trial['failures']


@pytest.mark.parametrize('telemetry', [False, True])
def test_series_switch_gate_follows_the_build_telemetry_flag(telemetry):
    """c69 (switch_telemetry false, no-J contract): the three-connection gate checks generator and loop ports but no
    T outcome counters, as relay_verdict does; a telemetry build still requires its outcomes."""
    module = load('candidate_series_telemetry_test', HW / 'candidate_series.py')
    rc = module.ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01'
    cfg = json.loads((rc / 'hw/config/rc01_m12p_c69_sdk9132_sel751_d20_persistence_graceful_950.json').read_text())
    build = cfg['builds'][cfg['arms'][0]['build']]
    build['switch_telemetry'] = telemetry
    lane = 3 * 20 + 2 * 3                      # three connections: 20 READs + SELECT + OPERATE each, all via app0
    k = cfg['service']['k']

    def snap(trig):
        loops = {r: {'dev_port': 48, '$OctetsReceived': 0, '$OctetsReceivedinGoodFrames': 0}
                 for r in ('n_ack_return', 't_in', 'held_return')}
        return {'outcomes': {}, 'loop_ports': loops,
                'pktgen': {'READ': {'trigger_counter': trig, 'batch_counter': trig, 'pkt_counter': 2 * k * trig}}}
    fails, _ = module.series_switch_gate(cfg, cfg['arms'][0], 20, {'before': snap(0), 'after': snap(lane)}, {})
    outcome_fails = [f for f in fails if 'outcome' in f]
    assert not [f for f in fails if 'trigger' in f or 'packets' in f or 'loop' in f], fails
    assert bool(outcome_fails) is telemetry, fails
