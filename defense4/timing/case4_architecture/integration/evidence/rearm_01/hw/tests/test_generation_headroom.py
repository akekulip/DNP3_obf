import importlib.util
import json
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def headroom_module():
    return load('generation_headroom_test',
                HW.parents[3] / 'integration/core/response_only_rearm/hw/generation_headroom.py')


def snapshot(read=40, operate=17):
    return {
        'valid': True,
        'errors': {},
        'software_read_fallbacks': [],
        'registers': {
            'p1.t_Ingress.gen_alloc_reg': {'t_Ingress.gen_alloc_reg.f1': [read]},
            'p1.t_Ingress.op_gen_alloc_reg': {'t_Ingress.op_gen_alloc_reg.f1': [operate]},
        },
    }


def test_generation_headroom_accepts_normal_budget_and_reports_remaining_capacity():
    module = headroom_module()
    evidence = module.assess_headroom(snapshot(read=40, operate=17), reserve=45)
    assert evidence['ok'] is True
    assert evidence['reserve'] == 45
    assert evidence['current'] == {'read': 40, 'operate': 17}
    assert evidence['remaining_after_reserve']['read'] == 65449
    assert evidence['remaining_after_reserve']['operate'] == 65472


def test_generation_headroom_refuses_near_exhaustion_before_trial_traffic():
    module = headroom_module()
    with pytest.raises(module.HeadroomError, match='read generation headroom exhausted'):
        module.assess_headroom(snapshot(read=65530, operate=17), reserve=5)


def test_generation_headroom_refuses_missing_or_malformed_register_evidence():
    module = headroom_module()
    missing = snapshot()
    del missing['registers']['p1.t_Ingress.op_gen_alloc_reg']
    with pytest.raises(module.HeadroomError, match='missing required hardware register'):
        module.assess_headroom(missing, reserve=1)

    malformed = snapshot()
    malformed['registers']['p1.t_Ingress.gen_alloc_reg'] = {'t_Ingress.gen_alloc_reg.f1': [True]}
    with pytest.raises(module.HeadroomError, match='no readable integer'):
        module.assess_headroom(malformed, reserve=1)

    fallback = snapshot()
    fallback['software_read_fallbacks'] = ['p1.t_Ingress.gen_alloc_reg']
    with pytest.raises(module.HeadroomError, match='software fallback'):
        module.assess_headroom(fallback, reserve=1)


def test_generation_headroom_direct_hardware_read_requires_authorization(monkeypatch):
    module = headroom_module()
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED', raising=False)
    with pytest.raises(module.HeadroomError, match='DEFENSE4_HW_AUTHORIZED=1'):
        module.require_authorized()


def configured_candidate61():
    module = load('candidate_campaign_headroom_test', HW / 'candidate_campaign.py')
    cfg = json.loads((module.ARCH /
                      'integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/'
                      'candidate61_fourarm_smoke.json').read_text())
    cfg['builds']['rearm_61_full04']['lifecycle_rearm'] = True
    cfg['trials'] = {'reads_per_trial': 1, 'trials_per_arm': 1}
    cfg['traffic']['master_port_range'] = {'first': 59530, 'last': 59533}
    cfg['evidence_dir'] = '/tmp/candidate_headroom_tests'
    return module, cfg


def test_candidate61_dry_run_records_headroom_gate_without_live_switch_read():
    module, cfg = configured_candidate61()
    campaign = module.CandidateCampaign(cfg, module.base.DryRunner(), 'dry_headroom',
                                        arms=['combined'], fixtures=['separate_ack'])
    trial = {'label': 'dry_headroom_separate_ack_combined_t0', 'reads': 1}
    campaign.record['arms'].append({'fixture': 'separate_ack', 'arm': 'combined',
                                    'build': 'rearm_61_full04', 'trials': [trial]})
    campaign.snapshot('/remote/out', 'dry_headroom_separate_ack_combined_t0_before')
    assert trial['generation_headroom']['ok'] is None
    assert trial['generation_headroom']['dry_run'] is True
    # candidate61 smoke: 1 READ + 1 SBO, one connection, not control-timed: read 1+2+16, operate 1+2+16.
    assert trial['generation_headroom']['reserve'] == {'read': 19, 'operate': 19}
    assert any('generation_headroom.py' in call[1] and '--reserve-read 19 --reserve-operate 19' in call[1]
               for call in campaign.rn.calls)


def test_non_candidate61_build_does_not_get_generation_headroom_gate():
    module = load('candidate_campaign_headroom_default_test', HW / 'candidate_campaign.py')
    cfg = module.base.load_config(str(module.ARCH / 'protocol/hw_vepa/config/precision_5ms_gap800us_14892.json'))
    cfg['builds']['mirror_fix_01']['lifecycle_rearm'] = True
    campaign = module.CandidateCampaign(cfg, module.base.DryRunner(), 'dry_default',
                                        arms=['combined'], fixtures=['separate_ack'])
    trial = {'label': 'dry_default_separate_ack_combined_t0', 'reads': 1}
    campaign.record['arms'].append({'fixture': 'separate_ack', 'arm': 'combined',
                                    'build': 'mirror_fix_01', 'trials': [trial]})
    campaign.snapshot('/remote/out', 'dry_default_separate_ack_combined_t0_before')
    assert 'generation_headroom' not in trial
    assert not any('generation_headroom.py' in call[1] for call in campaign.rn.calls)


MAX = 0xfffe


def test_workload_reserve_counts_every_allocating_transaction():
    module = headroom_module()
    # m3 repeated SBO (audit probe): 65 READs + 64 SELECT + 64 OPERATE on the read lane, 64 OPERATEs.
    reserve, why = module.workload_reserve(65, 64, 1, control_timed=True)
    assert reserve == {'read': 65 + 128 + 2 + 16, 'operate': 64 + 2 + 16} == {'read': 211, 'operate': 82}
    assert why['read_lane_per_connection'] == 193
    # candidate61 times READ only; OPERATE still bumps its own allocator.
    assert module.workload_reserve(65, 64, 1, control_timed=False)[0] == {'read': 83, 'operate': 82}
    # T disabled: only OPEN/RESET allocate.
    assert module.workload_reserve(65, 64, 1, control_timed=True, timed=False)[0] == {'read': 18, 'operate': 18}
    # Three connections (reconnect / same-tuple series) multiply the per-connection workload and lifecycle.
    assert module.workload_reserve(20, 1, 3, control_timed=True)[0] == {'read': 3 * 22 + 6 + 16, 'operate': 3 + 6 + 16}
    # A cancelled SELECT costs its own REQUEST on a control-timed lane, nothing on candidate61.
    assert module.workload_reserve(20, 1, 1, True, cancelled_selects=2)[0]['read'] == 22 + 2 + 2 + 16
    assert module.workload_reserve(20, 1, 1, False, cancelled_selects=2)[0]['read'] == 20 + 2 + 16
    for bad in (-1, True, 1.5):
        with pytest.raises(module.HeadroomError):
            module.workload_reserve(bad, 1, 1, True)
    with pytest.raises(module.HeadroomError):
        module.workload_reserve(1, 1, 0, True)


def test_audit_probe_near_exhaustion_is_refused_with_the_full_budget():
    module = headroom_module()
    reserve, _ = module.workload_reserve(65, 64, 1, control_timed=True)
    evidence = module.evaluate_headroom(snapshot(read=65450, operate=0), reserve)
    assert evidence['ok'] is False
    assert evidence['failures'] == ['read generation headroom exhausted: current 65450 + reserve 211 > 65534']
    assert evidence['remaining_after_reserve'] == {'read': -127, 'operate': MAX - 82}


@pytest.mark.parametrize('role', ['read', 'operate'])
def test_each_allocator_passes_just_enough_and_refuses_one_short(role):
    module = headroom_module()
    reserve, _ = module.workload_reserve(65, 64, 1, control_timed=True)
    other = 'operate' if role == 'read' else 'read'
    just = {role: MAX - reserve[role], other: 0}
    assert module.evaluate_headroom(snapshot(**just), reserve)['ok'] is True
    short = {role: MAX - reserve[role] + 1, other: 0}
    evidence = module.evaluate_headroom(snapshot(**short), reserve)
    assert evidence['ok'] is False and len(evidence['failures']) == 1
    assert evidence['failures'][0].startswith('%s generation headroom exhausted' % role)


def test_per_role_reserve_is_validated():
    module = headroom_module()
    for bad in ({'read': 5}, {'read': 5, 'operate': 0}, {'read': 5, 'operate': True}, 0):
        with pytest.raises(module.HeadroomError):
            module.evaluate_headroom(snapshot(), bad)


def test_cli_requires_one_reserve_form(tmp_path, capsys):
    module = headroom_module()
    out = str(tmp_path / 'h.json')
    for args in (['--reserve-read', '3'], [], ['--reserve', '3', '--reserve-read', '3', '--reserve-operate', '3']):
        with pytest.raises(SystemExit):
            module.main(['--build-out', str(tmp_path), '--switch-tools', str(tmp_path), '--output', out] + args)


def ctl_campaign(scenario=None):
    module = load('candidate_campaign_ctl_headroom_test', HW / 'candidate_campaign.py')
    cfg = json.loads((module.ARCH / 'integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config/'
                      'ctl_timing_repeat_sbo_950_b1.json').read_text())
    cfg['evidence_dir'] = '/tmp/candidate_headroom_tests'
    campaign = module.CandidateCampaign(cfg, module.base.DryRunner(), 'dry_ctl', arms=['combined', 'off'],
                                        fixtures=['separate_ack'])
    campaign.scenario = scenario
    return module, cfg, campaign


def test_control_timed_campaign_reserves_selects_and_operates_from_the_config():
    _module, cfg, campaign = ctl_campaign()
    build = cfg['arms'][0]['build']
    assert cfg['builds'][build]['control_timed'] is True and cfg['traffic']['sbo_cycles'] == 64
    reserve, why = campaign._headroom_reserve({'reads': 65}, {'build': build, 'T': 1})
    assert reserve == {'read': 211, 'operate': 82} and why['control_timed'] is True
    # The untimed arm of the same build allocates only on OPEN/RESET.
    assert campaign._headroom_reserve({'reads': 65}, {'build': build, 'T': 0})[0] == {'read': 18, 'operate': 18}
    # The reconnect scenario budgets three connections.
    _module, _cfg, reconnect = ctl_campaign(scenario='reconnect')
    assert reconnect._headroom_reserve({'reads': 65}, {'build': build, 'T': 1})[0] == \
        {'read': 3 * 193 + 6 + 16, 'operate': 3 * 64 + 6 + 16}


def test_cli_single_reserve_still_parses(tmp_path, monkeypatch):
    module = headroom_module()
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED', raising=False)
    out = tmp_path / 'h.json'
    assert module.main(['--build-out', str(tmp_path), '--switch-tools', str(tmp_path), '--output', str(out),
                        '--reserve', '3']) == 1          # parses, then refuses the unauthorized hardware read
    assert json.loads(out.read_text())['reserve'] == 3


def test_control_timed_dry_run_command_carries_both_reserves():
    _module, cfg, campaign = ctl_campaign()
    build = cfg['arms'][0]['build']
    trial = {'label': 'dry_ctl_separate_ack_combined_t0', 'reads': 65}
    campaign.record['arms'].append({'fixture': 'separate_ack', 'arm': 'combined', 'T': 1, 'build': build,
                                    'trials': [trial]})
    campaign.snapshot('/remote/out', 'dry_ctl_separate_ack_combined_t0_before')
    assert trial['generation_headroom']['reserve'] == {'read': 211, 'operate': 82}
    assert any('--reserve-read 211 --reserve-operate 82' in call[1] for call in campaign.rn.calls)


def test_budget_refuses_unknown_or_mislabelled_builds_and_preflight_reports_it():
    module, cfg, campaign = ctl_campaign()
    build = cfg['arms'][0]['build']
    with pytest.raises(ValueError, match='needs the arm build'):
        campaign._headroom_reserve({'reads': 65}, None)
    with pytest.raises(ValueError, match='needs the arm build'):
        campaign._headroom_reserve({'reads': 65}, {'build': 'nonexistent', 'T': 1})
    cfg['builds'][build]['control_timed'] = False
    with pytest.raises(ValueError, match='does not declare control_timed'):
        campaign._headroom_reserve({'reads': 65}, {'build': build, 'T': 1})
    assert any('generation budget for' in e and 'control_timed' in e for e in campaign.preflight())
    cfg['builds'][build]['control_timed'] = True
    cfg['traffic']['cancelled_selects'] = -1
    assert any('generation budget for' in e and 'cancelled_selects' in e for e in campaign.preflight())
    cfg['traffic']['cancelled_selects'] = 0
    assert not any('generation budget' in e for e in campaign.preflight())
