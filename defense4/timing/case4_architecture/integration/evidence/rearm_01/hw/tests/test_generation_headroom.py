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
    assert trial['generation_headroom']['reserve'] == 19
    assert any('generation_headroom.py' in call[1] for call in campaign.rn.calls)


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
