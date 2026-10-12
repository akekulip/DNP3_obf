import importlib.util
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidate_rows_retain_normalization_and_add_final_qualified_commit():
    entry = load('candidate_installer_test', HW.parents[3] /
                 'integration/core/response_only_rearm/hw/bringup_composite.py')
    cp = entry.installer.rows.cp
    relay = cp.rp.Endpoint('192.168.10.62', 20000, 9)
    master = cp.rp.Endpoint('192.168.10.61', 54500, 9)
    rows = cp.e_conn_rows(0, relay, master, n_ack_return=48)
    reverse_ports = {dict(row[1])['eg.egress_port'] for row in rows if row[2] == 'Egress.rev_conn'}
    assert reverse_ports == {9, 48}
    assert len(rows) == len(cp.base.e_conn_rows(0, relay, master, n_ack_return=48)) + 1


def configured():
    module = load('candidate_campaign_test', HW / 'candidate_campaign.py')
    cfg = module.base.load_config(str(module.ARCH / 'protocol/hw_vepa/config/precision_5ms_gap800us_14892.json'))
    return module, cfg


def test_baseline_cannot_silently_use_candidate_installer():
    module, cfg = configured()
    with pytest.raises(ValueError, match='lifecycle_rearm:true'):
        module.CandidateCampaign(cfg, module.base.DryRunner(), 'offline_candidate_test')


def test_corrupt_candidate_deployment_is_rejected(monkeypatch):
    module, cfg = configured()
    cfg['builds']['mirror_fix_01']['lifecycle_rearm'] = True
    runner = module.base.DryRunner()
    campaign = module.CandidateCampaign(cfg, runner, 'offline_candidate_test')
    monkeypatch.setattr(module.base.Campaign, 'deploy_switch', lambda self: None)
    runner.dry = False
    monkeypatch.setattr(campaign, 'step', lambda *args, **kwargs: module.base.Result(0, 'bad /wrong/path', ''))
    with pytest.raises(module.base.StepFailed, match='identity mismatch'):
        campaign.deploy_switch()
