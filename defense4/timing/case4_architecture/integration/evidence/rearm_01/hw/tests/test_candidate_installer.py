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


def candidate_text():
    return (HW.parents[3]/'integration/core/response_only_rearm/evidence/incremental_55/response_only.p4').read_text()


def test_candidate_installer_reads_actual_provenance_parser_ports(tmp_path):
    entry=load('candidate_ports_test',HW.parents[3]/'integration/core/response_only_rearm/hw/bringup_composite.py')
    (tmp_path/'response_only.p4pp').write_text(candidate_text())
    ports,errors=entry.installer.build_ports.read(tmp_path)
    assert errors==[]
    assert ports['e_ports']==[9,48]
    assert entry.installer.build_ports.check_endpoints(ports,9,9)==[]
    assert entry.installer.build_ports.loopback_ports(ports)==dict(n_ack_return=48,t_in=180,hb_return=181,held_return=182)


@pytest.mark.parametrize('old,new',[
    ('9w48: provenance;', '9w64: provenance;'),
    ('16w0: eth; default: reject;', '16w1: eth; default: reject;'),
    ('16w0: eth; default: reject;', '16w0: eth; default: accept;'),
    ('9w48: provenance;', '9w48: eth;'),
    ('9w48: provenance;', '9w48: provenance; 9w64: provenance;'),
])
def test_candidate_port_guard_rejects_malformed_private_dispatch(tmp_path,old,new):
    entry=load('candidate_bad_ports_test',HW.parents[3]/'integration/core/response_only_rearm/hw/bringup_composite.py')
    text=candidate_text()
    assert text.count(old)==1
    (tmp_path/'response_only.p4pp').write_text(text.replace(old,new))
    assert entry.installer.build_ports.read(tmp_path)[1]


def test_candidate_snapshot_uses_the_same_strict_parser_guard(tmp_path):
    root=HW.parents[3]/'integration/core/response_only_rearm'
    entry=load('candidate_snapshot_test',root/'hw/snapshot_counters.py')
    (tmp_path/'response_only.p4pp').write_text(candidate_text())
    ports,errors=entry.snapshot.build_ports.read(tmp_path)
    assert errors==[] and ports['e_ports']==[9,48]
    text=candidate_text().replace('16w0: eth; default: reject;','16w0: eth; default: accept;')
    (tmp_path/'response_only.p4pp').write_text(text)
    assert entry.snapshot.build_ports.read(tmp_path)[1]


def test_candidate_campaign_routes_all_counter_snapshots_to_its_guard():
    module,cfg=configured()
    cfg['builds']['mirror_fix_01']['lifecycle_rearm']=True
    run=module.CandidateCampaign(cfg,module.base.DryRunner(),'snapshot_cmd')
    command=run.switch_cmd('snapshot_counters.py','--build-out /test/out -o /test/snap.json')
    assert '/src/integration/core/response_only_rearm/hw/snapshot_counters.py' in command
    assert 'integration/core/response_only_rearm/hw/snapshot_counters.py' in module.EXTRA_FILES


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
