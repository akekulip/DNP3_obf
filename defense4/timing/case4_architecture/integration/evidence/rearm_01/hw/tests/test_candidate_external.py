import importlib.util
from pathlib import Path
import sys

import pytest

HW=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HW))
import candidate_external as ce
from test_candidate_isolation import config
from test_vision_replay import artifacts, vp


def configured():
    cfg=config()
    cfg['traffic']['master_port_range']=dict(first=59400,last=59400)
    evidence=ce.ARCH/'integration/evidence/campaign_hw_vepa'
    return cfg,evidence/'rearm_native_reference_01/rearm_native_reference_01_native_t0', \
        evidence/'rearm_native_rst_archive_03/series/c1'


def make_run(cfg=None):
    original,graceful,rst=configured()
    return ce.ExternalIsolationCampaign(cfg or original,ce.base.DryRunner(),'external_test',
        arms=['combined'],fixtures=['separate_ack'],old_graceful=graceful,old_rst=rst)


def test_constructor_binds_real_native_fin_rst_archives_and_fixed_port():
    run=make_run()
    assert set(run.record['old_capture_identity'])=={'graceful','rst'}
    assert 'token_isolation' not in run.record
    assert run.series_vision_cmd('fixed',59400,1).endswith('fixed --master-port 59400 --padding 1 --apply')
    cfg,_,_=configured();cfg['traffic']['master_port_range']=dict(first=59401,last=59401)
    with pytest.raises(ValueError,match='59400'):make_run(cfg)


def test_execute_has_no_hardware_side_effect_before_local_authorization(monkeypatch):
    run=make_run();run.rn.dry=False
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED',raising=False)
    with pytest.raises(ValueError,match='DEFENSE4_HW_AUTHORIZED'):run.execute()


def test_vision_deployment_includes_transitive_isolation_helper(monkeypatch):
    run=make_run()
    monkeypatch.setattr(ce.cs.CandidateSeriesCampaign,'vision_identity',lambda self:None)
    run.vision_identity()
    assert set(run.record['external_vision_identity'])=={
        'vision_replay.py','vision_isolation.py','replay_old_packets.py','token_window.py','snapshot_lifecycle.py'}


def test_root_reproduces_filtering_and_rejects_changed_current_evidence(tmp_path):
    raw=tmp_path/'c2';artifacts(raw);vp.derive_current(raw)
    before=(raw/'out.pcap').read_bytes()
    ce.ExternalIsolationCampaign.verify_current_derivation(raw)
    with (raw/'current/in.pcap').open('ab') as stream:stream.write(b'changed')
    with pytest.raises(ValueError,match='derived current bytes'):
        ce.ExternalIsolationCampaign.verify_current_derivation(raw)
    assert (raw/'out.pcap').read_bytes()==before


def test_root_rejects_forged_filtering_proof(tmp_path):
    import json
    raw=tmp_path/'c2';artifacts(raw);vp.derive_current(raw)
    path=raw/'current/filter.json';value=json.loads(path.read_text());value['removed']+=1
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='retained replay filtering proof'):
        ce.ExternalIsolationCampaign.verify_current_derivation(raw)
