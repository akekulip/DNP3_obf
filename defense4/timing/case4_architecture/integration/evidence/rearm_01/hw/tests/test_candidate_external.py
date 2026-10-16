import importlib.util
from pathlib import Path
import sys

import pytest

HW=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HW))
import candidate_external as ce
from test_candidate_isolation import barrier_config as config
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
    assert run.series_vision_cmd('fixed',59400,1).endswith('fixed --master-port 59400 --padding 1 --control-padding 1 --image-len 58 --apply')
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


def test_c2_standards_captures_bind_current_to_raw_filter_proof(tmp_path):
    import json
    raw=tmp_path/'c2';artifacts(raw);vp.derive_current(raw)
    captures=ce.ExternalIsolationCampaign.connection_standards_captures(raw,raw/'current','c2')
    assert captures['filter_proof']['path']==str(raw/'current/filter.json')
    assert captures['out']['path']==str(raw/'current/out.pcap')
    assert captures['out']['filtered_from']=={'raw_out':str(raw/'out.pcap')}
    assert captures['in']['filtered_from']=={'raw_in':str(raw/'in.pcap')}
    assert captures['out']['filter_procedure']==json.loads((raw/'current/filter.json').read_text())
    assert 'filtered_from' not in ce.ExternalIsolationCampaign.connection_standards_captures(raw,raw,'c1')['out']


def pool_run():
    original,graceful,rst=configured()
    evidence=ce.ARCH/'integration/evidence/campaign_hw_vepa'
    second=evidence/'rearm_fresh_native_fin_01/rearm_fresh_native_fin_01_native_t0'
    return ce.ExternalIsolationCampaign(original,ce.base.DryRunner(),'external_pool_test',
        arms=['combined'],fixtures=['separate_ack'],old_graceful=[graceful,second],old_rst=rst),graceful,second


def test_pool_takes_first_unambiguous_archive_and_never_relaxes_the_guard(monkeypatch):
    run,first,second=pool_run()
    seen=[]
    def guard(old,new_paths,port,client,server):
        seen.append(old['isns']['client'])
        if len(seen)==1:raise ValueError('new client ISN overlaps ambiguous old sequence range')
        return {'client':client,'server':server}
    monkeypatch.setattr(ce.replay,'fresh_guard',guard)
    assert run.choose_archive('graceful','fresh.pcap',59400,{'client':1,'server':2})==1
    assert run.old_archives['graceful']==second.resolve()
    assert len(seen)==2


def test_pool_fails_closed_when_every_archive_is_ambiguous_and_propagates_other_errors(monkeypatch):
    run,_,_=pool_run()
    def ambiguous(*args):raise ValueError('new server ISN overlaps ambiguous old sequence range')
    monkeypatch.setattr(ce.replay,'fresh_guard',ambiguous)
    with pytest.raises(ValueError,match='no retained old graceful archive'):
        run.choose_archive('graceful','fresh.pcap',59400,{'client':1,'server':2})
    def other(*args):raise ValueError('declared new ISNs do not match fresh same-tuple handshake')
    monkeypatch.setattr(ce.replay,'fresh_guard',other)
    with pytest.raises(ValueError,match='declared new ISNs'):
        run.choose_archive('graceful','fresh.pcap',59400,{'client':1,'server':2})


def test_pool_pins_every_member_and_rejects_duplicates():
    run,first,second=pool_run()
    assert len(run.record['old_capture_identity']['graceful'])==4
    original,graceful,rst=configured()
    with pytest.raises(ValueError,match='distinct'):
        ce.ExternalIsolationCampaign(original,ce.base.DryRunner(),'dup',arms=['combined'],fixtures=['separate_ack'],
                                     old_graceful=[graceful,graceful],old_rst=rst)


INJECTED='standards: packet_boundary: injected rejection'
PROFILE_INJECTED = 'profile: profile not conformant: attempt #3 (READ): injected rejection'


@pytest.mark.parametrize('rejection', [[], [INJECTED], [PROFILE_INJECTED]])
def test_verdict_fails_the_trial_when_the_standards_validator_rejects(monkeypatch,tmp_path,rejection):
    import json
    import vision_candidate
    run=make_run();run.rn.dry=False;run.out=lambda *_:None
    pins={run.V+'/'+name:ce.base.sha256_file(path) for name,path in ce.cs.VISION_EXTRA.items()}
    pins.update({run.V+'/'+name:ce.base.sha256_file(path) for name,path in (
        ('vision_run.py',ce.ARCH/'protocol/hw_vepa/vision_run.py'),('vision_isolation.py',ce.HERE/'vision_isolation.py'),
        ('vision_replay.py',ce.HERE/'vision_replay.py'),('replay_old_packets.py',ce.HERE/'replay_old_packets.py'),
        ('token_window.py',ce.HERE/'token_window.py'),('snapshot_lifecycle.py',ce.HERE/'snapshot_lifecycle.py'))})
    (tmp_path/'scenario.json').write_text(json.dumps(dict(
        ok=True,source_sha256=pins,scenario='candidate_same_tuple_replay',applied=True,padding=1,reads=1,
        master_port=59400,read_pause_ms=25,close_mode='rst',close_grace_ms=1000,
        tuple=['192.168.10.61',59400,'192.168.10.62',20000],namespaces=['ns_vepa_a','ns_vepa_b'],
        nic='enp59s0f0np0',switch_mutations=False)))
    for cn in ('c1','c2','c3'):
        (tmp_path/cn).mkdir();(tmp_path/cn/'verdict.json').write_text(json.dumps(dict(ok=True)))
    (tmp_path/'c2/current').mkdir();(tmp_path/'c2/master.json').write_text(json.dumps(dict(first_read_issued_ns=2)))
    run.window.update(monitor_ok=True,before={},after={},current_isns=dict(client=1,server=2),completed_vision_ns=1)
    # Every other collaborator passes, so the standards wrapper is the only possible failure.
    monkeypatch.setattr(run,'verify_current_derivation',lambda raw:{})
    monkeypatch.setattr(vision_candidate,'evaluate',lambda *a,**kw:[])
    monkeypatch.setattr(ce.cs.wc,'parse',lambda path:([],[]))
    monkeypatch.setattr(ce.cs,'freshness_gate',lambda *a,**kw:dict(server_isn=2))
    monkeypatch.setattr(ce,'compare_quiet_generation',lambda *a,**kw:dict(ok=True,failures=[]))
    monkeypatch.setattr(ce.cs,'series_switch_gate',lambda *a,**kw:([],{}))
    monkeypatch.setattr(ce.cs,'lifecycle_gate',lambda *a,**kw:([],{}))
    monkeypatch.setattr(run,'run_standards_checker',lambda *a,**kw:dict(ok=True))
    calls=[]
    monkeypatch.setattr(run,'validate_standards_file',lambda *a,**kw:calls.append(kw['connection_id']) or list(rejection))
    trial=dict(reads=1,master_port=59400);arm=run.arms[0];vision=ce.base.Result(0,'','')
    if not rejection:
        run.verdict(trial,{},'ext_standards',str(tmp_path),vision,arm,'separate_ack')
        assert trial['ok'] is True and trial['failures']==[]
    else:
        with pytest.raises(ce.base.StepFailed,match='injected rejection'):
            run.verdict(trial,{},'ext_standards',str(tmp_path),vision,arm,'separate_ack')
        assert trial['ok'] is False and 'c1: '+rejection[0] in trial['failures']
    assert calls==['c1','c2','c3']
