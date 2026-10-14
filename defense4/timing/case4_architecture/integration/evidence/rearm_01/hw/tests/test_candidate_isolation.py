import copy
import sys
import json
import shlex
import subprocess
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import candidate_isolation as ci


def config():
    cfg=ci.base.load_config(str(ci.ARCH/'protocol/hw_vepa/config/precision_5ms_gap800us_14892.json'))
    cfg['builds']['mirror_fix_01']['lifecycle_rearm']=True
    cfg['trials']=dict(reads_per_trial=1,trials_per_arm=1)
    cfg['evaluation']=dict(purpose='stale_source_characterization',read_precision=False)
    cfg['traffic']['master_port_range']=dict(first=59412,last=59412)
    cfg['hosts']['vision_run_dir']=ci.BARRIER_DIRECTORY
    cfg['endpoint']['binary_sha256']=ci.BARRIER_BINARY
    return cfg


def test_diagnostic_cannot_use_legacy_endpoint_or_qualify_precision():
    cfg=config()
    run=ci.TokenIsolationCampaign(cfg,ci.base.DryRunner(),'token_test',arms=['combined'],fixtures=['separate_ack'])
    assert run.units()[0]['reads']==1
    for field,value in [('trials',dict(reads_per_trial=20,trials_per_arm=1)),
                        ('evaluation',dict(purpose='qualification',read_precision=True))]:
        wrong=copy.deepcopy(cfg);wrong[field]=value
        with pytest.raises(ValueError):ci.TokenIsolationCampaign(wrong,ci.base.DryRunner(),'bad',arms=['combined'],fixtures=['separate_ack'])
    wrong=copy.deepcopy(cfg);wrong['endpoint']['binary_sha256']='a'*64
    with pytest.raises(ValueError):ci.TokenIsolationCampaign(wrong,ci.base.DryRunner(),'bad',arms=['combined'],fixtures=['separate_ack'])


def test_fixed_isolation_command_has_one_read_and_no_external_replay():
    run=ci.TokenIsolationCampaign(config(),ci.base.DryRunner(),'token_cmd',arms=['combined'],fixtures=['separate_ack'])
    run._series_padding=1
    command=run.series_vision_cmd('fixed',59412,1,8,0)
    assert 'vision_isolation.py fixed --master-port 59412 --padding 1 --control-padding 1 --image-len 58 --apply' in command
    assert 'vision_candidate.py' not in command and 'replay' not in command


def test_strict_build_passes_native_control_expectation():
    cfg=config()
    for build in cfg['builds'].values():
        build['control_padding']=False
    run=ci.TokenIsolationCampaign(cfg,ci.base.DryRunner(),'token_cmd',arms=['combined'],fixtures=['separate_ack'])
    run._series_padding=1
    assert '--padding 1 --control-padding 0 --image-len 58 --apply' in run.series_vision_cmd('fixed',59412,1,8,0)


def test_marker_reader_command_never_prints_arbitrary_files():
    command=ci.marker_command('/safe/run/c2/pre_read_ready.json')
    assert 'pre_read_ready.json' in command and 'monotonic_ns' in command
    assert 'read_bytes' not in command


def test_marker_reader_retries_partial_write_without_accepting_it(tmp_path):
    path=tmp_path/'pre_read_ready.json';path.write_text('{')
    result=subprocess.run(shlex.split(ci.marker_command(str(path))),capture_output=True,text=True)
    assert result.returncode==0
    assert json.loads(result.stdout)['marker_status']=='incomplete'
    assert json.loads(result.stdout)['marker'] is None
    path.write_text(json.dumps(dict(tcp_open=True,opens=1)))
    result=subprocess.run(shlex.split(ci.marker_command(str(path))),capture_output=True,text=True)
    assert json.loads(result.stdout)['marker_status']=='complete'


def test_hardware_execute_refuses_missing_local_authorization_before_any_step(monkeypatch):
    runner=ci.base.DryRunner();runner.dry=False
    run=ci.TokenIsolationCampaign(config(),runner,'no_auth',arms=['combined'],fixtures=['separate_ack'])
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED',raising=False)
    with pytest.raises(ValueError,match='DEFENSE4_HW_AUTHORIZED'):run.execute()


def test_new_barrier_config_is_pinned_to_its_isolated_directory():
    cfg=config()
    cfg['hosts']['vision_run_dir']='/home/decps/pad58b_rearm_barrier_20261012'
    with pytest.raises(ValueError,match='exact pinned'):
        ci.TokenIsolationCampaign(cfg,ci.base.DryRunner(),'old_barrier',arms=['combined'],fixtures=['separate_ack'])


INJECTED='standards: packet_boundary: injected rejection'


@pytest.mark.parametrize('rejection',[[],[INJECTED]])
def test_verdict_fails_the_trial_when_the_standards_validator_rejects(monkeypatch,tmp_path,rejection):
    import vision_candidate
    runner=ci.base.DryRunner();runner.dry=False
    run=ci.TokenIsolationCampaign(config(),runner,'iso_standards',arms=['combined'],fixtures=['separate_ack'],out=lambda *_:None)
    pins={run.V+'/'+name:ci.base.sha256_file(path) for name,path in ci.cs.VISION_EXTRA.items()}
    pins.update({run.V+'/'+name:ci.base.sha256_file(path) for name,path in (
        ('vision_isolation.py',ci.HERE/'vision_isolation.py'),('vision_run.py',ci.ARCH/'protocol/hw_vepa/vision_run.py'),
        ('token_window.py',ci.HERE/'token_window.py'),('snapshot_lifecycle.py',ci.HERE/'snapshot_lifecycle.py'))})
    (tmp_path/'scenario.json').write_text(json.dumps(dict(
        ok=True,source_sha256=pins,scenario='candidate_same_tuple_isolation',applied=True,padding=1,reads=1,
        master_port=59412,read_pause_ms=25,close_mode='rst',close_grace_ms=1000,
        tuple=['192.168.10.61',59412,'192.168.10.62',20000],namespaces=['ns_vepa_a','ns_vepa_b'],
        nic='enp59s0f0np0',switch_mutations=False)))
    for cn in ('c1','c2','c3'):
        (tmp_path/cn).mkdir();(tmp_path/cn/'verdict.json').write_text(json.dumps(dict(ok=True)))
    run.window.update(monitor_ok=True,marker_observation=dict(marker={}),before={},after={},restored_vision_ns=0)
    # Every other collaborator passes, so the standards wrapper is the only possible failure.
    monkeypatch.setattr(ci.cs.checks,'application_checks',lambda *a,**kw:[])
    monkeypatch.setattr(ci.cs.wc,'parse',lambda path:([],[]))
    monkeypatch.setattr(ci.cs,'freshness_gate',lambda *a,**kw:dict(server_isn=1))
    monkeypatch.setattr(vision_candidate,'evaluate',lambda *a,**kw:[])
    monkeypatch.setattr(ci,'compare_quiet_generation',lambda *a,**kw:dict(ok=True,failures=[]))
    monkeypatch.setattr(ci,'window_proof',lambda *a,**kw:dict(ok=True,failures=[],old_packets_during_pause=4))
    monkeypatch.setattr(ci,'rejection_counts',lambda *a,**kw:{})
    monkeypatch.setattr(ci,'rejection_delta',lambda *a,**kw:4)
    monkeypatch.setattr(ci,'full_run_rejections',lambda *a,**kw:dict(strict_stale_total=0))
    monkeypatch.setattr(ci,'operate_rejection_proof',lambda *a,**kw:{})
    monkeypatch.setattr(ci.cs,'series_switch_gate',lambda *a,**kw:([],{}))
    monkeypatch.setattr(ci.cs,'lifecycle_gate',lambda *a,**kw:([],{}))
    monkeypatch.setattr(run,'run_standards_checker',lambda *a,**kw:dict(ok=True))
    calls=[]
    monkeypatch.setattr(run,'validate_standards_file',lambda *a,**kw:calls.append(kw['connection_id']) or list(rejection))
    trial=dict(reads=1,master_port=59412);arm=run.arms[0];vision=ci.base.Result(0,'','')
    if not rejection:
        run.verdict(trial,{},'iso_standards',str(tmp_path),vision,arm,'separate_ack')
        assert trial['ok'] is True and trial['failures']==[]
    else:
        with pytest.raises(ci.base.StepFailed,match='injected rejection'):
            run.verdict(trial,{},'iso_standards',str(tmp_path),vision,arm,'separate_ack')
        assert trial['ok'] is False and 'c1: '+INJECTED in trial['failures']
    assert calls==['c1','c2','c3']
