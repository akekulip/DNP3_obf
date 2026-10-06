from dataclasses import replace
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from defense4.timing.latency_search import focused_campaign as f


def test_split_and_schedule():
    p=f.protocol()
    assert len(p['training_repetitions'])==40
    assert len(p['test_repetitions'])==60
    assert not set(p['training_repetitions']) & set(p['test_repetitions'])
    schedule=f.rc.build_schedule(random_plan_paths=[Path(f.POLICY+'.json')],repeats=100,
        seed=p['seed'],off_every=1,count=100,run_name='focused')
    assert len(schedule)==200
    assert sum(3*b.count for b in schedule)==60000
    for protected,native in zip(schedule[::2],schedule[1::2]):
        assert protected.replicate==native.replicate
        assert protected.kind=='random_policy' and native.kind=='off_reference'


def fake_run(tmp_path):
    identity=tmp_path/'program_identity.json'
    f.rc.write_json(identity,dict(program='defense4_timing',ingress_stages=7,
                                  egress_stages=0,source_sha256='test'))
    f.rc.write_json(tmp_path/'protocol.json',f.protocol())
    schedule=f.rc.build_schedule(random_plan_paths=[Path(f.POLICY+'.json')],repeats=2,
        seed=1,off_every=1,count=100,run_name='test')
    return f.rc.PreparedRun(tmp_path,'screen',100,2,1,schedule,'fixed','off','restore',identity)


def test_failure_restores_and_does_not_retry(tmp_path,monkeypatch):
    run=fake_run(tmp_path); events=[]
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED','1')
    monkeypatch.setattr(f,'identity_snapshot',lambda *args:None)
    monkeypatch.setattr(f.rc,'_base_upload_files',lambda run:[])
    monkeypatch.setattr(f.rc,'_restore',lambda *args:events.append('restore'))
    def fail(*args,**kwargs):
        events.append('traffic')
        raise RuntimeError('failure')
    monkeypatch.setattr(f.rc,'run_block',fail)
    with pytest.raises(RuntimeError,match='failure'):
        f.execute(run,f.OfflineTransport())
    assert events==['traffic','restore']
    assert f.rc._load_json(tmp_path/'final_status.json')['configuration_restored']
    with pytest.raises(RuntimeError,match='restart'):
        f.execute(run,f.OfflineTransport())


def test_stop_file_waits_for_block_completion(tmp_path,monkeypatch):
    run=fake_run(tmp_path);events=[]
    monkeypatch.setenv('DEFENSE4_HW_AUTHORIZED','1')
    monkeypatch.setattr(f,'identity_snapshot',lambda *args:None)
    monkeypatch.setattr(f.rc,'_base_upload_files',lambda run:[])
    monkeypatch.setattr(f.rc,'_restore',lambda *args:events.append('restore'))
    def block(spec,run,**kwargs):
        events.append('completed')
        (run.run_dir/'STOP_AFTER_BLOCK').touch()
        return {'label':spec.label}
    monkeypatch.setattr(f.rc,'run_block',block)
    f.execute(run,f.OfflineTransport())
    assert events==['completed','restore']
    assert len(f.rc._load_json(tmp_path/'progress.json'))==1
    assert f.rc._load_json(tmp_path/'final_status.json')['stopped_after_block']
