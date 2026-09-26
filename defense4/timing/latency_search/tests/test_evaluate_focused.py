import copy
from pathlib import Path
import sys

import numpy as np
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import evaluate_focused as f


def rows():
    return [dict(session=str(rep),replicate=rep,block=f'b{rep}_{arm}',arm=arm,
        policy_name=f.focused_campaign.POLICY if arm=='obfuscated' else 'OFF',
        txn_class=op,txn_index=j*20+i,ack_ms=5.+i*.01,clrt_ms=1.+i*.01,
        rt_ms=6.+i*.02,request_gap_ms=400.,rand8=i,selected_da_ms=5.)
        for rep in range(2) for arm in ('native','obfuscated')
        for j,op in enumerate(f.base.a.CLASSES) for i in range(20)]


def protocol():
    return dict(training_repetitions=[0],test_repetitions=[1],count_per_operation=20,
                primary_exchanges=240,policy_name=f.focused_campaign.POLICY)


def test_missing_duplicate_wrong_policy_rejected():
    r=rows();p=protocol();f.validate_rows(r,p,True)
    for broken in (r[:-1],r+[r[0]]):
        with pytest.raises(ValueError): f.validate_rows(broken,p,True)
    r[0]['policy_name']='other'
    with pytest.raises(ValueError,match='policy'):f.validate_rows(r,p,True)


def test_heldout_changes_cannot_change_training_fingerprint():
    r=rows();p=protocol();before=f.digest(f.split_rows(r,p,'training'))
    for x in r:
        if x['replicate']==1:
            x['ack_ms']=9999.;x['txn_class']='OPERATE'
    assert before==f.digest(f.split_rows(r,p,'training'))
    assert {x['block'] for x in f.split_rows(r,p,'training')}.isdisjoint(
        {x['block'] for x in f.split_rows(r,p,'test')})


@pytest.mark.parametrize('representation',['raw','levels'])
def test_feature_projection_excludes_telemetry(representation):
    levels={'da_ms':[4.5,4.833,5.167,5.5],'gap_ms':[.5,.833,1.167,1.5]}
    a=rows();b=copy.deepcopy(a)
    for row in b:
        row['rand8']=999;row['selected_da_ms']=999;row['func']=99
    assert f.project(a,representation,levels)==f.project(b,representation,levels)
    projected=f.project(a,representation,levels)
    assert all('rand8' not in row and 'func' not in row and 'selected_da_ms' not in row for row in projected)


def test_pooling_keeps_arms_blocks_and_partition_separate():
    r=rows();p=protocol();spec=dict(classes=list(f.base.a.CLASSES),pool=20,representation='raw')
    train=f.pooled(f.split_rows(r,p,'training'),spec,{},'obfuscated')
    test=f.pooled(f.split_rows(r,p,'test'),spec,{},'obfuscated')
    assert len(train)==len(test)==3
    assert all(x['block']=='b0_obfuscated' and x['pool_size']==20 for x in train)
    assert all(x['block']=='b1_obfuscated' for x in test)


def test_full_model_inventory():
    jobs=f.jobs(f.focused_campaign.protocol())
    assert len(jobs)==180
    assert len({j['key'] for j in jobs})==180
    assert all(j['training_arm']=='obfuscated' for j in jobs if j['representation']=='levels')


def test_scoring_artifact_and_confusion(tmp_path):
    r=rows();spec=dict(key='smoke',classes=list(f.base.a.CLASSES),pool=1,
        representation='raw',training_arm='native',model='logistic',feature='ack_clrt',task='three_class')
    train=f.pooled(f.split_rows(r,protocol(),'training'),spec,{},'native')
    estimator=f.base.a._model('logistic')
    estimator.fit(f.base.a._pooled_feature_matrix(train,'ack_clrt'),[x['txn_class'] for x in train])
    path=tmp_path/'smoke.pkl';path.write_bytes(f.pickle.dumps(estimator))
    record=dict(spec=spec,model_sha256=f.sha(path))
    result=f.score_one(record,f.split_rows(r,protocol(),'test'),{},tmp_path,tmp_path/'pred')
    assert {x['scenario'] for x in result}=={'fixed_on_native','fixed_on_obfuscated'}
    assert all(sum(map(sum,x['confusion_matrix']))==60 for x in result)
    assert all(x['groups']==['1'] for x in result)
    path.write_bytes(b'changed')
    with pytest.raises(ValueError,match='artifact'):f.score_one(record,r,{},tmp_path,tmp_path/'pred')


def test_fit_cache_is_bound_to_training_inputs(tmp_path,monkeypatch):
    r=[]
    for rep in range(5):
        for row in rows()[:120]:
            item=dict(row,replicate=rep,session=str(rep),block=f'fit{rep}_{row["arm"]}')
            r.append(item)
    spec=dict(key='fit_test',classes=list(f.base.a.CLASSES),pool=1,
        representation='raw',training_arm='native',model='logistic',feature='ack_clrt',task='three_class')
    provenance=dict(training_sha256=f.digest(r))
    monkeypatch.setitem(f.base.PARAMS,'logistic',{'logisticregression__C':[1.]})
    record=f.fit_one(spec,r,{},tmp_path,provenance)
    assert record['training_groups']==list(map(str,range(5)))
    assert f.fit_one(spec,r,{},tmp_path,provenance)==record
    with pytest.raises(ValueError,match='stale'):
        f.fit_one(spec,r,{},tmp_path,dict(training_sha256='changed'))
