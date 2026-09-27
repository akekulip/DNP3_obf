import gzip
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit_grid as audit


def fixture(tmp_path,pool):
    classes=['READ','SELECT']
    rows=[dict(replicate=rep,block='b'+str(rep),txn_class=op,txn_index=i+j*4,arm='obfuscated')
          for rep in (40,41) for j,op in enumerate(classes) for i in range(4)]
    record=dict(pool=pool,scenario='adaptive_on_obfuscated',class_order=classes)
    keys=sorted(audit.prediction_keys(rows,record))
    ledger=[dict(group=str(rep),block=block,actual=op,predicted='READ',
                 txn_index=start if pool==1 else None,pool_start=start if pool!=1 else None)
            for rep,block,op,start in keys]
    path=tmp_path/'predictions.jsonl.gz'
    with gzip.open(path,'wt') as f:
        for row in ledger:f.write(json.dumps(row)+'\n')
    count=len(keys)//2
    record.update(predictions=str(path),predictions_sha256=audit.core.sha(path),
        n_test_signatures=len(keys),confusion_matrix=[[count,0],[count,0]],
        groups=['40','41'],fold_scores=[.5,.5],mean_accuracy=.5,per_class_recall=[1.,0.])
    return rows,record,ledger


@pytest.mark.parametrize('pool',[1,2,4])
def test_recomputes_scores_and_exact_signature_inventory(tmp_path,pool):
    rows,record,_=fixture(tmp_path,pool)
    assert audit.audit_predictions(record,rows,[40,41])==16//pool
    record['mean_accuracy']=.9
    with pytest.raises(ValueError,match='accuracy mismatch'):
        audit.audit_predictions(record,rows,[40,41])


@pytest.mark.parametrize('change',['duplicate','missing','wrong_group','wrong_source_class','wrong_block'])
def test_rejects_wrong_prediction_identity_even_when_rehashed(tmp_path,change):
    rows,record,ledger=fixture(tmp_path,1)
    if change=='duplicate':ledger[-1]=ledger[0]
    if change=='missing':ledger.pop()
    if change=='wrong_group':ledger[0]['group']='0'
    if change=='wrong_source_class':ledger[0]['actual']='SELECT'
    if change=='wrong_block':ledger[0]['block']='another_policy_off'
    path=Path(record['predictions'])
    with gzip.open(path,'wt') as f:
        for row in ledger:f.write(json.dumps(row)+'\n')
    record['predictions_sha256']=audit.core.sha(path)
    with pytest.raises(ValueError):audit.audit_predictions(record,rows,[40,41])


def test_rejects_unbound_ledger_and_fabricated_group_scores(tmp_path):
    rows,record,_=fixture(tmp_path,2)
    record['fold_scores']=[.4,.6]
    with pytest.raises(ValueError,match='Per-round'):
        audit.audit_predictions(record,rows,[40,41])
    record['predictions_sha256']='wrong'
    with pytest.raises(ValueError,match='Changed prediction'):
        audit.audit_predictions(record,rows,[40,41])
