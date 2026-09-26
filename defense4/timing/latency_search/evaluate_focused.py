#!/usr/bin/env python3
"""Frozen-training, later-block evaluation of the focused hardware experiment."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import gzip
import hashlib
import json
from pathlib import Path
import pickle
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import evaluate as base
import evaluate_level_attack as levels_attack
import focused_campaign
import numpy as np
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, recall_score
from sklearn.model_selection import GridSearchCV, GroupKFold


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,allow_nan=False).encode()).hexdigest()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def code_digest():
    return hashlib.sha256(b''.join((HERE/n).read_bytes() for n in
        ('evaluate_focused.py','evaluate.py','analysis.py','evaluate_level_attack.py','focused_campaign.py'))).hexdigest()


def split_rows(rows, protocol, partition):
    allowed=set(protocol[partition+'_repetitions'])
    return [r for r in rows if int(r['replicate']) in allowed]


def validate_rows(rows, protocol, complete):
    from collections import Counter
    allowed=set(protocol['training_repetitions']+protocol['test_repetitions'])
    counts=Counter()
    blocks={}
    keys=set()
    for r in rows:
        rep=int(r['replicate']);arm=r['arm'];op=r['txn_class']
        if rep not in allowed or arm not in ('native','obfuscated') or op not in base.a.CLASSES:
            raise ValueError('Unknown repetition, arm or operation')
        if r['policy_name'] != (protocol['policy_name'] if arm=='obfuscated' else 'OFF'):
            raise ValueError('Unexpected policy')
        key=(r['block'],int(r['txn_index']))
        if key in keys:
            raise ValueError('Duplicate primary transaction')
        keys.add(key)
        counts[rep,arm,op]+=1
        blocks.setdefault((rep,arm),set()).add(r['block'])
    required=allowed if complete else set(protocol['training_repetitions'])
    for rep in required:
        for arm in ('native','obfuscated'):
            if len(blocks.get((rep,arm),set()))!=1 or any(counts[rep,arm,op]!=protocol['count_per_operation'] for op in base.a.CLASSES):
                raise ValueError('Incomplete required paired repetition: '+str((rep,arm)))
    if complete and len(rows)!=protocol['primary_exchanges']:
        raise ValueError('Unexpected total exchange count')


def load(measurements, transactions, protocol_path, complete=False):
    protocol=json.loads(Path(protocol_path).read_text())
    if protocol != focused_campaign.protocol():
        raise ValueError('Unrecognized focused protocol')
    directory=Path(protocol_path).parent
    frozen=json.loads((directory/'frozen_inputs.json').read_text())
    for name,expected in frozen.items():
        if sha(directory/name)!=expected:
            raise ValueError('Changed frozen input: '+name)
    doc=json.loads(Path(measurements).read_text())
    if doc['status'] not in ('partial','ok') or (complete and doc['status']!='ok'):
        raise ValueError('Scoring requires completed and restored acquisition')
    if Path(doc['run_dir']).resolve()!=directory.resolve():
        raise ValueError('Measurement summary belongs to another run')
    if doc['primary_csv_sha256']!=sha(transactions):
        raise ValueError('Measurement/CSV hash mismatch')
    rows=base.read_rows(transactions)
    if len(rows)!=doc['row_count']:
        raise ValueError('Row count differs from measurement summary')
    validate_rows(rows,protocol,complete)
    plan=json.loads((directory/'plans'/(protocol['policy_name']+'.json')).read_text())
    return rows,protocol,levels_attack.policy_levels(plan)


def project(rows, representation, levels):
    result=[]
    for row in rows:
        # Replicate and class are grouping/target metadata, never feature columns.
        r={k:row[k] for k in ('session','block','arm','txn_class','txn_index')}
        r['session']=str(int(row['replicate']))
        for key in ('ack_ms','clrt_ms','rt_ms','request_gap_ms'):
            r[key]=row.get(key)
        if representation=='levels':
            r=levels_attack.project(r,levels)
        result.append(r)
    return result


def jobs(protocol):
    result=[]
    for task,classes in protocol['tasks'].items():
        for pool in protocol['pools']:
            for model in protocol['models']:
                for representation,arms,features in (
                    ('raw',('native','obfuscated'),protocol['features']),
                    ('levels',('obfuscated',),('clrt','ack_clrt'))):
                    for arm in arms:
                        for feature in features:
                            key='_'.join((task,str(pool),model,representation,arm,feature))
                            result.append(dict(key=key,task=task,classes=classes,pool=pool,
                                model=model,representation=representation,training_arm=arm,feature=feature))
    return result


def pooled(rows, spec, levels, arm):
    selected=[r for r in rows if r['arm']==arm and r['txn_class'] in spec['classes']]
    return base.a.pooled_rows(project(selected,spec['representation'],levels),spec['pool'])


def fit_one(spec, training, levels, directory, provenance):
    directory=Path(directory);path=directory/(spec['key']+'.pkl');meta=directory/(spec['key']+'.json')
    if meta.exists() and path.exists():
        old=json.loads(meta.read_text())
        if old.get('provenance')==provenance and old.get('spec')==spec and old.get('model_sha256')==sha(path):
            return old
        raise ValueError('Refusing stale model cache: '+spec['key'])
    rows=pooled(training,spec,levels,spec['training_arm'])
    estimator=base.a._model(spec['model'])
    if spec['model']=='rf':
        estimator.set_params(randomforestclassifier__n_jobs=1)
    search=GridSearchCV(estimator,base.PARAMS[spec['model']],scoring='balanced_accuracy',
        cv=GroupKFold(n_splits=5),n_jobs=1,refit=True,error_score='raise')
    search.fit(base.a._pooled_feature_matrix(rows,spec['feature']),
        [r['txn_class'] for r in rows],groups=[r['session'] for r in rows])
    directory.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix('.tmp')
    temporary.write_bytes(pickle.dumps(search.best_estimator_,protocol=4));temporary.replace(path)
    record=dict(spec=spec,provenance=provenance,model_sha256=sha(path),
        chosen_params=search.best_params_,training_signatures=len(rows),
        training_groups=sorted({r['session'] for r in rows},key=int))
    base.save(meta,record)
    return record


def train(rows, protocol, levels, directory, workers=8):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    training=split_rows(rows,protocol,'training')
    # The cache fingerprint deliberately depends only on training data.
    provenance=dict(training_sha256=digest(training),protocol_sha256=digest(protocol),
                    code_sha256=code_digest(),sklearn_version=base.sklearn.__version__)
    records=[]
    with ProcessPoolExecutor(max_workers=workers) as executor:
        pending=[executor.submit(fit_one,spec,training,levels,directory,provenance) for spec in jobs(protocol)]
        for future in as_completed(pending):
            record=future.result();records.append(record)
            print('FITTED',record['spec']['key'],flush=True)
    manifest=dict(provenance=provenance,models=sorted(records,key=lambda r:r['spec']['key']),
        note='All model selection used only repetitions 0–39; no held-out predictions used for fitting.')
    base.save(directory/'models.json',manifest)
    return manifest


def score_one(record, test, levels, directory, out):
    spec=record['spec'];path=Path(directory)/(spec['key']+'.pkl')
    if sha(path)!=record['model_sha256']:
        raise ValueError('Model artifact changed')
    # Only locally generated, hash-verified model files are loaded.
    estimator=pickle.loads(path.read_bytes())
    scenarios=[('fixed_on_native','native'),('fixed_on_obfuscated','obfuscated')] if spec['training_arm']=='native' else [
        ('adaptive_on_offset_residuals' if spec['representation']=='levels' else 'adaptive_on_obfuscated','obfuscated')]
    results=[];out=Path(out);out.mkdir(parents=True,exist_ok=True)
    for scenario,arm in scenarios:
        rows=pooled(test,spec,levels,arm)
        true=[r['txn_class'] for r in rows]
        pred=estimator.predict(base.a._pooled_feature_matrix(rows,spec['feature']))
        groups=sorted({r['session'] for r in rows},key=int)
        scores=[]
        for group in groups:
            ids=[i for i,r in enumerate(rows) if r['session']==group]
            scores.append(float(balanced_accuracy_score([true[i] for i in ids],pred[ids])))
        predictions=out/(spec['key']+'_'+scenario+'.jsonl.gz')
        with gzip.open(predictions,'wt') as stream:
            for r,y in zip(rows,pred):
                stream.write(json.dumps(dict(group=r['session'],block=r['block'],
                    txn_index=r.get('txn_index'),pool_start=r.get('pool_start'),
                    actual=r['txn_class'],predicted=str(y)))+'\n')
        results.append(dict(model=spec['model'],feature=spec['feature'],pool=spec['pool'],
            task=spec['task'],representation=spec['representation'],scenario=scenario,
            groups=groups,fold_scores=scores,mean_accuracy=float(balanced_accuracy_score(true,pred)),
            confusion_matrix=confusion_matrix(true,pred,labels=spec['classes']).tolist(),
            class_order=spec['classes'],per_class_recall=recall_score(true,pred,labels=spec['classes'],average=None,zero_division=0).tolist(),
            n_test_signatures=len(rows),predictions=str(predictions),predictions_sha256=sha(predictions)))
    return results


def score(rows, protocol, levels, directory, out, workers=8):
    validate_rows(rows,protocol,complete=True)
    directory=Path(directory);out=Path(out)
    manifest=json.loads((directory/'models.json').read_text())
    expected=dict(training_sha256=digest(split_rows(rows,protocol,'training')),
        protocol_sha256=digest(protocol),code_sha256=code_digest(),sklearn_version=base.sklearn.__version__)
    if manifest['provenance']!=expected:
        raise ValueError('Training data, protocol, environment or code differs from frozen models')
    if sorted(r['spec']['key'] for r in manifest['models'])!=sorted(s['key'] for s in jobs(protocol)):
        raise ValueError('Incomplete model coverage')
    test=split_rows(rows,protocol,'test');records=[]
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures=[executor.submit(score_one,r,test,levels,directory,out/'predictions') for r in manifest['models']]
        for future in as_completed(futures): records.extend(future.result())
    result=dict(protocol=protocol,model_manifest_sha256=sha(directory/'models.json'),
        complete_attack_coverage=True,test_sha256=digest(test),tasks={})
    for task,classes in protocol['tasks'].items():
        subset=[r for r in records if r['task']==task]
        envelopes={}
        for family in ('ack_response','all_timing'):
            env=base.bounds([r for r in subset if r['representation']=='raw'],family)
            env['scope']='Frozen models; fresh held-out repetitions 40–99; approximate paired-block bootstrap'
            env['passes']=env['upper_bound']<=1/len(classes)+protocol['chance_margin']
            envelopes[family]=env
        env=base.bounds([r for r in subset if r['representation']=='levels'],'ack_response')
        env['scope']='Supplemental level-aware attack; separate approximate uncertainty bound'
        envelopes['level_aware']=env
        # A combined bound includes supplemental attacks without relaxing the original criterion.
        combined=base.bounds(subset,'all_timing')
        combined['scope']='All tested protected attacks, including supplemental level-aware models'
        combined['passes']=combined['upper_bound']<=1/len(classes)+protocol['chance_margin']
        envelopes['all_tested']=combined
        result['tasks'][task]=dict(chance=1/len(classes),threshold=1/len(classes)+protocol['chance_margin'],
            records=subset,envelopes=envelopes)
    result['meets_full_criterion']=all(t['envelopes']['all_tested']['passes'] for t in result['tasks'].values())
    base.save(out/'attacks_heldout.json',result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=('fit','score'),required=True)
    parser.add_argument('--measurements',type=Path,required=True)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--models',type=Path,required=True)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--jobs',type=int,default=8)
    args=parser.parse_args()
    if args.jobs<1 or (args.phase=='score' and args.out is None): parser.error('invalid jobs or missing --out')
    rows,protocol,levels=load(args.measurements,args.input,args.protocol,args.phase=='score')
    if args.phase=='fit': train(rows,protocol,levels,args.models,args.jobs)
    else: score(rows,protocol,levels,args.models,args.out,args.jobs)


if __name__=='__main__': main()
