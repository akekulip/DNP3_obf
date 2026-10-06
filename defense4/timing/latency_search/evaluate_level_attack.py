#!/usr/bin/env python3
"""Exploratory adaptive attack that subtracts the nearest public timing level.

Hardware selections are used only to audit inference accuracy, never as model
features. This diagnostic supplements rather than replaces the frozen screen.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import json
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evaluate as base
import numpy as np


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def nearest(value, levels):
    return min(levels, key=lambda level:(abs(value-level), level))


def policy_levels(plan):
    return {key: sorted({float(entry[key]) for entry in plan['entries']})
            for key in ('da_ms', 'gap_ms')}


def project(row, levels):
    # Explicit whitelist keeps telemetry and the true selected offsets out of
    # both the model and pooling code. Labels are used only by supervised training
    # and the pre-existing known-same-operation pooling procedure.
    result = {key:row[key] for key in ('session','block','arm','txn_class','txn_index')}
    for metric, key in (('ack_ms','da_ms'), ('clrt_ms','gap_ms')):
        value = float(row[metric])
        if not np.isfinite(value):
            raise ValueError('nonfinite observed timing')
        result[metric] = value-nearest(value, levels[key])
    return result


def inference_audit(rows, levels):
    result = {}
    for metric, truth, key in (('ack_ms','selected_da_ms','da_ms'),
                                ('clrt_ms','selected_gap_ms','gap_ms')):
        error = [abs(nearest(float(row[metric]), levels[key])-float(row[truth])) for row in rows]
        result[metric] = dict(n=len(error), distinct_levels=len(levels[key]),
            selection_agreement_within_1us=float(np.mean(np.asarray(error)<=.001)))
    return result


def evaluate_policy(rows, name, levels):
    rows = [project(row, levels) for row in rows]
    groups = sorted({row['session'] for row in rows})
    if len(groups) != 5:
        raise ValueError('requires all five protected repetitions')
    for group in groups:
        if [sum(r['session']==group and r['txn_class']==op for r in rows)
            for op in base.a.CLASSES] != [100,100,100]:
            raise ValueError('incomplete protected repetition')
    result = dict(policy=name, tasks={})
    for task, classes in (('three_class',base.a.CLASSES),('read_select',base.a.BINARY_CLASSES)):
        records = []
        for pool in (1,5,20):
            pooled = base.a.pooled_rows([r for r in rows if r['txn_class'] in classes],pool)
            for feature in ('clrt','ack_clrt'):
                for model in base.PARAMS:
                    scores, tuning = [], []
                    for group in groups:
                        train = [r for r in pooled if r['session'] != group]
                        test = [r for r in pooled if r['session'] == group]
                        estimator, setting = base.train(model,train,feature,True)
                        scores.append(base.score(estimator,test,feature))
                        tuning.append(dict(held_out=group,params=setting))
                    records.append(dict(model=model,feature=feature,pool=pool,
                        scenario='adaptive_on_offset_residuals',fold_scores=scores,
                        mean_accuracy=float(np.mean(scores)),groups=groups,tuning=tuning))
        result['tasks'][task] = dict(chance=1/len(classes),records=records,
            envelope=base.bounds(records,'ack_response'))
    return result


def cached_evaluate(rows, name, levels, cache_key, cache):
    path = cache/(name+'.json')
    old = json.loads(path.read_text()) if path.exists() else {}
    if old.get('cache_key') == cache_key:
        return old['result']
    result = evaluate_policy(rows,name,levels)
    base.save(path,dict(cache_key=cache_key,result=result))
    return result


def load(measurements, transactions, inspect_only):
    doc = json.loads(measurements.read_text())
    if doc.get('status') not in ('ok','partial') or (doc['status'] != 'ok' and not inspect_only):
        raise ValueError('classifier evaluation requires completed acquisition')
    if doc.get('primary_csv_sha256') != sha(transactions):
        raise ValueError('transaction hash mismatch')
    raw = base.read_rows(transactions)
    if len(raw) != doc['row_count']:
        raise ValueError('row count mismatch')
    policies = {}
    for name in sorted({r['policy_name'] for r in raw if r['arm']=='obfuscated'}):
        paths = [Path(p) for p in doc['inputs_sha256']
                 if Path(p).parent.name == 'plans' and Path(p).stem == name]
        if len(paths) != 1 or sha(paths[0]) != doc['inputs_sha256'][str(paths[0])]:
            raise ValueError('missing or changed validated plan: '+name)
        plan = json.loads(paths[0].read_text())
        rows = [r for r in raw if r['arm']=='obfuscated' and r['policy_name']==name]
        policies[name] = (rows,policy_levels(plan),sha(paths[0]))
    if not policies:
        raise ValueError('no protected policies')
    return doc, policies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--measurements',type=Path,required=True)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--inspect-only',action='store_true')
    parser.add_argument('--jobs',type=int,default=12)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    doc, policies = load(args.measurements,args.input,args.inspect_only)
    code_sha = hashlib.sha256(b''.join(p.read_bytes() for p in
        (Path(__file__),HERE/'evaluate.py',HERE/'analysis.py'))).hexdigest()
    result = dict(source_sha256=sha(args.input),measurements_sha256=sha(args.measurements),
        code_sha256=code_sha,sklearn_version=base.sklearn.__version__,summary_status=doc['status'],
        exploratory=True,inspect_only=args.inspect_only,complete_attack_coverage=False,
        tuning_grid=base.PARAMS,
        feature_transform='observed ACK or CLRT minus nearest public policy offset; lower-value tie break',
        attacker_knowledge='configured offset levels; no per-request digest or true selected offset',
        scope='additional diagnostic, not the preregistered acceptance test',
        selection_audit={},per_policy={})
    for name,(rows,levels,plan_sha) in policies.items():
        result['selection_audit'][name] = dict(plan_sha256=plan_sha,levels=levels,
                                               **inference_audit(rows,levels))
    if args.inspect_only:
        base.save(args.out,result)
        print('INSPECTED',len(policies),'policies; no classifier evaluation')
        return
    key = {k:result[k] for k in ('source_sha256','measurements_sha256','code_sha256','sklearn_version')}
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {executor.submit(cached_evaluate,rows,name,levels,dict(key,plan_sha256=plan_sha),
                    args.out.parent/'attack_cache_levels'):name
                   for name,(rows,levels,plan_sha) in policies.items()}
        for future in as_completed(futures):
            name = futures[future]
            result['per_policy'][name] = future.result()
            result['complete_attack_coverage'] = len(result['per_policy']) == len(policies)
            base.save(args.out,result)
            print('DONE',name,{k:round(v['envelope']['max_accuracy'],3)
                  for k,v in result['per_policy'][name]['tasks'].items()},flush=True)


if __name__=='__main__':
    main()
