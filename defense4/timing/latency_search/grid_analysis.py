#!/usr/bin/env python3
"""Matched grid analysis with frozen training and policy-simultaneous bounds."""
import argparse
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import evaluate_focused as core
import grid_campaign as campaign
np=core.np


def policy_protocol(name,protocol):
    if name not in protocol['policy_names']:raise ValueError('Unknown grid policy')
    p=core.focused_campaign.protocol()
    p.update(policy_name=name,seed=protocol['seed'],
        training_repetitions=protocol['training_rounds'],test_repetitions=protocol['test_rounds'],
        parent_grid_protocol_sha256=core.digest(protocol),grid_analysis_sha256=core.sha(Path(__file__)))
    return p


def select_rows(rows,pairs,name):
    mapping={}
    for pair in pairs:
        if pair['policy']!=name:continue
        for field,arm in (('protected','obfuscated'),('native','native')):
            label=pair[field]
            if label in mapping:raise ValueError('Duplicate paired block')
            mapping[label]=(int(pair['round']),arm)
    selected=[]
    for row in rows:
        if row['block'] not in mapping:continue
        rep,arm=mapping[row['block']]
        if int(row['replicate'])!=rep or row['arm']!=arm:
            raise ValueError('Row contradicts frozen pair identity')
        if row['policy_name']!=(name if arm=='obfuscated' else 'OFF'):
            raise ValueError('Wrong policy in paired block')
        selected.append(row)
    return selected


def load(run,measurements,transactions,complete=False):
    prepared=campaign.load_run(run)
    protocol=campaign.rc._load_json(run/'protocol.json')
    pairs=campaign.rc._load_json(run/'pairing.json')
    doc=campaign.rc._load_json(measurements)
    if doc['status'] not in ('partial','ok') or (complete and doc['status']!='ok'):
        raise ValueError('Scoring requires complete restored grid acquisition')
    if Path(doc['run_dir']).resolve()!=run.resolve() or doc['primary_csv_sha256']!=core.sha(transactions):
        raise ValueError('Measurements belong to another run or changed CSV')
    rows=core.base.read_rows(transactions)
    if len(rows)!=doc['row_count'] or (complete and len(rows)!=protocol['primary_exchanges']):
        raise ValueError('Grid exchange count differs from protocol')
    allowed={b.label for b in prepared.schedule}
    if any(r['block'] not in allowed for r in rows):raise ValueError('Unknown acquisition block')
    subsets={}
    for name in protocol['policy_names']:
        subset=select_rows(rows,pairs,name);p=policy_protocol(name,protocol)
        core.validate_rows(subset,p,complete)
        plan=campaign.rc._load_json(run/'plans'/(name+'.json'))
        subsets[name]=(subset,p,core.levels_attack.policy_levels(plan))
    if sum(len(s[0]) for s in subsets.values())!=len(rows):raise ValueError('Rows missing or duplicated across policy pairs')
    return protocol,subsets


def joint_bounds(results,protocol,family='ack_clrt'):
    """One shared bootstrap margin over all policies/attacks, separately per task."""
    output={}
    for task,classes in protocol['tasks'].items():
        records=[]
        for name,result in results.items():
            for r in result['tasks'][task]['records']:
                if r['scenario']=='fixed_on_native':continue
                if family=='ack_clrt' and r['feature'] not in protocol['primary_features']:continue
                if list(map(int,r['groups']))!=protocol['test_rounds']:
                    raise ValueError('Missing or misordered held-out rounds')
                records.append((name,r))
        if not records:raise ValueError('No eligible attack records')
        matrix=np.array([r['fold_scores'] for _,r in records],dtype=float)
        if matrix.shape[1]!=len(protocol['test_rounds']) or not np.isfinite(matrix).all():
            raise ValueError('Invalid grouped scores')
        means=matrix.mean(axis=1)
        rng=np.random.default_rng(protocol['seed'])
        draws=rng.integers(matrix.shape[1],size=(protocol['bootstrap_resamples'],matrix.shape[1]))
        # Bounded memory even with all four policies and hundreds of attacks.
        maxima=[]
        for start in range(0,len(draws),250):
            maxima.extend((matrix[:,draws[start:start+250]].mean(axis=2)-means[:,None]).max(axis=0).tolist())
        margin=max(0.,float(np.quantile(maxima,protocol['confidence_per_task'])))
        per_policy={}
        for name in protocol['policy_names']:
            ids=[i for i,(n,_) in enumerate(records) if n==name]
            if not ids:raise ValueError('Policy missing from simultaneous comparison')
            best=max(ids,key=lambda i:means[i]);r=records[best][1]
            upper=min(1.,float(means[best])+margin)
            per_policy[name]=dict(max_accuracy=float(means[best]),upper_bound=upper,
                passes=upper<=1/len(classes)+protocol['chance_margin'],
                strongest_attack={k:r[k] for k in ('scenario','model','feature','pool')})
        output[task]=dict(chance=1/len(classes),threshold=1/len(classes)+protocol['chance_margin'],
            confidence_per_task=protocol['confidence_per_task'],shared_margin=margin,
            n_rounds=matrix.shape[1],n_policy_attack_comparisons=len(records),per_policy=per_policy)
    return output


def rank_policies(bounds,latencies):
    names=list(next(iter(bounds.values()))['per_policy'])
    passing=[n for n in names if all(t['per_policy'][n]['passes'] for t in bounds.values())]
    passing.sort(key=lambda n:(latencies[n]['worst_added_median_ms'],latencies[n]['worst_p99_ms'],latencies[n]['center_da_ms']))
    return dict(passing_policies=passing,selected_policy=passing[0] if passing else None,
        scope='Lowest overhead among these four tested policies; not a global minimum or universal attacker guarantee')


def fit(run,measurements,transactions,out,workers=8):
    protocol,subsets=load(run,measurements,transactions)
    for name,(rows,p,levels) in subsets.items():
        print('FIT POLICY',name,flush=True)
        core.train(rows,p,levels,out/name/'models',workers)
    campaign.rc.write_json(out/'training_complete.json',dict(policies=list(subsets),
        grid_protocol_sha256=core.digest(protocol),grid_analysis_sha256=core.sha(Path(__file__))))


def score(run,measurements,transactions,out,workers=8):
    protocol,subsets=load(run,measurements,transactions,True)
    results={}
    for name,(rows,p,levels) in subsets.items():
        print('SCORE POLICY',name,flush=True)
        results[name]=core.score(rows,p,levels,out/name/'models',out/name/'final',workers)
    result=dict(protocol=protocol,complete_attack_coverage=True,
        measurements_sha256=core.sha(measurements),transactions_sha256=core.sha(transactions),
        policy_results_sha256={n:core.sha(out/n/'final/attacks_heldout.json') for n in results},
        primary_ack_clrt=joint_bounds(results,protocol,'ack_clrt'),
        all_timing_diagnostic=joint_bounds(results,protocol,'all_timing'),
        note='Primary criterion includes level-aware attacks and simultaneous comparison of all four policies. Cadence features remain a separate diagnostic; policy selection uses measured latency in grid_report.json.')
    campaign.rc.write_json(out/'grid_attacks.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase',choices=('fit','score'),required=True)
    for name in ('run','measurements','input','out'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--jobs',type=int,default=8)
    a=p.parse_args()
    if a.jobs<1:p.error('jobs must be positive')
    (fit if a.phase=='fit' else score)(a.run,a.measurements,a.input,a.out,a.jobs)
