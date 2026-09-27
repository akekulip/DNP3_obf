#!/usr/bin/env python3
"""Verify retained grid evidence and recompute scores from prediction ledgers.

Read-only with respect to hardware and existing evidence. Does not refit models or
change the frozen analysis criterion. Writes a separate audit result only.
"""
import argparse
from collections import defaultdict
import gzip
import json
from pathlib import Path

import grid_analysis as analysis

core = analysis.core
np = analysis.np


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prediction_keys(rows, record):
    """Build expected signature identities directly from the held-out CSV."""
    arm = 'native' if record['scenario'] == 'fixed_on_native' else 'obfuscated'
    groups = defaultdict(list)
    for row in rows:
        if row['arm'] == arm and row['txn_class'] in record['class_order']:
            groups[int(row['replicate']), row['block'], row['txn_class']].append(int(row['txn_index']))
    pool = int(record['pool'])
    require(pool > 0, 'Invalid prediction pool')
    expected = set()
    for key, indices in groups.items():
        require(len(indices) == len(set(indices)), 'Duplicate source transaction')
        starts = sorted(indices) if pool == 1 else range(0, len(indices)-pool+1, pool)
        expected.update(key + (start,) for start in starts)
    return expected


def audit_predictions(record, rows, rounds):
    path = Path(record['predictions'])
    require(core.sha(path) == record['predictions_sha256'], 'Changed prediction ledger')
    classes = record['class_order']
    require(len(classes) == len(set(classes)), 'Duplicate prediction class')
    index = {op:i for i,op in enumerate(classes)}
    expected = prediction_keys(rows, record)
    seen = set()
    confusion = np.zeros((len(classes), len(classes)), dtype=int)
    grouped = {rep:np.zeros_like(confusion) for rep in rounds}
    with gzip.open(path, 'rt') as stream:
        for line in stream:
            row = json.loads(line)
            rep = int(row['group'])
            require(rep in grouped and row['actual'] in index and row['predicted'] in index,
                    'Unknown held-out group or class')
            start = row['txn_index'] if record['pool'] == 1 else row['pool_start']
            key = (rep, row['block'], row['actual'], start)
            require(key in expected and key not in seen, 'Unexpected or duplicate prediction identity')
            seen.add(key)
            i,j = index[row['actual']], index[row['predicted']]
            confusion[i,j] += 1
            grouped[rep][i,j] += 1
    require(seen == expected and len(seen) == record['n_test_signatures'], 'Missing prediction signatures')
    require(confusion.tolist() == record['confusion_matrix'], 'Confusion matrix differs from predictions')
    require(all((m.sum(axis=1) > 0).all() for m in grouped.values()), 'Missing class within held-out round')
    recall = confusion.diagonal()/confusion.sum(axis=1)
    scores = [float((grouped[rep].diagonal()/grouped[rep].sum(axis=1)).mean()) for rep in rounds]
    require(list(map(int, record['groups'])) == rounds, 'Held-out round order mismatch')
    require(np.allclose(recall, record['per_class_recall'], atol=1e-12, rtol=0), 'Class recall mismatch')
    require(abs(float(recall.mean())-record['mean_accuracy']) < 1e-12, 'Balanced accuracy mismatch')
    require(np.allclose(scores, record['fold_scores'], atol=1e-12, rtol=0), 'Per-round score mismatch')
    return len(seen)


def record_key(record):
    return tuple(record[k] for k in ('task','model','representation','feature','pool','scenario'))


def audit(run, results, out):
    final = results/'final'
    measurement = final/'measurements.json'
    transactions = final/'primarytransactions.csv'
    protocol, subsets = analysis.load(run, measurement, transactions, complete=True)
    doc = json.loads(measurement.read_text())
    for path, expected in doc['inputs_sha256'].items():
        require(core.sha(Path(path)) == expected, 'Changed raw input: '+path)
    grid_path = results/'grid_attacks.json'
    grid = json.loads(grid_path.read_text())
    require(grid['protocol'] == protocol and grid['complete_attack_coverage'], 'Grid protocol or coverage mismatch')
    require(grid['measurements_sha256'] == core.sha(measurement) and
            grid['transactions_sha256'] == core.sha(transactions), 'Grid input provenance mismatch')
    require(set(grid['policy_results_sha256']) == set(subsets), 'Missing policy result')
    model_count = record_count = prediction_count = 0
    policy_results = {}
    for name, (rows, p, levels) in subsets.items():
        directory = results/name
        manifest_path = directory/'models/models.json'
        manifest = json.loads(manifest_path.read_text())
        provenance = dict(training_sha256=core.digest(core.split_rows(rows,p,'training')),
            protocol_sha256=core.digest(p),code_sha256=core.code_digest(),sklearn_version=core.base.sklearn.__version__)
        require(manifest['provenance'] == provenance, 'Model provenance mismatch: '+name)
        expected_jobs = {s['key']:s for s in core.jobs(p)}
        require(len(manifest['models']) == len(expected_jobs) and
                {m['spec']['key'] for m in manifest['models']} == set(expected_jobs), 'Incomplete model inventory')
        for model in manifest['models']:
            spec = model['spec']
            require(spec == expected_jobs[spec['key']] and model['provenance'] == provenance,
                    'Model specification/provenance mismatch')
            require(list(map(int,model['training_groups'])) == protocol['training_rounds'], 'Training/test group contamination')
            expected_count = len(protocol['training_rounds'])*len(spec['classes'])*(protocol['count_per_operation']//spec['pool'])
            require(model['training_signatures'] == expected_count, 'Training signature count mismatch')
            require(core.sha(directory/'models'/(spec['key']+'.pkl')) == model['model_sha256'], 'Changed model artifact')
            require(json.loads((directory/'models'/(spec['key']+'.json')).read_text()) == model, 'Model metadata differs from manifest')
            model_count += 1
        result_path = directory/'final/attacks_heldout.json'
        require(core.sha(result_path) == grid['policy_results_sha256'][name], 'Changed policy scoring result')
        result = json.loads(result_path.read_text())
        test = core.split_rows(rows,p,'test')
        require(result['protocol'] == p and result['test_sha256'] == core.digest(test), 'Held-out data provenance mismatch')
        require(result['model_manifest_sha256'] == core.sha(manifest_path) and result['complete_attack_coverage'],
                'Scoring model inventory mismatch')
        expected_records = set()
        for spec in expected_jobs.values():
            scenarios = ('fixed_on_native','fixed_on_obfuscated') if spec['training_arm']=='native' else (
                'adaptive_on_offset_residuals' if spec['representation']=='levels' else 'adaptive_on_obfuscated',)
            for scenario in scenarios:
                expected_records.add(record_key(dict(spec,scenario=scenario)))
        records = [r for task in result['tasks'].values() for r in task['records']]
        require(len(records) == len(expected_records) and {record_key(r) for r in records} == expected_records,
                'Incomplete or duplicate attack inventory')
        for record in records:
            require(record['class_order'] == protocol['tasks'][record['task']], 'Task class order mismatch')
            prediction_count += audit_predictions(record,test,protocol['test_rounds'])
            record_count += 1
        policy_results[name] = result
        print('AUDITED',name,flush=True)
    require(grid['primary_ack_clrt'] == analysis.joint_bounds(policy_results,protocol), 'Primary bound mismatch')
    require(grid['all_timing_diagnostic'] == analysis.joint_bounds(policy_results,protocol,'all_timing'), 'Diagnostic bound mismatch')
    result = dict(status='passed',primary_exchanges=doc['row_count'],raw_input_hashes=len(doc['inputs_sha256']),
        model_artifacts=model_count,scored_attacks=record_count,prediction_signatures=prediction_count,
        training_rounds=protocol['training_rounds'],heldout_rounds=protocol['test_rounds'],
        inputs_sha256={str(path.resolve()):core.sha(path) for path in (measurement,transactions,grid_path,Path(__file__))},
        scope='Retained input/model hashes, exact group/signature inventories, and confusion/recall/accuracy recomputed from prediction ledgers. Bounds re-evaluated with the frozen implementation; no claim of independent statistical-method validation.')
    analysis.campaign.rc.write_json(out,result)
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('run','results','out'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(audit(args.run.resolve(),args.results.resolve(),args.out.resolve()),indent=2))
