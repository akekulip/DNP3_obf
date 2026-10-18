"""Locked, portable publication estimators. No hardware calls or implicit fitting.

Manifest/CSV contract is documented in task-3-report.md. All numerical features
are observed values; missing features are excluded per estimator and accounted.
The explicit fixture APIs produce analysis-only artifacts, never main claims.
"""
import csv
import hashlib
import json
import math
import platform
import importlib.metadata
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB

SCHEMA_VERSION = 1
ARMS = ('off', 'timing_only', 'size_only', 'combined')
CLASSES = ('READ', 'SELECT', 'OPERATE')
CONDITIONS = (('D05_J2p4', 5., 2.4), ('D10_J2p4', 10., 2.4),
              ('D15_J2p4', 15., 2.4), ('D20_J2p4', 20., 2.4),
              ('D10_J5', 10., 5.), ('D10_J10', 10., 10.),
              ('D10_J15', 10., 15.), ('D10_J20', 10., 20.))
RF_SETTINGS = dict(n_estimators=200, min_samples_leaf=5, class_weight='balanced', random_state=0)
FEATURES = {'clrt': ('clrt_ms',), 'ack_clrt': ('ack_ms', 'clrt_ms'),
            'size': ('resp_len',), 'joint': ('ack_ms', 'clrt_ms', 'resp_len')}
METADATA_FEATURES = ('request_len', 'response_len', 'request_packets',
                     'response_packets', 'request_duration_ms', 'response_duration_ms',
                     'out_request_packet_count', 'out_response_packet_count',
                     'in_request_packet_count', 'in_response_packet_count',
                     'out_payload_packet_count', 'in_payload_packet_count',
                     'ack_ms', 'clrt_ms', 'rt_ms')
ALLOWED_FEATURES = frozenset(sum(FEATURES.values(), ()) + METADATA_FEATURES)
NUMERICAL = ALLOWED_FEATURES | {'rt_ms', 'observed_at_ms', 'internal_bytes',
             'timestamp_precision_ns', 'loss', 'fallback', 'realized_j_ms', 'correct'}
SEED = 20260828


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def safe_path(root, relative):
    root = Path(root).resolve()
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('artifact path must be safe and relative')
    path = (root / relative).resolve()
    if root not in path.parents:
        raise ValueError('artifact escapes release directory')
    return path


def read_json(path):
    return json.loads(Path(path).read_text(), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n')


def load_rows(path):
    with open(path, newline='') as handle:
        raw = list(csv.DictReader(handle))
    result = []
    for source in raw:
        row = dict(source)
        row['example_id'] = row.get('example_id') or row.get('exchange_id')
        row['condition_id'] = row.get('condition_id') or row.get('condition')
        for field in NUMERICAL:
            value = row.get(field)
            row[field] = None if value in ('', None, 'null') else float(value)
            if row[field] is not None and not math.isfinite(row[field]):
                raise ValueError('nonfinite observed metric '+field)
        for field in ('round', 'sequence'):
            row[field] = None if row.get(field) in ('', None) else int(row[field])
        for field in ('connection_id','session_id','trial'):
            row[field] = None if row.get(field) in ('',None) else row[field]
        result.append(row)
    return result


def feature_matrix(rows, fields):
    if not fields or any(field not in ALLOWED_FEATURES for field in fields):
        raise ValueError('forbidden or empty feature selection')
    used, matrix, missing = [], [], Counter()
    for index, row in enumerate(rows):
        absent = [field for field in fields if row.get(field) is None]
        missing.update(absent)
        if absent:
            continue
        values = [float(row[field]) for field in fields]
        invalid = [field+'_invalid' for field,value in zip(fields,values) if not math.isfinite(value) or value < 0]
        if invalid:
            missing.update(invalid)
            continue
        used.append(index)
        matrix.append(values)
    return np.asarray(matrix, dtype=float).reshape((-1, len(fields))), used, dict(missing)


def histogram(values, high):
    if high < .001 or not math.isfinite(high):
        raise ValueError('histogram H must be finite and >=1us (0.001ms)')
    values = np.asarray(values, dtype=float)
    if not np.isfinite(values).all() or np.any(values < 0):
        raise ValueError('invalid CLRT')
    # 199 regular half-open bins and one overflow bin, including x == H.
    indices = np.minimum(np.floor(values / high * 199), 199).astype(int)
    return np.bincount(indices, minlength=200)


def make_windows(rows, k):
    if k not in (8, 32, 64):
        raise ValueError('unsupported observation window size')
    groups = defaultdict(list)
    accounting = dict(input=len(rows), missing=0, rejected=0, leftover=0, used=0)
    fields=('condition_id','arm','operation','block_id','round','connection_id','session_id','split')
    uncertain=[]
    for row in rows:
        key=tuple(row.get(field) for field in fields)
        if any(value in (None,'') for value in key) or row.get('sequence') is None:
            # Without boundary/order evidence the barrier cannot be positioned.
            # Reject every compatible known group rather than silently bridging it.
            uncertain.append(key)
            accounting['rejected']+=1
            continue
        groups[key].append(row)
    windows = []
    for key in sorted(groups, key=str):
        if any(all(value in (None,'') or value==actual for value,actual in zip(pattern,key)) for pattern in uncertain):
            accounting['rejected']+=len(groups[key])
            continue
        ordered = sorted(groups[key], key=lambda r: r['sequence'])
        if len({r['sequence'] for r in ordered}) != len(ordered):
            accounting['rejected'] += len(ordered)
            continue
        pending = []
        last_time = None
        for row in ordered:
            value = row.get('clrt_ms')
            timestamp=row.get('observed_at_ms')
            missing=value is None or timestamp is None
            invalid=(not missing and (not math.isfinite(value) or value<0 or not math.isfinite(timestamp) or timestamp<0))
            if missing or invalid:
                accounting['leftover'] += len(pending)
                pending = []
                accounting['missing' if missing else 'rejected'] += 1
                last_time = None
                continue
            if last_time is not None and row['observed_at_ms'] < last_time:
                accounting['leftover'] += len(pending)
                pending = []
                accounting['rejected'] += 1
                last_time = None
                continue
            last_time = row['observed_at_ms']
            pending.append(row)
            if len(pending) == k:
                values = [r['clrt_ms'] for r in pending]
                item = {field: pending[0][field] for field in ('condition_id', 'arm', 'operation',
                        'round', 'split', 'block_id', 'connection_id', 'session_id')}
                item.update(window_id=digest([r['example_id'] for r in pending]), k=k,
                    member_ids=[r['example_id'] for r in pending], values=values,
                    elapsed_ms=pending[-1]['observed_at_ms']-pending[0]['observed_at_ms'],
                    mean_ms=float(np.mean(values)), variance_ms2=float(np.var(values, ddof=1)),
                    scope='oracle-assisted operation-grouped; no device-class claim')
                windows.append(item)
                accounting['used'] += k
                pending = []
        accounting['leftover'] += len(pending)
    return windows, accounting


def training_fingerprint(rows):
    return digest(sorted(rows, key=lambda row: row['example_id']))


def _freeze_rf(model):
    trees = []
    for tree in model.estimators_:
        t = tree.tree_
        value = t.value[:, 0, :]
        value = value / value.sum(axis=1, keepdims=True)
        trees.append(dict(left=t.children_left.tolist(), right=t.children_right.tolist(),
                          feature=t.feature.tolist(), threshold=t.threshold.tolist(), value=value.tolist()))
    return dict(kind='RF', classes=model.classes_.tolist(), settings=RF_SETTINGS, trees=trees)


def frozen_probabilities(model, matrix):
    # sklearn's forest prediction converts inputs to float32 before comparisons.
    matrix = np.asarray(matrix, dtype=np.float32 if model['kind']=='RF' else float)
    if not len(matrix):
        return np.empty((0, len(model['classes'])))
    if model['kind'] == 'RF':
        result = np.zeros((len(matrix), len(model['classes'])))
        for tree in model['trees']:
            nodes = np.zeros(len(matrix), dtype=int)
            active = np.ones(len(matrix), dtype=bool)
            left, right = np.array(tree['left']), np.array(tree['right'])
            features, thresholds = np.array(tree['feature']), np.array(tree['threshold'])
            while active.any():
                idx = np.flatnonzero(active)
                leaves = left[nodes[idx]] == -1
                active[idx[leaves]] = False
                idx = idx[~leaves]
                if len(idx):
                    n = nodes[idx]
                    nodes[idx] = np.where(matrix[idx, features[n]] <= thresholds[n], left[n], right[n])
            result += np.asarray(tree['value'])[nodes]
        return result / len(model['trees'])
    scores = matrix @ np.asarray(model['feature_log_prob']).T + np.asarray(model['class_log_prior'])
    scores -= scores.max(axis=1, keepdims=True)
    result = np.exp(scores)
    return result / result.sum(axis=1, keepdims=True)


def fit_models(rows):
    if not rows or any(r['split'] != 'training' or r['round'] not in range(1, 9) for r in rows):
        raise ValueError('fit accepts training rounds1..8 only')
    lock = dict(schema_version=1, training_sha256=training_fingerprint(rows),
                training_ids=sorted(r['example_id'] for r in rows), fit_max_round=max(r['round'] for r in rows),
                settings=dict(RF=RF_SETTINGS, NB=dict(alpha=1.), bootstrap_seed=SEED),
                fit_environment=dict(python=platform.python_version(),numpy=importlib.metadata.version('numpy'),
                                     sklearn=importlib.metadata.version('scikit-learn')),
                models=[], unavailable=[])
    for condition in sorted({r['condition_id'] for r in rows}):
        for train_arm in ARMS:
            subset = [r for r in rows if r['condition_id'] == condition and r['arm'] == train_arm]
            diagnostic = tuple(field for field in METADATA_FEATURES if any(r.get(field) is not None for r in subset))
            for name, fields in list(FEATURES.items()) + [('metadata_diagnostic', diagnostic)]:
                identity = dict(condition_id=condition, train_arm=train_arm, feature=name, fields=list(fields))
                if not fields:
                    lock['unavailable'].append(dict(identity,reason='no observed training diagnostic fields'))
                    continue
                matrix, used, missing = feature_matrix(subset, fields)
                if {subset[i]['operation'] for i in used} != set(CLASSES):
                    lock['unavailable'].append(dict(identity, reason='missing training class/observed features', missing=missing))
                    continue
                model = RandomForestClassifier(**RF_SETTINGS).fit(matrix, [subset[i]['operation'] for i in used])
                lock['models'].append(dict(identity, estimator=_freeze_rf(model),
                   training_ids=[subset[i]['example_id'] for i in used], missing=missing))
            valid = [r['clrt_ms'] for r in subset if r.get('clrt_ms') is not None and r['clrt_ms']>=0]
            high = max(.001, 1.05*max(valid)) if valid else .001
            for k in (8, 32, 64):
                windows, accounting = make_windows(subset, k)
                identity = dict(condition_id=condition, train_arm=train_arm, feature='nb', k=k, high_ms=high,
                    edges_ms=np.linspace(0.,high,200).tolist(),
                    binning='199 equal half-open bins [0,H); bin199 overflow [H,infinity); x==H overflow; units ms')
                if {w['operation'] for w in windows} != set(CLASSES):
                    lock['unavailable'].append(dict(identity, reason='missing training window class', accounting=accounting))
                    continue
                matrix = np.array([histogram(w['values'], high) for w in windows])
                model = MultinomialNB(alpha=1.).fit(matrix, [w['operation'] for w in windows])
                estimator = dict(kind='NB', classes=model.classes_.tolist(), alpha=1.,
                    feature_log_prob=model.feature_log_prob_.tolist(), class_log_prior=model.class_log_prior_.tolist())
                lock['models'].append(dict(identity, estimator=estimator, training_windows=[w['member_ids'] for w in windows],
                                            accounting=accounting, training_bin_counts=matrix.sum(axis=0).tolist(),
                                            training_overflow=int(matrix[:, 199].sum())))
    return lock


def verify_training_lock(rows, lock):
    training = [r for r in rows if r['split'] == 'training']
    if lock.get('schema_version') != 1 or lock.get('fit_max_round', 99) > 8 or any(r['round'] > 8 for r in training):
        raise ValueError('invalid training-only lock')
    if lock['training_sha256'] != training_fingerprint(training) or lock['training_ids'] != sorted(r['example_id'] for r in training):
        raise ValueError('training membership/values changed after lock')
    if lock.get('settings') != dict(RF=RF_SETTINGS,NB=dict(alpha=1.),bootstrap_seed=SEED):
        raise ValueError('frozen estimator settings differ from protocol')
    training_ids = set(lock['training_ids'])
    for model in lock['models']:
        if model['feature']!='nb' and (not model.get('fields') or any(f not in ALLOWED_FEATURES for f in model['fields'])):
            raise ValueError('forbidden frozen feature selection')
        ids = model.get('training_ids', sum(model.get('training_windows', []), []))
        if not set(ids) <= training_ids:
            raise ValueError('model fit membership contains held-out observations')
    return True


def predict_models(rows, lock):
    predictions = []
    for record in lock['models']:
        arms = ARMS if record['train_arm'] == 'off' else (record['train_arm'],)
        for arm in arms:
            subset = [r for r in rows if r['condition_id'] == record['condition_id'] and r['arm'] == arm]
            if record['feature'] == 'nb':
                examples, _ = make_windows(subset, record['k'])
                matrix = np.asarray([histogram(w['values'], record['high_ms']) for w in examples])
            else:
                matrix, used, _ = feature_matrix(subset, record['fields'])
                examples = [subset[i] for i in used]
            probabilities = frozen_probabilities(record['estimator'], matrix)
            classes = record['estimator']['classes']
            # Native own-arm model supplies both identical fixed and adaptive baselines.
            attackers = ('fixed', 'adaptive') if record['train_arm'] == 'off' and arm == 'off' else (
                ('fixed',) if record['train_arm'] == 'off' else ('adaptive',))
            for attacker in attackers:
                for index, (row, probability) in enumerate(zip(examples, probabilities)):
                    item = dict(condition_id=row['condition_id'], arm=arm, attacker=attacker,
                        feature=record['feature'], k=record.get('k'), round=row['round'], block_id=row['block_id'],
                        example_id=row.get('example_id', row.get('window_id')), truth=row['operation'],
                        prediction=classes[int(np.argmax(probability))],
                        probabilities={c: float(p) for c, p in zip(classes, probability)})
                    if 'member_ids' in row:
                        item.update(member_ids=row['member_ids'], elapsed_ms=row['elapsed_ms'])
                    if record['feature'] == 'nb':
                        # the window's histogram under this attacker's own edges, overflow kept (review A5)
                        item.update(bin_counts=matrix[index].tolist(), overflow=int(matrix[index][199]))
                    predictions.append(item)
    return predictions


def confusion_scores(rows):
    cm = np.zeros((3, 3), dtype=int)
    for row in rows:
        cm[CLASSES.index(row['truth']), CLASSES.index(row['prediction'])] += 1
    support = cm.sum(axis=1)
    recall = np.divide(np.diag(cm), support, out=np.zeros(3), where=support != 0)
    denom = support + cm.sum(axis=0)
    f1 = np.divide(2*np.diag(cm), denom, out=np.zeros(3), where=denom != 0)
    return dict(confusion=cm.tolist(), support=support.tolist(), n=int(support.sum()),
                balanced_accuracy=float(recall.mean()) if (support > 0).all() else None,
                macro_f1=float(f1.mean()) if (support > 0).all() else None)


def paired_bootstrap(native, defended, n_resamples=10000, seed=SEED):
    expected = set(range(9, 17))
    if set(native) != expected or set(defended) != expected:
        raise ValueError('paired inference requires all eight independent test round blocks')
    differences = np.array([native[r]-defended[r] for r in sorted(expected)])
    rng = np.random.default_rng(seed)
    sampled = differences[rng.integers(0, 8, size=(n_resamples, 8))].mean(axis=1)
    low, high = np.quantile(sampled, [.025, .975])
    return dict(estimate=float(differences.mean()), lower=float(low), upper=float(high),
                resamples=n_resamples, seed=seed, blocks=8,
                interpretation='conditional95% paired round-block bootstrap; secondary intervals pointwise; no near-chance guarantee')


def summarize_predictions(predictions):
    grouped = defaultdict(list)
    # Missing fits and missing held-out observations remain visible table rows.
    for condition,_,_ in CONDITIONS:
        for attacker in ('fixed','adaptive'):
            for feature,k in [(name,None) for name in list(FEATURES)+['metadata_diagnostic']]+[('nb',k) for k in (8,32,64)]:
                for arm in ARMS:
                    grouped[condition,attacker,feature,k,arm]
    for row in predictions:
        grouped[tuple(row.get(f) for f in ('condition_id','attacker','feature','k','arm'))].append(row)
    summaries, blocks = [], {}
    for key, rows in sorted(grouped.items(), key=str):
        condition, attacker, feature, k, arm = key
        value = dict(condition_id=condition, attacker=attacker, feature=feature, k=k, arm=arm,
                     **confusion_scores(rows))
        value['unavailable_reason'] = None if rows else 'no eligible frozen fit or complete observed test examples'
        by_round = {r: confusion_scores([x for x in rows if x['round'] == r]) for r in range(9,17)}
        value['round_support'] = {str(r): v['support'] for r,v in by_round.items()}
        blocks[key] = by_round
        summaries.append(value)
    comparisons = []
    for key, by_round in blocks.items():
        condition, attacker, feature, k, arm = key
        if arm == 'off':
            continue
        native = blocks.get((condition, attacker, feature, k, 'off'), {})
        value = dict(condition_id=condition, attacker=attacker, feature=feature, k=k, arm=arm,
                     primary=(condition=='D10_J2p4' and attacker=='fixed' and feature=='joint' and arm=='combined'))
        value['intervals'] = {}
        for metric in ('balanced_accuracy','macro_f1'):
            a = {r:s[metric] for r,s in native.items() if s[metric] is not None}
            b = {r:s[metric] for r,s in by_round.items() if s[metric] is not None}
            try:
                value['intervals'][metric] = paired_bootstrap(a,b)
            except ValueError:
                value['intervals'][metric] = dict(unavailable='missing classes/paired round support', native_rounds=sorted(a), defended_rounds=sorted(b))
        native_rows = grouped.get((condition,attacker,feature,k,'off'),[])
        baseline = confusion_scores(native_rows)['balanced_accuracy']
        value['native_competent_descriptive'] = baseline is not None and baseline > 1/3+.05
        comparisons.append(value)
    return summaries, comparisons


def validate_ledger_rows(root, artifacts, ledger, rows):
    """Bind analysis labels, window membership and costs to immutable raw evidence.

    Called by main hardware validation after its full artifact/hash checks.
    Internal-byte values are optional trial averages, never operation samples.
    No evidence format for the other four optional costs is currently supported;
    those columns must remain null rather than trusting CSV assertions.
    """
    captured=[r for r in ledger['records'] if r.get('record_type')=='captured_exchange']
    observed={r['exchange_id']:r for r in captured}
    if len(observed)!=len(captured) or set(observed)!=set(r['example_id'] for r in rows):
        raise ValueError('analysis rows differ from audited attempted-exchange ledger')
    capture_hashes={a['sha256'] for a in artifacts if a['kind']=='capture'}
    trials=defaultdict(list)
    for original in captured:
        trials[original.get('trial')].append(original)
    trial_costs={}
    for row in rows:
        original=observed[row['example_id']]
        if (original.get('capture_out_sha256') not in capture_hashes
                or original.get('capture_in_sha256') not in capture_hashes
                or row['operation']!=original.get('txn_class')
                or row['arm']!=('off' if original.get('arm')=='baseline' else original.get('arm'))):
            raise ValueError('analysis identity/capture binding differs from hardware ledger')
        expected={field:original.get(field) for field in ALLOWED_FEATURES | {
            'observed_at_ms','connection_id','session_id','sequence','trial','block_id','round','split'}}
        expected['condition_id']=original.get('condition_id',original.get('condition'))
        for metric,source in (('ack_ms','ack_latency_ns'),('clrt_ms','clrt_ns'),('rt_ms','response_latency_ns'),
                              ('realized_j_ms','operate_hold_ns')):
            ns=original.get(source)
            expected[metric]=None if ns is None else ns/1000000.
        for field,value in expected.items():
            if row.get(field)!=value:
                raise ValueError('publication field differs from observed hardware ledger: '+field)
        for field in ('timestamp_precision_ns','loss','fallback','correct'):
            if row.get(field) is not None:
                raise ValueError('no implemented observed-evidence proof for cost field: '+field)
        if row.get('internal_bytes') is None:
            continue
        trial=original.get('trial')
        if not trial:
            raise ValueError('internal-byte cost requires an observed trial identity')
        if trial not in trial_costs:
            members=trials[trial]
            if (len(members)!=193 or len({r.get('arm') for r in members})!=1
                    or any(r.get('complete') is not True for r in members)
                    or Counter(r.get('txn_class') for r in members)!=Counter(READ=65,SELECT=64,OPERATE=64)):
                raise ValueError('internal-byte denominator lacks193 complete trial exchanges')
            snapshots=[]
            for suffix in ('before','after'):
                candidates=[a for a in artifacts if a['kind']=='counters' and
                    Path(a['path']).parent.name=='snapshots' and Path(a['path']).name==trial+'_'+suffix+'.json']
                if len(candidates)!=1:
                    raise ValueError('internal-byte cost requires unique hash-bound raw trial snapshots')
                record=candidates[0]
                path=safe_path(root,record['path'])
                if sha256(path)!=record['sha256']:
                    raise ValueError('internal-byte raw snapshot hash mismatch')
                snapshots.append(read_json(path))
            before,after=snapshots
            changes=[]
            for role in ('n_ack_return','t_in','hb_return','held_return'):
                try:
                    start=before['loop_ports'][role]['$OctetsReceived']
                    stop=after['loop_ports'][role]['$OctetsReceived']
                except (KeyError,TypeError):
                    raise ValueError('internal-byte raw snapshot lacks loop RXoctets')
                if (isinstance(start,bool) or isinstance(stop,bool) or not isinstance(start,(int,float))
                        or not isinstance(stop,(int,float)) or not math.isfinite(start) or not math.isfinite(stop)
                        or start<0 or stop<start):
                    raise ValueError('invalid/reset loop RXoctet counters')
                changes.append(stop-start)
            # Matches unchanged cost_report.trial_cost for a qualified193-exchange trial.
            trial_costs[trial]=round(sum(changes)/193,1)
        if row['internal_bytes']!=trial_costs[trial]:
            raise ValueError('internal-byte CSV cost differs from raw trial RXoctet derivation')
    return True


def validate_release(directory, training=False, _fixture=False):
    root = Path(directory).resolve()
    manifest = read_json(root/'release_manifest.json')
    if manifest.get('schema_version') != 1:
        raise ValueError('unsupported release manifest version')
    if not _fixture and manifest.get('evidence_kind') != 'hardware':
        raise ValueError('main results require hardware captures AND counters; fixtures excluded')
    provenance = manifest.get('hardware_provenance',{})
    if not _fixture and (provenance.get('platform')!='Tofino-1' or provenance.get('target')!='m11_09'
            or provenance.get('endpoint')!='OpenDNP3' or len(provenance.get('source_sha256',''))!=64):
        raise ValueError('missing physical Tofino-1/m11_09/OpenDNP3 source provenance')
    if not manifest.get('campaign_id'):
        raise ValueError('missing campaign identity')
    actual_conditions = {(c['condition_id'],float(c['D_ms']),float(c['J_ms'])) for c in manifest['conditions']}
    if actual_conditions != set(CONDITIONS) or len(manifest['conditions']) != 8:
        raise ValueError('requires eight frozen conditions')
    artifacts = {}
    block_kinds = defaultdict(set)
    block_artifacts = defaultdict(list)
    physical_paths = set()
    for record in manifest['artifacts']:
        path = safe_path(root, record['path'])
        if path in physical_paths or record['path'] in artifacts or not path.is_file() or sha256(path) != record['sha256']:
            raise ValueError('missing/duplicate/hash-mismatched artifact '+record['path'])
        physical_paths.add(path)
        if not _fixture:
            if record['kind']=='validation':
                if record.get('evidence_kind') not in ('model_validation','compiler_validation','profile_metadata'):
                    raise ValueError('validation prerequisite must retain explicit nonhardware evidence type')
            elif record.get('evidence_kind')!='hardware':
                # explicit only: an unlabelled artifact is not hardware evidence (review A6)
                raise ValueError('nonhardware or unlabelled artifact cannot supply main analysis inputs')
        artifacts[record['path']] = record
        block_kinds[record.get('block_id')].add(record['kind'])
        block_artifacts[record.get('block_id')].append(record)
        if not _fixture and record['kind']=='capture':
            with open(path,'rb') as handle:
                header = handle.read(41)
            if len(header)<41 or header[:4] not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'):
                raise ValueError('capture artifact is not a nonempty classic pcap')
        if not _fixture and record['kind']=='counters':
            counters = read_json(path)
            if not isinstance(counters,dict) or not counters:
                raise ValueError('counter artifact must be a nonempty observed JSON object')
    for field, kind in (('rows_file','rows'),('schedule_file','schedule'),('cohort_file','cohort')):
        if manifest[field] not in artifacts or artifacts[manifest[field]]['kind'] != kind:
            raise ValueError('required file lacks correct artifact hash binding: '+field)
    schedule = read_json(safe_path(root,manifest['schedule_file']))
    expected = {(r,c[0]) for r in range(1,17) for c in CONDITIONS}
    if len(schedule)!=128 or {(b['round'],b['condition_id']) for b in schedule} != expected:
        raise ValueError('requires complete frozen128-block schedule')
    ids = [b['block_id'] for b in schedule]
    if len(set(ids))!=128 or [b['round'] for b in schedule] != sorted(b['round'] for b in schedule):
        raise ValueError('schedule IDs/order invalid; all training must precede testing')
    for b in schedule:
        expected_split = 'training' if b['round'] <= 8 else 'testing'
        r = b['round']-1
        rotation = r%8
        expected_condition = [c[0] for c in CONDITIONS][rotation:]+[c[0] for c in CONDITIONS][:rotation]
        actual = [v['condition_id'] for v in schedule if v['round']==b['round']]
        arm_rotation = r%4
        expected_arms = list(ARMS[-arm_rotation:]+ARMS[:-arm_rotation]) if arm_rotation else list(ARMS)
        if b['split'] != expected_split or b['arms'] != expected_arms or actual != expected_condition:
            raise ValueError('frozen round condition/arm rotation mismatch')
    cohort = read_json(safe_path(root,manifest['cohort_file']))
    completed = cohort.get('blocks',[])
    required = {b['block_id'] for b in schedule if not training or b['round']<=8}
    if cohort.get('schema_version')!=1 or len(completed)!=len(required) or {b['block_id'] for b in completed}!=required:
        raise ValueError('incomplete/mismatched cohort')
    rows = load_rows(safe_path(root,manifest['rows_file']))
    schedule_by = {b['block_id']:b for b in schedule}
    seen = set()
    counts = Counter()
    operation_counts = Counter()
    rows_by_block = defaultdict(list)
    for row in rows:
        identity = row.get('example_id')
        if not identity or identity in seen:
            raise ValueError('missing or duplicate example identity')
        seen.add(identity)
        block = schedule_by.get(row.get('block_id'))
        if not block or row['block_id'] not in required or any(row.get(f)!=block[f] for f in ('round','split','condition_id')):
            raise ValueError('row split/block does not match frozen schedule')
        if row['arm'] not in ARMS or row['operation'] not in CLASSES:
            raise ValueError('unknown arm/operation')
        counts[row['block_id'],row['arm']] += 1
        operation_counts[row['block_id'],row['arm'],row['operation']] += 1
        rows_by_block[row['block_id']].append(row)
    for block in completed:
        if block.get('complete') is not True or not {'capture','counters'} <= block_kinds[block['block_id']]:
            raise ValueError('hardware block missing captures/counters or incomplete')
        if not _fixture:
            audit = {Path(a['path']).name:a for a in block_artifacts[block['block_id']] if a['kind']=='audit'}
            required_audit = ('campaign_run.json','restore_verify.json','evaluation_postcheck.json','publication_ledger.json')
            if any(name not in audit for name in required_audit):
                raise ValueError('hardware block lacks source/restore/extraction audit evidence')
            run,restore,post,ledger = [read_json(safe_path(root,audit[name]['path'])) for name in required_audit]
            sources = run.get('source_identity',{}).get('build_sources',{}).values()
            if (run.get('ok') is not True or restore.get('ok') is not True or post.get('ok') is not True
                    or post.get('evidence_kind')!='hardware' or post.get('block_id')!=block['block_id']
                    or post.get('campaign_record_sha256')!=audit['campaign_run.json']['sha256']
                    or post.get('ledger_sha256')!=audit['publication_ledger.json']['sha256']
                    or not any(s.get('source_sha256')==provenance['source_sha256'] for s in sources)):
                raise ValueError('hardware source/restore/postcheck binding failed')
            validate_ledger_rows(root,block_artifacts[block['block_id']],ledger,rows_by_block[block['block_id']])
        for arm in ARMS:
            if (block['expected_per_arm'].get(arm)!=193 or block['observed_per_arm'].get(arm)!=193
                    or counts[block['block_id'],arm]!=193):
                raise ValueError('attempted cohort count mismatch (193 exchanges per arm required)')
            actual = Counter({c:operation_counts[block['block_id'],arm,c] for c in CLASSES})
            if actual != Counter(READ=65,SELECT=64,OPERATE=64):
                raise ValueError('cohort operation count mismatch')
    if not training:
        name = manifest.get('model_lock_file')
        if name not in artifacts or artifacts[name]['kind']!='model_lock':
            raise ValueError('missing hashed training model lock')
        lock = read_json(safe_path(root,name))
        verify_training_lock(rows,lock)
        if lock.get('training_schedule_sha256') != digest([b for b in schedule if b['round']<=8]):
            raise ValueError('training schedule differs from lock')
        if lock.get('campaign_id') != manifest['campaign_id'] or lock.get('evidence_kind')!=manifest['evidence_kind']:
            raise ValueError('lock campaign/evidence identity mismatch')
        # A hashed durable hook record proves the lock existed before the controller began test9.
        attestation = manifest.get('fit_attestation_file')
        if not _fixture:
            if attestation not in artifacts or artifacts[attestation]['kind'] != 'fit_attestation':
                raise ValueError('missing durable pre-test fit attestation')
            att = read_json(safe_path(root,attestation))
            if (att.get('model_lock_sha256') != artifacts[name]['sha256'] or
                    att.get('fit_after_round') != 8 or att.get('before_round') != 9 or
                    att.get('ok') is not True or att.get('campaign_id')!=manifest['campaign_id']):
                raise ValueError('invalid training-before-test attestation')
    return dict(root=root, manifest=manifest, schedule=schedule, cohort=cohort, rows=rows,
                manifest_sha256=sha256(root/'release_manifest.json'))


def validate_fixture_release(directory, training=False):
    """Explicit analysis-only validation; never used by main CLI."""
    return validate_release(directory,training=training,_fixture=True)


def coverage(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[tuple(row[f] for f in ('condition_id','round','split','arm','operation'))].append(row)
    result = []
    for key, subset in sorted(grouped.items()):
        value = dict(zip(('condition_id','round','split','arm','operation'),key))
        value['attempted'] = len(subset)
        for field in sorted(NUMERICAL):
            value[field+'_observed'] = sum(r.get(field) is not None for r in subset)
            value[field+'_missing'] = len(subset)-value[field+'_observed']
            value[field+'_invalid'] = sum(r.get(field) is not None and r[field]<0 for r in subset)
        result.append(value)
    return result
