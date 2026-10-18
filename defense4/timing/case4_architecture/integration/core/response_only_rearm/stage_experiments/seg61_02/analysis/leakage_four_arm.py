"""Four-arm leakage analysis: campaign_v2's estimators, extended from two arms to four (Part 2, 2026-10-17).

  python3 leakage_four_arm.py TRANSACTIONS.csv OUT.json [--n-perm N]

Arms: baseline (Timing OFF, no padding), size_only, timing_only, combined (FOUR_ARM_DESIGN_REVIEW.md section 0).
campaign_v2's two arm labels are accepted as aliases: native = baseline, obfuscated = timing_only.

Nothing in the method is new. The estimators are imported from campaign_v2/repro/leakage_campaign.py and used
unchanged: MI in bits on CLRT against a within-run permutation null (mi_block), the Random Forest settings (RF), and
the descriptive held-out-run spread (spread). The extension is only in which arms are compared:
  - attacker A (fixed): trained once per fold on baseline traffic of the training runs, then applied unchanged to the
    held-out run of every arm;
  - attacker B (adaptive): retrained per fold on each defended arm's training runs, tested on that arm.
Folds are leave-one-grouped-run-out. Main inputs require all four arms and three classes in at least three blocks.
Features: CLRT, request-to-ACK plus CLRT, observed response TCP-payload octets, and all three together. No interval is reported (campaign_v2's
rejected estimators stay rejected).

Restricted to baseline and timing_only, the output equals leakage_campaign.py's on the same input
(tests/test_leakage_four_arm.py checks it on campaign_v2's canonical table when present; validated at 30 permutations).
With size_only present, timing_only's MI permutations come later in the one seeded generator than in campaign_v2.

Competence gate (code review C1): a defended arm 'at chance' means nothing unless the same attacker sees the leak on
the undefended baseline. For each feature set, attacker A's mean held-out balanced accuracy on baseline must exceed
chance + 0.05 (a margin borrowed from the 2026-09-26 preregistration, where it bounded the defense; here it is the
attacker's competence floor); otherwise that feature set's comparison is reported as
uninformative. A block-level shift that the held-out block does not share (e.g. a fixture delay that differs by block)
is exactly what makes the baseline attacker fail.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import importlib.util
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, confusion_matrix

REPO = Path(__file__).resolve().parents[9]
_spec = importlib.util.spec_from_file_location(
    'leakage_campaign', REPO / 'defense4/timing/evidence/campaign_v2/repro/leakage_campaign.py')
lc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lc)

ARMS = ('baseline', 'size_only', 'timing_only', 'combined')
COMPETENCE_MARGIN = 0.05
ALIASES = {'native': 'baseline', 'obfuscated': 'timing_only'}
FEATURES = {'clrt': [1], 'ack_clrt': [0, 1], 'size': [2], 'ack_clrt_size': [0, 1, 2]}
FEATURE_NAMES = ['ack_ms', 'clrt_ms', 'resp_len']


def _check_counts(path, rows):
    counts_path = Path(str(path) + '.counts.json')
    if not counts_path.is_file():
        raise ValueError('main comparison requires the extraction counts sidecar')
    counts = json.loads(counts_path.read_text())
    if not isinstance(counts, dict) or counts.get('_problems'):
        raise ValueError('extraction counts record unresolved input problems')
    bound = counts.get('_table') or {}
    digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if (bound.get('sha256') != hashlib.sha256(Path(path).read_bytes()).hexdigest() or
            bound.get('rows') != len(rows) or
            bound.get('exchange_ids_sha256') != digest(sorted(r['exchange_id'] for r in rows)) or
            bound.get('capture_ids_sha256') != digest(sorted({r['capture_identity'] for r in rows}))):
        raise ValueError('table digest/count/identities differ from extraction counts')
    by = Counter((r['run'], r['arm'], r['txn_class']) for r in rows)
    runs = {r['run'] for r in rows}
    if {key for key in counts if not key.startswith('_')} != runs:
        raise ValueError('table blocks differ from extraction counts')
    for run in runs:
        first = next(r for r in rows if r['run'] == run)
        meta = counts[run].get('_metadata', {})
        if (meta.get('condition') != first['condition'] or meta.get('build_identity') != first['build_identity'] or
                str(Path(meta.get('block_dir', '')).resolve()) != str(Path(first['block_dir']).resolve())):
            raise ValueError('table metadata differs from extraction counts')
        for arm in ARMS:
            record = counts[run].get(arm, {})
            total = 0
            for kind in lc.CLASSES:
                stat = record.get('classes', {}).get(kind, {})
                observed = stat.get('observed')
                if (stat.get('written') != by[run, arm, kind] or observed != stat.get('expected') or
                        observed != sum(stat.get(key, 0) for key in
                                        ('written', 'incomplete', 'missing_interval', 'invalid'))):
                    raise ValueError('table class/request counts differ from extraction counts')
                total += stat['written']
            if record.get('written') != total:
                raise ValueError('table arm counts differ from extraction counts')


def load(path):
    runs, arms, cls, feats, labels = [], [], [], [], set()
    with open(path) as f:
        rows = list(csv.DictReader(f))
    labels = {r['arm'] for r in rows}
    legacy = bool(labels & set(ALIASES))
    if legacy and labels - set(ALIASES):
        raise ValueError('table mixes campaign_v2 labels and four-arm labels: %s' % sorted(labels))
    if not legacy:
        _check_counts(path, rows)
    identities, captures, blocks, conditions, builds = set(), {}, {}, set(), set()
    for r in rows:
        arm = ALIASES.get(r['arm'], r['arm'])
        if arm not in ARMS:
            raise ValueError('unknown arm %r' % r['arm'])
        if not legacy:
            for key in ('condition', 'build_identity', 'exchange_id', 'capture_identity', 'block_dir', 'trial',
                        'capture_out_sha256', 'capture_in_sha256'):
                if not r.get(key):
                    raise ValueError('main comparison requires %s' % key)
            if r['exchange_id'] in identities:
                raise ValueError('duplicate exchange identity %s' % r['exchange_id'])
            identities.add(r['exchange_id'])
            capture_group = (r['run'], arm, r['trial'])
            if captures.setdefault(r['capture_identity'], capture_group) != capture_group:
                raise ValueError('capture reused across blocks/arms/trials')
            for key in ('capture_out_sha256', 'capture_in_sha256'):
                if captures.setdefault(r[key], capture_group) != capture_group:
                    raise ValueError('capture reused across blocks/arms/trials')
            block_path = str(Path(r['block_dir']).resolve())
            if blocks.setdefault(r['run'], block_path) != block_path:
                raise ValueError('duplicate block name %s' % r['run'])
            conditions.add(r['condition']); builds.add(r['build_identity'])
        runs.append(r['run']); arms.append(r['arm']); cls.append(r['txn_class'])
        values = [float(r['ack_ms']), float(r['clrt_ms'])]
        if not legacy:
            values.append(float(r['resp_len']))
        feats.append(values)
    if not legacy and (len(conditions) != 1 or len(builds) != 1):
        raise ValueError('main comparison mixes condition/build metadata')
    if len(set(blocks.values())) != len(blocks):
        raise ValueError('duplicate input block path')
    return np.array(runs), np.array(arms), np.array(cls), np.array(feats, dtype=float)


def validate(runs, arms, cls, X, legacy):
    if not len(runs) or not (len(runs) == len(arms) == len(cls) == len(X)):
        raise ValueError('empty or inconsistent experiment arrays')
    if X.shape != (len(runs), 2 if legacy else 3) or not np.isfinite(X).all():
        raise ValueError('invalid or nonfinite observed features')
    if not legacy and (np.any(X[:, 2] <= 0) or np.any(X[:, 2] != np.floor(X[:, 2]))):
        raise ValueError('response TCP-payload length must be a positive integer')
    required_arms = ('baseline', 'timing_only') if legacy else ARMS
    if set(arms) != set(required_arms) or len(set(runs)) < (2 if legacy else 3):
        raise ValueError('coverage requires %s and independent blocks' % (required_arms,))
    for block in sorted(set(runs)):
        for arm in required_arms:
            for partition in (runs == block, runs != block):
                if set(cls[partition & (arms == arm)]) != set(lc.CLASSES):
                    raise ValueError('coverage: block %s arm %s lacks READ/SELECT/OPERATE in train/test' % (block, arm))


def spread(vals):
    """lc.spread with the interpretation stated for this table's own run count (code review M1)."""
    d = lc.spread(vals)
    d['interpretation'] = ('within-campaign held-out-run variability across the %d grouped runs (blocks); the folds '
                           'share training data and this is a descriptive range, not a confidence interval' % d['n_runs'])
    return d


def folds(runs, arms, cls, X, idx, present):
    """Per-fold balanced accuracy of attacker A on every arm and attacker B on every defended arm."""
    used = []
    a_scores = {arm: [] for arm in present}
    b_scores = {arm: [] for arm in present if arm != 'baseline'}
    cms = {('A', arm): np.zeros((3, 3)) for arm in present}
    cms.update({('B', arm): np.zeros((3, 3)) for arm in b_scores})
    base = arms == 'baseline'
    for r in sorted(set(runs)):
        te, tr = runs == r, runs != r
        if not (tr & base).any():
            continue
        used.append(r)
        a = RandomForestClassifier(**lc.RF).fit(X[tr & base][:, idx], cls[tr & base])
        for arm in present:
            m = te & (arms == arm)
            if m.any():
                p = a.predict(X[m][:, idx])
                a_scores[arm].append(balanced_accuracy_score(cls[m], p))
                cms[('A', arm)] += confusion_matrix(cls[m], p, labels=lc.CLASSES)
        for arm in b_scores:
            m_tr, m_te = tr & (arms == arm), te & (arms == arm)
            if m_tr.any() and m_te.any():
                b = RandomForestClassifier(**lc.RF).fit(X[m_tr][:, idx], cls[m_tr])
                p = b.predict(X[m_te][:, idx])
                b_scores[arm].append(balanced_accuracy_score(cls[m_te], p))
                cms[('B', arm)] += confusion_matrix(cls[m_te], p, labels=lc.CLASSES)
    return a_scores, b_scores, cms, used


def analyse(runs, arms, cls, X, seed=lc.SEED):
    legacy = bool(set(arms) & set(ALIASES))
    if legacy and set(arms) - set(ALIASES):
        raise ValueError('mixed legacy and four-arm labels')
    arms = np.array([ALIASES.get(a, a) for a in arms])
    validate(runs, arms, cls, X, legacy)
    present = [a for a in ARMS if (arms == a).any()]
    if 'baseline' not in present:
        raise ValueError('the fixed attacker needs baseline traffic')
    rng = np.random.default_rng(seed)
    res = dict(seed=seed, arms=present, chance_balanced_accuracy=round(1 / 3, 4), n_folds=len(set(runs)),
               classifier='RandomForest ' + json.dumps(lc.RF), n_permutations=lc.N_PERM,
               method='campaign_v2/repro/leakage_campaign.py estimators, unchanged; arms extended',
               comparison_scope=('campaign_v2 timing reproduction' if legacy else 'complete paired four-arm comparison'),
               classifier_scope=('results characterise the evaluated Random-Forest attackers and this feature set; '
                                 'they do not generalise to all fingerprinting classifiers'),
               mutual_information={}, classifiers={}, confusion_all_folds={}, confusion_support={},
               mutual_information_scope='marginal CLRT MI only; no joint or size MI is claimed',
               observable_scope=('ACK latency, CLRT and observed response TCP-payload octets; plaintext DNP3 '
                                 'function codes remain visible and are outside these features'),
               coverage={str(r): {a: {k: int(np.sum((runs == r) & (arms == a) & (cls == k)))
                                     for k in lc.CLASSES} for a in present} for r in sorted(set(runs))})
    for arm in present:                                      # campaign_v2's order: baseline before timing_only
        m = arms == arm
        res['mutual_information'][arm] = lc.mi_block(X[m][:, [1]], cls[m], runs[m], rng)
    for name, idx in FEATURES.items():
        if legacy and 2 in idx:
            continue
        a_scores, b_scores, cms, used = folds(runs, arms, cls, X, idx, present)
        base_mean = float(np.mean(a_scores['baseline'])) if a_scores['baseline'] else None
        competent = base_mean is not None and base_mean > 1 / 3 + COMPETENCE_MARGIN
        res['classifiers'][name] = dict(
            features=[FEATURE_NAMES[i] for i in idx],
            A_fixed_baseline_trained={'tested_on_' + arm: spread(v) for arm, v in a_scores.items() if v},
            B_adaptive_arm_trained={'tested_on_' + arm: spread(v) for arm, v in b_scores.items() if v},
            folds_per_arm={arm: len(v) for arm, v in a_scores.items()}, folds_used=len(used),
            adaptive_anomalies={'tested_on_' + arm: round(float(np.mean(v)), 4) for arm, v in b_scores.items()
                                if v and np.mean(v) < 1 / 3 - COMPETENCE_MARGIN},
            competence=dict(baseline_mean_balanced_accuracy=None if base_mean is None else round(base_mean, 4),
                            required_above=round(1 / 3 + COMPETENCE_MARGIN, 4), competent=competent,
                            comparison=('informative' if competent else
                                        'UNINFORMATIVE: the fixed attacker does not see the undefended baseline\'s '
                                        'leak, so defended arms at chance say nothing about the defense')))
        for (who, arm), cm in cms.items():
            if cm.sum():
                tag = '%s/%s_%s' % (name, who, arm)
                support = cm.sum(axis=1)
                res['confusion_support'][tag] = support.astype(int).tolist()
                res['confusion_all_folds'][tag] = [
                    (row / n).round(4).tolist() if n else None for row, n in zip(cm, support)]
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('transactions')
    ap.add_argument('out')
    ap.add_argument('--n-perm', type=int, default=lc.N_PERM)
    a = ap.parse_args(argv)
    lc.N_PERM = a.n_perm
    res = analyse(*load(a.transactions))
    res['transactions_sha256'] = hashlib.sha256(Path(a.transactions).read_bytes()).hexdigest()
    counts_path = Path(a.transactions + '.counts.json')
    if counts_path.exists():
        res['extraction_counts'] = json.loads(counts_path.read_text())
    Path(a.out).write_text(json.dumps(res, indent=1, allow_nan=False) + '\n')
    for arm, d in res['mutual_information'].items():
        print('MI %-11s %.5f bits  null p95 %.5f  p=%.5f' % (arm, d['observed_bits'], d['null_p95_bits'],
                                                            d['p_value_empirical']))
    for name, c in res['classifiers'].items():
        if not c['competence']['competent']:
            print('WARNING %s %s' % (name, c['competence']['comparison']))
        for arm, value in c['adaptive_anomalies'].items():
            print('WARNING %s adaptive anomaly %s balanced accuracy %s' % (name, arm, value))
        for who in ('A_fixed_baseline_trained', 'B_adaptive_arm_trained'):
            for k, v in c[who].items():
                print('%-8s %-24s %-22s mean %.4f  [%.4f, %.4f]' % (name, who, k, v['mean'], v['min'], v['max']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
