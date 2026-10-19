"""Post hoc attacker analyses for the paper, on the locked campaign splits.

These estimators are NOT the pre-registered evaluation; the primary statistic and every
pre-registered estimate stay in the campaign's results/. They answer questions the paper must
address and that the pre-registered set does not:

  * feature ablation by observation point: which fields an observer on the master link uses
    (the native request, the defended response, or both);
  * two binary tasks: READ versus SELECT, and READ split by its preceding request gap.

Each model is an adaptive attacker: trained per condition and arm on rounds 1-8 of that arm and
tested on rounds 9-16, with the campaign's Random-Forest settings. Rows come from release/rows.csv
through the frozen loader, so field parsing is identical to the campaign analysis.
"""
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

from publication_analysis import ARMS, CONDITIONS, RF_SETTINGS, feature_matrix, load_rows

# Observation point of every field the campaign analysis may use. Both endpoints share Vision's
# switch-facing NIC: "out" holds what the endpoints transmit (the master's own request, the
# outstation's native response), "in" what the switch delivers back (the request the outstation
# receives, the defended response the master receives). An observer on the master link therefore
# sees the master's transmitted request ("out") and the delivered response ("in"). All packet counts
# are constant in this campaign (1 request, 2 response packets), so they cannot carry information.
REQUEST = ('request_len', 'out_request_packet_count')
RESPONSE = ('ack_ms', 'clrt_ms', 'rt_ms', 'resp_len', 'in_response_packet_count')
GROUPS = {
    'request': REQUEST,
    'response': RESPONSE,
    'master_link': REQUEST + RESPONSE,
}
JOINT = ('ack_ms', 'clrt_ms', 'resp_len')
FIELDS = ('task', 'feature_group', 'condition_id', 'arm', 'balanced_accuracy',
          'block_min', 'block_max', 'test_blocks', 'n_train', 'n_test', 'classes', 'fields')


def _fit_score(train, test, fields, label):
    xtr, used_tr, _ = feature_matrix(train, fields)
    xte, used_te, _ = feature_matrix(test, fields)
    ytr = [label(train[i]) for i in used_tr]
    yte = [label(test[i]) for i in used_te]
    if len(set(ytr)) < 2 or len(set(yte)) < 2:
        return None
    model = RandomForestClassifier(**RF_SETTINGS).fit(xtr, ytr)
    pred = model.predict(xte)
    blocks = defaultdict(lambda: ([], []))
    for i, p, y in zip(used_te, pred, yte):
        truth, guess = blocks[test[i]['block_id']]
        truth.append(y)
        guess.append(p)
    per_block = [balanced_accuracy_score(t, g) for t, g in blocks.values() if len(set(t)) > 1]
    return dict(balanced_accuracy=balanced_accuracy_score(yte, pred),
                block_min=min(per_block), block_max=max(per_block), test_blocks=len(per_block),
                n_train=len(ytr), n_test=len(yte), classes='|'.join(sorted(set(ytr))),
                fields='|'.join(fields))


def _preceding_gaps(rows):
    """Gap (ms) from the previous request in the same session to each request."""
    by_session = defaultdict(list)
    for row in rows:
        by_session[row['session_id']].append(row)
    gap = {}
    for members in by_session.values():
        members.sort(key=lambda r: int(r['request_timestamp_ns']))
        for previous, current in zip(members, members[1:]):
            gap[current['example_id']] = (int(current['request_timestamp_ns'])
                                          - int(previous['request_timestamp_ns'])) / 1e6
    return gap


def run(release):
    rows = load_rows(Path(release) / 'rows.csv')
    if {r['split'] for r in rows} != {'training', 'testing'}:
        raise ValueError('rows must carry the locked training/testing split')
    if any((r['split'] == 'training') != (r['round'] in range(1, 9)) for r in rows):
        raise ValueError('split does not match rounds 1-8 / 9-16')
    gaps = _preceding_gaps(rows)
    out = []
    for condition, _, _ in CONDITIONS:
        for arm in ARMS:
            subset = [r for r in rows if r['condition_id'] == condition and r['arm'] == arm]
            train = [r for r in subset if r['split'] == 'training']
            test = [r for r in subset if r['split'] == 'testing']
            for group, fields in GROUPS.items():
                result = _fit_score(train, test, fields, lambda r: r['operation'])
                if result:
                    out.append(dict(result, task='operation', feature_group=group, condition_id=condition, arm=arm))
            pair = lambda rs: [r for r in rs if r['operation'] in ('READ', 'SELECT')]
            result = _fit_score(pair(train), pair(test), JOINT, lambda r: r['operation'])
            if result:
                out.append(dict(result, task='read_vs_select', feature_group='joint', condition_id=condition, arm=arm))
            reads = lambda rs: [r for r in rs if r['operation'] == 'READ' and r['example_id'] in gaps]
            cut = statistics.median(gaps[r['example_id']] for r in reads(train))
            result = _fit_score(reads(train), reads(test), JOINT,
                                lambda r: 'long_gap' if gaps[r['example_id']] > cut else 'short_gap')
            if result:
                out.append(dict(result, task='read_preceding_gap', feature_group='joint',
                                condition_id=condition, arm=arm))
    return out


def formby_shift(release):
    """Post hoc: the pre-registered Formby-style naive Bayes, trained on unobfuscated rounds 1-8 of a
    setting, tested on unobfuscated rounds 9-16 shifted by one constant. A constant delay is the
    baseline that separates replacing CLRT from merely moving it out of the learned histogram."""
    from sklearn.naive_bayes import MultinomialNB
    from publication_analysis import histogram, make_windows
    rows = load_rows(Path(release) / 'rows.csv')
    out = []
    for condition, _, _ in CONDITIONS:
        off = [r for r in rows if r['condition_id'] == condition and r['arm'] == 'off']
        comb = [r for r in rows if r['condition_id'] == condition and r['arm'] == 'combined']
        train = [r for r in off if r['split'] == 'training']
        high = max(.001, 1.05 * max(r['clrt_ms'] for r in train))
        test_off = [r for r in off if r['split'] == 'testing']
        test_comb = [r for r in comb if r['split'] == 'testing']
        to_median = statistics.median(r['clrt_ms'] for r in test_comb) - statistics.median(r['clrt_ms'] for r in test_off)
        for k in (8, 32, 64):
            def feats(sub, shift=0.0):
                wins, _ = make_windows([dict(r, clrt_ms=r['clrt_ms'] + shift) for r in sub], k)
                return np.array([histogram(w['values'], high) for w in wins]), [w['operation'] for w in wins]
            xtr, ytr = feats(train)
            model = MultinomialNB(alpha=1.).fit(xtr, ytr)
            for name, sub, shift in (('none', test_off, 0.0), ('+0.3 ms', test_off, 0.3), ('+1 ms', test_off, 1.0),
                                     ('to Timing+Size median', test_off, to_median), ('Timing+Size (measured)', test_comb, 0.0)):
                x, y = feats(sub, shift)
                out.append(dict(task='formby_shift', feature_group=name, condition_id=condition, arm='off' if sub is test_off else 'combined',
                                balanced_accuracy=balanced_accuracy_score(y, model.predict(x)), block_min='', block_max='',
                                test_blocks='', n_train=len(ytr), n_test=len(y), classes='|'.join(sorted(set(ytr))),
                                fields='nb k=%d H=%.4f shift=%.4f' % (k, high, shift)))
    return out


def write(rows, path):
    with open(path, 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator='\n')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (repr(round(v, 12)) if isinstance(v, float) else v) for k, v in row.items()})


__all__ = ['GROUPS', 'run', 'write']
