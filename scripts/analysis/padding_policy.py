#!/usr/bin/env python3
"""Offline padding-policy study (plan Phase C): attainable response-size assignments under the c72 rules, their
size-only and joint classifier scores on the retained rows, and their byte cost. No P4 or profile file is changed.

Every result is qualified by the targets, framing rules and limits in RULES (file:line, checked against the files
at run time). READ grows only by one prefix link frame of reserved G1V2 points ahead of the unchanged native frame
(read_policy_expect.construct). SELECT/OPERATE grow only by transport reframing of their 32 application octets,
because added objects break the Rule 8 echo. Classifiers are formby_eval's (nb_predict, make_windows, fit_high) on
the same chronological split (repetitions 1-8 train, 9-16 test per D), with block-bootstrap intervals over test blocks.

  $RESEARCH_PYTHON scripts/analysis/padding_policy.py [--rows ROWS_CSV] [--output OUT_DIR]
"""
import argparse
import collections
import csv
import functools
import hashlib
import json
import platform
import sys
from pathlib import Path

import numpy as np
import sklearn

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'scripts/model'))
import dnp3_std  # noqa: E402
import formby_eval as fe  # noqa: E402

SCHEMA = 'c72-padding-policy-v1'
OPERATIONS, WORKLOADS = fe.CLASSES, ('mixed', 'integrity')
KEYS = ('mixed', 'integrity', 'SELECT', 'OPERATE')
OPERATION_K, WORKLOAD_K = (8, 32, 64), (8, 16, 32, 64)
PROFILE = 'results/builds/c72/supported_profile.json'
CONSTANTS = 'tests/fixtures/vectors/constants_two_read_relay.json'
ROWS = ROOT / 'results/analysis/evaluation/final/rows/rows.csv'
FORMBY = ROOT / 'results/analysis/evaluation/final/formby/formby_results.json'
OUT = ROOT / 'results/analysis/padding_policy'
LINK_USER_MAX = 250            # LEN is one octet and counts 5 header octets plus the user octets
SEGMENT_MAX = 249              # application octets per transport segment
PREFIX_FIXED_USER = 1 + 4 + 7  # transport header + app control/function/IIN + G1V2 q0x01 header (16-bit start/stop)
DISPLACED_POINTS = 4           # the continuation carries 4 point octets in place of the moved app header/IIN
LABEL_JOINT = 'offline policy estimate assuming unchanged timing, not a hardware result'
QUALIFIER = 'under the enumerated targets, framing rules and limits'
RULES = [  # (path, first line, last line, text that must occur there, rule)
    (PROFILE, 52, 59, '"native_input_octets"', 'native response octets: READ 91 (mixed) / 134 (integrity), SBO 49'),
    (PROFILE, 60, 60, '"output_octets": 60', 'one SELECT/OPERATE image length (60) shared by both operations'),
    (PROFILE, 62, 75, '"read_images"', 'two READ targets: 91->141, 134->158'),
    (PROFILE, 67, 70, '"control_application_partition"', 'SBO reframed as transport 15+17 application octets'),
    (PROFILE, 77, 80, '"control_frames"', 'SBO image link frames [28, 32]'),
    ('p4/profile_template.json', 118, 161, '"frames_out"', 'READ images: prefix frame + unchanged native frame'),
    ('p4/profile_template.json', 162, 168, '"SELECT_OPERATE": 60', 'output lengths READ 141/158, SBO 60'),
    ('scripts/model/dnp3_std.py', 27, 34, 'header8[2] == 5 + len(user)', 'one-octet LEN = 5 + user (<= 250)'),
    ('scripts/model/dnp3_std.py', 59, 61, 'return 10 + user_len + 2 * (-(-user_len // 16))',
     'frame length = 10 + u + 2*ceil(u/16)'),
    ('scripts/model/dnp3_std.py', 70, 73, 'Table 12-8', 'G12V1 responses echo the request qualifiers'),
    ('scripts/model/dnp3_std.py', 196, 203, 'Rule 8', 'Rule 8: response objects equal the request objects'),
    ('scripts/model/dnp3_std.py', 252, 254, 'if not 1 <= len(app) <= 249', 'transport segment: 1..249 app octets'),
    (CONSTANTS, 7, 10, '"reserved_range"', 'reserved padding indices 1024..4095'),
    (CONSTANTS, 15, 15, '158 is the prefix floor (134 + 24)', 'smallest prefix frame: 24 octets'),
    (CONSTANTS, 42, 56, '"prefix_user_len": 34', 'mixed: 26 points, 34 prefix user octets, 50-octet prefix'),
    (CONSTANTS, 90, 104, '"prefix_user_len": 12', 'integrity: 4 points, 12 prefix user octets, 24-octet prefix'),
    ('scripts/model/read_policy_expect.py', 264, 277, 'def construct(native, c=None):',
     'prefix = transport+app header/IIN+padobj_head; continuation = 4 zero points + native objects'),
    ('scripts/model/relay_sbo_vectors.py', 30, 36, 'def control_image(native):', 'SBO 15+17 reframing'),
    ('scripts/model/model_relay_sbo.py', 23, 37, '[28, 32]', 'SBO image keeps all 32 application octets'),
    ('p4/response_only.p4', 2125, 2127, 'mixed prefix block 0 (16 B)', 'P4 emits fixed 50-B/24-B prefix headers'),
]


def check_rules():
    """Each cited line range must still contain its text; returns the citations with that check recorded."""
    out = []
    for path, first, last, needle, rule in RULES:
        lines = (ROOT / path).read_text().splitlines()[first - 1:last]
        if not any(needle in line for line in lines):
            raise ValueError('citation %s:%d-%d no longer contains %r' % (path, first, last, needle))
        out.append(dict(cite='%s:%d-%d' % (path, first, last), rule=rule, verified=True))
    return out


def load_rules():
    """Native sizes, current targets and the construction constants, checked for internal consistency."""
    enc = json.loads((ROOT / PROFILE).read_text())['encoding']
    shapes = json.loads((ROOT / CONSTANTS).read_text())['shapes']
    shape = {name.split('_')[0]: s for name, s in shapes.items()}
    native = dict(mixed=shape['mixed']['native_total'], integrity=shape['integrity']['native_total'],
                  SELECT=enc['native_input_octets']['SELECT'], OPERATE=enc['native_input_octets']['OPERATE'])
    images = enc['read_images']
    current = dict(mixed=images[str(native['mixed'])], integrity=images[str(native['integrity'])],
                   SELECT=enc['output_octets'], OPERATE=enc['output_octets'])
    for key in WORKLOADS:
        s = shape[key]
        if (s['prefix_user_len'] != PREFIX_FIXED_USER + s['padding_points'] - DISPLACED_POINTS
                or dnp3_std.frame_length(s['prefix_user_len']) != s['prefix_frame_len']
                or not s['native_total'] + s['prefix_frame_len'] == s['target'] == current[key]):
            raise ValueError('READ construction constants disagree with the frame rules for %s' % key)
    partition = enc['control_application_partition']
    frames = [dnp3_std.frame_length(1 + a) for a in partition]
    if frames != enc['control_frames'] or sum(frames) != current['SELECT'] or \
            dnp3_std.frame_length(1 + sum(partition)) != native['SELECT']:
        raise ValueError('SBO partition disagrees with the frame rules')
    return dict(native=native, current=current, partition=partition, app_octets=sum(partition))


def reachable_read(native, max_user=LINK_USER_MAX):
    """{total: prefix user octets} for one prefix frame of u in [12, max_user] octets; the native maps to None."""
    totals = {native: None}
    for u in range(PREFIX_FIXED_USER, max_user + 1):
        totals.setdefault(native + dnp3_std.frame_length(u), u)
    return totals


def reachable_sbo(app_octets, max_segment=SEGMENT_MAX):
    """{total: witness partition} over every split of the application octets into 1..max_segment-octet segments,
    each in its own link frame (fewest segments kept as the witness)."""
    @functools.lru_cache(maxsize=None)
    def split(n):
        out = {}
        for first in range(1, min(n, max_segment) + 1):
            head = dnp3_std.frame_length(1 + first)
            tails = {0: ()} if first == n else split(n - first)
            for total, parts in tails.items():
                candidate = (first,) + parts
                if head + total not in out or len(candidate) < len(out[head + total]):
                    out[head + total] = candidate
        return out
    return {total: list(parts) for total, parts in sorted(split(app_octets).items())}


def assignments(rules):
    native, current = rules['native'], rules['current']
    read = {k: reachable_read(native[k]) for k in WORKLOADS}
    sbo = reachable_sbo(rules['app_octets'])
    padded = {k: {t for t, u in read[k].items() if u is not None} for k in WORKLOADS}
    full = min(padded['mixed'] & padded['integrity'] & set(sbo))
    overlap = min(padded['mixed'] & set(sbo))
    plans = [('native', 'reference: unpadded native sizes', native),
             ('current', '(i) current c72 targets', current),
             ('merged_read', '(ii) both READ workloads at the integrity target',
              dict(current, mixed=current['integrity'])),
             ('full_merge', '(iii) smallest size reachable by all four classes', dict.fromkeys(KEYS, full)),
             ('mixed_sbo_overlap', '(iii) smallest size shared by mixed READ and SBO; integrity unchanged',
              dict(current, mixed=overlap, SELECT=overlap, OPERATE=overlap))]
    out = []
    for name, label, sizes in plans:
        construction = {k: dict(prefix_user_octets=read[k].get(sizes[k]),
                                prefix_frame_octets=sizes[k] - native[k] if read[k].get(sizes[k]) else 0)
                        for k in WORKLOADS}
        witness = rules['partition'] if sizes['SELECT'] == current['SELECT'] else sbo.get(sizes['SELECT'])
        construction['SBO'] = dict(application_partition=witness)
        # Two READ workloads can never need more than the two permitted READ targets, so no extra check is needed.
        attainable = (all(sizes[k] in read[k] for k in WORKLOADS) and sizes['SELECT'] in sbo
                      and sizes['SELECT'] == sizes['OPERATE'])
        out.append(dict(name=name, label=label, sizes=sizes, attainable=attainable, construction=construction))
    return out, read, sbo


def class_key(row):
    return row['read_class'] if row['operation'] == 'READ' else row['operation']


def apply_assignment(rows, sizes, source):
    """Copies of rows with resp_len := sizes[class]; a row whose resp_len is not source[class] is refused."""
    out = []
    for row in rows:
        key = class_key(row)
        if row['resp_len'] != source[key]:
            raise ValueError('%s response of %d octets is not the declared %d' % (key, row['resp_len'], source[key]))
        out.append(dict(row, resp_len=sizes[key]))
    return out


def ceiling(rows, sizes, source, classes):
    """Ideal BA upper bound: classes with identical size distributions cannot be separated (their recalls sum to
    at most 1), so BA <= distinct distributions / classes."""
    by = collections.defaultdict(collections.Counter)
    for row in apply_assignment(rows, sizes, source):
        label = row['operation'] if classes == OPERATIONS else row['read_class']
        if label in classes:
            by[label][row['resp_len']] += 1
    dists = {tuple(sorted((s, round(n / sum(c.values()), 12)) for s, n in c.items())) for c in by.values()}
    return len(dists) / len(classes)


def workload_rows(rows):
    return [dict(r, operation=r['read_class']) for r in rows if r['operation'] == 'READ']


def window_fits(rows, k):
    """K fits only if every block/arm holds at least K READs of each workload (windows never cross blocks)."""
    counts = collections.Counter((r['block_id'], r['arm'], r['read_class']) for r in rows
                                 if r['operation'] == 'READ' and not r['piggyback'])
    cells = {(b, a) for b, a, _ in counts}
    return bool(cells) and all(counts[(b, a, w)] >= k for b, a in cells for w in WORKLOADS)


def workload_windows(rows, feature, k):
    return fe.make_windows(workload_rows(rows), feature, k)


def recall_ba(truth, prediction, classes):
    return float(np.mean([np.mean([p == c for t, p in zip(truth, prediction) if t == c]) for c in classes]))


def evaluate(rows, feature, k, classes):
    """NB on one D and arm (formby_eval.evaluate_arm's NB path): train reps 1-8, test 9-16, H from training rows,
    per-test-block BA and its block bootstrap. Workload windows exist only for K that fits every block."""
    source = rows if classes == OPERATIONS else workload_rows(rows)
    if classes == WORKLOADS and not window_fits(rows, k):
        return dict(unavailable='K=%d exceeds the READs of one workload in some block (windows never cross '
                                'blocks)' % k)
    windows = fe.make_windows(source, feature, k)
    train = [w for w in windows if w['split'] == 'train']
    test = [w for w in windows if w['split'] == 'test']
    if {w['operation'] for w in train} != set(classes) or {w['operation'] for w in test} != set(classes):
        return dict(unavailable='a class has no complete window at K=%d' % k)
    prediction = fe.nb_predict(train, test, feature, fe.fit_high(source, feature))
    truth = [w['operation'] for w in test]
    per_block = {}
    for rep in sorted({w['repetition'] for w in test}):
        idx = [i for i, w in enumerate(test) if w['repetition'] == rep]
        if {truth[i] for i in idx} == set(classes):
            per_block[rep] = recall_ba([truth[i] for i in idx], [prediction[i] for i in idx], classes)
    ci, reason = fe.block_interval(per_block, sorted({r['repetition'] for r in rows if r['split'] == 'test'}),
                                   fe.SEED)
    confusion = [[sum(t == a and q == b for t, q in zip(truth, prediction)) for b in classes] for a in classes]
    return dict(balanced_accuracy=recall_ba(truth, prediction, classes), confusion=confusion, classes=list(classes),
                train_windows=len(train), test_windows=len(test), test_blocks=len(per_block),
                per_block_ba=per_block, ci=ci, ci_unavailable=reason)


evaluate_operation = functools.partial(evaluate, classes=OPERATIONS)
evaluate_workload = functools.partial(evaluate, classes=WORKLOADS)


def added_bytes(rows, sizes, source):
    mapped = apply_assignment(rows, sizes, source)
    added = sum(m['resp_len'] - r['resp_len'] for m, r in zip(mapped, rows))
    response = sum(r['resp_len'] for r in rows)
    request = sum(r['req_len'] for r in rows)
    return dict(per_class={k: sizes[k] - source[k] for k in KEYS}, exchanges=len(rows), added_response_octets=added,
                added_per_transaction=added / len(rows), response_payload_pct=100 * added / response,
                request_response_payload_pct=100 * added / (response + request))


def run(rows, rules):
    plans, read, sbo = assignments(rules)
    native, current = rules['native'], rules['current']
    off = [r for r in rows if r['arm'] == 'off']
    results = []
    for plan in plans:
        plan['ceiling_operation'] = ceiling(off, plan['sizes'], native, OPERATIONS)
        plan['ceiling_workload'] = ceiling(off, plan['sizes'], native, WORKLOADS)
        plan['overhead'] = added_bytes(off, plan['sizes'], native)
        for d in sorted({r['d_ms'] for r in rows}):
            combined = [r for r in rows if r['d_ms'] == d and r['arm'] == 'combined']
            cells = (('size', 'off', apply_assignment([r for r in off if r['d_ms'] == d], plan['sizes'], native)),
                     ('joint', 'combined', apply_assignment(combined, plan['sizes'], current)))
            for feature, arm, cell in cells:
                for task, ks, evaluate in (('operation', OPERATION_K, evaluate_operation),
                                           ('workload', WORKLOAD_K, evaluate_workload)):
                    for k in ks:
                        label = LABEL_JOINT if feature == 'joint' else 'size-only, native sizes mapped by class'
                        results.append(dict(assignment=plan['name'], d_ms=d, task=task, feature=feature, k=k,
                                            rows_arm=arm, label=label, **evaluate(cell, feature, k)))
    return plans, read, sbo, results


def cross_check(results):
    """Assignments that equal a recorded arm must reproduce formby_results.json's retrained NB BA."""
    retained = {(r['d_ms'], r['arm'], r['feature'], r['k']): r['nb']['balanced_accuracy']
                for r in json.loads(FORMBY.read_text())['results'] if r['attacker'] == 'retrained' and 'nb' in r}
    pairs = {('native', 'size'): 'off', ('current', 'size'): 'size_only', ('current', 'joint'): 'combined'}
    out = []
    for r in results:
        arm = pairs.get((r['assignment'], r['feature']))
        if arm and r['task'] == 'operation' and 'balanced_accuracy' in r:
            old = retained[(r['d_ms'], arm, r['feature'], r['k'])]
            out.append(dict(assignment=r['assignment'], feature=r['feature'], d_ms=r['d_ms'], k=r['k'], arm=arm,
                            ours=r['balanced_accuracy'], retained=old, equal=abs(old - r['balanced_accuracy']) < 1e-12))
    return out


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def table(head, body):
    fmt = lambda v: '%.4f' % v if isinstance(v, float) else str(v)  # noqa: E731
    return ['| ' + ' | '.join(head) + ' |', '|' + '---|' * len(head)] + \
        ['| ' + ' | '.join(fmt(v) for v in row) + ' |' for row in body]


def ranges(values):
    """Compact '115-119, 122-137, ...' view of a sorted integer set."""
    values, out, start = sorted(values), [], None
    for i, v in enumerate(values):
        start = v if start is None else start
        if i + 1 == len(values) or values[i + 1] != v + 1:
            out.append(str(start) if start == v else '%d-%d' % (start, v))
            start = None
    return ', '.join(out)


def cell_text(c):
    if 'unavailable' in c:
        return 'n/a'
    return '%.3f [%s]' % (c['balanced_accuracy'], '%.3f, %.3f' % (c['ci']['lower'], c['ci']['upper'])
                          if c['ci'] else 'no CI')


def summary(record):
    plans, results, r = record['assignments'], record['results'], record['reachable']
    find = {(x['assignment'], x['d_ms'], x['task'], x['feature'], x['k']): x for x in results}
    u158 = r['read_prefix_user']['mixed'].get('158')
    lines = ['# Padding-policy study (offline; no P4 or profile change)', '',
             'Schema `%s`. Rows `%s` (sha256 `%s`). Every statement below holds %s cited here; the files were '
             'checked at run time for the cited text.' % (SCHEMA, record['inputs']['rows'],
                                                         record['inputs']['rows_sha256'][:16], QUALIFIER), '',
             '## Rules and limits (file:line)', ''] + ['- `%s`: %s' % (c['cite'], c['rule']) for c in record['rules']]
    lines += ['', '## Reachable response totals (octets)', '',
              '- Mixed READ (native 91), one prefix frame of u = 12..250 user octets (u - 8 <= 242 reserved points, '
              'inside 1024..4095): 91 or %s.' % ranges(r['mixed']),
              '- Integrity READ (native 134): 134 or %s; the 24-octet prefix floor makes %d the smallest padded total.'
              % (ranges(r['integrity']), min(r['integrity'])),
              '- SELECT/OPERATE (native 49), reframing of the 32 application octets only (witness partitions in the '
              'JSON; 60 is the implemented 15+17): %s.' % ranges(r['sbo']),
              '- Mixed READ -> 158: %s.' % ('attainable %s with a %d-octet prefix frame (u = %d user octets, %d '
                                            'reserved points)' % (QUALIFIER, 158 - 91, u158, u158 - 8)
                                            if u158 else 'not attainable %s' % QUALIFIER),
              '- Alternatives other than (i) need new P4 prefix headers and constants (p4/response_only.p4:2125-2127 '
              'emits fixed 50-B/24-B prefixes); none was compiled or resource-checked here.', '',
              '## Assignments and added bytes (d)', '',
              'Ideal ceiling: if READ sizes remain separate from SBO and SELECT/OPERATE have identical size '
              'distributions, the ideal size-only three-class BA ceiling is 2/3. In general the bound is (classes '
              'with distinct size distributions) / (classes). Added bytes are response payload octets relative to '
              'native, over the %d retained off-arm exchanges.' % plans[0]['overhead']['exchanges'], '']
    lines += table(['assignment', 'mixed', 'integrity', 'SELECT/OPERATE', 'attainable', 'ceiling 3-class',
                    'ceiling workload', 'added B/txn', 'req+resp %', 'resp %'],
                   [[p['name']] + ['%d (+%d)' % (p['sizes'][k], p['overhead']['per_class'][k])
                                   for k in ('mixed', 'integrity', 'SELECT')] +
                    [p['attainable'], p['ceiling_operation'], p['ceiling_workload']] +
                    [p['overhead'][k] for k in ('added_per_transaction', 'request_response_payload_pct',
                                                'response_payload_pct')] for p in plans])
    for feature, title in (('size', 'Size-only NB on the off arm with mapped sizes (retrained, test reps 9-16)'),
                           ('joint', 'Joint CLRT+size on the combined arm: %s' % LABEL_JOINT.upper())):
        lines += ['', '## ' + title, '', 'BA [block-bootstrap 95% interval over test blocks]; n/a = unavailable.', '']
        for task, ks in (('operation', OPERATION_K), ('workload', WORKLOAD_K)):
            body = [[p['name'], d] + [cell_text(find[(p['name'], d, task, feature, k)]) for k in ks]
                    for p in plans for d in (5, 10, 15, 20)]
            lines += ['%s classifier:' % task, ''] + table(['assignment', 'D ms'] + ['K=%d' % k for k in ks], body)
            lines.append('')
    checks = record['cross_check']
    lines += ['## Cross-check against formby_results.json', '',
              '%d of %d recorded cells reproduced exactly (native size = off, current size = size_only, current joint '
              '= combined; retrained NB).' % (sum(c['equal'] for c in checks), len(checks)), '',
              'Workload K=64 is unavailable: each block holds 33 mixed and 32 integrity READs, and windows never '
              'cross blocks. SELECT and OPERATE windows have identical size signatures; MultinomialNB then returns '
              'the first class in its sorted order (OPERATE), which the confusion matrices in the JSON show. '
              'Intervals of zero width reflect deterministic per-class sizes, not measurement precision.', '',
              '## Findings (%s)' % QUALIFIER, '']
    combos = [(t, f) for f in ('size', 'joint') for t in ('operation', 'workload')]

    def span(name, t, f):
        v = [x['balanced_accuracy'] for x in results
             if (x['assignment'], x['task'], x['feature']) == (name, t, f) and 'balanced_accuracy' in x]
        return '%.3f-%.3f' % (min(v), max(v))
    lines += table(['assignment'] + ['%s %s BA range over D, K' % (f, t) for t, f in combos] + ['added B/txn'],
                   [[p['name'] + ': ' + p['label']] + [span(p['name'], t, f) for t, f in combos] +
                    [p['overhead']['added_per_transaction']] for p in plans])
    same = all(x.get('balanced_accuracy') == find[('native',) + key[1:]].get('balanced_accuracy')
               for key, x in find.items() if key[0] == 'current' and key[3] == 'size')
    lines += ['', 'Joint columns are %s. Construction on the retained rows: %s responses at their current target '
              '(padded arms). Size-only scores of `current` %s the native ones in every D/K cell%s.' % (
                  LABEL_JOINT, ', '.join('%s %d/%d' % (arm, c['at_target'], c['responses'])
                                         for arm, c in sorted(record['construction'].items())),
                  'equal' if same else 'differ from',
                  ': the mapping relabels the native size classes without merging them, so the size leakage '
                  'measured by these classifiers remains' if same else '')]
    return '\n'.join(lines)


def write_csv(path, fields, records):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--rows', type=Path, default=ROWS)
    parser.add_argument('--output', type=Path, default=OUT)
    args = parser.parse_args(argv)
    citations, rules = check_rules(), load_rules()
    rows = fe.load_rows(args.rows)
    plans, read, sbo, results = run(rows, rules)
    record = dict(schema=SCHEMA, qualifier=QUALIFIER, joint_label=LABEL_JOINT, rules=citations, constants=rules,
                  inputs=dict(rows=str(args.rows), rows_sha256=sha(args.rows), formby_results_sha256=sha(FORMBY),
                              **{p: sha(ROOT / p) for p in sorted({c[0] for c in RULES})}),
                  analysis_sha256=sha(__file__), environment=dict(python=platform.python_version(),
                                                                  numpy=np.__version__, sklearn=sklearn.__version__),
                  reachable=dict(**{k: sorted(t for t, u in read[k].items() if u is not None) for k in WORKLOADS},
                                 sbo=sorted(t for t, parts in sbo.items() if len(parts) > 1),
                                 sbo_witness={str(t): p for t, p in sbo.items()},
                                 read_prefix_user={k: {str(t): u for t, u in read[k].items()} for k in WORKLOADS}),
                  assignments=plans, results=results, cross_check=cross_check(results),
                  construction={arm: dict(responses=sum(r['arm'] == arm for r in rows), at_target=sum(
                      r['arm'] == arm and r['resp_len'] == rules['current'][class_key(r)] for r in rows))
                      for arm in ('size_only', 'combined')})
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'padding_policy.json').write_text(json.dumps(record, indent=1, default=float) + '\n')
    write_csv(args.output / 'padding_policy_results.csv',
              ('assignment', 'd_ms', 'task', 'feature', 'k', 'rows_arm', 'balanced_accuracy', 'ci_lower', 'ci_upper',
               'test_windows', 'test_blocks', 'unavailable', 'label'),
              [dict(x, ci_lower=(x.get('ci') or {}).get('lower', ''), ci_upper=(x.get('ci') or {}).get('upper', ''))
               for x in results])
    write_csv(args.output / 'padding_policy_overhead.csv',
              ['assignment', 'attainable'] + ['%s_octets' % k for k in KEYS] + ['added_%s' % k for k in KEYS] +
              ['added_per_transaction', 'request_response_payload_pct', 'response_payload_pct'],
              [dict(assignment=p['name'], attainable=p['attainable'], **{'%s_octets' % k: p['sizes'][k] for k in KEYS},
                    **{'added_%s' % k: p['overhead']['per_class'][k] for k in KEYS}, **p['overhead']) for p in plans])
    (args.output / 'SUMMARY.md').write_text(summary(record) + '\n')
    print(json.dumps(dict(assignments={p['name']: p['sizes'] for p in plans}, results=len(results),
                          cross_check_mismatches=sum(not c['equal'] for c in record['cross_check'])), indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
