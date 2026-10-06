#!/usr/bin/env python3
"""Account for every exchange; independently labelled arrival groups are never inferred."""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import json
import math
from pathlib import Path
import numpy as np

REQUIRED = ('transaction_id','da_ms','requested_gap_ms','realized_gap_ms','request_ns','ack_ns','response_ns','arrival_group','outcome','body_equal')


def _number(value, name):
    try:
        n = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('invalid ' + name) from exc
    if not math.isfinite(n):
        raise ValueError('nonfinite ' + name)
    return n


def _timestamp(value, name, optional=False):
    if value in ('', None) and optional:
        return None
    try:
        n = int(value)
    except (ValueError, TypeError) as exc:
        raise ValueError('invalid timestamp ' + name) from exc
    if str(n) != str(value) or n < 0:
        raise ValueError('expected nonnegative integer ' + name)
    return n


def _stats(values):
    if not values:
        return {'n': 0, 'mean': None, 'sample_variance': None, 'sd': None,
                'quantiles': {}, 'max': None}
    a = np.asarray(values, dtype=float)
    return {'n': len(values), 'mean': float(np.mean(a)),
            'sample_variance': float(np.var(a, ddof=1)) if len(a)>1 else None,
            'sd': float(np.std(a, ddof=1)) if len(a)>1 else None,
            'quantiles': {str(q): float(np.quantile(a,q)) for q in (0.5,0.9,0.95,0.99,0.999)},
            'max': float(np.max(a))}


def analyze_rows(rows, min_group_samples=200, min_normal_samples=6000, profile='full', expected_ids=None):
    if min_group_samples < 1 or min_normal_samples < 1 or profile not in ('full','smoke','custom'):
        raise ValueError('invalid profile/sample minimum')
    if profile == 'full':
        min_group_samples = max(200, min_group_samples)
        min_normal_samples = max(6000, min_normal_samples)
    elif profile == 'smoke':
        min_normal_samples = max(100, min_normal_samples)
    records, seen = [], set()
    for raw in rows:
        if any(k not in raw for k in REQUIRED):
            raise ValueError('missing required column')
        r = dict(raw)
        ident = r['transaction_id']
        if not ident or ident in seen:
            raise ValueError('empty/duplicate transaction_id: ' + str(ident))
        seen.add(ident)
        for key in ('da_ms','requested_gap_ms','realized_gap_ms'):
            r[key] = _number(r[key], key)
        if r['da_ms'] not in (5,10,15,20) or r['requested_gap_ms'] != 1 or r['realized_gap_ms'] != 0.999936:
            raise ValueError('row does not match approved DA/gap configuration')
        for key in ('request_ns','ack_ns','response_ns'):
            r[key] = _timestamp(r[key], key, key != 'request_ns')
        req, ack, resp = (r[k] for k in ('request_ns','ack_ns','response_ns'))
        if (ack is not None and ack < req) or (resp is not None and resp < req):
            raise ValueError('noncausal timestamps')
        if r['arrival_group'] not in ('early','late','unknown') or r['outcome'] not in ('normal','watchdog','bypass','failure'):
            raise ValueError('invalid arrival_group/outcome')
        val = r['body_equal']
        if val is True or val == 'true': r['body_equal'] = True
        elif val is False or val == 'false': r['body_equal'] = False
        elif val in ('', None, 'unknown'): r['body_equal'] = None
        else: raise ValueError('body_equal must be true/false/unknown')
        r['retransmit_count'] = _timestamp(r.get('retransmit_count'), 'retransmit_count', True)
        records.append(r)
    manifest = None if expected_ids is None else list(expected_ids)
    if manifest is not None and (any(not isinstance(i, str) or not i for i in manifest) or len(set(manifest)) != len(manifest)):
        raise ValueError('expected IDs must be unique nonempty strings')
    missing_ids = sorted(set(manifest or []) - seen)
    unexpected_ids = sorted(seen - set(manifest or [])) if manifest is not None else []
    manifest_ok = manifest is not None and not missing_ids and not unexpected_ids
    counts = dict(Counter(r['outcome'] for r in records))
    counts.update(total=len(records), planned_total=len(manifest) if manifest is not None else None, missing_planned=len(missing_ids), unexpected=len(unexpected_ids), ordering_violations=sum(r['ack_ns'] is not None and r['response_ns'] is not None and r['response_ns'] < r['ack_ns'] for r in records), missing_response=sum(r['response_ns'] is None for r in records),
                  missing_ack=sum(r['ack_ns'] is None for r in records),
                  body_mismatch=sum(r['body_equal'] is False for r in records),
                  body_unverified=sum(r['body_equal'] is None for r in records),
                  retransmit_unknown=sum(r['retransmit_count'] is None for r in records),
                  retransmits_observed=sum(r['retransmit_count'] or 0 for r in records))
    by_da = {}
    for da in sorted({r['da_ms'] for r in records}):
        da_rows = [r for r in records if r['da_ms'] == da]
        normal = [r for r in da_rows if r['outcome'] == 'normal']
        groups = {'total':len(da_rows), 'normal':len(normal), 'normal_coverage': 'sufficient' if len(normal)>=min_normal_samples else 'insufficient', 'outcomes':dict(Counter(r['outcome'] for r in da_rows))}
        groups['all_observed_latency'] = {
            'request_to_ack_us': _stats([(r['ack_ns'] - r['request_ns']) / 1000 for r in da_rows if r['ack_ns'] is not None]),
            'request_to_response_us': _stats([(r['response_ns'] - r['request_ns']) / 1000 for r in da_rows if r['response_ns'] is not None]),
        }
        for group in ('all','early','late','unknown'):
            selected = [r for r in normal if (group == 'all' or r['arrival_group'] == group) and r['ack_ns'] is not None and r['response_ns'] is not None]
            clrt = [(r['response_ns'] - r['ack_ns'])/1000 for r in selected]
            errors = [abs(x-r['realized_gap_ms']*1000) for x,r in zip(clrt,selected)]
            median = float(np.median(errors)) if errors else None
            fraction = sum(e <= 50 for e in errors)/len(errors) if errors else None
            groups[group] = {'n':len(selected), 'coverage':'sufficient' if len(selected)>=min_group_samples else 'insufficient', 'clrt_us':_stats(clrt), 'request_to_ack_us':_stats([(r['ack_ns'] - r['request_ns']) / 1000 for r in selected]), 'request_to_response_us':_stats([(r['response_ns'] - r['request_ns']) / 1000 for r in selected]), 'absolute_error_us':_stats(errors), 'median_absolute_error_us':median, 'fraction_within_50us':fraction, 'timing_pass':bool(errors and median<=10 and fraction>=0.999)}
        groups['accepted'] = (groups['normal_coverage'] == 'sufficient' and
                              all(groups[g]['coverage'] == 'sufficient' and groups[g]['timing_pass'] for g in ('early','late')) and
                              groups['all']['timing_pass'] and
                              all(r['outcome'] == 'normal' and r['body_equal'] is True and r['ack_ns'] is not None and r['response_ns'] is not None and r['response_ns'] >= r['ack_ns'] for r in da_rows))
        by_da[str(int(da))] = groups
    delivery_ok = bool(records) and all(r['outcome']=='normal' and r['body_equal'] is True and r['ack_ns'] is not None and r['response_ns'] is not None and r['response_ns'] >= r['ack_ns'] for r in records)
    coverage = bool(by_da) and all(d['normal_coverage']=='sufficient' and all(d[g]['coverage']=='sufficient' for g in ('early','late')) for d in by_da.values())
    timing_ok = bool(by_da) and all(all(d[g]['timing_pass'] for g in ('all','early','late')) for d in by_da.values())
    subgroup_coverage = coverage
    if profile == 'full':
        coverage = coverage and set(by_da) == {'5','10','15','20'}
    elif profile == 'smoke':
        coverage = bool(by_da) and all(d['normal_coverage'] == 'sufficient' for d in by_da.values())
        timing_ok = bool(by_da) and all(d['all']['timing_pass'] for d in by_da.values())
        for d in by_da.values():
            d['accepted'] = d['normal_coverage'] == 'sufficient' and d['all']['timing_pass'] and delivery_ok
    retransmit_verified = bool(records) and counts['retransmit_unknown'] == 0 and counts['retransmits_observed'] == 0
    evidence_ok = manifest_ok and retransmit_verified
    if profile != 'custom':
        for da, d in by_da.items():
            da_rows = [r for r in records if r['da_ms'] == int(da)]
            d['accepted'] = d['accepted'] and manifest_ok and all(r['retransmit_count'] == 0 for r in da_rows)
    accepted = delivery_ok and coverage and timing_ok and (profile == 'custom' or evidence_ok)
    return {'profile':profile, 'min_group_samples':min_group_samples, 'min_normal_samples':min_normal_samples,
            'counts':counts, 'by_da':by_da, 'delivery_integrity_pass':delivery_ok,
            'coverage':'sufficient' if coverage else 'insufficient', 'timing_pass':timing_ok,
            'accepted':accepted, 'full_acceptance':accepted and profile == 'full',
            'subgroup_coverage':'sufficient' if subgroup_coverage else 'insufficient',
            'retransmission_evidence_pass':retransmit_verified,
            'manifest_verified':manifest_ok, 'missing_transaction_ids':missing_ids, 'unexpected_transaction_ids':unexpected_ids,
            'latency_measurement':'Observed request-to-ACK and request-to-response durations in microseconds; no added latency is inferred without a reference.',
            'scope':'Full profile requires all four DAs; smoke/custom evaluate DA values present.',
            'arrival_evidence':'arrival_group labels are supplied by the caller and must be verified against independent evidence'}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('csv', type=Path)
    ap.add_argument('--profile', choices=('full','smoke','custom'), default='full')
    ap.add_argument('--min-group-samples', type=int, default=200)
    ap.add_argument('--min-normal-samples', type=int)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--expected-ids', type=Path, help='JSON array of every planned transaction ID')
    a = ap.parse_args(argv)
    with a.csv.open(newline='') as stream:
        report = analyze_rows(csv.DictReader(stream), a.min_group_samples,
                              a.min_normal_samples if a.min_normal_samples is not None else (100 if a.profile=='smoke' else 6000), a.profile, None if a.expected_ids is None else json.loads(a.expected_ids.read_text()))
    text = json.dumps(report, indent=2, sort_keys=True, allow_nan=False)+'\n'
    if a.output: a.output.write_text(text)
    else: print(text,end='')
    return 0 if report['accepted'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
