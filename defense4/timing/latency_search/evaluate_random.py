#!/usr/bin/env python3
"""Use frozen development attacks with a time-matched OFF block per repetition."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evaluate as base


def midpoint(rows):
    times = sorted(int(row['t_req_ns']) for row in rows)
    if not times:
        raise ValueError('empty timestamp group')
    return (times[(len(times)-1)//2] + times[len(times)//2]) // 2


def paired_rows(rows, name):
    protected = [r for r in rows if r['arm']=='obfuscated' and r['policy_name']==name]
    if not protected:
        raise ValueError('unknown protected policy '+name)
    chosen = {}
    selected = list(protected)
    for group in sorted({r['session'] for r in protected}):
        target = midpoint([r for r in protected if r['session']==group])
        candidates = {}
        for row in rows:
            if row['arm']=='native' and row['session']==group:
                candidates.setdefault(row['block'], []).append(row)
        if not candidates:
            raise ValueError('no paired OFF block in '+group)
        block = min(candidates, key=lambda key:(abs(midpoint(candidates[key])-target),
                                               midpoint(candidates[key]), key))
        chosen[group] = {'block':block, 'midpoint_ns':midpoint(candidates[block]),
                         'protected_midpoint_ns':target,
                         'distance_ns':abs(midpoint(candidates[block])-target)}
        selected.extend(candidates[block])
    return sorted(selected, key=lambda r:(r['session'],r['arm'],r['block'],int(r['txn_index']))), chosen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--measurements', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=12)
    parser.add_argument('--quick', action='store_true')
    args = parser.parse_args()
    measurement = json.loads(args.measurements.read_text())
    source_sha = hashlib.sha256(args.input.read_bytes()).hexdigest()
    if measurement.get('status') != 'ok' or measurement.get('primary_csv_sha256') != source_sha:
        parser.error('requires a completed, restored and hash-matched acquisition summary')
    rows = base.read_rows(args.input)
    if len(rows) != measurement['row_count'] or args.jobs < 1:
        parser.error('row-count mismatch or invalid job count')
    names = sorted({r['policy_name'] for r in rows if r['arm']=='obfuscated'})
    if not names:
        parser.error('no protected policies')
    code_sha = hashlib.sha256(b''.join(path.read_bytes() for path in
        (Path(__file__), HERE/'evaluate.py', HERE/'analysis.py'))).hexdigest()
    cache_key = {'source_sha256':source_sha,'code_sha256':code_sha,
                 'quick':args.quick,'sklearn_version':base.sklearn.__version__}
    result = dict(cache_key, measurements_sha256=hashlib.sha256(args.measurements.read_bytes()).hexdigest(),
                  tuning_grid=base.PARAMS, per_policy={}, off_pairing={}, complete_attack_coverage=False,
                  pairing_rule='nearest OFF midpoint within repetition; earlier-time tie break')
    cache = args.out.parent / ('attack_cache_quick' if args.quick else 'attack_cache')
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        pending = {}
        for name in names:
            paired, chosen = paired_rows(rows,name)
            result['off_pairing'][name] = chosen
            pending[executor.submit(base.cached_evaluate,paired,name,args.quick,cache_key,cache)] = name
        for future in as_completed(pending):
            name = pending[future]
            result['per_policy'][name] = future.result()
            result['complete_attack_coverage'] = not args.quick and len(result['per_policy'])==len(names)
            base.save(args.out,result)
            print('DONE',name,{k:round(v['envelopes']['ack_response']['max_accuracy'],3)
                  for k,v in result['per_policy'][name]['tasks'].items()},flush=True)


if __name__=='__main__':
    main()
