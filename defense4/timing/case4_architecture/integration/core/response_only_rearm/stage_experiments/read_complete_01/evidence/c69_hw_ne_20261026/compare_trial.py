#!/usr/bin/env python3
"""Read-only final-placement comparison of one resource-experiment candidate against c69 (and a retained one).

  python3 compare_trial.py CANDIDATE_BUILD --out REPORT.json [--also RETAINED_BUILD]

Reuses resources() from the c69 comparator (c69_no_operate_hold_20261026/compare_resources.py, left unchanged; its
compare() asserts c69-specific facts and is not used). Reads only the final compiler reports of a verified compile:
per-gress stages, MAU totals, per-stage MAU rows (pipe level), PHV group usage and stateful tables.

Retention rule, fixed before any trial compile: a candidate is RETAINED only if no gress stage count increases, no
pipe exceeds 12 stages, none of SRAM, TCAM, Map RAM, Meter ALU or PHV containers/bits used increases in any pipe, and
at least one of those or a gress stage count strictly decreases. Everything else is reported but does not decide.
"""
import argparse
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[2]
EVIDENCE = STAGE / 'ctl_timing_01/evidence'
C69 = EVIDENCE / 'm12p_c69_sdk9132'
PHYSICAL = ('SRAM', 'TCAM', 'Map RAM', 'Meter ALU')
PER_STAGE = ('Logical TableID', 'Meter ALU', 'SRAM', 'TCAM', 'Gateway', 'VLIW Instr')

_spec = importlib.util.spec_from_file_location('c69_compare_resources',
                                               HERE.parent / 'c69_no_operate_hold_20261026/compare_resources.py')
_c69 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_c69)


def _table(rows):
    header = [h.strip() for h in rows[0].split('|')[1:-1]]
    return [dict(zip(header, (v.strip() for v in row.split('|')[1:-1]))) for row in rows[1:]]


def details(build):
    """Per-stage MAU rows and PHV usage per pipe, from the same final reports resources() hashes."""
    out = {}
    for logs in sorted((build / 'compile_local/out').glob('p*/logs')):
        rows = [l for l in (logs / 'mau.resources.log').read_text().splitlines() if l.startswith('|')]
        start = next(i for i, l in enumerate(rows) if 'Stage Number' in l)
        end = next(i for i in range(start + 1, len(rows)) if not rows[i].split('|')[1].strip().isdigit())
        stages = _table(rows[start:end])          # the allocated-count table only (a percentage table follows)
        summaries = list(logs.glob('phv_allocation_summary_*.log'))
        phv = max(summaries, key=lambda p: int(re.search(r'_(\d+)\.log$', p.name).group(1))).read_text().splitlines()
        groups = [l for l in phv if l.startswith('|') and not l.startswith('|-')]
        head = next(i for i, l in enumerate(groups) if 'MAU Group' in l)
        usage = {r['MAU Group']: {k: int(v.split()[0]) for k, v in r.items() if k != 'MAU Group'}
                 for r in _table(groups[head:]) if r['MAU Group'].startswith(('Usage', 'Overall'))}
        out[logs.parent.name] = {
            'per_stage': {int(r['Stage Number']): {k: int(r[k]) for k in PER_STAGE} for r in stages},
            'phv_usage': usage}
    return out


def measure(build):
    result = _c69.resources(build)
    for pipe, extra in details(build).items():
        result['pipes'][pipe].update(extra)
    return result


def delta(base, cand):
    out = {}
    for pipe in base['pipes']:
        a, b = base['pipes'][pipe], cand['pipes'][pipe]
        out[pipe] = {
            'stages': {g: b['stages'][g] - a['stages'][g] for g in a['stages']},
            'mau_totals': {k: b['allocated_mau_totals'][k] - v for k, v in a['allocated_mau_totals'].items()},
            'phv_overall': {k: b['phv_usage']['Overall PHV Usage'][k] - v
                            for k, v in a['phv_usage']['Overall PHV Usage'].items()},
            'stateful_table_count': b['stateful_table_count'] - a['stateful_table_count'],
            'per_stage': {s: {k: b['per_stage'].get(s, {}).get(k, 0) - a['per_stage'].get(s, {}).get(k, 0)
                              for k in PER_STAGE}
                          for s in sorted(set(a['per_stage']) | set(b['per_stage']))}}
    return out


def verdict(base, cand):
    d = delta(base, cand)
    worse, better = [], []
    for pipe, x in d.items():
        if max(cand['pipes'][pipe]['stages'].values()) > 12:
            worse.append('%s exceeds 12 stages' % pipe)
        for gress, change in x['stages'].items():
            (worse if change > 0 else better if change < 0 else []).append('%s %s stages %+d' % (pipe, gress, change))
        for key in PHYSICAL:
            change = x['mau_totals'][key]
            (worse if change > 0 else better if change < 0 else []).append('%s %s %+d' % (pipe, key, change))
        for key in ('Containers Used', 'Bits Used'):
            change = x['phv_overall'][key]
            (worse if change > 0 else better if change < 0 else []).append('%s PHV %s %+d' % (pipe, key, change))
    return {'retained': bool(better) and not worse, 'improved': better, 'worsened': worse, 'delta': d}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--also', type=Path, help='a previously retained candidate to compare against as well')
    args = parser.parse_args()
    base, cand = measure(C69), measure(args.candidate.resolve())
    report = {'schema': 'c69-trial-resource-comparison-v1', 'rule': __doc__.split('Retention rule, ')[1].strip(),
              'baseline': base, 'candidate': cand, 'versus_c69': verdict(base, cand), 'hardware_evaluated': False}
    if args.also:
        report['versus_retained'] = verdict(measure(args.also.resolve()), cand)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'out': str(args.out), 'versus_c69': {k: report['versus_c69'][k]
                                                           for k in ('retained', 'improved', 'worsened')}}, indent=1))


if __name__ == '__main__':
    main()
