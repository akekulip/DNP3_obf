#!/usr/bin/env python3
"""Compare verified final SDK placement and resources of explicit builds.

Stage depth is max occupied MAU stage + 1. PHV allocation is compiler accounting.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
C69 = ROOT / 'results/builds/c69_baseline'
PER_STAGE = ('Logical TableID', 'Meter ALU', 'SRAM', 'TCAM', 'Gateway', 'VLIW Instr')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resources(build):
    compiled = build / 'compile_local'
    spec = importlib.util.spec_from_file_location('compiler_evidence', ROOT / 'scripts/build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    verification = module.verify_evidence(compiled, source_root=build)
    if not verification['compiled_artifacts_verified'] and (compiled / 'compiler_evidence.json').is_file():
        verification = module.restore_evidence(compiled, source_root=build)
    if not verification['compiled_artifacts_verified']:
        raise ValueError('compiler evidence does not verify: ' + str(build))
    manifest = json.loads((compiled / 'manifest.json').read_text())
    result = {'source_sha256': sha(build / 'response_only.p4'), 'compiler': manifest['compiler'],
              'verification': verification, 'pipes': {}, 'report_sha256': {}}
    for pipe, context_file in module.pipeline_contexts(compiled / 'out').items():
        context = json.loads((compiled / 'out' / context_file).read_text())
        logs = compiled / 'out' / context_file.parent / 'logs'
        mau = logs / 'mau.resources.log'
        rows = [line for line in mau.read_text().splitlines() if line.startswith('|')]
        header = next(line for line in rows if 'Stage Number' in line)
        total = next(line for line in rows if line.split('|')[1].strip() == 'Totals')
        keys = [value.strip() for value in header.split('|')[2:-1]]
        values = [int(value.strip()) for value in total.split('|')[2:-1]]
        if len(keys) != len(values):
            raise ValueError('compiler resource columns disagree')
        summaries = list(logs.glob('phv_allocation_summary_*.log'))
        phv = max(summaries, key=lambda p: int(re.search(r'_(\d+)\.log$', p.name).group(1)))
        phv_row = next(line for line in phv.read_text().splitlines() if '| Overall PHV Usage |' in line)
        tables = context['tables']
        state = sorted(t['name'] for t in tables if t['table_type'] == 'stateful')
        names = sorted(t['name'] for t in tables)
        result['pipes'][pipe] = {'stages': manifest['resources']['pipes'][pipe]['stages'],
            'allocated_mau_totals': dict(zip(keys, values)), 'stateful_tables': state,
            'stateful_table_count': len(state), 'table_names': names,
            'compiler_phv_summary': phv_row.strip()}
        for path in (mau, phv):
            result['report_sha256'][str(path.relative_to(build))] = sha(path)
    return result


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
    result = resources(build)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--baseline', type=Path, default=C69)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    base, candidate = measure(args.baseline.resolve()), measure(args.candidate.resolve())
    depths = {pipe: item['stages'] for pipe, item in candidate['pipes'].items()}
    target = (depths['p0']['ingress'] <= 10 and depths['p0']['egress'] <= 10
              and depths['p1']['ingress'] <= 8 and depths['p1']['egress'] <= 4)
    report = {'schema': 'current-resource-comparison-v1', 'baseline': base, 'candidate': candidate,
              'candidate_minus_baseline': delta(base, candidate),
              'stage_target_met': target, 'hardware_evaluated': False}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'out': str(args.out), 'stage_target_met': target, 'depths': depths}))


if __name__ == '__main__':
    main()
