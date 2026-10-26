#!/usr/bin/env python3
"""Read-only compiler comparison; writes only the requested derived report."""
import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

STAGE = Path(__file__).resolve().parents[3]
ARCH = STAGE.parents[3]
sys.path.insert(0, str(STAGE / 'm12_fullsize'))
from m12gen.common import combined

J_NAMES = {'op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg', 'operate_generation_access',
           'operate_anchor_access', 'op_go_check', 'operate_completion_access', 'hb_verdict'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resources(build):
    compiled = build / 'compile_local'
    spec = importlib.util.spec_from_file_location('compiler_evidence', ARCH / 'build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    verification = module.verify_evidence(compiled, source_root=build)
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


def compare(baseline, candidate):
    old, new = resources(baseline), resources(candidate)
    old_source, new_source = [(build / 'response_only.p4').read_text() for build in (baseline, candidate)]
    identical = {role: combined.segment(old_source, role) == combined.segment(new_source, role)
                 for role in ('N', 'E')}
    names = new['pipes']['p1']['table_names']
    retired = [name for name in names if name.split('.')[-1] in J_NAMES]
    if retired or not all(identical.values()):
        raise ValueError('retired J table remains or N/E source changed: ' + repr(retired))
    if old['pipes']['p1']['stateful_table_count'] - new['pipes']['p1']['stateful_table_count'] != 3:
        raise ValueError('three J stateful banks were not removed')
    delta = {}
    for pipe in old['pipes']:
        a, b = old['pipes'][pipe], new['pipes'][pipe]
        delta[pipe] = {key: b['allocated_mau_totals'][key] - value
                       for key, value in a['allocated_mau_totals'].items()}
        if max(b['stages'].values()) > 12:
            raise ValueError('candidate exceeds the device stage limit')
    return {'schema': 'c69-compiler-resource-comparison-v1', 'baseline': old, 'candidate': new,
            'n_e_source_identical': identical, 'retired_j_tables_remaining': retired,
            'candidate_minus_baseline_mau_totals': delta, 'hardware_evaluated': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    evidence = STAGE / 'ctl_timing_01/evidence'
    report = compare(evidence / 'm12p_c68_sdk9132', evidence / 'm12p_c69_sdk9132')
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'out': str(args.out), 'delta': report['candidate_minus_baseline_mau_totals']}))
