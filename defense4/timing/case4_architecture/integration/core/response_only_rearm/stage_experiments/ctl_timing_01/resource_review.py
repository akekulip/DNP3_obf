#!/usr/bin/env python3
"""Resource review of one ctl_timing build: per-role stages (N/E/T) and mirror guard for each compile present,
against the candidate61 baseline, plus E byte-identity and the artifact hashes the sealed profile pins.

  python3 resource_review.py BUILD_DIR      # writes BUILD_DIR/resource_review.json
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASELINE = HERE / 'evidence/m10_03'
sys.path.insert(0, str(HERE.parents[2] / 'response_only'))   # core/response_only: check_mirror_select
import check_mirror_select as cms  # noqa: E402

spec = importlib.util.spec_from_file_location('ctl_generate', HERE / 'generate.py')
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stage_numbers(node):
    if isinstance(node, dict):
        if 'stage_number' in node:
            yield node['stage_number']
        for value in node.values():
            yield from stage_numbers(value)
    elif isinstance(node, list):
        for value in node:
            yield from stage_numbers(value)


def placement(context):
    result = {}
    for direction in ('ingress', 'egress'):
        tables = [t for t in context['tables'] if (t.get('direction') or t.get('gress')) == direction]
        numbers = sorted({n for t in tables for n in stage_numbers(t) if type(n) is int and n >= 0})
        result[direction] = dict(occupied_indices=numbers, occupied_count=len(numbers),
            maximum_occupied_stage=max(numbers) if numbers else None,
            stage_span=max(numbers) - min(numbers) + 1 if numbers else 0,
            stateful=[dict(name=t['name'], size=t.get('size'), stages=sorted(set(stage_numbers(t))))
                      for t in tables if t.get('table_type') == 'stateful'])
    return result


def layout(out):
    result = {}
    for pipe, names in (('p0', {'ingress': 'N', 'egress': 'E'}),
                        ('p1', {'ingress': 'T', 'egress': 'p1_egress'})):
        context = json.loads((Path(out) / pipe / 'context.json').read_text())
        dependency = Path(out) / pipe / 'logs/table_dependency_summary.log'
        lines = dependency.read_text().splitlines() if dependency.is_file() else []
        for direction, record in placement(context).items():
            record.update(pipeline=pipe, direction=direction,
                dependency_chain_note='Raw SDK dependency-report levels; occupied indices above come from context.json.',
                critical_dependency_chains=[line.strip() for line in lines
                    if ' -> ' in line and line.rstrip().endswith('(' + direction + ')')])
            result[names[direction]] = record
    return result


def stages(out):
    # Keep the historical field's meaning (maximum index + 1); placement gives actual count and span.
    return {name: (record['maximum_occupied_stage'] + 1 if record['occupied_count'] else 0)
            for name, record in layout(out).items() if name != 'p1_egress'}


def resources(out):
    """Count physical resource units; shared/unattributed units remain at pipeline granularity."""
    result = {}
    kinds = {'sram': ('rams', 'srams'), 'tcam': ('tcams', 'tcams'),
             'stateful_alu': ('meter_alus', 'meters'), 'crossbar_bytes': ('xbar_bytes', 'bytes')}
    for pipe in ('p0', 'p1'):
        logs = Path(out) / pipe / 'logs'
        resource_file, phv_file = logs / 'resources.json', logs / 'phv.json'
        if not resource_file.is_file():
            result[pipe] = {'available': False}
            continue
        raw = json.loads(resource_file.read_text())['resources']
        totals = {kind: 0 for kind in kinds}
        per = {direction: dict(totals) for direction in ('ingress', 'egress', 'shared_or_unattributed')}
        for stage in raw['mau']['mau_stages']:
            for kind, (group, key) in kinds.items():
                for unit in stage[group][key]:
                    usages = unit.get('usages', [])
                    if kind == 'stateful_alu' and not any(u.get('used_for') == 'stateful_ram' for u in usages):
                        continue
                    directions = set()
                    for usage in usages:
                        name = usage.get('used_by', '')
                        if name.startswith(('n_Ingress.', 't_Ingress.')):
                            directions.add('ingress')
                        elif name.startswith('r_Egress.'):
                            directions.add('egress')
                    direction = next(iter(directions)) if len(directions) == 1 else 'shared_or_unattributed'
                    totals[kind] += 1
                    per[direction][kind] += 1
        phv = json.loads(phv_file.read_text()) if phv_file.is_file() else None
        pressure = {}
        if phv is not None:
            for direction in ('ingress', 'egress'):
                containers = [c for c in phv['containers'] if c['gress'] == direction and c.get('slices')]
                pressure[direction] = dict(allocated_containers=len(containers),
                    allocated_capacity_bits=sum(c['bit_width'] for c in containers))
        result[pipe] = dict(available=True, pipeline_totals=totals, attributed=per, phv=pressure,
            mirror_resources={d['gress']: d.get('mirror_table') for d in raw.get('deparser', [])},
            report_sha256={p.name: sha(p) for p in (resource_file, phv_file) if p.is_file()})
    return result


def review(build):
    build = Path(build)
    text = (build / 'response_only.p4').read_text()
    out = {'candidate_sha256': sha(build / 'response_only.p4'),
           'E_byte_identical': gen.combined.segment(text, 'E') == gen.combined.segment(
               (BASELINE / 'response_only.p4').read_text(), 'E'),
           'E_sha256': hashlib.sha256(gen.combined.segment(text, 'E').encode()).hexdigest(),
           'baseline_source_sha256': sha(BASELINE / 'response_only.p4'), 'compiles': {}}
    for compile_dir in ('compile_local', 'compile_switch_9132'):
        o = build / compile_dir / 'out'
        manifest = build / compile_dir / 'manifest.json'
        if not manifest.is_file():
            out['compiles'][compile_dir] = {'present': False}
            continue
        m = json.loads(manifest.read_text())
        ok, notes = cms.check_out(o)
        base_out = BASELINE / compile_dir / 'out'
        out['compiles'][compile_dir] = {
            'compiler': m.get('compiler'), 'exit_code': m.get('exit_code'), 'source_sha256': m.get('source_sha256'),
            'stages': stages(o), 'baseline_stages': stages(base_out) if base_out.is_dir() else None,
            'placement': layout(o), 'resources': resources(o),
            'mirror_guard': ('PASS ' if ok else 'FAIL ') + ';'.join(notes),
            'bfrt_json_sha256': sha(o / 'bfrt.json'), 'p4pp_sha256': sha(o / 'response_only.p4pp')}
    out['source_matches_compiles'] = all(c.get('source_sha256') == out['candidate_sha256']
                                         for c in out['compiles'].values() if c.get('present', True))
    return out


if __name__ == '__main__':
    result = review(sys.argv[1])
    (Path(sys.argv[1]) / 'resource_review.json').write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    print(json.dumps({k: (v if k != 'compiles' else {n: (c.get('stages'), c.get('mirror_guard', '')[:4])
                                                       for n, c in v.items()}) for k, v in result.items()}, indent=1))
