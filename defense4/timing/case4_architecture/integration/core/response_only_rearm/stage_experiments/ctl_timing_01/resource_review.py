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
BASELINE = HERE.parent / 'seg61_02/evidence/full_04'
sys.path.insert(0, str(HERE.parents[2] / 'response_only'))   # core/response_only: check_mirror_select
import check_mirror_select as cms  # noqa: E402

spec = importlib.util.spec_from_file_location('ctl_generate', HERE / 'generate.py')
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stages(out):
    res = {}
    for pipe, names in (('p0', {'ingress': 'N', 'egress': 'E'}), ('p1', {'ingress': 'T'})):
        context = json.loads((Path(out) / pipe / 'context.json').read_text())
        per = {}
        for table in context['tables']:
            gress = table.get('direction') or table.get('gress')
            for st in table.get('stage_tables', []):
                per.setdefault(gress, set()).add(st['stage_number'])
        for gress, numbers in per.items():
            if gress in names:
                res[names[gress]] = max(numbers) + 1
    return res


def review(build):
    build = Path(build)
    text = (build / 'response_only.p4').read_text()
    out = {'candidate_sha256': sha(build / 'response_only.p4'),
           'E_byte_identical': gen.combined.segment(text, 'E') == gen.combined.segment(gen.frozen(), 'E'),
           'E_sha256': hashlib.sha256(gen.combined.segment(text, 'E').encode()).hexdigest(),
           'compiles': {}}
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
