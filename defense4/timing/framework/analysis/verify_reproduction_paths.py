#!/usr/bin/env python3
"""Run the unchanged campaign gate on a verified path-normalized temporary view.

Only provenance path strings with identical metadata and verified SHA-256 content
can change. Frozen data, original reproduction output and publication gate remain
untouched. The result records each relocation rather than hiding gate failures.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
GATE = ROOT / 'defense4/timing/evidence/campaign_v2/repro/publication_gate.py'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(reproduction, output):
    spec = importlib.util.spec_from_file_location('frozen_campaign_gate', GATE)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    relocations = []

    def normalize(a, b, field):
        if isinstance(a, dict) and isinstance(b, dict):
            if 'path' in a and 'sha256' in a:
                if {k: v for k, v in a.items() if k != 'path'} != {k: v for k, v in b.items() if k != 'path'}:
                    raise ValueError('content or metadata differs: '+field)
                actual = ROOT / a['path']
                if sha(actual) != a['sha256']:
                    raise ValueError('regenerated provenance hash invalid: '+field)
                replacement = dict(a, path=b['path'])
                if a['path'] != b['path']:
                    relocations.append(dict(field=field, regenerated_path=a['path'],
                        published_path=b['path'], verified_sha256=a['sha256']))
                return replacement
            if a.keys() != b.keys():
                raise ValueError('metadata keys differ: '+field)
            return {k: normalize(a[k], b[k], field+'.'+k) for k in a}
        if isinstance(a, list) and isinstance(b, list):
            if len(a) != len(b):
                raise ValueError('input denominator differs: '+field)
            return [normalize(x, y, field+f'[{i}]') for i, (x, y) in enumerate(zip(a, b))]
        if a != b:
            raise ValueError('non-path metadata differs: '+field)
        return a

    with tempfile.TemporaryDirectory(prefix='campaign_path_gate_') as tmp:
        view = Path(tmp)
        for p in reproduction.iterdir():
            if p.name != 'figs':
                (view / p.name).symlink_to(p.resolve(), target_is_directory=p.is_dir())
        (view / 'figs').mkdir()
        for p in (reproduction / 'figs').iterdir():
            dest = view / 'figs' / p.name
            if not p.name.endswith('.provenance.json'):
                dest.symlink_to(p.resolve())
                continue
            a = json.loads(p.read_text())
            b = json.loads((gate.PUB_FIGS / p.name).read_text())
            normalized = copy.deepcopy(a)
            normalized['inputs'] = normalize(a['inputs'], b['inputs'], p.name+'.inputs')
            for key in ('pdf', 'data_csv'):
                normalized['outputs'][key] = normalize(a['outputs'][key], b['outputs'][key],
                    p.name+'.outputs.'+key)
            dest.write_text(json.dumps(normalized, indent=1)+'\n')
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = gate.main(view, update=False)
    record = dict(passed=code == 0, gate_sha256=sha(GATE),
        scope='Unchanged strict publication/content/hash gate on verified relocated provenance paths; no acquisition or frozen edits',
        reproduction=str(reproduction.relative_to(ROOT)), relocations=relocations,
        stdout=stdout.getvalue())
    output.write_text(json.dumps(record, indent=2)+'\n')
    print(stdout.getvalue(), end='')
    print('Verified path relocations:', len(relocations))
    return code


if __name__ == '__main__':
    raise SystemExit(main(Path(sys.argv[1]).resolve(), Path(sys.argv[2])))
