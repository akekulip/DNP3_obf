#!/usr/bin/env python3
"""Offline source/artifact consistency gate; passing never authorizes deployment."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from defense4.timing.stage_reduction.build import context_stages, final_allocation


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _artifact(build, paths, expected_hash):
    """Check every retained copy; gz hashes refer to the original compiler bytes."""
    found = []
    payload = None
    for relative in paths:
        path = build / relative
        if not path.exists():
            continue
        data = gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()
        _require(_sha(data) == expected_hash, 'artifact hash mismatch: ' + relative)
        found.append(relative)
        payload = data
    _require(bool(found), 'missing artifact: ' + ' or '.join(paths))
    return payload, found


def verify_build(source, build_dir):
    source, build = Path(source), Path(build_dir)
    result = {'passed': False, 'deployment_authorized': False,
              'scope': 'Offline current-source/compiler-artifact consistency and stage limit only.',
              'source': str(source), 'build_dir': str(build), 'errors': []}
    try:
        manifest = json.loads((build / 'manifest.json').read_text())
        expected_source = manifest['source_sha256']
        current_hash = _sha(source.read_bytes())
        snapshot_hash = _sha((build / 'defense4_timing.p4').read_bytes())
        result['source_sha256'] = current_hash
        _require(current_hash == snapshot_hash == expected_source,
                 'current source, immutable build snapshot, and manifest source hash must match')
        _require(type(manifest['exit_code']) is int and manifest['exit_code'] == 0,
                 'compiler did not exit successfully')
        _require(isinstance(manifest.get('compiler'), str) and bool(manifest['compiler'].strip()),
                 'missing compiler identity')
        command = manifest['command']
        _require(isinstance(command, list) and all(isinstance(x,str) for x in command),
                 'compiler command must be an argument array')
        _require('-DU_BOR' in command or '-DU_BOR=1' in command,
                 'compiler command missing enabled U_BOR flag')
        _require(not any(x.startswith('-UU_BOR') for x in command) and
                 not any(x.startswith('-DU_BOR=') and x != '-DU_BOR=1' for x in command) and
                 not any(command[i] in ('-U','-D') and command[i+1].split('=')[0] == 'U_BOR' for i in range(len(command)-1)),
                 'ambiguous or disabled U_BOR command flags')
        _require(bool(command) and Path(command[-1]).name == 'defense4_timing.p4',
                 'compiler command must compile the immutable source snapshot')
        hashes = manifest['artifact_sha256']
        context_bytes, context_paths = _artifact(build, ('context.json.gz','context.json','out/pipe/context.json'), hashes['pipe/context.json'])
        bfrt_bytes, bfrt_paths = _artifact(build, ('bfrt.json','out/bfrt.json'), hashes['bfrt.json'])
        context = json.loads(context_bytes)
        bfrt = json.loads(bfrt_bytes)
        _require(isinstance(context.get('tables'),list) and isinstance(bfrt.get('tables'),list),
                 'context and BFRT must contain table arrays')
        actual = context_stages(context)
        result['context_stages'] = actual
        _require(manifest['context_stages'] == actual,
                 'manifest context-stage count disagrees with retained context')
        summaries = [p for p in (build/'table_summary.log',build/'out/pipe/logs/table_summary.log') if p.exists()]
        _require(bool(summaries), 'missing final table allocation report')
        for summary in summaries:
            final = final_allocation(summary.read_text())
            _require(all(manifest.get(k) == v for k,v in final.items()),
                     'manifest disagrees with final allocation report: ' + str(summary))
            _require(all(final[k] == v for k,v in actual.items()),
                     'final allocation report disagrees with context stages')
        _require(0 < actual['ingress_stages'] <= 7 and actual['egress_stages'] == 0,
                 'stage limit requires at most 7 ingress and exactly 0 egress stages')
        result.update(passed=True, compiler=manifest['compiler'],
                      verified_artifacts={'context': context_paths, 'bfrt': bfrt_paths},
                      artifact_sha256={k: hashes[k] for k in ('pipe/context.json','bfrt.json')})
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError) as exc:
        result['errors'].append(str(exc))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('build_dir', type=Path)
    args = parser.parse_args(argv)
    report = verify_build(args.source, args.build_dir)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
