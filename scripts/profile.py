#!/usr/bin/env python3
"""Package the canonical P4 and its current, source-bound profile; never generate P4."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
MARKERS = {'N': '/* Generated isolated N protected reconnect candidate. */',
           'E': '/* Generated isolated E protected reconnect candidate. */',
           'T': '/* Generated isolated T reconnect candidate. */'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def role_hashes(text):
    result = {}
    for name in ('N', 'E', 'T'):
        marker = MARKERS[name]
        if text.count(marker) != 1:
            raise ValueError('canonical source must contain exactly one %s role marker' % name)
        start = text.index(marker)
        end = text.index(MARKERS[{'N': 'E', 'E': 'T'}[name]]) if name != 'T' else text.index('\nPipeline(')
        result[name] = hashlib.sha256(text[start:end].encode()).hexdigest()
    return result


def compiler_module():
    spec = importlib.util.spec_from_file_location('current_compiler_evidence', ROOT / 'scripts/build.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def package(output, source=None):
    """Create an exclusive build directory, with no artifact pins until compilation."""
    output = Path(output).resolve()
    source = Path(source or ROOT / 'p4/response_only.p4').resolve()
    template = ROOT / 'p4/profile_template.json'
    inputs = json.loads(template.read_text())
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(source, output / 'response_only.p4')
    digest = sha(output / 'response_only.p4')
    segments = role_hashes((output / 'response_only.p4').read_text())
    closure_paths = [Path(__file__).resolve(), ROOT / 'scripts/build.py', template]
    closure_paths.extend(sorted((ROOT / 'tests/fixtures/vectors').glob('*.json')))
    closure = {str(path.relative_to(ROOT)): sha(path) for path in closure_paths}
    closure['p4/response_only.p4'] = digest
    closure_digest = hashlib.sha256(json.dumps(closure, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    inputs.update(source_sha256=digest, segment_sha256=segments,
                  package_files=closure, package_sha256=closure_digest)
    candidate = dict(build=output.name, milestone=inputs['milestone'], source_sha256=digest,
                     segment_sha256=segments, artifact_sha256={})
    inputs['supported_profile']['candidate'] = candidate
    _write(output, inputs)
    return inputs


def _write(output, inputs):
    (output / 'response_only.inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (output / 'supported_profile.json').write_text(json.dumps(inputs['supported_profile'], indent=2) + '\n')


def verify_package(output):
    output = Path(output).resolve()
    inputs = json.loads((output / 'response_only.inputs.json').read_text())
    profile = json.loads((output / 'supported_profile.json').read_text())
    digest = sha(output / 'response_only.p4')
    segments = role_hashes((output / 'response_only.p4').read_text()) if inputs.get('source_sha256') == digest else None
    closure = inputs.get('package_files') or {}
    closure_digest = hashlib.sha256(json.dumps(closure, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    # The source snapshot is deliberately independent of later canonical edits. Every
    # other packaging input must still have exactly the bytes recorded for this build.
    closure_matches = bool(closure) and inputs.get('package_sha256') == closure_digest
    for name, expected in closure.items():
        path = output / 'response_only.p4' if name == 'p4/response_only.p4' else ROOT / name
        if Path(name).is_absolute() or '..' in Path(name).parts:
            closure_matches = False
        elif not path.is_file() or sha(path) != expected:
            closure_matches = False
    candidate = profile.get('candidate') or {}
    return dict(source_matches=inputs.get('source_sha256') == candidate.get('source_sha256') == digest,
                roles_match=segments is not None and segments == inputs.get('segment_sha256') == candidate.get('segment_sha256'),
                profiles_match=inputs.get('supported_profile') == profile,
                package_closure_matches=closure_matches)


def record_artifacts(output):
    """Pin only a verified SDK 9.13.2 compile of this exact source and package."""
    output = Path(output).resolve()
    if not all(verify_package(output).values()):
        raise ValueError('build package does not verify')
    inputs = json.loads((output / 'response_only.inputs.json').read_text())
    compiled = output / 'compile_local'
    manifest = json.loads((compiled / 'manifest.json').read_text())
    if manifest.get('exit_code') != 0 or manifest.get('source_sha256') != inputs['source_sha256']:
        raise ValueError('compile_local is not a successful compile of this source')
    if not re.match(r'^p4c\s+9\.13\.2(?:\s|$)', manifest.get('compiler', '')):
        raise ValueError('compile_local must use SDK 9.13.2')
    if not compiler_module().verify_evidence(compiled, source_root=output)['compiled_artifacts_verified']:
        raise ValueError('compile_local compiler evidence does not verify')
    artifacts = dict(manifest['artifact_sha256'])
    preprocessed = compiled / 'out/response_only.p4pp'
    if not preprocessed.is_file():
        raise ValueError('compile_local lacks preprocessed source')
    artifacts['response_only.p4pp'] = sha(preprocessed)
    inputs['supported_profile']['candidate']['artifact_sha256'] = {'compile_local': artifacts}
    _write(output, inputs)
    compiler_module().retain_evidence(compiled, source_root=output)
    return inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--compile', action='store_true')
    parser.add_argument('--event-logger', action='store_true')
    parser.add_argument('--record-artifacts', action='store_true')
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if args.verify:
        result = verify_package(args.output)
        print(json.dumps(result, indent=2))
        return 0 if all(result.values()) else 1
    if args.record_artifacts:
        record_artifacts(args.output)
    else:
        package(args.output, args.source)
        if args.compile:
            result = compiler_module().compile_candidate(args.output.resolve() / 'response_only.p4',
                args.output.resolve() / 'compile_local', event_logger=args.event_logger)
            if result['exit_code'] != 0:
                return result['exit_code']
            record_artifacts(args.output)
    print(json.dumps({'build': str(args.output), 'source_sha256': sha(args.output / 'response_only.p4')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
