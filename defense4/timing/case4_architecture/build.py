#!/usr/bin/env python3
"""Immutable TNA compile evidence. Never loads/configures a target device.

Installed-switch compiler evidence uses a read-only SSH compiler identity check.

Only owned source, logs and derived JSON are versioned. SDK artifacts stay under
ignored out/; qualification must recheck their actual bytes on the current host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

DEFAULT_COMPILER = Path('/home/philip/bf-sde-9.13.1/install/bin/bf-p4c')
SWITCH_BUILD_HOST = 'decps@10.10.54.81'
SWITCH_COMPILER = '/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c'


def compiler_identity_matches(report):
    if 'compiler_host' not in report:
        compiler = Path(report['compiler_path'])
        return compiler.is_file() and sha(compiler) == report.get('compiler_sha256')
    if (report['compiler_host'] != SWITCH_BUILD_HOST or
            report['compiler_path'] != SWITCH_COMPILER):
        return False
    try:
        result = subprocess.run(
            ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', SWITCH_BUILD_HOST,
             'sha256sum ' + SWITCH_COMPILER], capture_output=True, text=True,
            timeout=12, check=True)
        return result.stdout.split()[0] == report.get('compiler_sha256')
    except (OSError, subprocess.SubprocessError, IndexError):
        return False


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files(source):
    """Resolve project-local quoted includes; system SDK files aren't copied."""
    root = source.parent
    pending = [source]
    result = {}
    while pending:
        path = pending.pop().resolve()
        if path in result:
            continue
        relative = path.relative_to(root)
        result[path] = str(relative)
        for name in re.findall(r'^\s*#\s*include\s*"([^"]+)"', path.read_text(), re.M):
            dependency = (path.parent / name).resolve()
            # Reject escapes: all owned dependencies must be in the source tree.
            dependency.relative_to(root)
            if not dependency.is_file():
                raise FileNotFoundError(dependency)
            pending.append(dependency)
    return result


def pipeline_contexts(out):
    """Use the compiler's pipeline inventory, including every functional pipe."""
    inventory = out / 'manifest.json'
    if not inventory.is_file():
        return {'pipe': Path('pipe/context.json')}
    manifest = json.loads(inventory.read_text())
    result = {}
    for program in manifest['programs']:
        for pipe in program['pipes']:
            path = Path(pipe['files']['context']['path'])
            if path.is_absolute() or '..' in path.parts or path.name != 'context.json':
                raise ValueError('invalid compiler context path')
            name = pipe['pipe_name']
            if name in result:
                raise ValueError('duplicate compiler pipeline name')
            result[name] = path
    if not result:
        raise ValueError('compiler pipeline inventory is empty')
    return result


def required_artifacts(out):
    required = {'bfrt.json'}
    for path in pipeline_contexts(out).values():
        required.update((str(path), str(path.parent / 'tofino.bin')))
    if (out / 'manifest.json').is_file():
        required.add('manifest.json')
    return required


def pipe_resources(out, context_path):
    context = json.loads((out / context_path).read_text())

    def stages(node):
        if isinstance(node, dict):
            if 'stage_number' in node:
                yield node['stage_number']
            for value in node.values():
                yield from stages(value)
        elif isinstance(node, list):
            for value in node:
                yield from stages(value)

    tables = context['tables']
    result = {'stages': {}, 'tables_by_type': {}, 'stateful_tables': []}
    for direction in ('ingress', 'egress'):
        result['stages'][direction] = 1 + max(
            (n for table in tables if table.get('direction') == direction
             for n in stages(table)), default=-1)
    for table in tables:
        key = table.get('table_type', 'unknown')
        result['tables_by_type'][key] = result['tables_by_type'].get(key, 0) + 1
        if key == 'stateful':
            result['stateful_tables'].append({k: table[k] for k in
                ('name', 'direction', 'size') if k in table})
    logs = out / context_path.parent / 'logs'
    summary = logs / 'table_summary.log'
    if summary.is_file():
        final = summary.read_text().rsplit('Table allocation done', 1)[-1]
        match = re.search(r'Critical path length through the table dependency graph: (\d+)', final)
        if match:
            result['critical_path'] = int(match[1])
    # Keep resource bytes local; retain content identities rather than SDK text.
    result['report_sha256'] = {str(p.relative_to(out)): sha(p)
        for p in logs.glob('*') if p.is_file() and
        any(name in p.name for name in ('phv', 'mau.resources', 'table_summary', 'dependency'))}
    return result


def resource_summary(out):
    pipes = {name:pipe_resources(out, path) for name, path in pipeline_contexts(out).items()}
    if set(pipes) == {'pipe'}:
        return pipes['pipe']  # Preserve existing single-pipe evidence format.
    result = {'pipes':pipes, 'stages':{direction:max(
        p['stages'][direction] for p in pipes.values()) for direction in ('ingress','egress')},
        'tables_by_type':{}, 'stateful_tables':[], 'report_sha256':{}}
    for name, pipe in pipes.items():
        for kind, count in pipe['tables_by_type'].items():
            result['tables_by_type'][kind] = result['tables_by_type'].get(kind, 0) + count
        result['stateful_tables'].extend(dict(table, pipeline=name) for table in pipe['stateful_tables'])
        result['report_sha256'].update(pipe['report_sha256'])
    lengths = [p['critical_path'] for p in pipes.values() if 'critical_path' in p]
    if lengths:
        result['critical_path'] = max(lengths)
    return result


def compile_candidate(source, output, compiler=DEFAULT_COMPILER, *, timeout=300, defines=()):
    source, output, compiler = Path(source).resolve(), Path(output).resolve(), Path(compiler).resolve()
    files = source_files(source)
    output.mkdir(parents=True, exist_ok=False)
    snapshot = output / 'source'
    snapshot.mkdir()
    source_hashes = {}
    for path, relative in files.items():
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        source_hashes[relative] = sha(target)
    command = [str(compiler), '--target', 'tofino', '--arch', 'tna', '-g',
               *['-D' + value for value in defines], '-o', str(output / 'out'),
               str(snapshot / source.name)]
    report = {'source': str(source), 'source_sha256': sha(snapshot / source.name),
              'source_files': source_hashes, 'compiler_path': str(compiler),
              'command': command, 'timeout_seconds': timeout,
              'milestone': 'compile_failed', 'full_target': False,
              'artifact_sha256': {}}
    start = time.monotonic()
    try:
        report['compiler_sha256'] = sha(compiler)
        version = subprocess.run([str(compiler), '--version'], capture_output=True,
                                 text=True, timeout=10, check=True)
        report['compiler'] = version.stdout.strip()
        with (output / 'compile.log').open('w') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                report['exit_code'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                terminate_group(process)
                report.update(exit_code=124, timed_out=True)
            except BaseException:
                terminate_group(process)
                report.update(exit_code=130, interrupted=True)
                raise
        if report['exit_code'] == 0:
            out = output / 'out'
            report['resources'] = resource_summary(out)
            report['artifact_sha256'] = {str(p.relative_to(out)): sha(p)
                for p in out.rglob('*') if p.is_file() and
                (p.name in ('bfrt.json', 'context.json', 'tofino.bin', 'manifest.json')
                 or p.suffix in ('.conf', '.bfa'))}
            required = required_artifacts(out)
            if not all(name in report['artifact_sha256'] for name in required):
                raise ValueError('successful compiler omitted required artifacts')
            report['milestone'] = 'primitive_compiled'
    except Exception as exc:
        report.setdefault('exit_code', 125)
        report['evidence_error'] = f'{type(exc).__name__}: {exc}'
        report['milestone'] = 'evidence_failed'
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - start, 3)
        log = output / 'compile.log'
        if log.is_file():
            report['compile_log_sha256'] = sha(log)
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def terminate_group(process):
    """Compiler helpers must not continue after cancellation or timeout."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    # A helper can ignore SIGTERM even when its parent has exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def verify_evidence(output):
    output = Path(output)
    report = json.loads((output / 'manifest.json').read_text())
    source_root = Path(report['source']).parent
    identity_matches = report['source_files'].get(Path(report['source']).name) == report['source_sha256']
    source_matches = identity_matches and all((source_root / name).is_file() and
        sha(source_root / name) == expected for name, expected in report['source_files'].items())
    snapshots_match = all((output / 'source' / name).is_file() and
        sha(output / 'source' / name) == expected for name, expected in report['source_files'].items())
    try:
        required = required_artifacts(output / 'out')
    except (OSError, ValueError, KeyError):
        required = {'invalid-pipeline-inventory'}
    artifact_matches = required <= report['artifact_sha256'].keys() and all(
        (output / 'out' / name).is_file() and sha(output / 'out' / name) == expected
        for name, expected in report['artifact_sha256'].items())
    log_matches = (output / 'compile.log').is_file() and (
        sha(output / 'compile.log') == report.get('compile_log_sha256'))
    compiler_matches = compiler_identity_matches(report)
    resources_match = False
    if artifact_matches:
        try:
            resources_match = resource_summary(output / 'out') == report.get('resources')
        except (OSError, ValueError, KeyError):
            pass
    return {'source_matches': source_matches, 'snapshots_match': snapshots_match,
            'compiler_matches': compiler_matches,
            'compiled_artifacts_verified': bool(report['exit_code'] == 0 and
                report['milestone'] == 'primitive_compiled' and source_matches and
                snapshots_match and artifact_matches and log_matches and resources_match and compiler_matches),
            'full_target': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--compiler', type=Path, default=DEFAULT_COMPILER)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('-D', dest='defines', action='append', default=[])
    args = parser.parse_args()
    result = compile_candidate(args.source, args.output, args.compiler,
                               timeout=args.timeout, defines=args.defines)
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(result['exit_code'] or (1 if 'evidence_error' in result else 0))


if __name__ == '__main__':
    main()
