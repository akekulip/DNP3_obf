#!/usr/bin/env python3
"""Retain closed c69 model logs for the existing restore_retained_logs.py.

Run after each model gate, or once after all runs finish. Missing launch records
are skipped. Existing raw logs, archives, and RAW_SHA256SUMS are never replaced.
Compression streams through one low-priority Python thread with xz preset 6.
"""
import hashlib
import json
import lzma
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[2]
REPO = STAGE.parents[6]
EVIDENCE = STAGE / 'ctl_timing_01/evidence'
MANIFEST = HERE / 'manifest.json'
SOURCE_SHA256 = '5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59'


def stream_hash(source, output=None):
    digest, size = hashlib.sha256(), 0
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
        digest.update(chunk)
        size += len(chunk)
        if output is not None:
            output.write(chunk)
    return digest.hexdigest(), size


def file_hash(path):
    with path.open('rb') as source:
        return stream_hash(source)


def relative(path):
    return str(path.relative_to(REPO))


def stable_stat(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def closed_run(run):
    launch_path, closure_path = run / 'launch_command.json', run / 'dependency_closure.json'
    if not launch_path.is_file() or not closure_path.is_file():
        return None
    launch_bytes, closure_bytes = launch_path.read_bytes(), closure_path.read_bytes()
    launch = json.loads(launch_bytes)
    if type(launch.get('exit_code')) is not int:
        return None
    closure = json.loads(closure_bytes)
    closure_sha = hashlib.sha256(closure_bytes).hexdigest()
    if launch.get('dependency_closure_sha256') != closure_sha:
        raise ValueError('%s: final closure does not match launch pin' % run.name)
    if launch.get('source_sha256') != SOURCE_SHA256 or launch.get('hardware') is not False:
        raise ValueError('%s: source/hardware scope mismatch' % run.name)
    return launch, closure, launch_bytes, closure_bytes


def archive_log(log, previous, closure):
    before = stable_stat(log)
    archive = log.with_name(log.name + '.xz')
    staged_archive = None
    raw_sha, raw_bytes = file_hash(log)
    closure_pin = closure.get('postchecks', {}).get('reset_application', {}).get('input_sha256', {}).get(log.name)
    if closure_pin is not None and raw_sha != closure_pin:
        raise ValueError('%s: raw bytes do not match reset closure pin' % log)
    if archive.exists():
        with lzma.open(archive, 'rb') as source:
            restored_sha, restored_bytes = stream_hash(source)
        if (restored_sha, restored_bytes) != (raw_sha, raw_bytes):
            raise ValueError('%s: existing archive differs from raw log' % archive)
    else:
        # Stage outside the evidence tree; publish with exclusive creation only.
        with tempfile.TemporaryFile() as staged:
            with log.open('rb') as source, lzma.LZMAFile(staged, 'wb', preset=6) as output:
                compressed_raw_sha, compressed_raw_bytes = stream_hash(source, output)
            if (compressed_raw_sha, compressed_raw_bytes) != (raw_sha, raw_bytes):
                raise ValueError('%s: raw log changed during compression' % log)
            if stable_stat(log) != before:
                raise ValueError('%s: raw log changed during compression' % log)
            staged.seek(0)
            with lzma.LZMAFile(staged, 'rb') as source:
                restored_sha, restored_bytes = stream_hash(source)
            if (restored_sha, restored_bytes) != (raw_sha, raw_bytes):
                raise ValueError('%s: staged archive round-trip failed' % log)
            staged.seek(0)
            with archive.open('xb') as output:
                staged_archive = stream_hash(staged, output)
    if stable_stat(log) != before:
        raise ValueError('%s: raw log changed during retention' % log)
    archive_sha, archive_bytes = file_hash(archive)
    if staged_archive is not None and staged_archive != (archive_sha, archive_bytes):
        raise ValueError('%s: published archive differs from verified staged bytes' % archive)
    record = dict(archive=relative(archive), archive_bytes=archive_bytes,
                  archive_sha256=archive_sha, raw_bytes=raw_bytes, sha256=raw_sha)
    if previous is not None and previous != record:
        raise ValueError('%s: existing retention pins differ' % log)
    return record


def retain_run(run, manifest):
    snapshot = closed_run(run)
    if snapshot is None:
        print('skip %s (no completed launch and final closure)' % run.name, flush=True)
        return
    launch, closure, launch_bytes, closure_bytes = snapshot
    logs = sorted({run / 'model.out'} | set(run.glob('model_*.log')))
    if not all(log.is_file() for log in logs):
        raise ValueError('%s: completed run lacks model.out' % run.name)
    records = {relative(log): archive_log(log, manifest['logs'].get(relative(log)), closure) for log in logs}
    checksums = ''.join('%s  %s\n' % (records[relative(log)]['sha256'], log.name) for log in logs)
    sums = run / 'RAW_SHA256SUMS'
    if sums.exists():
        if sums.read_text() != checksums:
            raise ValueError('%s: existing raw checksum file differs' % run.name)
    else:
        with sums.open('x') as output:
            output.write(checksums)
    results = {}
    for result in sorted(run.glob('*results.json')):
        result_sha, result_bytes = file_hash(result)
        results[result.name] = dict(sha256=result_sha, bytes=result_bytes,
                                   summary=json.loads(result.read_text()).get('summary'))
    if ((run / 'launch_command.json').read_bytes() != launch_bytes
            or (run / 'dependency_closure.json').read_bytes() != closure_bytes):
        raise ValueError('%s: completion records changed during retention' % run.name)
    record = dict(exit_code=launch['exit_code'], launch_sha256=hashlib.sha256(launch_bytes).hexdigest(),
                  dependency_closure_sha256=hashlib.sha256(closure_bytes).hexdigest(),
                  logs=list(records), results=results)
    previous = manifest['runs'].get(relative(run))
    if previous is not None and previous != record:
        raise ValueError('%s: existing retained run metadata differs' % run.name)
    manifest['logs'].update(records)
    manifest['runs'][relative(run)] = record
    print('ok %s: exit=%s, %s logs' % (run.name, launch['exit_code'], len(logs)), flush=True)


def main():
    os.nice(10)
    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else dict(
        candidate='c69', source_sha256=SOURCE_SHA256, compression='xz preset 6, single thread',
        scope='Byte-exact model.out and model_*.log retention for completed fresh c69 attempts, '
              'including failed fixtures. Final closure bytes must match each launch pin. '
              'Raw files and completion evidence are preserved; retention does not qualify a run.',
        logs={}, runs={})
    if manifest.get('candidate') != 'c69' or manifest.get('source_sha256') != SOURCE_SHA256:
        raise ValueError('retention manifest source/candidate mismatch')
    for run in sorted(EVIDENCE.glob('model_*_m12p_c69_sdk9132_*')):
        if run.is_dir():
            retain_run(run, manifest)
    rendered = json.dumps(manifest, indent=2, sort_keys=True) + '\n'
    # Only this manifest is mutable; preserve a valid JSON file across interruption.
    if not MANIFEST.exists() or MANIFEST.read_text() != rendered:
        with tempfile.NamedTemporaryFile('w', dir=HERE, delete=False, prefix='.manifest-', suffix='.tmp') as output:
            output.write(rendered)
            staged = Path(output.name)
        staged.replace(MANIFEST)
    print('retained %s logs from %s completed c69 attempts' % (len(manifest['logs']), len(manifest['runs'])))


if __name__ == '__main__':
    main()
