#!/usr/bin/env python3
"""Retain and restore logs only for the explicit current build's selected model attempts."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import tempfile

VERSION = 'current-model-log-retention-v1'
MANIFEST = 'model_log_retention.json'
STDOUT_VERSION = 'current-model-stdout-retention-v1'
STDOUT_MANIFEST = 'model_stdout_retention.json'   # separate: launch_command.json binds MANIFEST's hash
STDOUT_NAMES = ('model_stdout.txt', 'startup_stdout.txt')
ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def decoded_identity(archive):
    result, size = hashlib.sha256(), 0
    with lzma.open(str(archive), 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            result.update(chunk)
            size += len(chunk)
    return result.hexdigest(), size


def _paths(run, record):
    raw, archive = record.get('raw', ''), record.get('archive', '')
    if (record.get('schema') != VERSION or not re.fullmatch(r'model_[A-Za-z0-9_.-]+\.log', raw)
            or archive != raw + '.xz'):
        raise ValueError('invalid retained log name or schema')
    return Path(run) / raw, Path(run) / archive


def archive_run(run, preserve_startup_stdout=False):
    """Compress one completed attempt and prove its decoded bytes before dropping stdout."""
    run = Path(run).resolve()
    logs = list(run.glob('model_*.log'))
    if len(logs) != 1:
        raise ValueError('completed attempt requires exactly one model log')
    raw = logs[0]
    archive = raw.with_name(raw.name + '.xz')
    raw_hash, raw_size = sha(raw), raw.stat().st_size
    if not archive.exists():
        with tempfile.NamedTemporaryFile(dir=str(run), prefix='.model_archive_', delete=False) as temp:
            temporary = Path(temp.name)
        try:
            with raw.open('rb') as source, lzma.open(str(temporary), 'wb', preset=1) as target:
                shutil.copyfileobj(source, target, 1 << 20)
            if decoded_identity(temporary) != (raw_hash, raw_size):
                raise ValueError('compressed model log failed its round-trip check')
            os.link(str(temporary), str(archive))
        finally:
            temporary.unlink()
    if decoded_identity(archive) != (raw_hash, raw_size):
        raise ValueError('existing model archive is not this raw log')
    record = dict(schema=VERSION, raw=raw.name, raw_sha256=raw_hash, raw_bytes=raw_size,
                  archive=archive.name, archive_sha256=sha(archive), archive_bytes=archive.stat().st_size)
    destination = run / MANIFEST
    if destination.exists() and json.loads(destination.read_text()) != record:
        raise ValueError('retained model log identity changed')
    destination.write_text(json.dumps(record, indent=2) + '\n')
    # Prune stdout only when its exact bytes are already retained. Otherwise
    # preserve it under an unignored name; overlap is not proof of duplication.
    stdout = run / 'model.out'
    if stdout.is_file():
        stdout_hash = sha(stdout)
        if stdout_hash == raw_hash and stdout.stat().st_size == raw_size:
            stdout.unlink()
        else:
            preserved = run / ('startup_stdout.txt' if preserve_startup_stdout else 'model_stdout.txt')
            kept = _retained_stdout_record(run, preserved.name)
            if not preserved.exists() and kept:
                # the preserved stdout now lives as verified XZ: compare against its recorded raw identity
                if (kept['raw_sha256'], kept['raw_bytes']) != (stdout_hash, stdout.stat().st_size):
                    raise ValueError('distinct model stdout already retained under the selected name')
                stdout.unlink()  # verified duplicate of the retained stdout
            elif preserved.exists():
                if sha(preserved) != stdout_hash:
                    raise ValueError('distinct model stdout already retained under the selected name')
                stdout.unlink()  # verified duplicate of the preserved stdout
            else:
                stdout.rename(preserved)
    compress_stdout(run)   # distinct stdout is kept as verified XZ, restorable by hash
    return record


def _compress_verified(raw, archive):
    raw_hash, raw_size = sha(raw), raw.stat().st_size
    with tempfile.NamedTemporaryFile(dir=str(raw.parent), prefix='.model_archive_', delete=False) as temp:
        temporary = Path(temp.name)
    try:
        with raw.open('rb') as source, lzma.open(str(temporary), 'wb', preset=1) as target:
            shutil.copyfileobj(source, target, 1 << 20)
        if decoded_identity(temporary) != (raw_hash, raw_size):
            raise ValueError('compressed stdout failed its round-trip check')
        os.link(str(temporary), str(archive))
    finally:
        temporary.unlink()
    return raw_hash, raw_size


def _retained_stdout_record(run, name):
    path = Path(run) / STDOUT_MANIFEST
    return json.loads(path.read_text())['files'].get(name) if path.is_file() else None


def compress_stdout(run):
    """Replace a preserved distinct stdout with a verified XZ copy; the raw bytes stay restorable by hash."""
    run = Path(run).resolve()
    destination = run / STDOUT_MANIFEST
    records = json.loads(destination.read_text())['files'] if destination.is_file() else {}
    for name in STDOUT_NAMES:
        raw, archive = run / name, run / (name + '.xz')
        if not raw.is_file():
            continue
        if archive.exists():
            if decoded_identity(archive) != (sha(raw), raw.stat().st_size):
                raise ValueError('existing stdout archive is not this raw stdout: ' + str(archive))
            raw_hash, raw_size = sha(raw), raw.stat().st_size
        else:
            raw_hash, raw_size = _compress_verified(raw, archive)
        record = dict(raw_sha256=raw_hash, raw_bytes=raw_size, archive=archive.name, archive_sha256=sha(archive))
        if name in records and records[name] != record:
            raise ValueError('retained stdout identity changed: ' + name)
        records[name] = record
        destination.write_text(json.dumps(dict(schema=STDOUT_VERSION, files=records), indent=2) + '\n')
        raw.unlink()
    return records


def restore_stdout(run):
    run = Path(run).resolve()
    destination = run / STDOUT_MANIFEST
    if not destination.is_file():
        return []
    restored = []
    manifest = json.loads(destination.read_text())
    if manifest.get('schema') != STDOUT_VERSION:
        raise ValueError('invalid stdout retention schema')
    for name, record in sorted(manifest['files'].items()):
        if name not in STDOUT_NAMES or record.get('archive') != name + '.xz':
            raise ValueError('invalid retained stdout name')
        raw, archive = run / name, run / record['archive']
        if not archive.is_file() or sha(archive) != record['archive_sha256']:
            raise ValueError('retained stdout archive hash differs: ' + str(archive))
        if raw.exists():
            if sha(raw) != record['raw_sha256'] or raw.stat().st_size != record['raw_bytes']:
                raise ValueError('restored stdout hash differs: ' + str(raw))
            continue
        with tempfile.NamedTemporaryFile(dir=str(run), prefix='.model_restore_', delete=False) as target:
            temporary = Path(target.name)
            try:
                with lzma.open(str(archive), 'rb') as source:
                    shutil.copyfileobj(source, target, 1 << 20)
                target.flush()
                if sha(temporary) != record['raw_sha256'] or temporary.stat().st_size != record['raw_bytes']:
                    raise ValueError('decoded retained stdout hash differs')
                os.link(str(temporary), str(raw))
            finally:
                temporary.unlink()
        restored.append(raw)
    return restored


def restore_run(run):
    run = Path(run).resolve()
    record = json.loads((run / MANIFEST).read_text())
    raw, archive = _paths(run, record)
    if not archive.is_file() or sha(archive) != record['archive_sha256']:
        raise ValueError('retained model archive hash differs: ' + str(archive))
    if raw.exists():
        if sha(raw) != record['raw_sha256'] or raw.stat().st_size != record['raw_bytes']:
            raise ValueError('restored log hash differs: ' + str(raw))
        restore_stdout(run)
        return raw
    with tempfile.NamedTemporaryFile(dir=str(run), prefix='.model_restore_', delete=False) as target:
        temporary = Path(target.name)
        try:
            with lzma.open(str(archive), 'rb') as source:
                shutil.copyfileobj(source, target, 1 << 20)
            target.flush()
            if sha(temporary) != record['raw_sha256'] or temporary.stat().st_size != record['raw_bytes']:
                raise ValueError('decoded retained model log hash differs')
            os.link(str(temporary), str(raw))
        finally:
            temporary.unlink()
    restore_stdout(run)
    return raw


def selected_runs(build):
    import model_summary
    latest = {}
    for item in model_summary.attempts(Path(build).resolve()):
        driver = item['driver']
        if driver not in latest or item['attempt'] > latest[driver]['attempt']:
            latest[driver] = item
    root = model_summary.model_root(build)
    return [root / latest[driver]['run'] for driver in sorted(latest)]


def restore_selected(build):
    problems = []
    for run in selected_runs(build):
        try:
            restore_run(run)
        except (OSError, ValueError, KeyError, lzma.LZMAError) as error:
            problems.append('%s: retained model log: %s' % (run.name, error))
    return problems


def retained_files(build):
    """Freeze inventory for selected attempts; raw logs can be restored from these pins."""
    result = []
    for run in selected_runs(build):
        result.extend(path for path in run.rglob('*') if path.is_file()
                      and '__pycache__' not in path.parts and path.name != 'model.out'
                      and path.name not in STDOUT_NAMES
                      and not re.fullmatch(r'model_.*\.log', path.name)
                      and not path.name.startswith('.model_'))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('archive', 'restore', 'compress-stdout'))
    parser.add_argument('build', type=Path)
    args = parser.parse_args()
    if args.mode == 'archive':
        for run in selected_runs(args.build):
            archive_run(run)
        problems = []
    elif args.mode == 'compress-stdout':
        import model_summary
        problems = []
        for run in sorted(path for path in model_summary.model_root(args.build).glob('model_*') if path.is_dir()):
            try:
                compress_stdout(run)
            except (OSError, ValueError, lzma.LZMAError) as error:
                problems.append('%s: %s' % (run.name, error))
    else:
        problems = restore_selected(args.build)
    print(json.dumps({'build': str(args.build), 'selected_attempts': len(selected_runs(args.build)),
                      'problems': problems}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
