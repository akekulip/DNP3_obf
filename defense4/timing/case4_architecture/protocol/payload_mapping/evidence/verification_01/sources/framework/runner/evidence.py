"""Exclusive acquisition directories, immutable inputs, and retained failure records.

Reservation is deliberately separate from execution: reserve before compilation,
namespace creation or capture. An inner namespace may claim the reservation once;
there is no overwrite, resume or force path. Interrupted runs retain reservation
and event files and have no successful completion record.
"""
import hashlib
import json
import os
import time
import traceback
import uuid
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


class EvidenceRun:
    def __init__(self, path, token):
        self.path, self.token = Path(path), token

    def _target(self, name):
        target = self.path / name
        target.resolve().relative_to(self.path.resolve())
        return target

    def write_bytes(self, name, data):
        if (self.path / 'completion.json').exists():
            raise FileExistsError('evidence run is already complete')
        target = self._target(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        return target

    def write_json(self, name, value):
        return self.write_bytes(name, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())

    def snapshot(self, source, name=None):
        source = Path(source)
        return self.write_bytes('sources/' + (name or source.name), source.read_bytes())

    def record(self, event, **details):
        if (self.path / 'completion.json').exists():
            raise FileExistsError('evidence run is already complete')
        directory = self.path / 'events'
        directory.mkdir(exist_ok=True)
        sequence = len(list(directory.glob('*.json')))
        return self.write_json('events/%06d.json' % sequence,
                               dict(event=event, time_ns=time.time_ns(), pid=os.getpid(), **details))

    def finish(self, status, details):
        if status not in ('passed', 'failed', 'blocked', 'aborted'):
            raise ValueError('invalid evidence completion status')
        if (self.path / 'completion.json').exists():
            raise FileExistsError('evidence run is already complete')
        self.record('completion', status=status)
        files = {str(p.relative_to(self.path)): sha256(p)
                 for p in sorted(self.path.rglob('*')) if p.is_file() and not p.is_symlink()}
        return self.write_json('completion.json', dict(status=status, details=details,
                                                       files_sha256=files, token=self.token))

    def __enter__(self):
        self.record('started')
        return self

    def __exit__(self, typ, value, tb):
        if typ is not None and not (self.path / 'completion.json').exists():
            self.finish('aborted' if issubclass(typ, KeyboardInterrupt) else 'failed', {'exception': str(value), 'exception_type': typ.__name__,
                                   'traceback': ''.join(traceback.format_exception(typ, value, tb))})
        elif not (self.path / 'completion.json').exists():
            self.finish('blocked', {'reason': 'execution ended without an explicit verdict'})
        return False


def reserve_run(path, metadata):
    """Atomically create a fresh run; existing files/directories/symlinks fail."""
    path = Path(path).absolute()
    # Validate serialisability before claiming the path, then use mkdir itself
    # as the exclusion primitive; a prior exists check would race.
    json.dumps(metadata)
    path.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex
    run = EvidenceRun(path, token)
    run.write_json('reservation.json', dict(token=token, metadata=metadata,
                                            reserved_ns=time.time_ns(), pid=os.getpid()))
    return run


def claim_run(path, token):
    """One-shot transfer to an inner acquisition process, never a resume."""
    path = Path(path).absolute()
    reservation = json.loads((path / 'reservation.json').read_text())
    if token != reservation['token']:
        raise ValueError('reservation token mismatch')
    if (path / 'completion.json').exists():
        raise FileExistsError('completed evidence cannot be claimed')
    run = EvidenceRun(path, token)
    run.write_json('claim.json', dict(token=token, claimed_ns=time.time_ns(), pid=os.getpid()))
    return run
