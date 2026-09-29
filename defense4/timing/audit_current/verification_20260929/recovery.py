#!/usr/bin/env python3
"""Verify frozen files and recover compressed evidence without overwriting conflicts."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def safe_path(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unsafe manifest path')
    target = (root / relative).resolve()
    if root.resolve() not in target.parents:
        raise ValueError('Escaping manifest path')
    return target


def pack(root, relative, archive_root):
    source = safe_path(root, relative)
    target = safe_path(archive_root, str(relative) + '.gz')
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as inp, target.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=6) as out:
            shutil.copyfileobj(inp, out)
    entry = dict(path=str(relative), size=source.stat().st_size, sha256=digest(source),
                 archive=str(target.relative_to(archive_root)), archive_sha256=digest(target))
    verify_archive(entry, archive_root)
    return entry


def verify_archive(entry, archive_root):
    path = safe_path(archive_root, entry['archive'])
    if digest(path) != entry['archive_sha256']:
        raise ValueError('Changed archive: ' + entry['archive'])
    h = hashlib.sha256(); count = 0
    with gzip.open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk); count += len(chunk)
    if h.hexdigest() != entry['sha256'] or count != entry['size']:
        raise ValueError('Incorrect archive payload: ' + entry['path'])


def restore_entry(entry, archive_root, destination):
    target = safe_path(destination, entry['path'])
    verify_archive(entry, archive_root)
    if target.exists():
        if digest(target) != entry['sha256']:
            raise ValueError('Restore conflict: ' + entry['path'])
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as temp:
        tmp = Path(temp.name)
        try:
            with gzip.open(safe_path(archive_root, entry['archive']), 'rb') as inp:
                shutil.copyfileobj(inp, temp)
            temp.flush()
            if digest(tmp) != entry['sha256']:
                raise ValueError('Archive changed during restore')
            # Atomic creation refuses to overwrite a concurrent writer.
            os.link(tmp, target)
        finally:
            tmp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['verify', 'frozen', 'restore'])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.command == 'frozen':
        entries = json.loads((HERE / 'frozen_inputs.json').read_text())['files']
        bad = [e['path'] for e in entries if not safe_path(args.root,e['path']).exists()
               or digest(safe_path(args.root,e['path'])) != e['sha256']]
        if bad:
            raise ValueError('Frozen files changed: ' + repr(bad))
        print(f'{len(entries)} frozen files unchanged')
        return
    manifest = json.loads((HERE / 'recovery_manifest.json').read_text())
    for entry in manifest['direct']:
        if digest(safe_path(args.root, entry['path'])) != entry['sha256']:
            raise ValueError('Changed direct input: ' + entry['path'])
    for entry in manifest['compressed']:
        if args.command == 'restore':
            if args.destination is None:
                parser.error('restore requires --destination')
            restore_entry(entry, HERE / 'recovery', args.destination)
        else:
            verify_archive(entry, HERE / 'recovery')
    print(f"Verified {len(manifest['direct'])} direct files and {len(manifest['compressed'])} compressed artifacts")


if __name__ == '__main__':
    main()
