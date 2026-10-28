"""Prune historical raw files only after their adjacent XZ reproduces every byte."""
import concurrent.futures
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'results/analysis/duplicate_log_verification.json'

def digest(stream):
    h, size = hashlib.sha256(), 0
    while data := stream.read(4 * 1024 * 1024):
        h.update(data)
        size += len(data)
    return h.hexdigest(), size

def verify(item):
    raw, archive = item
    before = raw.stat()
    with raw.open('rb') as stream:
        raw_hash, raw_size = digest(stream)
    with lzma.open(archive, 'rb') as stream:
        restored_hash, restored_size = digest(stream)
    assert (raw_hash, raw_size) == (restored_hash, restored_size), str(raw)
    assert (before.st_ino, before.st_size, before.st_mtime_ns) == (
        raw.stat().st_ino, raw.stat().st_size, raw.stat().st_mtime_ns)
    with archive.open('rb') as stream:
        archive_hash, archive_size = digest(stream)
    return {'raw': str(raw.relative_to(ROOT)), 'archive': str(archive.relative_to(ROOT)),
            'sha256': raw_hash, 'raw_bytes': raw_size, 'archive_sha256': archive_hash,
            'archive_bytes': archive_size, 'verified_round_trip': True,
            'raw_was_tracked': str(raw.relative_to(ROOT)) in TRACKED}

if __name__ == '__main__':
    TRACKED = set(subprocess.check_output(['git','ls-files','-z'], cwd=ROOT).decode().split('\0'))
    pairs = []
    for root, dirs, files in os.walk(ROOT/'defense4'):
        for name in files:
            archive = Path(root)/name
            if name.endswith('.xz') and archive.with_suffix('').is_file():
                pairs.append((archive.with_suffix(''),archive))
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for row in pool.map(verify, pairs):
            # Persist proof before removal. A tracked raw remains until archive migration.
            rows.append(row)
            OUT.write_text(json.dumps({'files':rows,'verified':len(rows), 'total':len(pairs)}, indent=2)+'\n')
            if not row['raw_was_tracked']:
                (ROOT/row['raw']).unlink()
                row['raw_pruned'] = True
            else:
                row['raw_pruned'] = False
            if len(rows) % 25 == 0:
                print('verified',len(rows),'of',len(pairs),flush=True)
    OUT.write_text(json.dumps({'files':rows,'verified':len(rows),'total':len(pairs),
                              'raw_bytes_pruned':sum(r['raw_bytes'] for r in rows if r['raw_pruned'])},indent=2)+'\n')
