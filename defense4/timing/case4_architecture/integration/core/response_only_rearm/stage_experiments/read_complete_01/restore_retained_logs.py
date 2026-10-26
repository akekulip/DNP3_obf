"""Restore byte-exact compressed model logs needed to recompute retained evidence.

The reset postcheck binds each contention run's model log by sha256 (dependency_closure.json
postchecks.reset_application.input_sha256). The logs are ~300 MB each, so the repository keeps byte-exact xz copies
beside them (model_*.log.xz). This writes each original back only if it is absent, and refuses unless the
decompressed bytes hash to the value that run's closure pinned at launch. An existing log is checked, never
replaced.

Additional evidence/*_dependency_retention_*/manifest.json files supply archive and original-byte pins for
other retained runs, including aborted attempts without a closure. Every listed archive must be present.
Restoring bytes does not qualify a run or create a closure. Conflicting pins fail before any restoration;
reset closure pins still apply.

  python3 restore_retained_logs.py      # exit 1 on any missing pin or hash mismatch
"""
import hashlib
import json
import lzma
import shutil
import sys
import tempfile
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / 'ctl_timing_01/evidence'
REPO = Path(__file__).resolve().parents[8]
RETENTION = Path(__file__).resolve().parent / 'evidence/c30_dependency_retention_20261024/manifest.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


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


def retained_logs():
    manifests = set(RETENTION.parent.parent.glob('*_dependency_retention_*/manifest.json'))
    if RETENTION.exists():
        manifests.add(RETENTION)
    retained, owners = {}, {}
    pin_fields = ('sha256', 'archive', 'archive_sha256')
    size_fields = ('archive_bytes', 'raw_bytes', 'uncompressed_bytes')
    for manifest in sorted(manifests):
        for log, record in json.loads(manifest.read_text()).get('logs', {}).items():
            previous = retained.get(log, {})
            if log in retained:
                if (any(record.get(key) != previous.get(key) for key in pin_fields)
                        or any(key in record and key in previous and record[key] != previous[key] for key in size_fields)):
                    raise ValueError('conflicting retained log pins for %s in %s and %s' % (log, owners[log], manifest))
            retained[log] = dict(previous, **record)
            owners[log] = manifest
    return retained


def main():
    try:
        retained = retained_logs()
    except (OSError, ValueError) as error:
        print('FAIL %s' % error)
        return 1
    archives = set(EVIDENCE.glob('model_*_m12p_*/model_*.log.xz')) | set(EVIDENCE.glob('model_*_m12p_*/model.out.xz'))
    candidates = {(archive.with_suffix(''), archive) for archive in archives}
    candidates.update((REPO / log, REPO / record['archive']) for log, record in retained.items())
    if not candidates:
        print('no retained log archives found under %s' % EVIDENCE)
        return 1
    failures = 0
    for log, archive in sorted(candidates):
        try:
            if not archive.is_file():
                print('FAIL %s: missing retained archive' % archive)
                failures += 1
                continue
            closure_path = archive.parent / 'dependency_closure.json'
            closure = json.loads(closure_path.read_text()) if closure_path.exists() else {}
            pinned = closure.get('postchecks', {}).get('reset_application', {}).get('input_sha256', {}).get(log.name)
            record = retained.get(str(log.relative_to(REPO)))
            raw_size = None
            if record is not None:
                archive_hash, archive_size = file_hash(archive)
                if (log != archive.with_suffix('')
                        or record['archive'] != str(archive.relative_to(REPO))
                        or archive_hash != record['archive_sha256']
                        or ('archive_bytes' in record and archive_size != record['archive_bytes'])
                        or (pinned is not None and pinned != record['sha256'])):
                    print('FAIL %s: retained archive pin mismatch' % log)
                    failures += 1
                    continue
                pinned = record['sha256']
                raw_size = record.get('raw_bytes', record.get('uncompressed_bytes'))
            if pinned is None:
                print('FAIL %s: not pinned by a retention manifest or its run closure' % log)
                failures += 1
                continue
            if log.exists():
                digest, size = file_hash(log)
                ok = digest == pinned and (raw_size is None or size == raw_size)
                print('%s %s (present)' % ('ok  ' if ok else 'FAIL', log.relative_to(REPO)))
                failures += not ok
                continue
            with tempfile.TemporaryFile() as staged:
                with lzma.open(archive, 'rb') as source:
                    digest, size = stream_hash(source, staged)
                if digest != pinned or (raw_size is not None and size != raw_size):
                    print('FAIL %s: archive does not decompress to the pinned sha256/size (mismatch)' % archive)
                    failures += 1
                    continue
                staged.seek(0)
                with log.open('xb') as output:
                    shutil.copyfileobj(staged, output, length=1024 * 1024)
        except FileExistsError:
            print('FAIL %s: appeared during restoration; existing bytes preserved' % log)
            failures += 1
            continue
        except (OSError, EOFError, lzma.LZMAError, ValueError) as error:
            print('FAIL %s: %s' % (archive, error))
            failures += 1
            continue
        print('ok   %s (restored, sha256 %s)' % (log.relative_to(REPO), pinned[:12]))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
