"""Restore byte-exact compressed model logs needed to recompute retained evidence.

The reset postcheck binds each contention run's model log by sha256 (dependency_closure.json
postchecks.reset_application.input_sha256). The logs are ~300 MB each, so the repository keeps byte-exact xz copies
beside them (model_*.log.xz). This writes each original back only if it is absent, and refuses unless the
decompressed bytes hash to the value that run's closure pinned at launch. An existing log is checked, never
replaced.

  python3 restore_retained_logs.py      # exit 1 on any missing pin or hash mismatch
"""
import hashlib
import json
import lzma
import sys
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / 'ctl_timing_01/evidence'
REPO = Path(__file__).resolve().parents[8]
RETENTION = Path(__file__).resolve().parent / 'evidence/c30_dependency_retention_20261024/manifest.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    retained = json.loads(RETENTION.read_text()).get('logs', {}) if RETENTION.exists() else {}
    archives = sorted(set(EVIDENCE.glob('model_*_m12p_*/model_*.log.xz')) |
                      set(EVIDENCE.glob('model_*_m12p_*/model.out.xz')))
    if not archives:
        print('no retained log archives found under %s' % EVIDENCE)
        return 1
    failures = 0
    for archive in archives:
        log = archive.with_suffix('')
        closure = json.loads((archive.parent / 'dependency_closure.json').read_text())
        pinned = closure.get('postchecks', {}).get('reset_application', {}).get('input_sha256', {}).get(log.name)
        record = retained.get(str(log.relative_to(REPO)))
        if record is not None:
            if (record['archive'] != str(archive.relative_to(REPO))
                    or sha(archive.read_bytes()) != record['archive_sha256']
                    or (pinned is not None and pinned != record['sha256'])):
                print('FAIL %s: retained archive pin mismatch' % log)
                failures += 1
                continue
            pinned = record['sha256']
        if pinned is None:
            print('FAIL %s: not pinned by its run closure' % log)
            failures += 1
            continue
        if log.exists():
            ok = sha(log.read_bytes()) == pinned
            print('%s %s (present)' % ('ok  ' if ok else 'FAIL', log.relative_to(EVIDENCE)))
            failures += not ok
            continue
        data = lzma.decompress(archive.read_bytes())
        if sha(data) != pinned:
            print('FAIL %s: archive does not decompress to the pinned sha256' % archive)
            failures += 1
            continue
        log.write_bytes(data)
        print('ok   %s (restored, sha256 %s)' % (log.relative_to(EVIDENCE), pinned[:12]))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
