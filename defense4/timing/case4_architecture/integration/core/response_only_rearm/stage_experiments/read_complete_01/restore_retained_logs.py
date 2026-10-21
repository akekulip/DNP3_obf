"""Restore the compressed model logs a fresh checkout needs before the m12p_b08 model gate can be recomputed.

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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    archives = sorted(EVIDENCE.glob('model_*_m12p_*/model_*.log.xz'))   # b08 and c12 (and later) retained logs
    if not archives:
        print('no retained log archives found under %s' % EVIDENCE)
        return 1
    failures = 0
    for archive in archives:
        log = archive.with_suffix('')
        closure = json.loads((archive.parent / 'dependency_closure.json').read_text())
        pinned = closure['postchecks']['reset_application']['input_sha256'].get(log.name)
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
