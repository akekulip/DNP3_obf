#!/usr/bin/env python3
"""Freeze record (version 2) for one build and its silicon blocks, and the check that gates every block.

  python3 freeze_gate.py write BUILD_DIR -o FREEZE.json --configs CONFIG [CONFIG ...] [--regen PATH=COMMAND ...]
  python3 freeze_gate.py check FREEZE.json [--record OUT.json]      # exit 1 on any changed or missing file

Review of 7637390c1 (freeze and reproducibility): the m9_01 freeze pinned the build and the caller scripts, but not
the acceptance modules that make the judgment (protocol/hw_vepa campaign.py, standards.py, clrt_check.py,
hold_check.py and others). Version 2 pins:
- the build's P4 source, inputs and generator copy;
- both compiles' manifests, bfrt.json, p4pp and tofino.bin;
- every non-test Python file of the harness, acceptance and installer directories (HARNESS_DIRS);
- run_block.sh;
- the verdict analysis scripts (ANALYSIS);
- the named block configs.
A pinned file that git does not track (compiler outputs; a config matching an ignore pattern) is listed with
`tracked: false`. A missing one fails the check with its regeneration command when one was recorded, so a fresh
clone fails clearly instead of passing silently. The check result can be retained beside the block's evidence
(--record); run_block_frozen.sh does that before calling run_block.sh.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HW = Path(__file__).resolve().parent
REPO = HW.parents[6]
A = 'defense4/timing/case4_architecture/'
HARNESS_DIRS = (A + 'protocol/hw_vepa', A + 'integration/evidence/rearm_01/hw',
                A + 'integration/core/response_only_rearm/hw', A + 'integration/core/response_only/hw')
HARNESS_FILES = (A + 'integration/evidence/rearm_01/hw/run_block.sh', A + 'integration/core/response_only_rearm/cp.py')
ANALYSIS = (A + 'integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/m5_summary.py',
            A + 'integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/isolation_v3.py',
            A + 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_summary.py')
BUILD_FILES = ('response_only.p4', 'response_only.inputs.json', 'generate.py', 'resource_review.json')
COMPILE_FILES = ('manifest.json', 'out/bfrt.json', 'out/response_only.p4pp', 'out/p0/tofino.bin', 'out/p1/tofino.bin')


def sha(path):
    return hashlib.sha256((REPO / path).read_bytes()).hexdigest()


def tracked(path):
    return subprocess.run(['git', '-C', str(REPO), 'ls-files', '--error-unmatch', path],
                          capture_output=True).returncode == 0


def rel(path):
    return str(Path(path).resolve().relative_to(REPO))


def collect(build, configs):
    files = [rel(build / f) for f in BUILD_FILES if (build / f).is_file()]
    files += [rel(build / c / f) for c in ('compile_local', 'compile_switch_9132') for f in COMPILE_FILES]
    for d in HARNESS_DIRS:
        files += [rel(p) for p in sorted((REPO / d).glob('*.py'))]
    files += list(HARNESS_FILES) + list(ANALYSIS) + [rel(c) for c in configs]
    return sorted(set(files))


def write(a):
    build = Path(a.build).resolve()
    files = collect(build, a.configs)
    missing = [f for f in files if not (REPO / f).is_file()]
    if missing:
        raise SystemExit('cannot freeze, missing: ' + ' '.join(missing))
    regen = dict(item.split('=', 1) for item in a.regen or [])
    record = dict(freeze_version='freeze-v2-20261017', build=rel(build), source_sha256=sha(rel(build / 'response_only.p4')),
                  files={f: dict(sha256=sha(f), tracked=tracked(f), regenerate=regen.get(f)) for f in files},
                  note='checked before every block by run_block_frozen.sh (freeze_gate.py check --record)')
    Path(a.output).write_text(json.dumps(record, indent=1) + '\n')
    print('wrote', a.output, len(files), 'files,', sum(not v['tracked'] for v in record['files'].values()), 'untracked')
    return 0


def check(a):
    frozen = json.loads(Path(a.freeze).read_text())
    changed, missing = [], []
    for f, v in frozen['files'].items():
        if not (REPO / f).is_file():
            missing.append(dict(path=f, regenerate=v.get('regenerate')))
        elif sha(f) != v['sha256']:
            changed.append(f)
    where = Path(a.freeze).resolve()
    result = dict(freeze=str(where.relative_to(REPO)) if REPO in where.parents else str(where), freeze_version=frozen.get('freeze_version'), source_sha256=frozen['source_sha256'],
                  files=len(frozen['files']), changed=changed, missing=missing, ok=not changed and not missing)
    if a.record:
        Path(a.record).parent.mkdir(parents=True, exist_ok=True)
        Path(a.record).write_text(json.dumps(result, indent=1) + '\n')
    print('freeze check:', 'OK' if result['ok'] else 'FAILED', len(changed), 'changed,', len(missing), 'missing')
    for m in missing:
        print('  missing', m['path'], ('regenerate: ' + m['regenerate']) if m['regenerate'] else '')
    for c in changed:
        print('  changed', c)
    return 0 if result['ok'] else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    w = sub.add_parser('write')
    w.add_argument('build')
    w.add_argument('-o', '--output', required=True)
    w.add_argument('--configs', nargs='+', default=[])
    w.add_argument('--regen', nargs='*', help='PATH=COMMAND for a file git does not track')
    c = sub.add_parser('check')
    c.add_argument('freeze')
    c.add_argument('--record')
    a = ap.parse_args(argv)
    return write(a) if a.cmd == 'write' else check(a)


if __name__ == '__main__':
    sys.exit(main())
