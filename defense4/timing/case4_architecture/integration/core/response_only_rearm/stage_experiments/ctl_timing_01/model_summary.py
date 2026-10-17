"""Every model attempt for one ctl_timing_01 build, and whether the build's model gate is blocked.

  python3 model_summary.py evidence/BUILD [--write]

Lists every evidence/model_<driver>_<BUILD>_NN directory: its launch record (source and driver hashes, milestone,
exit code) and its results summary. A driver's verdict is its LATEST attempt; an earlier pass never stands in for a
later failure (review of 2990864ec: the hand-written m8_02 summary counted contention _01 283/283 and omitted the
failing _02). The build is blocked while a required driver is missing, a driver's latest attempt failed or was
bound to a different source, or any attempt carries an unresolved FAILURE_*.md (one without a line starting
'RESOLVED:'). --write replaces BUILD/model_summary.json, first keeping an existing hand-written summary as
model_summary_superseded_<date>.json.
"""
import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REQUIRED = ('smoke', 'packets', 'rearm', 'dup', 'repeat', 'select_lifecycle', 'control_timing', 'contention', 'abort')


def attempts(build):
    pattern = re.compile(r'^model_(?P<driver>.+)_%s_(?P<n>\d\d)$' % re.escape(build.name))
    for path in sorted(build.parent.glob('model_*_%s_*' % build.name)):
        match = pattern.match(path.name)
        if not match or not path.is_dir():
            continue
        launch = path / 'launch_command.json'
        record = json.loads(launch.read_text()) if launch.is_file() else {}
        results = sorted(path.glob('*_results.json'))
        summary = json.loads(results[0].read_text()).get('summary', {}) if len(results) == 1 else {}
        failures = [f.name for f in sorted(path.glob('FAILURE_*.md'))
                    if not any(line.startswith('RESOLVED:') for line in f.read_text().splitlines())]
        yield dict(run=path.name, driver=match['driver'], attempt=int(match['n']),
                   source_sha256=record.get('source_sha256'), driver_sha256=record.get('driver_sha256'),
                   milestone=record.get('MILESTONE'), pb_injected=record.get('pb_injected'),
                   exit_code=record.get('exit_code'), passed=summary.get('passed'), total=summary.get('total'),
                   failed=summary.get('failed', []), unresolved_failure_notes=failures,
                   results_files=[r.name for r in results])


def summarize(build):
    build = Path(build).resolve()
    source = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    runs = list(attempts(build))
    latest, reasons = {}, []
    for r in runs:
        if r['driver'] not in latest or r['attempt'] > latest[r['driver']]['attempt']:
            latest[r['driver']] = r
    for driver in REQUIRED:
        if driver not in latest:
            reasons.append('%s: no attempt' % driver)
    for driver, r in sorted(latest.items()):
        ok = (r['exit_code'] == 0 and r['total'] and r['passed'] == r['total'] and not r['failed']
              and r['source_sha256'] == source)
        if not ok:
            reasons.append('%s: latest attempt %s did not pass on this source (%s/%s, exit %s)'
                           % (driver, r['run'], r['passed'], r['total'], r['exit_code']))
    for r in runs:
        for note in r['unresolved_failure_notes']:
            reasons.append('%s: unresolved %s' % (r['run'], note))
    return dict(build=build.name, source_sha256=source, generated_by='ctl_timing_01/model_summary.py',
                qualification='blocked' if reasons else 'model_gate_passed', blocked_reasons=reasons,
                latest_by_driver={d: r['run'] for d, r in sorted(latest.items())}, runs=runs,
                note='every attempt listed; a driver is judged by its latest attempt; an earlier pass never '
                     'stands in for a later failure')


# ---- summary version 2 (review of 7637390c1, finding 3; summarize() above unchanged for its recorded files) ----
SUMMARY_V2 = 'model-summary-v2-20261017'
# a wrapper driver runs another driver's code; its results meta records the executed driver's sha256
WRAPPERS = {'abort': 'contention'}
# section coverage each driver must have run (results meta 'sections'; None = the driver has no section selector)
REQUIRED_SECTIONS = {'abort': ['abort'], 'contention': 'all'}
REPO = HERE.parents[7]


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _resolution(note, run_dir):
    """A FAILURE note is resolved only by a line 'RESOLVED: <reference>' whose reference names an existing path
    (relative to the run directory, the evidence directory or the repository) or a commit known to git."""
    import subprocess
    for line in note.read_text().splitlines():
        if not line.startswith('RESOLVED:'):
            continue
        for token in re.findall(r'[\w./-]+', line[len('RESOLVED:'):]):
            if ('/' in token and any((base / token).exists() for base in (run_dir, run_dir.parent, REPO))) \
                    or (token.startswith('model_') and (run_dir.parent / token).is_dir()):
                return token
            if re.fullmatch(r'[0-9a-f]{7,40}', token) and subprocess.run(
                    ['git', '-C', str(REPO), 'cat-file', '-e', token + '^{commit}'],
                    capture_output=True).returncode == 0:
                return token
    return None


def _abort_negatives(results):
    """Abort negatives (48/50 octets ahead while held): no master reset, no E-16, and the held response survives,
    released exactly once (review finding: the driver asserted only the first two)."""
    bad = []
    for row in (results.get('meta') or {}).get('points', []):
        if not str(row.get('tag', '')).startswith('abort_') or row.get('offset') not in (48, 50):
            continue
        released = sum((row.get('t_deltas') or {}).get(k, 0) for k in ('RESP_RELEASE', 'RESP_FALLBACK'))
        if row.get('resets_seq') != [] or row.get('e_reset_front_delta') != 0 or row.get('responses') != 1 \
                or released != 1:
            bad.append(row.get('tag'))
    return bad


def summarize_v2(build):
    """summarize() plus verified provenance and coverage. A driver's latest attempt passes only if:
    - its launch record's driver_sha256 equals the sha256 of its retained driver_source.py;
    - for a wrapper (WRAPPERS), the executed driver's sha256 (results meta driver_sha256) is recorded and equals a
      retained driver_source.py of that driver for the same build;
    - its results meta 'sections' equals REQUIRED_SECTIONS where listed;
    - source, totals and exit code pass as in v1;
    - for abort, the negatives also show the surviving response (_abort_negatives).
    A FAILURE note anywhere blocks unless its RESOLVED line names a reference that exists (_resolution)."""
    base = summarize(build)
    build = Path(build).resolve()
    reasons = list(base['blocked_reasons'])
    reasons = [r for r in reasons if ': unresolved FAILURE_' not in r]       # re-judged below with references
    retained = {}
    for r in base['runs']:
        src = build.parent / r['run'] / 'driver_source.py'
        if src.is_file():
            retained.setdefault(r['driver'], set()).add(_sha(src))
    for r in base['runs']:
        run_dir = build.parent / r['run']
        src = run_dir / 'driver_source.py'
        results_files = sorted(run_dir.glob('*_results.json'))
        results = json.loads(results_files[0].read_text()) if len(results_files) == 1 else {}
        meta = results.get('meta') or {}
        r['driver_source_sha256'] = _sha(src) if src.is_file() else None
        r['executed_driver_sha256'] = meta.get('driver_sha256')
        r['sections'] = meta.get('sections')
        problems = []
        if not r['driver_sha256'] or r['driver_source_sha256'] != r['driver_sha256']:
            problems.append('launch driver_sha256 missing or not the retained driver_source.py')
        if r['driver'] in WRAPPERS:
            inner = WRAPPERS[r['driver']]
            if not r['executed_driver_sha256'] or r['executed_driver_sha256'] not in retained.get(inner, set()):
                problems.append('executed %s driver %s not among the retained %s copies'
                                % (inner, r['executed_driver_sha256'], inner))
        if r['driver'] in REQUIRED_SECTIONS and r['sections'] != REQUIRED_SECTIONS[r['driver']]:
            problems.append('sections %r, required %r' % (r['sections'], REQUIRED_SECTIONS[r['driver']]))
        if r['driver'] == 'abort':
            neg = _abort_negatives(results)
            r['abort_negative_failures'] = neg
            if neg or not any(str(x.get('tag', '')).endswith(('plus48', 'plus50'))
                              for x in meta.get('points', [])):
                problems.append('abort negatives without the surviving response: %s' % (neg or 'none run'))
        r['provenance_problems'] = problems
        notes = []
        for note in sorted(run_dir.glob('FAILURE_*.md')):
            ref = _resolution(note, run_dir)
            notes.append(dict(note=note.name, resolution=ref))
            if ref is None:
                reasons.append('%s: unresolved %s (no RESOLVED reference that exists)' % (r['run'], note.name))
        r['failure_notes'] = notes
    for driver, run in sorted(base['latest_by_driver'].items()):
        r = next(x for x in base['runs'] if x['run'] == run)
        for p in r['provenance_problems']:
            reasons.append('%s: latest attempt %s: %s' % (driver, run, p))
    return dict(base, summary_version=SUMMARY_V2, generated_by='ctl_timing_01/model_summary.py (v2)',
                qualification='blocked' if reasons else 'model_gate_passed', blocked_reasons=reasons)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('build')
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--v2', action='store_true', help='verified provenance and coverage; writes model_summary_v2.json')
    ap.add_argument('--enforce', action='store_true', help='exit 1 unless the model gate passed')
    a = ap.parse_args(argv)
    build = (HERE / a.build) if not Path(a.build).is_absolute() else Path(a.build)
    result = summarize_v2(build) if a.v2 else summarize(build)
    text = json.dumps(result, indent=1) + '\n'
    if a.write and a.v2:
        (build / 'model_summary_v2.json').write_text(text)
    elif a.write:
        target = build / 'model_summary.json'
        if target.is_file() and json.loads(target.read_text()).get('generated_by') != result['generated_by']:
            keep = build / ('model_summary_superseded_%s.json' % datetime.date.today().strftime('%Y%m%d'))
            if not keep.exists():
                keep.write_bytes(target.read_bytes())
        target.write_text(text)
    print(result['qualification'], *result['blocked_reasons'], sep='\n  ')
    return 1 if a.enforce and result['qualification'] != 'model_gate_passed' else 0


if __name__ == '__main__':
    sys.exit(main())
