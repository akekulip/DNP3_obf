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
REQUIRED = ('smoke', 'packets', 'rearm', 'dup', 'repeat', 'select_lifecycle', 'control_timing', 'contention')


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


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('build')
    ap.add_argument('--write', action='store_true')
    a = ap.parse_args(argv)
    build = (HERE / a.build) if not Path(a.build).is_absolute() else Path(a.build)
    result = summarize(build)
    text = json.dumps(result, indent=1) + '\n'
    if a.write:
        target = build / 'model_summary.json'
        if target.is_file() and json.loads(target.read_text()).get('generated_by') != result['generated_by']:
            keep = build / ('model_summary_superseded_%s.json' % datetime.date.today().strftime('%Y%m%d'))
            if not keep.exists():
                keep.write_bytes(target.read_bytes())
        target.write_text(text)
    print(result['qualification'], *result['blocked_reasons'], sep='\n  ')
    return 0


if __name__ == '__main__':
    sys.exit(main())
