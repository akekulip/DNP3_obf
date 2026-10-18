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
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))         # run_model and record_closure, imported by name below
REQUIRED = ('smoke', 'packets', 'rearm', 'dup', 'repeat', 'select_lifecycle', 'control_timing', 'contention', 'abort')


def _driver_names():
    import run_model
    return sorted(run_model.DRIVERS, key=len, reverse=True)


def attempts(build):
    # the driver is one of run_model's names, so model_abort_probe_x_m9_01_01 (build probe_x_m9_01) is not read as
    # an attempt of build m9_01 (found 2026-10-17: '.+' let efficiency-probe runs block m9_01's re-evaluation)
    pattern = re.compile(r'^model_(?P<driver>%s)_%s_(?P<n>\d\d)$'
                         % ('|'.join(map(re.escape, _driver_names())), re.escape(build.name)))
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
                   supported_profile_sha256=record.get('supported_profile_sha256'),
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
WRAPPERS = {'abort': 'contention', 'egress_diag': 'contention'}
# section coverage each driver must have run (results meta 'sections'; None = the driver has no section selector)
REQUIRED_SECTIONS = {'abort': ['abort'], 'egress_diag': ['egress_diag'], 'contention': 'all'}
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


def _disclosed_exception(note, run, base, run_dir):
    """Philip, 2026-10-17 (attempt 04): an unresolved FAILURE note may stand as a disclosed exception, never as a
    resolution. Accepted only if the note has a line 'DISCLOSED UNRESOLVED: <reference>' naming an existing evidence
    path, and the latest attempt of the same driver is a later attempt that passed completely on this build's source
    (exit 0, every case passed). Returns that later attempt's name, else None."""
    lines = [line for line in note.read_text().splitlines() if line.startswith('DISCLOSED UNRESOLVED:')]
    if not lines or not any('/' in token and any((b / token).exists() for b in (run_dir, run_dir.parent, REPO))
                            for line in lines for token in re.findall(r'[\w./-]+', line[len('DISCLOSED UNRESOLVED:'):])):
        return None
    latest = next((x for x in base['runs'] if x['run'] == base['latest_by_driver'].get(run['driver'])), None)
    if latest is None or latest['attempt'] <= run['attempt']:
        return None
    if not (latest['exit_code'] == 0 and latest['total'] and latest['passed'] == latest['total']
            and not latest['failed'] and latest['source_sha256'] == base['source_sha256']):
        return None
    return latest['run']


def _abort_negatives(results):
    """Abort negatives (48/50 octets ahead while held): no master reset, no E-16, and the held response survives,
    released exactly once (review finding: the driver asserted only the first two)."""
    expected = {'abort_held_%s_plus%d' % (kind, offset)
                for kind in ('READ', 'SELECT') for offset in (48, 50)}
    points = (results.get('meta') or {}).get('points', [])
    tags = [row.get('tag') for row in points if row.get('tag') in expected]
    bad = ['missing or duplicate: ' + tag for tag in sorted(expected) if tags.count(tag) != 1]
    for row in points:
        # selected by tag as well as offset (review finding 5: a required tag without a usable offset was skipped)
        if row.get('tag') not in expected and (not str(row.get('tag', '')).startswith('abort_')
                                               or row.get('offset') not in (48, 50)):
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
    retained, exceptions = {}, []
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
            disclosed = None if ref else _disclosed_exception(note, r, base, run_dir)
            notes.append(dict(note=note.name, resolution=ref, disclosed_exception_after=disclosed))
            if ref is None and disclosed is None:
                reasons.append('%s: unresolved %s (no RESOLVED reference that exists)' % (r['run'], note.name))
            elif disclosed:
                exceptions.append(dict(run=r['run'], note=note.name, passed_later_attempt=disclosed))
        r['failure_notes'] = notes
    for driver, run in sorted(base['latest_by_driver'].items()):
        r = next(x for x in base['runs'] if x['run'] == run)
        for p in r['provenance_problems']:
            reasons.append('%s: latest attempt %s: %s' % (driver, run, p))
    return dict(base, summary_version=SUMMARY_V2, generated_by='ctl_timing_01/model_summary.py (v2)',
                qualification='blocked' if reasons else 'model_gate_passed', blocked_reasons=reasons,
                disclosed_unresolved=exceptions)


# ---- summary version 3 (review of af7bd434; Philip 2026-10-17: dependency evidence is mandatory for new runs) ----
SUMMARY_V3 = 'model-summary-v3-20261017'


def _closure_problems(build, r):
    """Why one attempt's dependency evidence does not qualify it ([] when it does).

    run_model.py launches every driver through record_closure.py, which writes dependency_closure.json: each
    repository file the driver executed, hashed when it ran. Required:
    - the closure exists, is the version record_closure writes, and its sha256 is the one launch_command.json records;
    - it contains the driver itself with the driver_sha256 of the launch record, and a wrapper's inner driver;
    - every listed file still exists with that sha256, so the run used the files the candidate now carries (the
      candidate freeze then pins the same list)."""
    import run_model
    import record_closure
    run_dir = build.parent / r['run']
    path = run_dir / 'dependency_closure.json'
    if not path.is_file():
        return ['no dependency_closure.json (dependency evidence missing)']
    launch = json.loads((run_dir / 'launch_command.json').read_text()) if (run_dir / 'launch_command.json').is_file() else {}
    closure = json.loads(path.read_text())
    problems = []
    if launch.get('dependency_closure_sha256') != _sha(path):
        problems.append('launch record does not bind dependency_closure.json')
    if closure.get('closure_version') != record_closure.CLOSURE_VERSION:
        problems.append('closure version %r' % closure.get('closure_version'))
    files = closure.get('files') or {}
    needed = {str(run_model.DRIVERS[r['driver']].resolve().relative_to(REPO)): r['driver_sha256']}
    if r['driver'] in WRAPPERS:
        inner = run_model.DRIVERS[WRAPPERS[r['driver']]]
        needed[str(inner.resolve().relative_to(REPO))] = r.get('executed_driver_sha256')
    for rel, sha in needed.items():
        if files.get(rel) is None or files.get(rel) != sha:
            problems.append('closure lacks %s at the recorded sha256' % rel)
    for rel, sha in sorted(files.items()):
        target = REPO / rel
        if not target.is_file():
            problems.append('closure file absent now: %s' % rel)
        elif _sha(target) != sha:
            problems.append('closure file changed since the run: %s' % rel)
    return problems


def _reset_application_problems(run_dir):
    """The report must cover the complete executed reset experiment, with consistent measured attribution."""
    import reset_application_check
    run_dir = Path(run_dir)
    try:
        result = reset_application_check.load_json(run_dir / 'reset_application.json')
        files = list(run_dir.glob('*_results.json'))
        if len(files) != 1:
            return ['expected one reset results file, found %d' % len(files)]
        results = reset_application_check.load_json(files[0])
    except (OSError, ValueError, TypeError) as error:
        return ['no readable reset application/results evidence (%s)' % error]
    return reset_application_check.coverage_problems(results, result)


def _postcheck_problems(run_dir, inputs_path):
    """Bind the reset checker's executed dependency closure, input evidence, output and exit status."""
    import record_closure
    run_dir = Path(run_dir)
    try:
        closure = json.loads((run_dir / 'dependency_closure.json').read_text())
        check = closure['postchecks']['reset_application']
        expected = {'reset_application.json': check['report_sha256'],
                    'reset_application.dependencies.json': check['dependency_closure_sha256']}
        for name, sha in expected.items():
            if _sha(run_dir / name) != sha:
                return ['reset postcheck output/dependency closure changed: %s' % name]
        recorded = check['input_sha256']
        inputs = list(run_dir.glob('*_results.json')) + list(run_dir.glob('model_*.log'))
        if len(inputs) != 2 or len(list(run_dir.glob('*_results.json'))) != 1:
            return ['reset postcheck needs exactly one results file and one model log']
        expected_inputs = {p.name: _sha(p) for p in inputs}
        expected_inputs['response_only.inputs.json'] = _sha(inputs_path)
        if recorded != expected_inputs:
            return ['reset postcheck does not bind its results, model log and build profile']
        if check['exit_code'] != 0:
            return ['reset postcheck did not pass (exit %r)' % check['exit_code']]
        checked = json.loads((run_dir / 'reset_application.dependencies.json').read_text())
        checker = HERE / 'reset_application_check.py'
        if Path(check['checker']).resolve() != checker.resolve():
            return ['reset postcheck ran a different checker']
        checker_rel = str(checker.resolve().relative_to(REPO))
        if (checked.get('closure_version') != record_closure.CLOSURE_VERSION or
                checked.get('target') != checker_rel or checked.get('target_sha256') != _sha(checker) or
                checked.get('files', {}).get(checker_rel) != _sha(checker)):
            return ['reset postcheck lacks the current executed checker']
        if any(closure.get('files', {}).get(k) != v for k, v in checked.get('files', {}).items()):
            return ['reset postcheck dependency files are absent from the bound closure']
    except (OSError, ValueError, KeyError, TypeError) as error:
        return ['missing/malformed bound reset postcheck evidence (%s)' % error]
    return []


def _unmeasured_points(run_dir):
    """Points that did not measure what their check names (code review of the m10_03 failure analysis), so the
    attempt is incomplete and blocks; never a pass:
    - committed_path_not_measured: a sweep point whose readiness fallback was the contract outcome;
    - abort_released_before_send: a held-branch abort point whose response T had released before the RST, so no
      held response was flushed by the reset;
    - abort_released_before_reset: the same, decided from T's passes in the model log (release before T applied
      the reset) when the pre-send register read was inconclusive;
    - abort_held_not_established: a held-branch abort point where T's admission of the response was never observed
      in the model log, so the held construction was not established.
    Applied to the contention driver and to the abort driver, which runs the same abort cases.
    An unreadable or ambiguous results file is itself a problem."""
    files = sorted(run_dir.glob('*_results.json'))
    if len(files) != 1:
        return ['expected one *_results.json, found %d' % len(files)]
    try:
        meta = json.loads(files[0].read_text()).get('meta') or {}
    except (OSError, ValueError) as e:
        return ['unreadable %s (%s)' % (files[0].name, e)]
    problems = []
    for key, what in (('committed_path_not_measured', 'committed path not measured'),
                      ('abort_released_before_send', 'held abort path not measured'),
                      ('abort_released_before_reset', 'held abort path not measured'),
                      ('abort_held_not_established', 'held abort path not measured')):
        if meta.get(key):
            problems.append('%s (incomplete, rerun required): %s' % (what, ', '.join(meta[key])))
    return problems


def summarize_v3(build):
    """summarize_v2() plus mandatory dependency evidence: a driver's latest attempt must carry a verified
    dependency closure (_closure_problems). For a build whose runs predate the closure recorder this blocks, and
    the summary says so under provenance_limitations; such a build keeps the status of its own retained v2
    summary, and its v3 result is a statement of the limitation, not a new verdict on its behaviour."""
    base = summarize_v2(build)
    build = Path(build).resolve()
    reasons = list(base['blocked_reasons'])
    limitations = []
    inputs_path = build / 'response_only.inputs.json'
    import model_profile
    profile = None
    has_inputs = inputs_path.is_file()
    if has_inputs:
        try:
            profile = model_profile.resolve(json.loads(inputs_path.read_text()), build / 'response_only.p4')
        except (OSError, ValueError, TypeError) as error:
            reasons.append('unsupported or inconsistent build profile: %s' % error)
    for driver, run in sorted(base['latest_by_driver'].items()):
        r = next(x for x in base['runs'] if x['run'] == run)
        problems = _closure_problems(build, r)
        run_profile = profile
        if not has_inputs:
            try:
                # Missing inputs can only select a retained historical source by its verified hash.
                run_profile = model_profile.resolve({'source_sha256': base['source_sha256']},
                    build / 'response_only.p4', r.get('milestone'))
            except (OSError, ValueError, TypeError) as error:
                problems.append('unsupported source/profile without build inputs: %s' % error)
        reset_required = bool(run_profile and run_profile['reset_restart_required'])
        if run_profile and not run_profile.get('historical_build') and \
                r.get('supported_profile_sha256') != _sha(inputs_path):
            problems.append('launch supported_profile_sha256 does not bind the current build inputs')
        if driver == 'contention' and reset_required:
            problems += _reset_application_problems(build.parent / run)
            if not run_profile.get('historical_build'):
                problems += _postcheck_problems(build.parent / run, inputs_path)
            problems += _unmeasured_points(build.parent / run)
        elif driver == 'abort' and reset_required:
            problems += _unmeasured_points(build.parent / run)
        r['dependency_problems'] = problems
        for p in problems:
            reasons.append('%s: latest attempt %s: %s' % (driver, run, p))
            if p.startswith('no dependency_closure.json'):
                limitations.append('%s: %s predates mandatory dependency evidence' % (driver, run))
    return dict(base, summary_version=SUMMARY_V3, generated_by='ctl_timing_01/model_summary.py (v3)',
                qualification='blocked' if reasons else 'model_gate_passed', blocked_reasons=reasons,
                provenance_limitations=limitations)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('build')
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--v2', action='store_true', help='verified provenance and coverage; writes model_summary_v2.json')
    ap.add_argument('--v3', action='store_true', help='v2 plus mandatory dependency evidence; writes '
                    'model_summary_v3.json. Required for every new qualifying build')
    ap.add_argument('--enforce', action='store_true', help='exit 1 unless the model gate passed')
    a = ap.parse_args(argv)
    build = (HERE / a.build) if not Path(a.build).is_absolute() else Path(a.build)
    result = summarize_v3(build) if a.v3 else summarize_v2(build) if a.v2 else summarize(build)
    text = json.dumps(result, indent=1) + '\n'
    if a.write and a.v3:
        (build / 'model_summary_v3.json').write_text(text)
    elif a.write and a.v2:
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
