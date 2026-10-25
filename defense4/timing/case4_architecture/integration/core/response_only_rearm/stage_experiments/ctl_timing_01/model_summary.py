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
RELAY_REQUIRED = REQUIRED + ('policy', 'policy_boundary', 'two_read_robust', 'smoke_sizeoff',
                             'abandon', 'relay_sbo', 'fin_busy')


def required_drivers(build):
    """The physical relay gate includes every existing driver and its new SBO/close proofs."""
    declared = set()
    documents = []
    inputs = Path(build) / 'response_only.inputs.json'
    if inputs.is_file():
        doc = json.loads(inputs.read_text())
        if not isinstance(doc, dict) or not isinstance(doc.get('supported_profile', {}), dict):
            raise ValueError('inputs must contain an object supported_profile')
        documents.extend((doc, doc.get('supported_profile', {})))
        declared.update(value for value in (doc.get('endpoint_profile'),
                        doc.get('supported_profile', {}).get('endpoint_profile')) if value is not None)
    profile = Path(build) / 'supported_profile.json'
    if profile.is_file():
        doc = json.loads(profile.read_text())
        if not isinstance(doc, dict):
            raise ValueError('supported profile must be an object')
        documents.append(doc)
        if doc.get('endpoint_profile') is not None:
            declared.add(doc['endpoint_profile'])
    if len(declared) > 1 or declared - {'software', 'sel751'}:
        raise ValueError('inconsistent or unsupported endpoint_profile: %r' % sorted(declared))
    for doc in documents:
        transforms = doc.get('transforms_applied', [])
        encoding = doc.get('encoding', {})
        if not isinstance(transforms, list) or not isinstance(encoding, dict):
            raise ValueError('qualification transforms/encoding have invalid types')
        native = encoding.get('native_input_octets', {})
        if not isinstance(native, dict):
            raise ValueError('qualification native_input_octets must be an object')
        relay = (bool({'relay_sbo', 'relay_ts'}.intersection(transforms))
                 or doc.get('tcp_profile') == 'sel751_ts'
                 or (native.get('SELECT') == 49 and native.get('OPERATE') == 49
                     and encoding.get('output_octets') == 60))
        if relay and declared != {'sel751'}:
            raise ValueError('relay semantics require endpoint_profile=sel751')
    contracts = {doc['timing_contract'] for doc in documents if doc.get('timing_contract') is not None}
    if len(contracts) > 1 or contracts - {'response_ready_ack_d_v1'}:
        raise ValueError('inconsistent or unsupported timing_contract')
    if contracts:
        from model_profile import validate_timing_contract
        for doc in documents:
            if doc.get('timing_contract') is not None:
                validate_timing_contract(doc)
        if declared != {'sel751'}:
            raise ValueError('response-ready requires the relay gate')
        return RELAY_REQUIRED + ('response_ready',)
    return RELAY_REQUIRED if declared == {'sel751'} else REQUIRED


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
    try:
        required = required_drivers(build)
    except (OSError, ValueError, TypeError) as error:
        required = REQUIRED
        reasons.append('invalid qualification profile: %s' % error)
    for r in runs:
        if r['driver'] not in latest or r['attempt'] > latest[r['driver']]['attempt']:
            latest[r['driver']] = r
    for driver in required:
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
                required_drivers=list(required),
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


def _abort_negatives(results, relay=False):
    """Abort negatives at native response length±1: no master reset, no E-16, and the held response survives,
    released exactly once (review finding: the driver asserted only the first two)."""
    offsets = {'READ': (90, 92) if relay else (48, 50), 'SELECT': (48, 50)}
    expected = {'abort_held_%s_plus%d' % (kind, offset): offset
                for kind, values in offsets.items() for offset in values}
    points = (results.get('meta') or {}).get('points', [])
    tags = [row.get('tag') for row in points if row.get('tag') in expected]
    bad = ['missing or duplicate: ' + tag for tag in sorted(expected) if tags.count(tag) != 1]
    for row in points:
        # selected by tag as well as offset (review finding 5: a required tag without a usable offset was skipped)
        if row.get('tag') not in expected:
            continue
        released = sum((row.get('t_deltas') or {}).get(k, 0) for k in ('RESP_RELEASE', 'RESP_FALLBACK'))
        if row.get('offset') != expected[row['tag']] or row.get('resets_seq') != [] \
                or row.get('e_reset_front_delta') != 0 or row.get('responses') != 1 \
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
            neg = _abort_negatives(results, relay='relay_sbo' in base['required_drivers'])
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
        checker_rel = str(checker.resolve().relative_to(REPO))
        # The recorded path is absolute in the checkout that ran it; another checkout of the same repository
        # binds the same checker when the repo-relative suffix matches (its sha256 is bound just below).
        recorded = Path(check['checker'])
        if recorded.resolve() != checker.resolve() and not str(recorded).endswith('/' + checker_rel):
            return ['reset postcheck ran a different checker']
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




def _single_child_problems(results):
    """Retain the full invalid-child state-immutability matrix and policy-off positive controls."""
    import copy
    required = {'N': {'owner', 'epoch', 'client', 'server'},
                'E': {'epoch', 'mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'},
                'T': {'cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg', 't0_reg', 'op_t0_reg',
                      'ack_done_reg', 'resp_done_reg', 'op_done_reg', 'child_seen0_reg',
                      'ack_commit_at_reg', 'ack_commit_gen_reg', 'outcomes'}}
    rows = (results.get('meta') or {}).get('single_child_probes') or []
    expected_cases = [('response', None, child) for child in (1, 2, 255)] + [
        ('held', role, child) for role in (14, 15, 16) for child in (1, 2, 255)] + [
        ('blocker', role, child) for role in (11, 12, 13) for child in (0, 1, 2, 255)]
    problems = []
    for kind, role, child in expected_cases:
        tag = '%s role%s child%d' % (kind, role, child)
        matches = [row for row in rows if (row.get('kind'), row.get('role'), row.get('child')) == (kind, role, child)]
        if len(matches) != 1:
            problems.append('missing or duplicate invalid-child proof: ' + tag)
            continue
        row = matches[0]
        before, after = row.get('before') or {}, row.get('after') or {}
        if set(before) != set(required) or any(set(before.get(domain, {})) != names for domain, names in required.items()):
            problems.append(tag + ': full N/E/T register state not measured')
            continue
        if not isinstance(before['T']['outcomes'], list) or len(before['T']['outcomes']) != 25:
            problems.append(tag + ': all 25 T outcomes not measured')
            continue
        expected = copy.deepcopy(before)
        if kind == 'blocker' and child == 0:
            expected['T']['outcomes'][12] = (expected['T']['outcomes'][12] + 1) & 0xffffffff
        if row.get('policy_off') is not (kind == 'blocker'):
            problems.append(tag + ': missing policy-off blocker construction')
        if row.get('expected_after') != expected or after != expected or row.get('output_frames') != 0:
            problems.append(tag + ': register/counter mutation or public output')
        if any(type(row.get(key)) is not int or not 0 < row[key] < limit
               for key, limit in (('epoch', 0x80000000), ('read_generation', 0xffff), ('operate_generation', 0xffff))):
            problems.append(tag + ': no live epoch and both generations')
    if len(rows) != len(expected_cases):
        problems.append('unexpected or missing invalid-child probe rows')
    return problems


def _generation_isolation_problems(results):
    from model_response_ready import generation_isolation_problems, delta, token_source_problems
    points = (results.get('meta') or {}).get('points') or []
    problems = []
    for kind in ('late_ACK', 'stale_response', 'expired_token'):
        for phase in ('waiting', 'committed'):
            tag = 'generation_A_%s_%s_B' % (kind, phase)
            matches = [point for point in points if point.get('tag') == tag]
            if len(matches) != 1:
                problems.append('missing or duplicate generation A-to-B proof: ' + tag)
                continue
            point = matches[0]
            if (point.get('stale_probe') or {}).get('kind') != kind or (point.get('stale_probe') or {}).get('phase') != phase:
                problems.append(tag + ': wrong A artifact or B phase')
            problems.extend(tag + ': ' + problem for problem in generation_isolation_problems(point))
            source = (point.get('stale_probe') or {}).get('source_tag')
            prior = [item for item in points if item.get('tag') == source]
            if len(prior) != 1:
                problems.append(tag + ': no unique executed A generation')
                continue
            prior = prior[0]
            probe = point.get('stale_probe') or {}
            artifact_key = {'late_ACK': 'ack', 'stale_response': 'response', 'expired_token': 'token'}[kind]
            frame = (prior.get('artifacts') or {}).get(artifact_key)
            if not frame or probe.get('frame_hex') != frame or                     prior.get('generation_after') != probe.get('source_generation') or prior.get('epoch') != probe.get('source_epoch'):
                problems.append(tag + ': artifact does not bind the actual prior A packet and generation')
            if kind == 'expired_token':
                problems.extend(tag + ': ' + issue for issue in token_source_problems(prior))
                expiry = prior.get('atomic_expiry_units') or []
                elapsed = None if len(expiry) != 1 else delta(expiry[0], prior.get('t0_units'))
                if (prior.get('lane') or {}).get('WAIT_EXPIRED') != 1 or prior.get('master_frames') != [] or                         elapsed is None or elapsed < -(-(500000000 + 512) // 256):
                    problems.append(tag + ': token does not name a genuinely expired A generation')
                if frame and (not frame.startswith('0b00') or int(frame[4:8], 16) != probe.get('source_generation')):
                    problems.append(tag + ': token is not the original A generation ACK blocker')
            else:
                units = prior.get('written_units') or {}
                if not isinstance(units.get('gap'), int) or not isinstance(units.get('response_wait_timeout'), int):
                    problems.append(tag + ': A has no actual timing parameters')
                else:
                    from model_response_ready import committed_problems
                    problems.extend(tag + ': prior A ' + issue for issue in committed_problems(
                        prior, units['gap'], units['response_wait_timeout']))

    return problems

def _response_ready_problems(results):
    """A partial response-ready run cannot qualify from totals alone."""
    from model_response_ready import committed_problems
    D_VALUES = (5000000, 10000000, 15000000, 20000000)
    meta = results.get('meta') or {}
    problems = []
    if meta.get('timing_contract') != 'response_ready_ack_d_v1':
        problems.append('missing response-ready timing contract in executed results')
    expected = {}
    for gap in D_VALUES:
        for order in ('ack_first', 'response_first'):
            prefix = 'D%d_%s' % (gap // 1000000, order)
            for cls in ('mixed', 'integrity'):
                for suffix, native, image in (('', 91 if cls == 'mixed' else 134, 141 if cls == 'mixed' else 158),
                                               ('_SELECT', 49, 60), ('_OPERATE', 49, 60)):
                    expected[prefix + '_' + cls + suffix] = (gap, native, image, order)
    points = meta.get('points') or []
    for tag, (gap, native, image, order) in expected.items():
        matches = [point for point in points if point.get('tag') == tag]
        if len(matches) != 1:
            problems.append('missing or duplicate response-ready point: ' + tag)
            continue
        point = matches[0]
        if point.get('order') != order:
            problems.append(tag + ': observed order does not match required ' + order)
        units = point.get('written_units') or {}
        gap_units = -(-(gap + 512) // 256)
        wait_units = -(-(500000000 + 512) // 256)
        if (point.get('native_octets'), point.get('image_octets')) != (native, image):
            problems.append(tag + ': wrong relay native/image shape')
        if set(units) != {'gap', 'op_j', 'response_wait_timeout', 'budget', 'enabled'} or \
                units.get('gap') != gap_units or units.get('response_wait_timeout') != wait_units:
            problems.append(tag + ': actual five-field parameter write does not exercise D and 500ms expiry')
        problems.extend(tag + ': ' + issue for issue in committed_problems(point, gap_units, wait_units))
    negatives = ('late98ms', 'absent', 'response_without_ACK', 'wrong_response', 'incomplete_response',
                 'duplicate_ack_response', 'duplicate_over_bound', 'request_retransmission', 'reset_held', 'commit_across_expiry')
    from model_response_ready import delta
    for tag in negatives:
        matches = [point for point in points if point.get('tag') == tag]
        if len(matches) != 1:
            problems.append('missing or duplicate response-ready negative/boundary: ' + tag)
            continue
        point = matches[0]
        lane = point.get('lane') or {}
        if tag in ('absent', 'response_without_ACK', 'wrong_response', 'incomplete_response', 'duplicate_over_bound'):
            expiry = point.get('atomic_expiry_units') or []
            elapsed = delta(expiry[0], point.get('t0_units')) if len(expiry) == 1 else None
            if point.get('master_frames') != [] or lane.get('ACK_COMMIT') != 0 or \
                    lane.get('RESP_RELEASE') != 0 or lane.get('WAIT_EXPIRED') != 1 or \
                    elapsed is None or elapsed < -(-(500000000 + 512) // 256):
                problems.append(tag + ': expiry without forwarding not proved on T clock')
            if tag == 'duplicate_over_bound':
                expiry = point.get('forced_expiry_before_response_units')
                late = delta(point.get('response_arrival_units'), expiry)
                if expiry is None or late is None or late >= 1 << 31:
                    problems.append(tag + ': response was not observed after actual expiry')
                recovery = [row for row in points if row.get('tag') == 'duplicate_over_bound_reconnect']
                if len(recovery) != 1 or recovery[0].get('recovery_of') != tag or recovery[0].get('epoch') == point.get('epoch'):
                    problems.append(tag + ': new-handshake recovery not measured')
                else:
                    units = recovery[0].get('written_units') or {}
                    if not isinstance(units.get('gap'), int) or not isinstance(units.get('response_wait_timeout'), int):
                        problems.append(tag + ': recovery timing parameters not measured')
                    else:
                        problems.extend(tag + ': recovery ' + issue for issue in committed_problems(
                            recovery[0], units['gap'], units['response_wait_timeout']))
        elif tag == 'reset_held':
            held, reset = point.get('held_ack_units'), point.get('reset_application_units')
            if held is None or reset is None or delta(reset, held) >= 1 << 31 or \
                    point.get('master_frames') != [] or lane.get('ACK_COMMIT') != 0 or lane.get('RESP_RELEASE') != 0:
                problems.append(tag + ': reset while actual ACK held was not proved')
        else:
            units = point.get('written_units') or {}
            if not isinstance(units.get('gap'), int) or not isinstance(units.get('response_wait_timeout'), int):
                problems.append(tag + ': no actual parameter units')
            else:
                problems.extend(tag + ': ' + issue for issue in committed_problems(
                    point, units['gap'], units['response_wait_timeout']))
            if tag == 'duplicate_ack_response':
                replay = point.get('post_release_replay')
                if not isinstance(replay, dict):
                    problems.append(tag + ': missing post-release replay proof')
                else:
                    from model_response_ready import post_release_replay_problems
                    problems.extend(tag + ': ' + issue for issue in post_release_replay_problems(replay))
            if tag == 'late98ms':
                age = delta(point.get('response_arrival_units'), point.get('t0_units'))
                if age is None or age * 256 < 98000000:
                    problems.append(tag + ': actual late native response was not constructed')
            if tag == 'commit_across_expiry':
                age = delta(point.get('response_release_units'), point.get('t0_units'))
                if age is None or age < -(-(500000000 + 512) // 256):
                    problems.append(tag + ': full D across expiry was not constructed')
    priority_edges = ['duplicate_over_bound', 'commit_across_expiry']
    expected_cases = priority_edges + ['expired_A_token_isolation'] + ['D%d_%s' % (gap // 1000000, order) for gap in D_VALUES
                      for order in ('ack_first', 'response_first')] + [case for case in negatives if case not in priority_edges] + [
                          'generation_A_to_B_isolation', 'invalid_child_ids', 'disabled_and_exhaustion']
    if meta.get('planned_cases') != expected_cases or meta.get('completed_cases') != expected_cases:
        problems.append('response-ready did not complete every planned connection/case')
    problems += _single_child_problems(results)
    problems += _generation_isolation_problems(results)
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
    if profile and profile.get('timing_contract') == 'response_ready_ack_d_v1':
        state_audit = model_profile.compiled_t_state_of_build(build)
        base['compiled_t_state_audit'] = state_audit
        reasons.extend('compiled T state precondition: ' + problem for problem in state_audit['problems'])
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
        if driver == 'control_timing' and run_profile and run_profile.get('timing_contract') == 'response_ready_ack_d_v1':
            result_files = list((build.parent / run).glob('*_results.json'))
            if len(result_files) == 1:
                problems += _single_child_problems(json.loads(result_files[0].read_text()))
            else:
                problems.append('response-ready control_timing needs exactly one results file')
        if driver == 'response_ready':
            result_files = list((build.parent / run).glob('*_results.json'))
            if len(result_files) == 1:
                problems += _response_ready_problems(json.loads(result_files[0].read_text()))
            else:
                problems.append('response-ready needs exactly one results file')
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
