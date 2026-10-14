"""Shared standards-evidence validator for hardware campaign artifacts.

The campaign record binds run/config/build identity. The standards artifact is
accepted only when it repeats that identity, hashes the actual captures, and
reports exact exchange counts, exact response lengths, transport verdicts, SBO
success verdicts, and packet-boundary proof.
"""
import hashlib
import json
import os
from pathlib import Path

import capture_boundary

SCHEMA_VERSION = 'dnp3-standards-v2'   # v2: observed.precision + qualification
SBO = ('SELECT', 'OPERATE')
PRECISION_STATUSES = ('pass', 'deferred', 'fail', 'not_applicable')
QUALIFICATIONS = ('qualified', 'measurement_only', 'rejected')

BOUNDARY_CAPTURE_KEYS = (
    'capture_offloads',
    'calibration_expected',
    'calibration_in',
    'calibration_out',
    'calibration_result',
    'run_result',
)


def packet_boundary_required(context, expected=None):
    config = (context or {}).get('config') or {}
    arm = (context or {}).get('arm') or _first_config_arm(config)
    build = _build(config, arm) or {}
    return bool(build.get('profile') == 'candidate61' or (context or {}).get('packet_boundary_required'))


def boundary_segment_requirement(context, expected):
    if not packet_boundary_required(context, expected):
        return None, 0
    counts = (expected or {}).get('expected', {}).get('counts') or {}
    lengths = (expected or {}).get('expected', {}).get('lengths') or {}
    transformed = [kind for kind, values in lengths.items() if values == [61]]
    if not transformed:
        return None, 0
    return 61, sum(int(counts.get(kind, 0)) for kind in transformed)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str).encode()


def effective_config_hash(config):
    return hashlib.sha256(_canonical(config or {})).hexdigest()


def profile_hash(build):
    return hashlib.sha256(_canonical(build or {})).hexdigest()


def dependency_closure_hash(files):
    entries = []
    for path in sorted(str(p) for p in files or []):
        p = Path(path)
        entries.append({'path': p.name, 'sha256': sha256_file(p)})
    return hashlib.sha256(_canonical(entries)).hexdigest()


def checker_version(files):
    return dependency_closure_hash(files)


def _first_config_arm(config, arm_name=None):
    for arm in (config or {}).get('arms', []):
        if arm_name is None or arm.get('name') == arm_name:
            return arm
    return None


def _build(config, arm):
    if not arm:
        return None
    return (config or {}).get('builds', {}).get(arm.get('build'))


def expected_lengths(config, arm, unbound_native=False):
    if arm is None:
        return {'READ': [49], 'SELECT': [37], 'OPERATE': [37]}
    build = _build(config, arm) or {}
    profile = build.get('profile')
    image_len = int(build.get('image_len', 58))
    padding = int(arm.get('padding', 0))
    name = arm.get('name')
    if unbound_native or profile == 'unbound_native':
        read, sbo = 49, 37
    elif profile == 'candidate61' or image_len == 61:
        if padding and name in ('size_only', 'combined'):
            read, sbo = 61, 61
        else:
            read, sbo = 49, 37
    elif profile == 'strict_comparison' or image_len == 58:
        read, sbo = (58, 37) if padding else (49, 37)
    else:
        read, sbo = (image_len, 37) if padding else (49, 37)
    return {'READ': [read], 'SELECT': [sbo], 'OPERATE': [sbo]}


def expected_counts(context):
    trial = context.get('trial') or {}
    reads = int(trial.get('reads', 0))
    run_sbo = bool((context.get('config') or {}).get('traffic', {}).get('run_sbo', True))
    counts = {'READ': reads}
    if run_sbo:
        counts.update({'SELECT': 1, 'OPERATE': 1})
    return counts


def _get_path(capture):
    if isinstance(capture, (str, os.PathLike)):
        return str(capture)
    if isinstance(capture, dict):
        return capture.get('path')
    return None


def _capture_hashes(captures):
    out = {}
    for name, capture in sorted((captures or {}).items()):
        path = _get_path(capture)
        if not path:
            out[name] = {'error': 'missing path'}
            continue
        try:
            out[name] = {'sha256': sha256_file(path)}
        except OSError as error:
            out[name] = {'error': str(error)}
            continue
        if isinstance(capture, dict) and capture.get('filtered_from'):
            sources = {}
            for source_name, source_path in sorted(capture['filtered_from'].items()):
                try:
                    sources[source_name] = {'sha256': sha256_file(source_path)}
                except OSError as error:
                    sources[source_name] = {'error': str(error)}
            out[name]['filtered_from'] = sources
            if 'filter_procedure' in capture:
                out[name]['filter_procedure'] = capture['filter_procedure']
    return out


def expected_identity(context):
    config = context.get('config') or {}
    arm = context.get('arm') or _first_config_arm(config)
    build = _build(config, arm) or {}
    run_record = context.get('run_record') or {}
    run_id = run_record.get('run_id') or context.get('run_id')
    trial = context.get('trial') or {}
    build_hashes = {}
    if arm:
        build_hashes = ((run_record.get('builds') or {}).get(arm.get('build')) or build.get('hashes') or {})
    return {
        'run': {
            'run_id': run_id,
            'trial': trial.get('label'),
            'connection': context.get('connection_id'),
            'arm': arm.get('name') if arm else None,
        },
        'identity': {
            'candidate_source_sha256': context.get('candidate_source_sha256'),
            'build': arm.get('build') if arm else None,
            'build_hashes': build_hashes,
            'profile': build.get('profile') or context.get('profile_identity') or (
                'candidate61' if int(build.get('image_len', 58)) == 61 else
                'strict_comparison' if int(build.get('image_len', 58)) == 58 else 'unbound_native'
            ),
            'profile_hash': profile_hash(build),
            'effective_config_sha256': effective_config_hash(config) if config else run_record.get('config_sha256'),
        },
        'checker': {
            'version': checker_version(context.get('checker_files')),
            'dependency_closure_sha256': dependency_closure_hash(context.get('checker_files')),
        },
        'expected': {
            'counts': expected_counts(context),
            'lengths': {kind: lengths for kind, lengths in expected_lengths(
                config, arm, bool(context.get('unbound_native'))
            ).items() if kind == 'READ' or kind in expected_counts(context)}
        },
    }


def _append_mismatch(failures, field, want, got):
    if got != want:
        failures.append('%s mismatch: expected %r, got %r' % (field, want, got))


def _exchange_by_kind(artifact):
    out = {}
    for row in artifact.get('observed', {}).get('exchanges', []):
        if isinstance(row, dict) and row.get('kind'):
            out[row['kind']] = row
    return out


def validate_standards(artifact, context, captures):
    if isinstance(artifact, (str, os.PathLike)):
        try:
            artifact = json.load(open(artifact))
        except (OSError, ValueError) as error:
            return {'ok': False, 'failures': ['artifact unreadable: %s' % error], 'qualification': 'rejected'}
    failures = []
    if not isinstance(artifact, dict):
        return {'ok': False, 'failures': ['artifact is not an object'], 'qualification': 'rejected'}
    try:
        expected = expected_identity(context)
    except (KeyError, TypeError, ValueError) as error:
        return {'ok': False, 'failures': ['context malformed: %s' % error], 'qualification': 'rejected'}
    failures += _validate_context(context, captures, expected)
    _append_mismatch(failures, 'schema_version', SCHEMA_VERSION, artifact.get('schema_version'))
    for group in ('run', 'identity', 'checker', 'expected'):
        if not isinstance(artifact.get(group), dict):
            failures.append('missing or malformed %s' % group)
    if failures:
        return {'ok': False, 'failures': failures, 'expected': expected.get('expected'), 'qualification': 'rejected'}
    for key, value in expected['run'].items():
        _append_mismatch(failures, 'run.%s' % key, value, artifact['run'].get(key))
    for key, value in expected['identity'].items():
        _append_mismatch(failures, 'identity.%s' % key, value, artifact['identity'].get(key))
    for key, value in expected['checker'].items():
        _append_mismatch(failures, 'checker.%s' % key, value, artifact['checker'].get(key))
    _append_mismatch(failures, 'expected.counts', expected['expected']['counts'], artifact['expected'].get('counts'))
    _append_mismatch(failures, 'expected.lengths', expected['expected']['lengths'], artifact['expected'].get('lengths'))

    capture_hashes = _capture_hashes(captures)
    artifact_captures = artifact.get('captures')
    if not isinstance(artifact_captures, dict) or not artifact_captures:
        failures.append('missing or malformed captures')
    else:
        for name, actual in capture_hashes.items():
            entry = artifact_captures.get(name)
            if not isinstance(entry, dict):
                failures.append('captures.%s missing' % name)
                continue
            if 'error' in actual:
                failures.append('captures.%s unreadable: %s' % (name, actual['error']))
            else:
                _append_mismatch(failures, 'captures.%s.sha256' % name, actual['sha256'], entry.get('sha256'))
            if 'filtered_from' in actual:
                expected_procedure = ((captures or {}).get(name) or {}).get('filter_procedure') \
                    if isinstance((captures or {}).get(name), dict) else None
                if not entry.get('filter_procedure'):
                    failures.append('captures.%s.filter_procedure missing for filtered capture' % name)
                elif expected_procedure is not None and entry.get('filter_procedure') != expected_procedure:
                    failures.append('captures.%s.filter_procedure mismatch: expected %r, got %r'
                                    % (name, expected_procedure, entry.get('filter_procedure')))
                if not isinstance(entry.get('filtered_from'), dict):
                    failures.append('captures.%s.filtered_from missing for filtered capture' % name)
                else:
                    for source, source_actual in actual['filtered_from'].items():
                        got = (entry['filtered_from'].get(source) or {}).get('sha256')
                        if 'error' in source_actual:
                            failures.append('captures.%s.filtered_from.%s unreadable: %s'
                                            % (name, source, source_actual['error']))
                        else:
                            _append_mismatch(failures, 'captures.%s.filtered_from.%s.sha256' % (name, source),
                                             source_actual['sha256'], got)

    observed = artifact.get('observed')
    if not isinstance(observed, dict):
        failures.append('missing or malformed observed')
    else:
        checker_result = observed.get('checker_result')
        if not isinstance(checker_result, dict):
            failures.append('observed.checker_result missing or malformed')
        else:
            if checker_result.get('conformant') is not True:
                failures.append('observed.checker_result.conformant is %r, expected True'
                                % checker_result.get('conformant'))
            if checker_result.get('require_handshake') is not True:
                failures.append('observed.checker_result.require_handshake is %r, expected True'
                                % checker_result.get('require_handshake'))
            if checker_result.get('expected_lengths') != expected['expected']['lengths']:
                failures.append('observed.checker_result.expected_lengths mismatch: expected %r, got %r'
                                % (expected['expected']['lengths'], checker_result.get('expected_lengths')))
            if checker_result.get('expected_counts') != expected['expected']['counts']:
                failures.append('observed.checker_result.expected_counts mismatch: expected %r, got %r'
                                % (expected['expected']['counts'], checker_result.get('expected_counts')))
        if observed.get('failures'):
            failures.append('observed.failures is non-empty: %r' % observed.get('failures'))
        for key in ('transport_ok', 'select_authorizes_operate', 'operate_success', 'aggregate_verdict'):
            if observed.get(key) is not True:
                failures.append('observed.%s is %r, expected True' % (key, observed.get(key)))
        exchanges = _exchange_by_kind(artifact)
        for kind, count in expected['expected']['counts'].items():
            row = exchanges.get(kind)
            if not isinstance(row, dict):
                failures.append('observed.exchanges missing %s' % kind)
                continue
            if row.get('count') != count or row.get('complete') != count:
                failures.append('observed.exchanges.%s count/complete mismatch: expected %d, got count=%r complete=%r'
                                % (kind, count, row.get('count'), row.get('complete')))
            if row.get('resp_len') != expected['expected']['lengths'].get(kind):
                failures.append('observed.exchanges.%s resp_len mismatch: expected %r, got %r'
                                % (kind, expected['expected']['lengths'].get(kind), row.get('resp_len')))
            if row.get('failures'):
                failures.append('observed.exchanges.%s failures is non-empty: %r' % (kind, row.get('failures')))

    if packet_boundary_required(context, expected):
        required_payload_len, expected_attempts = boundary_segment_requirement(context, expected)
        checker_result = (artifact.get('observed') or {}).get('checker_result') if isinstance(artifact.get('observed'), dict) else None
        boundary_result = capture_boundary.validate_boundary_evidence(
            captures, required_payload_len=required_payload_len, expected_attempts=expected_attempts,
            checker_result=checker_result)
        for failure in boundary_result.get('failures', []):
            failures.append('packet_boundary: ' + failure)

    purpose = ((context or {}).get('config') or {}).get('evaluation', {}).get('purpose', 'qualification')
    precision = (artifact.get('observed') or {}).get('precision') if isinstance(artifact.get('observed'), dict) else None
    precision_failures = _validate_precision(artifact['observed'], context, purpose) \
        if isinstance(artifact.get('observed'), dict) else []
    failures += precision_failures
    return {'ok': not failures, 'failures': failures, 'expected': expected['expected'],
            'capture_hashes': capture_hashes,
            'precision': precision if not precision_failures else None,
            'qualification': qualification(not failures, precision, purpose)}


def _is_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _validate_context(context, captures, expected):
    failures = []
    context = context or {}
    config = context.get('config') or {}
    arm = context.get('arm') or _first_config_arm(config)
    build = _build(config, arm) or {}
    for field, value in expected['run'].items():
        if value in (None, ''):
            failures.append('context.run.%s is missing' % field)
    if not arm or not arm.get('name') or not arm.get('build'):
        failures.append('context.arm must bind an arm name and build')
    if build.get('profile') not in ('candidate61', 'strict_comparison', 'unbound_native'):
        failures.append('context.identity.profile must be explicit, got %r' % build.get('profile'))
    if not _is_sha(expected['identity'].get('candidate_source_sha256')):
        failures.append('context.identity.candidate_source_sha256 must be a pinned sha256')
    hashes = expected['identity'].get('build_hashes')
    if not isinstance(hashes, dict) or not hashes or any(not _is_sha(v) for v in hashes.values()):
        failures.append('context.identity.build_hashes must contain pinned sha256 values')
    files = context.get('checker_files')
    if not isinstance(files, list) or not files:
        failures.append('context.checker_files must list checker/dependency files')
    else:
        for path in files:
            if not Path(path).is_file():
                failures.append('context.checker_files missing file: %s' % path)
    if not isinstance(captures, dict):
        failures.append('context.captures must be a mapping')
    else:
        required_captures = ['out', 'in']
        if packet_boundary_required(context, expected):
            required_captures.extend(BOUNDARY_CAPTURE_KEYS)
        for name in required_captures:
            entry = captures.get(name)
            path = _get_path(entry)
            if not path:
                failures.append('context.captures.%s path is missing' % name)
            elif not Path(path).is_file():
                failures.append('context.captures.%s path is unreadable: %s' % (name, path))
    counts = expected['expected'].get('counts')
    lengths = expected['expected'].get('lengths')
    if not isinstance(counts, dict) or any(not isinstance(v, int) or isinstance(v, bool) or v < 0
                                           for v in counts.values()):
        failures.append('context.expected.counts malformed')
    if not isinstance(lengths, dict) or any(not isinstance(v, list) or len(v) != 1
                                            or not isinstance(v[0], int) or isinstance(v[0], bool) or v[0] <= 0
                                            for v in lengths.values()):
        failures.append('context.expected.lengths malformed')
    return failures


def _observed_from_timing(timing, observed):
    if observed and observed.get('exchanges'):
        return observed['exchanges']
    summary = (timing or {}).get('summary') or {}
    rows = []
    for kind, item in summary.items():
        if not isinstance(item, dict):
            continue
        rows.append({'kind': kind, 'count': item.get('logical_requests'), 'resp_len': item.get('resp_len'),
                     'complete': item.get('complete'), 'failures': []})
    return rows


PRECISION_MINIMUM_ELIGIBLE = 20
PRECISION_MAXIMUM_P99_US = 100


def precision_requirement(context):
    """(required, reason) derived from the run context, never from the artifact: a timed arm on the
    separate-ACK fixture with READ precision enabled claims a READ timing target, unless the campaign code path
    declared an explicit exemption (context['precision_exempt'], e.g. a loss trial) or the connection is an
    unbound native one."""
    config = (context or {}).get('config') or {}
    arm = (context or {}).get('arm') or _first_config_arm(config) or {}
    trial = (context or {}).get('trial') or {}
    evaluation = config.get('evaluation', {}) or {}
    if not arm.get('T'):
        return False, 'arm %s has no timing target (T=0)' % arm.get('name')
    if trial.get('fixture', 'separate_ack') != 'separate_ack':
        return False, 'fixture %s: READ CLRT is undefined without a separate ACK' % trial.get('fixture')
    if evaluation.get('read_precision', True) is not True:
        return False, 'READ precision disabled for %s' % evaluation.get('purpose')
    if context.get('unbound_native'):
        return False, 'unbound native connection: no timing target'
    if context.get('precision_exempt'):
        return False, str(context['precision_exempt'])
    return True, None


def _precision_numbers(precision):
    eligible = precision.get('eligible')
    p99 = (precision.get('absolute_error_us') or {}).get('p99')
    ok = (isinstance(eligible, int) and not isinstance(eligible, bool) and
          isinstance(p99, (int, float)) and not isinstance(p99, bool))
    return (eligible, p99) if ok else (None, None)


def precision_block(required, precision=None, purpose='qualification', reason=None):
    """READ precision status, kept apart from standards conformance.

    required: the trial claims a READ timing target (see precision_requirement).
    precision: checks.read_precision output, or None when the path produced none.
    A required block without usable evidence fails. Only a p99 exceedance over enough eligible READs in an
    explicit timing-characterization run is deferred (measurement only); everything else that misses fails.
    """
    if not required:
        return {'required': False, 'status': 'not_applicable',
                'reasons': [reason or 'no READ timing target for this arm/fixture'], 'evidence': precision}
    eligible, p99 = _precision_numbers(precision) if isinstance(precision, dict) else (None, None)
    if eligible is None:
        return {'required': True, 'status': 'fail', 'reasons': ['READ precision evidence missing'],
                'evidence': precision}
    if eligible >= PRECISION_MINIMUM_ELIGIBLE and p99 <= PRECISION_MAXIMUM_P99_US:
        return {'required': True, 'status': 'pass', 'reasons': [], 'evidence': precision}
    message = 'READ precision: eligible=%s (minimum%d), p99 absolute CLRT error=%s us (maximum%d)' % (
        eligible, PRECISION_MINIMUM_ELIGIBLE, p99, PRECISION_MAXIMUM_P99_US)
    deferrable = (purpose == 'timing_precision_characterization' and eligible >= PRECISION_MINIMUM_ELIGIBLE)
    return {'required': True, 'status': 'deferred' if deferrable else 'fail', 'reasons': [message],
            'evidence': precision}


def qualification(structural_ok, precision, purpose='qualification'):
    """Overall verdict for the selected research configuration: conformance AND precision AND purpose."""
    if not structural_ok or not isinstance(precision, dict) or precision.get('status') not in PRECISION_STATUSES:
        return 'rejected'
    if precision['status'] == 'fail':
        return 'rejected'
    if precision['status'] == 'deferred' or purpose != 'qualification':
        return 'measurement_only'
    return 'qualified'


def _validate_precision(observed, context, purpose):
    """The artifact's precision block must agree with the context-derived requirement, and a claimed pass or
    deferral must be supported by its own evidence against the fixed bound (not a bound the artifact states)."""
    failures = []
    block = observed.get('precision')
    if not isinstance(block, dict):
        return ['observed.precision missing or malformed']
    status, required, reasons = block.get('status'), block.get('required'), block.get('reasons')
    if status not in PRECISION_STATUSES:
        failures.append('observed.precision.status %r not in %r' % (status, PRECISION_STATUSES))
    if not isinstance(required, bool):
        failures.append('observed.precision.required is %r, expected boolean' % (required,))
    if not isinstance(reasons, list):
        failures.append('observed.precision.reasons is %r, expected list' % (reasons,))
    if failures:
        return failures
    want_required, _ = precision_requirement(context)
    if required is not want_required:
        failures.append('observed.precision.required is %r but the context requires %r' % (required, want_required))
    if required and status == 'not_applicable':
        failures.append('observed.precision: required but status not_applicable')
    if not required and status != 'not_applicable':
        failures.append('observed.precision: not required but status %r' % status)
    if status in ('fail', 'deferred', 'not_applicable') and not reasons:
        failures.append('observed.precision.status %r without reasons' % status)
    if status == 'deferred' and purpose != 'timing_precision_characterization':
        failures.append('observed.precision deferred outside timing_precision_characterization')
    if status in ('pass', 'deferred'):
        evidence = block.get('evidence')
        eligible, p99 = _precision_numbers(evidence) if isinstance(evidence, dict) else (None, None)
        if eligible is None:
            failures.append('observed.precision.evidence does not support status %r (no eligible/p99)' % status)
        elif eligible < PRECISION_MINIMUM_ELIGIBLE:
            failures.append('observed.precision.evidence does not support status %r: eligible %d < %d'
                            % (status, eligible, PRECISION_MINIMUM_ELIGIBLE))
        elif (status == 'pass') != (p99 <= PRECISION_MAXIMUM_P99_US):
            failures.append('observed.precision.evidence does not support status %r: p99 %s us against %d'
                            % (status, p99, PRECISION_MAXIMUM_P99_US))
    return failures


def build_standards_artifact(context, captures, observed=None):
    observed = dict(observed or {})
    expected = expected_identity(context)
    capture_hashes = _capture_hashes(captures)
    artifact = {
        'schema_version': SCHEMA_VERSION,
        **expected,
        'captures': capture_hashes,
        'observed': {
            'checker_result': observed.get('checker_result'),
            'exchanges': _observed_from_timing(observed.get('timing'), observed),
            'failures': observed.get('failures') or [],
            'transport_ok': observed.get('transport_ok') is True,
            'select_authorizes_operate': observed.get('select_authorizes_operate') is True,
            'operate_success': observed.get('operate_success') is True,
            'aggregate_verdict': observed.get('aggregate_verdict') is True,
            'precision': observed.get('precision'),
        },
    }
    return artifact


# ---- candidate61 profile-exact verdict, bound to the same run, build, config and captures ------------------

PROFILE_SCHEMA_VERSION = 'dnp3-profile-v1'
PROFILE_CAPTURES = ('in', 'out')


def profile_required(context):
    """The campaign claims the candidate61 encoding (or its native arms) for this trial/connection."""
    return expected_identity(context)['identity']['profile'] == 'candidate61'


def build_profile_artifact(context, captures, result, checker_file):
    expected = expected_identity(context)
    return {
        'schema_version': PROFILE_SCHEMA_VERSION,
        'run': expected['run'],
        'identity': expected['identity'],
        'expected': expected['expected'],
        'checker': {'profile_check_sha256': sha256_file(checker_file)},
        'captures': _capture_hashes({k: v for k, v in (captures or {}).items() if k in PROFILE_CAPTURES}),
        'result': result,
    }


def validate_profile(artifact, context, captures, checker_file):
    if isinstance(artifact, (str, os.PathLike)):
        try:
            artifact = json.load(open(artifact))
        except (OSError, ValueError) as error:
            return {'ok': False, 'failures': ['profile artifact unreadable: %s' % error]}
    if not isinstance(artifact, dict):
        return {'ok': False, 'failures': ['profile artifact is not an object']}
    failures = []
    try:
        expected = expected_identity(context)
    except (KeyError, TypeError, ValueError) as error:
        return {'ok': False, 'failures': ['context malformed: %s' % error]}
    _append_mismatch(failures, 'schema_version', PROFILE_SCHEMA_VERSION, artifact.get('schema_version'))
    for group in ('run', 'identity', 'expected'):
        if artifact.get(group) != expected[group]:
            failures.append('%s mismatch: expected %r, got %r' % (group, expected[group], artifact.get(group)))
    try:
        _append_mismatch(failures, 'checker.profile_check_sha256', sha256_file(checker_file),
                         (artifact.get('checker') or {}).get('profile_check_sha256'))
    except OSError as error:
        failures.append('profile checker unreadable: %s' % error)
    actual = _capture_hashes({k: v for k, v in (captures or {}).items() if k in PROFILE_CAPTURES})
    for name in PROFILE_CAPTURES:
        if name not in actual or 'error' in actual[name]:
            failures.append('captures.%s missing or unreadable' % name)
        else:
            _append_mismatch(failures, 'captures.%s.sha256' % name, actual[name]['sha256'],
                             ((artifact.get('captures') or {}).get(name) or {}).get('sha256'))
    result = artifact.get('result')
    if not isinstance(result, dict):
        failures.append('profile result missing or malformed')
    else:
        if result.get('conformant') is not True:
            failures.append('profile not conformant: %r' % (result.get('failures') or [])[:4])
        _append_mismatch(failures, 'result.expected_lengths', expected['expected']['lengths'],
                         result.get('expected_lengths'))
        _append_mismatch(failures, 'result.counts', expected['expected']['counts'], result.get('counts'))
        if (context or {}).get('master_port') is not None:
            _append_mismatch(failures, 'result.master_port', context['master_port'], result.get('master_port'))
        if not isinstance(result.get('attempts'), int) or not isinstance(result.get('responses'), int) or \
                result['attempts'] < result['responses'] or result['responses'] < 1:
            failures.append('profile attempts/responses malformed: %r/%r'
                            % (result.get('attempts'), result.get('responses')))
    return {'ok': not failures, 'failures': failures}
