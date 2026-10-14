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

SCHEMA_VERSION = 'dnp3-standards-v1'
SBO = ('SELECT', 'OPERATE')

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
            return {'ok': False, 'failures': ['artifact unreadable: %s' % error]}
    failures = []
    if not isinstance(artifact, dict):
        return {'ok': False, 'failures': ['artifact is not an object']}
    try:
        expected = expected_identity(context)
    except (KeyError, TypeError, ValueError) as error:
        return {'ok': False, 'failures': ['context malformed: %s' % error]}
    failures += _validate_context(context, captures, expected)
    _append_mismatch(failures, 'schema_version', SCHEMA_VERSION, artifact.get('schema_version'))
    for group in ('run', 'identity', 'checker', 'expected'):
        if not isinstance(artifact.get(group), dict):
            failures.append('missing or malformed %s' % group)
    if failures:
        return {'ok': False, 'failures': failures, 'expected': expected.get('expected')}
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

    return {'ok': not failures, 'failures': failures, 'expected': expected['expected'],
            'capture_hashes': capture_hashes}


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
        },
    }
    return artifact
