"""Shared standards-evidence validator for hardware campaign artifacts.

The campaign record binds run/config/build identity. The standards artifact is
accepted only when it repeats that identity, hashes the actual captures, and
reports exact exchange counts, exact response lengths, transport verdicts, SBO
success verdicts, and packet-boundary proof.
"""
import hashlib
import json
import os
import struct
from pathlib import Path

import capture_boundary
import read_classes

# v2 and v3 are retained artifacts written by earlier checkers; they also carried host-observed timing blocks
# (observed.precision, observed.objectives), which this checker ignores. v4 (everything build_standards_artifact
# writes now) has no CLRT precision or piggyback latency criterion. Applicable software OPERATE hold evidence is
# derived from the bound captures and checked against configured J. An artifact labelled v2/v3 that claims the
# current checker is rejected (the current checker only writes v4).
SCHEMA_VERSION = 'dnp3-standards-v2'
SCHEMA_VERSION_V3 = 'dnp3-standards-v3'
SCHEMA_VERSION_V4 = 'dnp3-standards-v4'
SCHEMA_VERSIONS = (SCHEMA_VERSION, SCHEMA_VERSION_V3, SCHEMA_VERSION_V4)
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
    classes = (expected or {}).get('expected', {}).get('read_classes')
    if classes is not None:
        # per-class READ declaration: when anything is transformed, every exchange of every kind and READ class is
        # bound to its own length ('READ:<class>' or the kind), never to a set of lengths
        if not any(e['image'] != e['native'] for e in classes.values()) and \
                not any(lengths.get(kind) == [61] for kind in SBO):
            return None, 0
        required = {'READ:' + cls: e['image'] for cls, e in classes.items()}
        required.update({kind: lengths[kind][0] for kind in SBO if kind in lengths and kind in counts})
        return required, sum(e['count'] for e in classes.values()) + sum(int(counts.get(k, 0)) for k in SBO)
    # A transformed kind is one at the candidate61 image (61), or a READ at the build's read_image_len (a
    # read_complete_01 policy build). Several lengths come back as a tuple.
    config = (context or {}).get('config') or {}
    read_len = (_build(config, (context or {}).get('arm') or _first_config_arm(config)) or {}).get('read_image_len')
    transformed = [kind for kind, values in lengths.items()
                   if values == [61] or (kind == 'READ' and read_len and values == [int(read_len)])]
    if not transformed:
        return None, 0
    sizes = tuple(sorted({lengths[kind][0] for kind in transformed}))
    return (sizes[0] if len(sizes) == 1 else sizes), sum(int(counts.get(kind, 0)) for kind in transformed)


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
            read, sbo = int(build.get('read_image_len') or 61), 61
        else:
            read, sbo = 49, 37
    elif profile == 'strict_comparison' or image_len == 58:
        read, sbo = (58, 37) if padding else (49, 37)
    else:
        read, sbo = (image_len, 37) if padding else (49, 37)
    return {'READ': [read], 'SELECT': [sbo], 'OPERATE': [sbo]}


def read_class_expectations(config, arm, trial=None, unbound_native=False):
    """read_classes.expectations for this arm: padded exactly when expected_lengths gives a non-native READ. None
    when the build declares no read_images (every legacy path); ReadClassError when a padded arm would run an
    unsupported class."""
    if arm is None:
        return None
    padded = expected_lengths(config, arm, unbound_native)['READ'] != [49]
    return read_classes.expectations(config, arm, trial, padded)


def read_class_failures(checker_result, classes):
    """Per-class READ verdicts of check_capture (raw_result or the result itself) against the declaration: every
    READ classified into a declared class, ok, at its class image, and exactly the declared count per class."""
    raw = (checker_result or {}).get('raw_result') if isinstance((checker_result or {}).get('raw_result'), dict) \
        else (checker_result or {})
    verdicts = raw.get('verdicts') if isinstance(raw, dict) else None
    if not isinstance(verdicts, list):
        return ['per-class READ verdicts missing from the checker result']
    failures, seen = [], {}
    for v in verdicts:
        if not isinstance(v, dict) or v.get('kind') != 'READ':
            continue
        cls = v.get('read_class')
        if cls not in classes:
            failures.append('READ verdict %r has undeclared class %r' % (v.get('index'), cls))
            continue
        seen[cls] = seen.get(cls, 0) + 1
        if v.get('ok') is not True:
            failures.append('READ %s verdict %r not ok: %s' % (cls, v.get('index'), v.get('error')))
        if v.get('wire_len') != classes[cls]['image']:
            failures.append('READ %s verdict %r wire length %r, expected %d'
                            % (cls, v.get('index'), v.get('wire_len'), classes[cls]['image']))
    for cls, e in sorted(classes.items()):
        if seen.get(cls, 0) != e['count']:
            failures.append('READ %s verdicts %d, expected %d' % (cls, seen.get(cls, 0), e['count']))
    return failures


def expected_counts(context):
    trial = context.get('trial') or {}
    reads = int(trial.get('reads', 0))
    traffic = (context.get('config') or {}).get('traffic', {}) or {}
    sbo = int(traffic.get('sbo_cycles') or 1) if traffic.get('run_sbo', True) else 0
    counts = {'READ': reads}
    if sbo:
        counts.update({'SELECT': sbo, 'OPERATE': sbo})
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
    lengths = {kind: lengths for kind, lengths in expected_lengths(
        config, arm, bool(context.get('unbound_native'))
    ).items() if kind == 'READ' or kind in expected_counts(context)}
    classes = read_class_expectations(config, arm, trial, bool(context.get('unbound_native')))
    expected = {'counts': expected_counts(context), 'lengths': lengths}
    if classes is not None:          # per-class declaration only; a legacy build keeps the exact legacy shape
        lengths['READ'] = sorted({e['image'] for e in classes['classes'].values()})
        expected['read_classes'] = classes['classes']
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
        'expected': expected,
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
    version = artifact.get('schema_version')
    if version not in SCHEMA_VERSIONS:
        failures.append('schema_version mismatch: expected one of %r, got %r' % (SCHEMA_VERSIONS, version))
    elif version != SCHEMA_VERSION_V4 and _current_checker(context):
        failures.append('schema_version %s is never written by the current checker (it writes %s): '
                        'relabelled or stale artifact' % (version, SCHEMA_VERSION_V4))
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
            if 'read_classes' in expected['expected']:
                if checker_result.get('expected_read_classes') != expected['expected']['read_classes']:
                    failures.append('observed.checker_result.expected_read_classes mismatch: expected %r, got %r'
                                    % (expected['expected']['read_classes'],
                                       checker_result.get('expected_read_classes')))
                failures += ['observed.checker_result: ' + f for f in
                             read_class_failures(checker_result, expected['expected']['read_classes'])]
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
            if kind == 'READ' and 'read_classes' in expected['expected']:
                pass        # per class: bound through the checker verdicts above, not the first-packet length set
            elif row.get('resp_len') != expected['expected']['lengths'].get(kind):
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

    if _software_hold_required(context):
        derived = _bound_operate_hold(context, captures)
        stated = observed.get('operate_hold') if isinstance(observed, dict) else None
        if not isinstance(stated, dict):
            failures.append('OPERATE hold evidence missing or malformed')
        elif stated != derived:
            failures.append('OPERATE hold evidence differs from the bound captures')
        if not derived['pass']:
            failures.append('OPERATE hold from bound captures: ' + '; '.join(derived['reasons']))

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
    several = {'READ'} if 'read_classes' in expected['expected'] else set()    # one image per declared class
    if not isinstance(lengths, dict) or any(not isinstance(v, list) or not v or (len(v) != 1 and k not in several)
                                            or any(not isinstance(n, int) or isinstance(n, bool) or n <= 0 for n in v)
                                            for k, v in lengths.items()):
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


def _current_checker(context):
    """The context's checker closure contains this standards.py: the artifact claims the current writer."""
    here = Path(__file__).resolve()
    return any(Path(str(f)).resolve() == here for f in ((context or {}).get('checker_files') or []))


def _software_hold_required(context):
    """Timed software SBO gates J where the calling path evaluates hold; recovery/runner exemptions persist."""
    config = (context or {}).get('config') or {}
    arm = (context or {}).get('arm') or _first_config_arm(config) or {}
    return bool(config.get('endpoint_profile', 'software') == 'software' and
                (context.get('trial') or {}).get('fixture') != 'physical_relay' and
                arm.get('T') and not context.get('unbound_native') and
                not context.get('operate_hold_exempt') and
                expected_counts(context).get('OPERATE') and
                'op_j' in (config.get('timing_params_ns') or {}))


def _bound_operate_hold(context, captures):
    """Recompute the software hold from the same out/in files whose hashes bind the artifact."""
    import hold_check
    config = context.get('config') or {}
    op_j = config['timing_params_ns']['op_j']
    count = expected_counts(context)['OPERATE']
    paths = {name: _get_path((captures or {}).get(name)) for name in ('out', 'in')}
    port = context.get('master_port')
    if port is None:
        port = (context.get('trial') or {}).get('master_port')
    try:
        if not all(paths.values()) or not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
            raise ValueError('out/in capture paths or master_port missing or malformed')
        outstation_port = (config.get('endpoints') or {}).get('outstation_port', 20000)
        hold = hold_check.analyze(paths['out'], paths['in'], port, outstation_port)
    except (OSError, ValueError, IndexError, struct.error) as error:
        result = hold_check.operate_hold(None, op_j, count, count)
        result['reasons'] = ['cannot recompute from bound captures: %s' % error]
        return result
    return hold_check.operate_hold(hold, op_j, count, count)


def build_standards_artifact(context, captures, observed=None):
    observed = dict(observed or {})
    expected = expected_identity(context)
    capture_hashes = _capture_hashes(captures)
    artifact = {
        'schema_version': SCHEMA_VERSION_V4,
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
    if _software_hold_required(context):
        artifact['observed']['operate_hold'] = _bound_operate_hold(context, captures)
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
