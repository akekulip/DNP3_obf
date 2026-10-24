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
import read_classes

# v2: observed.precision + qualification. Every retained artifact is v2 and keeps its validation path and verdict;
# SCHEMA_VERSION keeps naming it for those readers. v3 (everything build_standards_artifact writes now): v2 plus the
# mandatory observed.objectives and a nearest-rank READ p99. A v3 artifact without objectives is rejected, and a
# v2 artifact is rejected when it carries objectives or claims the current checker (which never writes v2): a v3
# artifact relabelled v2 by hand therefore cannot fall back to the pre-objective path under this checker.
SCHEMA_VERSION = 'dnp3-standards-v2'
SCHEMA_VERSION_V3 = 'dnp3-standards-v3'
SCHEMA_VERSIONS = (SCHEMA_VERSION, SCHEMA_VERSION_V3)
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


def validate_standards(artifact, context, captures, hold_analyzer=None):
    """hold_analyzer(out, in, master_port, outstation_port): what derives the OPERATE hold from the bound captures
    (default hold_check.analyze); the campaign passes its own so a harness with placeholder captures can stand in."""
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
    version = artifact.get('schema_version')
    if version not in SCHEMA_VERSIONS:
        failures.append('schema_version mismatch: expected one of %r, got %r' % (SCHEMA_VERSIONS, version))
    elif version == SCHEMA_VERSION and _current_checker(context):
        failures.append('schema_version %s is never written by the current checker (it writes %s): '
                        'relabelled or stale artifact' % (SCHEMA_VERSION, SCHEMA_VERSION_V3))
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

    purpose = ((context or {}).get('config') or {}).get('evaluation', {}).get('purpose', 'qualification')
    precision = (artifact.get('observed') or {}).get('precision') if isinstance(artifact.get('observed'), dict) else None
    v3 = artifact.get('schema_version') == SCHEMA_VERSION_V3
    precision_failures = _validate_precision(artifact['observed'], context, purpose, nearest_rank=v3) \
        if isinstance(artifact.get('observed'), dict) else []
    failures += precision_failures
    objectives = (artifact.get('observed') or {}).get('objectives') if isinstance(artifact.get('observed'), dict) \
        and 'objectives' in artifact['observed'] else None
    objective_failures = _validate_objectives(artifact['observed'], context, purpose, v3, captures,
                                              hold_analyzer) \
        if isinstance(artifact.get('observed'), dict) else []
    failures += objective_failures
    # conformance (ok), READ precision and the other timing objectives stay separate fields; qualification
    # combines them with the purpose
    return {'ok': not failures, 'failures': failures, 'expected': expected['expected'],
            'capture_hashes': capture_hashes,
            'precision': precision if not precision_failures else None,
            'objectives': ({name: (objectives.get(name) or {}).get('status') for name in OBJECTIVES}
                           if isinstance(objectives, dict) and not objective_failures else None),
            'qualification': qualification(not failures, precision, purpose,
                                           objectives if 'objectives' in (artifact.get('observed') or {}) else None)}


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


def _current_checker(context):
    """The context's checker closure contains this standards.py: the artifact claims the current writer."""
    here = Path(__file__).resolve()
    return any(Path(str(f)).resolve() == here for f in ((context or {}).get('checker_files') or []))


def _precision_numbers(precision, nearest_rank=None):
    """(eligible, p99) of a READ precision evidence dict. The nearest-rank p99 (checks.read_precision_gate) is
    used whenever present and is mandatory when nearest_rank is True (v3); v2 evidence used clrt_check.stats."""
    eligible = precision.get('eligible')
    if nearest_rank or (nearest_rank is None and 'p99_nearest_rank_abs_error_us' in precision):
        p99 = precision.get('p99_nearest_rank_abs_error_us')
    else:
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


def qualification(structural_ok, precision, purpose='qualification', objectives=None):
    """Overall verdict for the selected research configuration: conformance AND precision AND purpose, and, when
    the artifact carries them, every timing objective. objectives=None is the pre-objective artifact shape, whose
    verdict is exactly what it always was. With objectives, a missing, malformed or failing block rejects; for
    purpose qualification every required objective must pass; a deferral or an exempted objective yields
    measurement_only at best."""
    if not structural_ok or not isinstance(precision, dict) or precision.get('status') not in PRECISION_STATUSES:
        return 'rejected'
    if precision['status'] == 'fail':
        return 'rejected'
    deferred = False
    if objectives is not None:
        if not isinstance(objectives, dict):
            return 'rejected'
        for name in OBJECTIVES:
            block = objectives.get(name)
            if not isinstance(block, dict) or block.get('status') not in PRECISION_STATUSES:
                return 'rejected'
            if block['status'] == 'fail':
                return 'rejected'
            if purpose == 'qualification' and block.get('required') is not False and block['status'] != 'pass':
                return 'rejected'
            # an exempted objective (required by the build/arm/fixture, declared unevaluated) caps the verdict
            deferred = deferred or block['status'] == 'deferred' or bool(block.get('exempted'))
    if precision['status'] == 'deferred' or deferred or purpose != 'qualification':
        return 'measurement_only'
    return 'qualified'


# ---- timing objectives beyond READ: SELECT/OPERATE CLRT, piggyback latency, OPERATE hold J ---------------------
# Each is its own block under observed.objectives, inside the same artifact whose run, identity, checker and
# capture hashes the READ block is bound by. Requirements are derived from the run context, never the artifact,
# and a claimed pass or deferral is re-checked against fixed bounds from the configuration.

OBJECTIVES = ('select_precision', 'operate_precision', 'piggyback_latency', 'operate_hold')
OBJECTIVE_LABELS = {'select_precision': 'SELECT precision', 'operate_precision': 'OPERATE precision',
                    'piggyback_latency': 'PIGGYBACK latency', 'operate_hold': 'OPERATE hold'}
PIGGYBACK_MINIMUM_SAMPLES = 20
PIGGYBACK_MARGIN_US = 250


def objective_bounds(config):
    """Fixed bounds from the configuration: pb (+ margin) for piggyback latency, op_j for the OPERATE hold."""
    t = (config or {}).get('timing_params_ns') or {}
    return {'piggyback_target_us': t['pb'] / 1000.0 + PIGGYBACK_MARGIN_US if 'pb' in t else None,
            'op_j_us': t['op_j'] / 1000.0 if 'op_j' in t else None}


def objective_requirements(context):
    """{objective: (required, reason, exempted)} derived from the run context alone (see checks.evaluate for the
    gates). exempted: the build/arm/fixture would require the objective but a code path (loss, reconnect, a runner
    that evaluates no objectives) declared it unevaluated -- recorded as not_applicable with the reason, and the
    artifact can then be measurement_only at best, never qualified."""
    context = context or {}
    config = context.get('config') or {}
    arm = context.get('arm') or _first_config_arm(config) or {}
    build = _build(config, arm) or {}
    trial = context.get('trial') or {}
    fixture = trial.get('fixture', 'separate_ack')
    timing = config.get('timing_params_ns') or {}
    sbo = expected_counts(context).get('OPERATE', 0)
    exempt = context.get('objectives_exempt') or context.get('precision_exempt')
    common = (('arm %s has no timing target (T=0)' % arm.get('name')) if not arm.get('T') else
              'unbound native connection: no timing target' if context.get('unbound_native') else None)
    read_required, read_reason = precision_requirement(dict(context, precision_exempt=None, objectives_exempt=None))
    base = {}
    for name in ('select_precision', 'operate_precision'):
        base[name] = ((False, common) if common else
                      (False, 'build %s is not control_timed: no SELECT/OPERATE CLRT target' % arm.get('build'))
                      if not build.get('control_timed') else
                      (False, 'no SELECT/OPERATE in this trial') if not sbo else
                      (False, read_reason) if not read_required else (True, None))
    base['piggyback_latency'] = (
        (False, common) if common else
        (False, 'build %s is not piggyback_bound' % arm.get('build')) if not build.get('piggyback_bound') else
        (False, 'fixture %s: no piggyback latency target' % fixture) if fixture != 'piggyback' else
        (False, 'timing_params_ns.pb absent') if 'pb' not in timing else (True, None))
    base['operate_hold'] = (
        (False, common) if common else
        (False, 'no OPERATE in this trial') if not sbo else
        (False, 'timing_params_ns.op_j absent') if 'op_j' not in timing else (True, None))
    return {name: ((False, 'exempted: %s' % exempt, True) if required and exempt else (required, reason, False))
            for name, (required, reason) in base.items()}


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _objective_numbers(name, evidence, bounds):
    """(sufficient, passes, message) re-derived from the evidence numbers against the fixed bounds, or None when
    the evidence carries no usable numbers. sufficient: only the threshold can be what failed."""
    label = OBJECTIVE_LABELS[name]
    if not isinstance(evidence, dict):
        return None
    if name in ('select_precision', 'operate_precision'):
        eligible, p99 = evidence.get('eligible'), evidence.get('p99')     # checks.kind_precision: nearest rank
        if not _int(eligible) or not _num(p99):
            return None
        sufficient = eligible >= PRECISION_MINIMUM_ELIGIBLE
        return sufficient, sufficient and p99 <= PRECISION_MAXIMUM_P99_US, (
            '%s: eligible=%s (minimum%d), nearest-rank p99 absolute CLRT error=%s us (maximum%d)'
            % (label, eligible, PRECISION_MINIMUM_ELIGIBLE, p99, PRECISION_MAXIMUM_P99_US))
    if name == 'piggyback_latency':
        n, p99, target = evidence.get('n'), evidence.get('p99'), (bounds or {}).get('piggyback_target_us')
        if not _int(n) or target is None or (n >= PIGGYBACK_MINIMUM_SAMPLES and not _num(p99)):
            return None
        if n < PIGGYBACK_MINIMUM_SAMPLES:
            return False, False, '%s: insufficient piggyback samples: %d < %d' % (label, n, PIGGYBACK_MINIMUM_SAMPLES)
        return True, p99 <= target, '%s: n=%d, nearest-rank p99 request-to-response %s us (target pb + margin %s us)' % (
            label, n, p99, target)
    sent, seen, minimum = evidence.get('sent'), evidence.get('observed'), evidence.get('min_transit_us')
    complete, expected, op_j = evidence.get('complete_operates'), evidence.get('expected_operates'), \
        (bounds or {}).get('op_j_us')
    if not _int(sent) or not _int(seen) or op_j is None:
        return None
    sufficient = (seen == sent and sent >= 1 and (not _int(expected) or sent >= expected)
                  and (not _int(complete) or seen >= complete) and _num(minimum))
    return sufficient, sufficient and minimum >= op_j, '%s: sent=%d observed=%d, minimum transit %s us (op_j %s us)' % (
        label, sent, seen, minimum, op_j)


def objective_block(name, required, evidence=None, purpose='qualification', reason=None, bounds=None,
                    exempted=False):
    """One timing objective's status, kept apart from conformance (same statuses as the READ block). A required
    block without usable evidence fails; only a threshold miss over sufficient evidence in an explicit
    timing-characterization run is deferred (measurement only). An exempted objective is not_applicable with
    exempted=True and caps the qualification at measurement_only."""
    label = OBJECTIVE_LABELS[name]
    if not required:
        return {'required': False, 'status': 'not_applicable', 'exempted': bool(exempted),
                'reasons': [reason or 'no %s target for this arm/fixture/build' % label], 'evidence': evidence}
    numbers = _objective_numbers(name, evidence, bounds)
    if numbers is None:
        return {'required': True, 'status': 'fail', 'reasons': ['%s evidence missing' % label], 'evidence': evidence}
    sufficient, passes, message = numbers
    if passes:
        return {'required': True, 'status': 'pass', 'reasons': [], 'evidence': evidence}
    reasons = [message] + [str(r) for r in (evidence.get('reasons') or [])]
    deferrable = purpose == 'timing_precision_characterization' and sufficient
    return {'required': True, 'status': 'deferred' if deferrable else 'fail', 'reasons': reasons,
            'evidence': evidence}


def _validate_objectives(observed, context, purpose, v3=True, captures=None, hold_analyzer=None):
    """v3: observed.objectives is mandatory and must hold every objective, each agreeing with the context-derived
    requirement and exemption, and supported by its own evidence against the configuration's fixed bounds; a
    claimed OPERATE hold pass/deferral is recomputed from the bound captures. v2 (retained, pre-objective):
    objectives must be absent, and the artifact validates as it always did."""
    if not v3:
        return ['dnp3-standards-v2 artifact carries observed.objectives (relabelled v3?)'] \
            if 'objectives' in observed else []
    if 'objectives' not in observed or observed.get('objectives') is None:
        return ['observed.objectives missing (mandatory in %s)' % SCHEMA_VERSION_V3]
    blocks = observed.get('objectives')
    if not isinstance(blocks, dict):
        return ['observed.objectives malformed']
    failures = []
    want = objective_requirements(context)
    bounds = objective_bounds((context or {}).get('config'))
    for name in OBJECTIVES:
        block = blocks.get(name)
        where = 'observed.objectives.%s' % name
        if not isinstance(block, dict):
            failures.append('%s missing or malformed' % where)
            continue
        status, required, reasons = block.get('status'), block.get('required'), block.get('reasons')
        if status not in PRECISION_STATUSES or not isinstance(required, bool) or not isinstance(reasons, list):
            failures.append('%s status/required/reasons malformed: %r/%r/%r' % (where, status, required, reasons))
            continue
        if required is not want[name][0]:
            failures.append('%s.required is %r but the context requires %r' % (where, required, want[name][0]))
        if bool(block.get('exempted')) is not want[name][2]:
            failures.append('%s.exempted is %r but the context declares %r' % (where, block.get('exempted'),
                                                                              want[name][2]))
        if required and status == 'not_applicable':
            failures.append('%s: required but status not_applicable' % where)
        if not required and status != 'not_applicable':
            failures.append('%s: not required but status %r' % (where, status))
        if status in ('fail', 'deferred', 'not_applicable') and not reasons:
            failures.append('%s.status %r without reasons' % (where, status))
        if status == 'deferred' and purpose != 'timing_precision_characterization':
            failures.append('%s deferred outside timing_precision_characterization' % where)
        if status in ('pass', 'deferred'):
            numbers = _objective_numbers(name, block.get('evidence'), bounds)
            if numbers is None:
                failures.append('%s.evidence does not support status %r (no usable numbers)' % (where, status))
            elif not numbers[0]:
                failures.append('%s.evidence does not support status %r: %s' % (where, status, numbers[2]))
            elif (status == 'pass') != numbers[1]:
                failures.append('%s.evidence does not support status %r: %s' % (where, status, numbers[2]))
            if name == 'operate_hold':
                failures += _recompute_hold(block.get('evidence'), context, captures, where, hold_analyzer)
    return failures


def _recompute_hold(evidence, context, captures, where, analyzer=None):
    """The stated OPERATE hold numbers must be what hold_check derives from the bound out/in captures."""
    paths = {k: _get_path((captures or {}).get(k)) for k in ('out', 'in')}
    port = (context or {}).get('master_port')
    if not all(paths.values()) or port is None or not isinstance(evidence, dict):
        return ['%s: cannot recompute from the bound captures (out/in paths or master_port missing)' % where]
    if analyzer is None:
        import hold_check     # campaign-side only, like checks.evaluate
        analyzer = hold_check.analyze
    try:
        outstation = (((context or {}).get('config') or {}).get('endpoints') or {}).get('outstation_port', 20000)
        derived = analyzer(paths['out'], paths['in'], port, outstation)
    except (OSError, ValueError, IndexError) as error:
        return ['%s: bound captures unreadable for recomputation: %s' % (where, error)]
    rows = derived['operates']
    seen = [r['transit_us'] for r in rows if r['observed']]
    got = {'sent': len(rows), 'observed': len(seen), 'min_transit_us': min(seen) if seen else None}
    stated = {k: evidence.get(k) for k in got}
    return [] if got == stated else ['%s.evidence %r differs from the bound captures %r' % (where, stated, got)]


def _validate_precision(observed, context, purpose, nearest_rank=False):
    """The artifact's precision block must agree with the context-derived requirement, and a claimed pass or
    deferral must be supported by its own evidence against the fixed bound (not a bound the artifact states).
    nearest_rank (v3): the evidence must carry the nearest-rank p99 and the status is re-checked on it."""
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
        eligible, p99 = _precision_numbers(evidence, nearest_rank) if isinstance(evidence, dict) else (None, None)
        if eligible is None:
            failures.append('observed.precision.evidence does not support status %r (no eligible/p99%s)'
                            % (status, ', nearest-rank p99 required' if nearest_rank else ''))
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
        'schema_version': SCHEMA_VERSION_V3,
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
    artifact['observed']['objectives'] = observed.get('objectives')   # v3: always present (None fails validation)
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
