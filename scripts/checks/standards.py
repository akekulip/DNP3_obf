"""Current run-bound SEL-751 receiver-visible standards validator."""
import hashlib
import json
import os
from pathlib import Path

SBO = ("SELECT", "OPERATE")

SCHEMA_VERSION_SEL751 = 'dnp3-standards-sel751-v1'
SEL751_SCOPE = 'sel751_receiver_visible'
# padded -> response octets per class (physical SEL-751 relay profile)
SEL751_IMAGES = {False: {'mixed': 91, 'integrity': 134, 'SELECT': 49, 'OPERATE': 49},
                 True: {'mixed': 141, 'integrity': 158, 'SELECT': 60, 'OPERATE': 60}}
SEL751_CAPTURE_FILES = {'out': 'out.pcap', 'in': 'in.pcap', 'master': 'master.json', 'run_result': 'result.json',
                        'capture_offloads': 'capture_offloads.json', 'relay_wire': 'relay_wire.json'}
SEL751_CAPTURES = tuple(SEL751_CAPTURE_FILES)
SEL751_NOT_EVALUATED = ('switch_emitted_boundaries', 'departure_timing', 'physical_event_protection')
SEL751_READ_ORDER = {'mixed_full': ('mixed', 'integrity'), 'mixed': ('mixed',), 'full': ('integrity',)}
# relay_check.master_checks findings about bytes and sockets (DNP3 framing/CRC/addresses, socket identity) are
# transport findings; the rest (outcomes, denominators, schedule) are application findings
SEL751_TRANSPORT_MASTER_FINDINGS = ('actual socket identity', 'request complete wire', 'response complete wire')
SEL751_TRIAL_LEVEL_CHECKS = ('TCP header/options are recomputed from the captures; FIN/RST close proof is '
                             'also required by the applicable trial gate (relay_wire.json is bound by hash)')



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
    """Run, identity and checker are shared; the expected part is the scope's own (software or SEL-751)."""
    config = context.get('config') or {}
    arm = context.get('arm') or _first_config_arm(config)
    build = _build(config, arm) or {}
    run_record = context.get('run_record') or {}
    run_id = run_record.get('run_id') or context.get('run_id')
    trial = context.get('trial') or {}
    build_hashes = {}
    if arm:
        build_hashes = ((run_record.get('builds') or {}).get(arm.get('build')) or build.get('hashes') or {})
    if not sel751_scope(context):
        raise ValueError('current standards require endpoint_profile sel751')
    expected = _sel751_expected(context)
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
            'profile': build.get('profile'),
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


def _is_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def sel751_scope(context):
    return ((context or {}).get('config') or {}).get('endpoint_profile') == 'sel751'


def _sel751_emission_required(context):
    """Only an explicit requirement counts here; the candidate61 label alone is a software-profile rule."""
    config = (context or {}).get('config') or {}
    build = _build(config, (context or {}).get('arm') or _first_config_arm(config)) or {}
    return bool((context or {}).get('packet_boundary_required') or build.get('packet_boundary_required') or
                (config.get('standards') or {}).get('packet_boundary_required'))


def _sel751_expected(context):
    config = context.get('config') or {}
    arm = context.get('arm') or _first_config_arm(config)
    counts = expected_counts(context)
    schedule = (config.get('traffic') or {}).get('read_schedule')
    if schedule not in SEL751_READ_ORDER:
        raise ValueError('SEL-751 read_schedule %r unsupported' % schedule)
    padded = bool(arm and arm.get('padding') and not context.get('unbound_native'))
    images = SEL751_IMAGES[padded]
    order = SEL751_READ_ORDER[schedule]
    classes = {}
    for i in range(counts['READ']):
        cls = order[i % len(order)]
        classes.setdefault(cls, {'count': 0, 'image': images[cls]})['count'] += 1
    lengths = {'READ': sorted({e['image'] for e in classes.values()})}
    lengths.update({kind: [images[kind]] for kind in SBO if kind in counts})
    return {'counts': counts, 'lengths': lengths, 'read_classes': classes, 'read_schedule': schedule,
            'padded': padded, 'planned_exchanges': sum(counts.values())}


def _sel751_root(captures):
    """All bound files sit in one trial/connection directory under their fixed names; returns it or failures."""
    failures, roots = [], set()
    for name, filename in SEL751_CAPTURE_FILES.items():
        path = _get_path((captures or {}).get(name))
        if not path:
            failures.append('context.captures.%s path is missing' % name)
        elif not Path(path).is_file():
            failures.append('context.captures.%s path is unreadable: %s' % (name, path))
        elif Path(path).name != filename:
            failures.append('context.captures.%s must be %s, got %s' % (name, filename, path))
        else:
            roots.add(Path(path).resolve().parent)
    if len(roots) > 1:
        failures.append('context.captures are not one trial directory: %s' % sorted(map(str, roots)))
    return (next(iter(roots)) if roots and not failures else None), failures


def _sel751_observed(context, captures, expected):
    """Recompute transport, CROB statuses/echo and sizes from located captured wire bytes.
    Master outcome and point strings are checked against decoded applications."""
    if __package__:
        from . import relay_check
    else:
        import relay_check
    root, missing = _sel751_root(captures)
    port = context.get('master_port')
    if port is None:
        port = (context.get('trial') or {}).get('master_port')
    counts = expected['counts']
    planned = {kind: int(counts.get(kind, 0)) for kind in ('READ', 'SELECT', 'OPERATE')}
    transport, application, sizes, rows, crob_failed = [], [], [], {}, set()
    try:
        if missing:
            raise ValueError('; '.join(missing))
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
            raise ValueError('master_port missing or malformed: %r' % (port,))
        master = json.loads((root / 'master.json').read_text())
        findings = relay_check.master_checks(master, port, planned, expected['read_schedule'])
        report = relay_check.analyze(root, port, planned, expected['read_schedule'])
        if report['failures'][:len(findings)] != findings:
            raise ValueError('relay_check failure order differs from its master checks')
        transport = [f for f in findings if f.startswith(SEL751_TRANSPORT_MASTER_FINDINGS)] + \
            report['failures'][len(findings):]
        application = [f for f in findings if not f.startswith(SEL751_TRANSPORT_MASTER_FINDINGS)]
        records = master.get('records') or []
        for record, exchange in zip(records, report['exchanges']):
            operation = record.get('operation')
            key = 'READ:%s' % record.get('workload') if operation == 'READ' else str(operation)
            row = rows.setdefault(key, {'count': 0, 'ok': 0, 'resp_len': []})
            row['count'] += 1
            decoded = exchange.get('application') or {}
            row['ok'] += record.get('outcome') == 'OK' and decoded.get('ok') is True
            try:
                size = len(bytes.fromhex(record.get('response_wire_hex') or ''))
            except ValueError:
                size = 0
            if size not in row['resp_len']:
                row['resp_len'] = sorted(row['resp_len'] + [size])
            want = SEL751_IMAGES[expected['padded']].get(record.get('workload') if operation == 'READ' else operation)
            if not exchange.get('response'):
                sizes.append('%s response not located in the in capture' % key)
            elif size != want:
                sizes.append('%s response %d octets, expected %s' % (key, size, want))
            if operation in SBO:
                points = decoded.get('points') or []
                bad = [point for point in points if point[1:] != ['SUCCESS']]
                if bad or not points or decoded.get('ok') is not True:
                    crob_failed.add(operation)
                    application.append('%s captured CROB not successful: %r; %s' %
                                       (operation, bad or points, '; '.join(decoded.get('failures') or [])))
        wanted = {'READ:' + cls: e['count'] for cls, e in expected['read_classes'].items()}
        wanted.update({kind: counts[kind] for kind in SBO if kind in counts})
        for key, count in sorted(wanted.items()):
            got = rows.get(key, {}).get('count', 0)
            if got != count:
                application.append('missing exchange: %s observed %d, planned %d' % (key, got, count))
        for key in sorted(set(rows) - set(wanted)):
            application.append('unplanned exchange class %s' % key)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        application.append('SEL-751 evidence unreadable: %s' % error)
    # an SBO step succeeds only with every planned response OK and every CROB point SUCCESS; TIMEOUT never does
    select_ok = 'SELECT' not in counts or ('SELECT' not in crob_failed and rows.get('SELECT', {}).get('ok') ==
                                           counts['SELECT'] == rows.get('SELECT', {}).get('count'))
    operate_ok = 'OPERATE' not in counts or (select_ok and 'OPERATE' not in crob_failed and
                                             rows.get('OPERATE', {}).get('ok') == counts['OPERATE'] ==
                                             rows.get('OPERATE', {}).get('count'))
    transport_ok = not transport and not any(f.startswith('SEL-751 evidence unreadable') for f in application)
    return {
        'exchanges': rows,
        'transport_failures': transport,
        'application_failures': application,
        'size_failures': sizes,
        'transport_ok': transport_ok,
        'select_authorizes_operate': bool(select_ok),
        'operate_success': bool(operate_ok),
        'size_ok': not sizes and transport_ok,
        'aggregate_verdict': bool(transport_ok and not application and not sizes and select_ok and operate_ok),
        'not_evaluated': {name: 'NOT EVALUATED' for name in SEL751_NOT_EVALUATED},
        'trial_level_checks': SEL751_TRIAL_LEVEL_CHECKS,
    }


def _build_sel751_artifact(context, captures):
    expected = expected_identity(context)
    return {
        'schema_version': SCHEMA_VERSION_SEL751,
        'scope': SEL751_SCOPE,
        **expected,
        'captures': _capture_hashes({k: v for k, v in (captures or {}).items() if k in SEL751_CAPTURES}),
        'observed': _sel751_observed(context, captures, expected['expected']),
    }


def _validate_sel751(artifact, context, captures, expected):
    failures = []
    config = context.get('config') or {}
    arm = context.get('arm') or _first_config_arm(config)
    build = _build(config, arm) or {}
    for field, value in expected['run'].items():
        if value in (None, ''):
            failures.append('context.run.%s is missing' % field)
    if not arm or not arm.get('name') or not arm.get('build'):
        failures.append('context.arm must bind an arm name and build')
    if not build.get('profile'):
        failures.append('context.identity.profile must be explicit, got %r' % build.get('profile'))
    if not _is_sha(expected['identity'].get('candidate_source_sha256')):
        failures.append('context.identity.candidate_source_sha256 must be a pinned sha256')
    hashes = expected['identity'].get('build_hashes')
    if not isinstance(hashes, dict) or not hashes or any(not _is_sha(v) for v in hashes.values()):
        failures.append('context.identity.build_hashes must contain pinned sha256 values')
    files = context.get('checker_files')
    if not isinstance(files, list) or not files or any(not Path(f).is_file() for f in files):
        failures.append('context.checker_files must list existing checker/dependency files')
    _, missing = _sel751_root(captures)
    failures += missing
    if _sel751_emission_required(context):
        failures.append('emission proof required, but SEL-751 receiver-visible evidence cannot provide it '
                        '(switch-emitted boundaries are NOT EVALUATED in this scope)')
    _append_mismatch(failures, 'schema_version', SCHEMA_VERSION_SEL751, artifact.get('schema_version'))
    _append_mismatch(failures, 'scope', SEL751_SCOPE, artifact.get('scope'))
    for group in ('run', 'identity', 'checker', 'expected'):
        if not isinstance(artifact.get(group), dict):
            failures.append('missing or malformed %s' % group)
    if failures:
        return {'ok': False, 'failures': failures, 'expected': expected['expected']}
    for group in ('run', 'identity', 'checker', 'expected'):
        for key, value in expected[group].items():
            _append_mismatch(failures, '%s.%s' % (group, key), value, artifact[group].get(key))
    capture_hashes = _capture_hashes({k: v for k, v in captures.items() if k in SEL751_CAPTURES})
    stated = artifact.get('captures') if isinstance(artifact.get('captures'), dict) else {}
    for name in SEL751_CAPTURES:
        actual = capture_hashes.get(name) or {'error': 'missing'}
        if 'error' in actual:
            failures.append('captures.%s unreadable: %s' % (name, actual['error']))
        else:
            _append_mismatch(failures, 'captures.%s.sha256' % name, actual['sha256'],
                             (stated.get(name) or {}).get('sha256'))
    derived = _sel751_observed(context, captures, expected['expected'])
    if artifact.get('observed') != derived:
        failures.append('observed SEL-751 verdicts differ from the bound captures')
    failures += ['transport: ' + f for f in derived['transport_failures']]
    failures += ['application: ' + f for f in derived['application_failures']]
    failures += ['size: ' + f for f in derived['size_failures']]
    for key in ('transport_ok', 'select_authorizes_operate', 'operate_success', 'size_ok', 'aggregate_verdict'):
        if derived[key] is not True:
            failures.append('observed.%s is %r, expected True' % (key, derived[key]))
    return {'ok': not failures, 'failures': failures, 'expected': expected['expected'],
            'capture_hashes': capture_hashes, 'scope': SEL751_SCOPE,
            'verdicts': {'transport': derived['transport_ok'],
                         'application': not derived['application_failures'] and derived['select_authorizes_operate']
                         and derived['operate_success'],
                         'size': derived['size_ok']},
            'not_evaluated': derived['not_evaluated']}


def build_standards_artifact(context, captures, observed=None):
    return _build_sel751_artifact(context, captures)


def validate_standards(artifact, context, captures):
    try:
        if isinstance(artifact, (str, os.PathLike)):
            artifact = json.loads(Path(artifact).read_text())
        if not isinstance(artifact, dict):
            raise ValueError('standards artifact must be an object')
        return _validate_sel751(artifact, context, captures, expected_identity(context))
    except (OSError, ValueError, TypeError, KeyError) as error:
        return {'ok': False, 'failures': ['standards not evaluated: ' + str(error)]}
