#!/usr/bin/env python3
"""Receive-offload helpers for physical Vision captures.

Records the campaign-level receive-offload baseline of the capture interface, restores and verifies it, and
disables receive aggregation for one capture (offload_capture_context), leaving file-backed evidence of the
before, during and after state.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess

PARENT = 'enp59s0f0np0'
MANAGED_OFFLOADS = ('gro', 'lro', 'rx-gro-hw', 'rx-gro-list')
FEATURE_ALIASES = {
    'generic-receive-offload': 'gro',
    'large-receive-offload': 'lro',
    'rx-gro-hw': 'rx-gro-hw',
    'rx-gro-list': 'rx-gro-list',
}


def sh(argv, **kw):
    return subprocess.run(list(argv), capture_output=True, text=True, **kw)


def _bool(value):
    if value == 'on':
        return True
    if value == 'off':
        return False
    return value


def parse_ethtool_features(raw):
    features = {}
    for line in (raw or '').splitlines():
        if ':' not in line:
            continue
        name, value = line.split(':', 1)
        name = name.strip()
        token = value.strip().split()[0].lower() if value.strip() else ''
        if token not in ('on', 'off'):
            continue
        key = FEATURE_ALIASES.get(name, name)
        features[key] = _bool(token)
    return features


def _run_checked(run, argv, commands):
    result = run(list(argv))
    commands.append(list(argv))
    if getattr(result, 'returncode', 0):
        raise RuntimeError('command failed: %s\n%s' % (' '.join(argv), getattr(result, 'stderr', '').strip()))
    return result


def snapshot_features(interface, run=sh):
    command = ['ethtool', '-k', interface]
    result = run(command)
    if result.returncode:
        raise RuntimeError('ethtool feature snapshot failed: ' + result.stderr.strip())
    return {'features': parse_ethtool_features(result.stdout), 'raw': result.stdout, 'command': command}


def receive_aggregation_failures(features):
    failures = []
    if features.get('gro') is not False:
        failures.append('GRO is not disabled on physical capture interface')
    for key in ('lro', 'rx-gro-hw', 'rx-gro-list'):
        if key in features and features[key] is not False:
            failures.append('%s is not disabled on physical capture interface' % key)
    return failures


def record_offload_baseline(path, interface=PARENT, run=sh):
    """Campaign-level receive-offload baseline, written once. An existing file means an earlier campaign never
    completed its restore, so the state now on the NIC may be that campaign's and is not taken as the baseline."""
    path = Path(path)
    if path.exists():
        return json.loads(path.read_text())
    snap = snapshot_features(interface, run=run)
    baseline = {'interface': interface, 'features': {k: v for k, v in snap['features'].items() if k in MANAGED_OFFLOADS},
                'raw': snap['raw']}
    path.write_text(json.dumps(baseline, indent=2) + '\n')
    return baseline


def restore_offload_baseline(path, interface=PARENT, run=sh):
    """Re-apply and verify the campaign baseline independently of any per-run context. Returns the errors; the
    baseline file is removed only after the NIC is verified equal to it."""
    path = Path(path)
    if not path.exists():
        return ['no receive-offload baseline recorded at %s' % path]
    baseline = json.loads(path.read_text())
    errors = []
    try:
        current = snapshot_features(interface, run=run)['features']
    except Exception as error:
        return [str(error)]
    for key, value in baseline['features'].items():
        if current.get(key) == value:       # never write a key already at baseline ([fixed] features refuse -K)
            continue
        result = run(['ethtool', '-K', interface, key, 'on' if value else 'off'])
        if getattr(result, 'returncode', 0):
            errors.append('ethtool -K %s %s failed: %s' % (key, value, getattr(result, 'stderr', '').strip()))
    try:
        after = snapshot_features(interface, run=run)['features']
    except Exception as error:
        return errors + [str(error)]
    errors += ['receive offload %s is %r, baseline %r' % (key, after.get(key), value)
               for key, value in baseline['features'].items() if after.get(key) != value]
    if not errors:
        path.unlink()
    return errors


@contextmanager
def offload_capture_context(evidence_dir, interface=PARENT, run=sh, evidence_name='capture_offloads.json'):
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    commands, restore_errors = [], []
    before = snapshot_features(interface, run=run)
    during = {}
    after = {}
    block_error = None
    try:
        for key in MANAGED_OFFLOADS:
            if before['features'].get(key) is True:
                _run_checked(run, ['ethtool', '-K', interface, key, 'off'], commands)
        during = snapshot_features(interface, run=run)
        failures = receive_aggregation_failures(during['features'])
        if failures:
            raise RuntimeError('; '.join(failures))
        yield {'interface': interface, 'before': before, 'during': during, 'commands': commands}
    except Exception as error:
        block_error = error
        raise
    finally:
        for key in MANAGED_OFFLOADS:
            if before['features'].get(key) is not True:
                continue
            try:
                _run_checked(run, ['ethtool', '-K', interface, key, 'on' if before['features'][key] else 'off'], commands)
            except Exception as error:
                restore_errors.append(str(error))
        try:
            after = snapshot_features(interface, run=run)
        except Exception as error:
            restore_errors.append(str(error))
        restore_ok = not restore_errors
        if after:
            for key in MANAGED_OFFLOADS:
                if key in before['features'] and after['features'].get(key) != before['features'][key]:
                    restore_ok = False
                    restore_errors.append('restore mismatch for %s' % key)
        evidence = {
            'interface': interface,
            'before': before,
            'during': during,
            'after': after,
            'restore_ok': restore_ok,
            'restore_errors': restore_errors,
            'commands': commands,
        }
        if block_error is not None:
            evidence['block_error'] = str(block_error)
        (evidence_dir / evidence_name).write_text(json.dumps(evidence, indent=2) + '\n')
        if not restore_ok and block_error is None:
            raise RuntimeError('receive offload restore failed: ' + '; '.join(restore_errors))

