#!/usr/bin/env python3
"""Durable serial campaign supervisor (Python 3.8, systemd user manager).

init MANIFEST creates MANIFEST.parent/campaign_id exclusively. Keep that directory
on persistent Gambit storage. start/resume detach immediately; status only reads.
Hooks must be deterministic offline commands. Hardware block commands must enter
through the existing run_block_frozen.sh wrapper. Fixtures never count as main
hardware evidence. No step is retried, reordered, replaced, or resumed internally.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
DAY = 24 * 60 * 60
SAFE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
ACTIVE = ('active', 'activating', 'reloading', 'deactivating', 'queued')
QUEUED_LIMIT_S = 600          # a start job still queued this long after launch is refused, never waited on forever


class Refused(RuntimeError):
    """Unsafe or ambiguous state; retain evidence and do not replay."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fsync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value, exclusive=False):
    """Publish only complete fsynced records, preserving existing terminal records."""
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temporary, str(path))
        else:
            os.replace(temporary, str(path))
        fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked(directory, name='state.lock', blocking=True):
    with open(directory / name, 'a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            raise Refused('another process owns ' + name)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise Refused('unreadable durable record %s: %s' % (path, error))


def valid_argv(argv):
    return (isinstance(argv, list) and bool(argv) and
            all(isinstance(arg, str) and arg and '\x00' not in arg for arg in argv))


def validate_manifest(data):
    if not isinstance(data, dict) or not SAFE_ID.fullmatch(str(data.get('campaign_id', ''))):
        raise Refused('campaign_id must be a safe, bounded unit/path component')
    if data.get('evidence_kind') not in ('hardware', 'supervision_fixture'):
        raise Refused('evidence_kind must be hardware or supervision_fixture')
    if not isinstance(data.get('steps'), list) or not data['steps']:
        raise Refused('manifest requires ordered nonempty steps')
    ids, commands, roots = set(), set(), set()
    for step in data['steps']:
        if not isinstance(step, dict) or not SAFE_ID.fullmatch(str(step.get('id', ''))):
            raise Refused('unsafe step ID')
        if step['id'] in ids or step.get('kind') not in ('block', 'hook'):
            raise Refused('duplicate step ID or invalid kind')
        ids.add(step['id'])
        if not valid_argv(step.get('argv')):
            raise Refused('argv must be nonempty strings without NUL')
        command = tuple(step['argv'])
        if command in commands:
            raise Refused('duplicate step argv')
        commands.add(command)
        if 'postcheck_argv' in step and not valid_argv(step['postcheck_argv']):
            raise Refused('invalid postcheck_argv')
        if step['kind'] == 'block':
            root = step.get('run_root')
            if not isinstance(root, str) or not Path(root).is_absolute():
                raise Refused('block run_root must be absolute')
            root = str(Path(root).resolve())
            if root in roots:
                raise Refused('duplicate block run_root')
            roots.add(root)
            if data['evidence_kind'] == 'hardware':
                argv = step['argv']
                wrapper = argv[1] if Path(argv[0]).name == 'bash' and len(argv) > 1 else argv[0]
                if Path(wrapper) != HERE / 'run_block_frozen.sh':
                    raise Refused('hardware blocks must invoke the existing frozen wrapper directly')


def initialize(manifest):
    manifest = Path(manifest).resolve(strict=True)
    raw = manifest.read_bytes()
    try:
        data = json.loads(raw)
    except ValueError as error:
        raise Refused('invalid manifest JSON: %s' % error)
    validate_manifest(data)
    directory = manifest.parent / data['campaign_id']
    directory.mkdir()  # never repair or overwrite a retained campaign
    fsync_directory(directory.parent)
    # An interrupted init leaves a retained, unusable directory; use a new ID.
    with open(directory / 'manifest.json', 'xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(str(directory / 'manifest.json'), 0o444)
    identity = {'campaign_id': data['campaign_id'], 'manifest_sha256': digest(raw),
                'evidence_kind': data['evidence_kind'], 'created': time.time()}
    atomic_json(directory / 'identity.json', identity, exclusive=True)
    (directory / 'steps').mkdir()
    for step in data['steps']:
        (directory / 'steps' / step['id']).mkdir()
    fsync_directory(directory / 'steps')
    state = dict(identity, started=False, start=None, deadline=None, active_step=None,
                 active_unit=None, controller_unit=None, controller_generation=0,
                 stop_after_current=False, stop_reason=None, phase='initialized',
                 steps={step['id']: {'status': 'unexecuted', 'rc': None,
                                    'restoration': None} for step in data['steps']})
    atomic_json(directory / 'state.json', state, exclusive=True)
    fsync_directory(directory)
    return directory


def load(directory):
    directory = Path(directory).resolve(strict=True)
    identity = read_json(directory / 'identity.json')
    raw = (directory / 'manifest.json').read_bytes()
    if digest(raw) != identity['manifest_sha256']:
        raise Refused('immutable manifest digest mismatch')
    data = json.loads(raw)
    validate_manifest(data)
    state = read_json(directory / 'state.json')
    if any(state.get(key) != identity[key] for key in
           ('campaign_id', 'manifest_sha256', 'evidence_kind')):
        raise Refused('state identity mismatch')
    if set(state['steps']) != {step['id'] for step in data['steps']}:
        raise Refused('planned step status set mismatch')
    return directory, data, state


def read_state(directory):
    return load(directory)[2]


def unit_name(directory, identity, suffix):
    # Path salt avoids collisions with another persistent storage location.
    salt = digest(str(directory).encode())[:12]
    unit = 'dnp3-eval-%s-%s-%s.service' % (identity, salt, suffix)   # dnp3-eval-* for monitoring (review R1)
    if len(unit) > 240 or not re.fullmatch(r'[A-Za-z0-9_-]+\.service', unit):
        raise Refused('unsafe generated service unit')
    return unit


class Systemd:
    """Only detached transient user services; no lifetime binding or block timeout."""
    def launch_command(self, unit, argv, cwd):
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.service', unit):
            raise Refused('unsafe unit name')
        return ['systemd-run', '--user', '--no-block', '--unit=' + unit,
                '--property=Restart=no', '--property=RemainAfterExit=yes',
                # nothing of the launching session: no stdin, no forwarded agent (review R1)
                '--property=StandardInput=null', '--property=UnsetEnvironment=SSH_AUTH_SOCK SSH_AGENT_PID',
                '--property=WorkingDirectory=' + str(cwd), '--'] + list(argv)

    def launch(self, unit, argv, cwd):
        result = subprocess.run(self.launch_command(unit, argv, cwd),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode:
            raise Refused('systemd launch failed (retain launch intent; do not replay): ' + result.stderr)

    def state(self, unit):
        result = subprocess.run(['systemctl', '--user', 'show', unit,
                                 '--property=LoadState,ActiveState,SubState,Job'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if values.get('Job') and values.get('ActiveState') in ('inactive', 'failed'):
            # a queued start job (only an inactive unit with a pending job; a stopping or reloading unit keeps its
            # own state, review W2b): launched but not yet running, not ambiguous (review W1: --no-block start on a
            # loaded host could otherwise read as inactive and stop the campaign); bounded in advance()
            return 'queued'
        if values.get('LoadState') == 'not-found':
            return 'absent'
        if result.returncode or not values.get('ActiveState'):
            raise Refused('cannot establish service state: ' + result.stderr)
        if values.get('SubState') == 'exited':
            return 'inactive'
        return values['ActiveState']

    def cancel(self, unit):
        """Cancel a unit whose start job never ran (no process has started, so nothing is interrupted)."""
        subprocess.run(['systemctl', '--user', 'stop', unit], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def preflight(self):
        result = subprocess.run(['loginctl', 'show-user', str(os.getuid()), '--property=Linger', '--value'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode or result.stdout.strip() != 'yes':
            raise Refused('user manager must have Linger=yes before detached campaign launch')


def launch_controller(directory, manager=None, resume=False):
    manager = manager or Systemd()
    directory = Path(directory).resolve(strict=True)
    # Start/resume dispatches serialize separately from controller state changes.
    with locked(directory, 'launch.lock', blocking=False):
        if hasattr(manager, 'preflight'):
            manager.preflight()
        with locked(directory):
            directory, manifest, state = load(directory)
            if not resume and state['started']:
                raise Refused('campaign already started; inspect and explicitly resume')
            if resume and not state['started']:
                raise Refused('campaign has not started')
            if state['phase'] in ('complete', 'stopped'):
                raise Refused('campaign is terminal; no replacement or retry')
            previous = state['controller_unit']
            if previous and manager.state(previous) in ACTIVE:
                raise Refused('controller service is already active')
            if resume and state['active_step']:
                step = next(s for s in manifest['steps'] if s['id'] == state['active_step'])
                if (directory / 'steps' / step['id'] / 'terminal.json').exists():
                    terminal_record(directory, manifest, step, state['active_unit'])
                elif manager.state(state['active_unit']) not in ACTIVE:
                    raise Refused('active step lacks terminal record and live service; resume refused')
            # flock additionally catches a controller detached from manager evidence.
            with locked(directory, 'controller.lock', blocking=False):
                state['started'] = True
                state['controller_generation'] += 1
                unit = unit_name(directory, state['campaign_id'],
                                 'controller-%d' % state['controller_generation'])
                state['controller_unit'] = unit
                state['phase'] = 'running'
                atomic_json(directory / 'state.json', state)
        manager.launch(unit, [sys.executable, str(Path(__file__).resolve()),
                              '_controller', str(directory)], directory)
        return unit


def terminal_record(directory, manifest, step, unit):
    path = directory / 'steps' / step['id'] / 'terminal.json'
    record = read_json(path)
    if (record.get('manifest_sha256') != digest((directory / 'manifest.json').read_bytes()) or
            record.get('id') != step['id'] or record.get('unit') != unit or
            record.get('status') not in ('completed', 'failed', 'unexecuted')):
        raise Refused('terminal record identity/status mismatch')
    if record.get('status') == 'unexecuted' and record.get('reason') not in (
            'deadline_expired', 'stop_after_current', 'testbed_refused'):
        raise Refused('invalid unexecuted terminal reason')
    if step['kind'] == 'block' and (record.get('restoration') or {}).get('ok'):
        restoration = restoration_identity(step)
        if restoration != record['restoration']:
            raise Refused('restoration evidence changed after terminal record')
    return record


def persist_report(directory, manifest, state):
    blocks = [s for s in manifest['steps'] if s['kind'] == 'block']
    report = dict(campaign_id=manifest['campaign_id'], evidence_kind=manifest['evidence_kind'],
        manifest_sha256=state['manifest_sha256'], start=state['start'], deadline=state['deadline'],
        stop_reason=state['stop_reason'], phase=state['phase'],
        result='COMPLETE' if state['phase'] == 'complete' else 'INCOMPLETE',
        excluded_from_main_evidence=manifest['evidence_kind'] == 'supervision_fixture')
    for status_value in ('completed', 'failed', 'unexecuted'):
        report[status_value] = [s['id'] for s in blocks if state['steps'][s['id']]['status'] == status_value]
    report['planned_blocks'] = len(blocks)
    report['steps'] = state['steps']
    atomic_json(directory / 'campaign_report.json', report)


def advance(directory, manager=None, now=None):
    """Reconcile one terminal record, then launch at most one next immutable step."""
    manager = manager or Systemd()
    directory = Path(directory).resolve(strict=True)
    with locked(directory):
        now = time.time() if now is None else now
        directory, manifest, state = load(directory)
        if state['phase'] in ('complete', 'stopped'):
            persist_report(directory, manifest, state)
            return state['phase']
        if state['active_step'] is not None:
            step = next(s for s in manifest['steps'] if s['id'] == state['active_step'])
            terminal = directory / 'steps' / step['id'] / 'terminal.json'
            if not terminal.exists():
                service = manager.state(state['active_unit'])
                launched = (state['steps'].get(step['id']) or {}).get('launched')
                if service == 'queued' and launched is not None and now - launched > QUEUED_LIMIT_S:
                    # cancel the queued job so it cannot start hardware later with no controller (review W2a)
                    manager.cancel(state['active_unit'])
                    after = manager.state(state['active_unit'])
                    raise Refused('start job still queued %d s after launch; cancelled (state now %s); not run, not '
                                  'replayed' % (QUEUED_LIMIT_S, after))
                if service in ACTIVE:
                    return 'waiting'
                raise Refused('active step lacks terminal record and live service; replay refused')
            record = terminal_record(directory, manifest, step, state['active_unit'])
            state['steps'][step['id']] = record
            state['active_step'] = state['active_unit'] = None
            if record['status'] != 'completed':
                state['stop_reason'] = record['reason']
                state['phase'] = 'stopped'
                atomic_json(directory / 'state.json', state)
                persist_report(directory, manifest, state)
                return 'stopped'
            atomic_json(directory / 'state.json', state)
        if state['stop_after_current']:
            state['phase'], state['stop_reason'] = 'stopped', 'stop_after_current'
        else:
            step = next((s for s in manifest['steps']
                         if state['steps'][s['id']]['status'] == 'unexecuted'), None)
            if step is None:
                state['phase'] = 'complete'
            elif step['kind'] == 'block' and state['deadline'] is not None and now >= state['deadline']:
                state['phase'], state['stop_reason'] = 'stopped', 'deadline_expired'
            else:
                if step['kind'] == 'block':
                    if os.path.lexists(step['run_root']):
                        raise Refused('block run_root already retained; refuse stale restoration evidence')
                    if state['deadline'] is None:
                        state['start'], state['deadline'] = now, now + DAY
                unit = unit_name(directory, state['campaign_id'], 'step-' + step['id'])
                if manager.state(unit) != 'absent':
                    raise Refused('planned unit already exists without launch record; replay refused')
                state['steps'][step['id']].update(status='running', unit=unit, launched=now)
                state['active_step'], state['active_unit'] = step['id'], unit
                state['phase'] = 'running'
                # The deadline and once-only launch intent reach disk BEFORE dispatch.
                atomic_json(directory / 'state.json', state)
                manager.launch(unit, [sys.executable, str(Path(__file__).resolve()),
                                      '_block', str(directory), step['id']], directory)
                return 'launched'
        atomic_json(directory / 'state.json', state)
        if state['phase'] in ('complete', 'stopped'):
            persist_report(directory, manifest, state)
        return state['phase']


def restoration_identity(step):
    path = Path(step['run_root']) / 'restore_verify.json'
    identity = {'path': str(path), 'ok': False}
    try:
        with open(path, 'rb') as stream:
            raw = stream.read()
            stat = os.fstat(stream.fileno())
        identity.update(sha256=digest(raw), size=stat.st_size, device=stat.st_dev,
                        inode=stat.st_ino, mtime_ns=stat.st_mtime_ns,
                        ok=json.loads(raw).get('ok') is True)
    except (OSError, ValueError, AttributeError) as error:
        identity['error'] = str(error)
    return identity


def command_to_log(argv, path, cwd, deadline=None):
    with open(path, 'xb', buffering=0) as log:
        if deadline is not None and time.time() >= deadline:
            log.write(b'deadline expired before command entry; no command launched\n')
            os.fsync(log.fileno())
            return None
        try:
            rc = subprocess.call(argv, stdout=log, stderr=subprocess.STDOUT, cwd=str(cwd))
        except OSError as error:
            log.write(('command launch failed: %s\n' % error).encode())
            rc = 127
        os.fsync(log.fileno())
    return rc


def retain_artifact_hashes(step, evidence_kind):
    root = Path(step['run_root'])
    if not root.is_dir():
        return None
    files = {}
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.name == 'artifact_manifest.json':
            continue
        h = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1048576), b''):
                h.update(chunk)
        files[str(path.relative_to(root))] = dict(sha256=h.hexdigest(), size=path.stat().st_size)
    target = root / 'artifact_manifest.json'
    atomic_json(target, dict(evidence_kind=evidence_kind, files=files), exclusive=True)
    return dict(path=str(target), sha256=digest(target.read_bytes()))


@contextmanager
def testbed_guard(directory, manifest, step):
    """Independent block owner holds one host-wide lock through restoration.

    Fixtures share a separate parent-local lock and can never poison hardware
    state. A lost hardware owner or unverified restoration leaves a durable
    refusal; a different campaign ID cannot bypass it.
    """
    if step['kind'] != 'block':
        yield None
        return
    root = (Path.home() / '.local/state/dnp3-evaluation/tofino1-testbed'
            if manifest['evidence_kind'] == 'hardware'
            else directory.parent / 'fixture_testbed')
    root.mkdir(parents=True, exist_ok=True)
    with locked(root, 'active.lock', blocking=False):
        state_path = root / 'ownership.json'
        if state_path.exists():
            previous = read_json(state_path)
            if previous.get('active') or previous.get('unsafe_restoration'):
                raise Refused('testbed has an unresolved owner or unverified restoration')
        yield state_path


def run_step(directory, step_id):
    """Independent service owner; terminal publication never needs the controller."""
    directory, manifest, _ = load(directory)
    step = next((s for s in manifest['steps'] if s['id'] == step_id), None)
    if step is None:
        raise Refused('unknown step')
    records = directory / 'steps' / step_id
    with locked(records, 'execution.lock', blocking=False):
        # Persist the exclusive claim before executing any user command.
        with locked(directory):
            _, _, state = load(directory)
            if state['active_step'] != step_id or state['steps'][step_id]['status'] != 'running':
                raise Refused('step has no matching active launch intent')
            if (records / 'claimed.json').exists() or (records / 'terminal.json').exists():
                raise Refused('step already claimed; never replay')
            unit = state['active_unit']
            atomic_json(records / 'claimed.json', {'id': step_id, 'unit': unit,
                        'claimed': time.time(), 'manifest_sha256': state['manifest_sha256']}, exclusive=True)
        record = {'id': step_id, 'kind': step['kind'], 'unit': unit,
                  'manifest_sha256': state['manifest_sha256'], 'started': time.time(),
                  'rc': None, 'restoration': None, 'postcheck_rc': None}
        try:
            with testbed_guard(directory, manifest, step) as ownership:
                # Check again at actual entry, after service queueing and lock
                # acquisition. An already active command is never interrupted.
                with locked(directory):
                    current = read_state(directory)
                    reason = ('stop_after_current' if current['stop_after_current'] else
                              'deadline_expired' if step['kind'] == 'block' and
                              current['deadline'] is not None and time.time() >= current['deadline'] else None)
                if reason:
                    record.update(status='unexecuted', reason=reason, finished=time.time())
                    atomic_json(records / 'terminal.json', record, exclusive=True)
                    return 1
                if ownership:
                    atomic_json(ownership, dict(active=True, unsafe_restoration=False,
                        campaign_dir=str(directory), step_id=step_id, unit=unit, entered=time.time()))
                record['hardware_entry'] = time.time() if step['kind'] == 'block' else None
                record['rc'] = command_to_log(step['argv'], records / 'command.log', directory,
                    deadline=current['deadline'] if step['kind'] == 'block' else None)
                if record['rc'] is None:
                    record.update(status='unexecuted', reason='deadline_expired', hardware_entry=None, finished=time.time())
                    atomic_json(records / 'terminal.json', record, exclusive=True)
                    if ownership:
                        atomic_json(ownership, dict(active=False, unsafe_restoration=False,
                            campaign_dir=str(directory), step_id=step_id, reason='deadline_expired_before_entry'))
                    return 1
                if step['kind'] == 'block':
                    record['restoration'] = restoration_identity(step)
                safe = step['kind'] == 'hook' or record['restoration']['ok']
                if safe and record['rc'] == 0 and step.get('postcheck_argv'):
                    record['postcheck_rc'] = command_to_log(step['postcheck_argv'], records / 'postcheck.log', directory)
                if not safe:
                    reason = 'unsafe_restoration'
                elif record['rc']:
                    reason = 'block_failed' if step['kind'] == 'block' else 'hook_failed'
                elif record['postcheck_rc']:
                    reason = 'postcheck_failed'
                else:
                    reason = None
                if step['kind'] == 'block':
                    record['artifact_manifest'] = retain_artifact_hashes(step, manifest['evidence_kind'])
                record.update(status='failed' if reason else 'completed', reason=reason, finished=time.time())
                atomic_json(records / 'terminal.json', record, exclusive=True)
                if ownership:
                    atomic_json(ownership, dict(active=False, unsafe_restoration=not safe,
                        campaign_dir=str(directory), step_id=step_id, unit=unit,
                        terminal_sha256=digest((records / 'terminal.json').read_bytes())))
                return 1 if reason else 0
        except Refused as error:
            record.update(status='unexecuted', reason='testbed_refused', refusal=str(error), finished=time.time())
            atomic_json(records / 'terminal.json', record, exclusive=True)
            return 1


def stop_after_current(directory):
    directory = Path(directory).resolve(strict=True)
    with locked(directory):
        _, _, state = load(directory)
        state['stop_after_current'] = True
        atomic_json(directory / 'state.json', state)


HARDWARE_TESTBED = Path.home() / '.local/state/dnp3-evaluation/tofino1-testbed'
RESTORE_VERIFY = HERE / 'restore_verify.py'


def running_eval_units():
    """Evaluation services still running (a oneshot that has exited is finished, not running)."""
    result = subprocess.run(['systemctl', '--user', 'list-units', 'dnp3-eval-*', '--all', '--plain',
                             '--no-legend', '--no-pager'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise Refused('cannot list evaluation units: ' + result.stderr)
    busy = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] in ACTIVE and fields[3] != 'exited':
            busy.append(fields[0])
    # a queued start job shows as 'inactive dead' in list-units (review): list jobs as well
    jobs = subprocess.run(['systemctl', '--user', 'list-jobs', 'dnp3-eval-*', '--plain', '--no-legend', '--no-pager'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if jobs.returncode:
        raise Refused('cannot list evaluation jobs: ' + jobs.stderr)
    busy += ['job: ' + line.strip() for line in jobs.stdout.splitlines() if line.strip()]
    # a manual run_block_frozen.sh holds a reservation in run_reservations/ and is not a dnp3-eval unit
    reservations = HERE / 'run_reservations'
    if reservations.is_dir():
        busy += ['reservation: ' + p.name for p in sorted(reservations.iterdir())]
    return busy


def rv_rules(name):
    """A comparison-rule set of restore_verify.py, read from its source (recorded, never altered)."""
    import ast
    for node in ast.parse(RESTORE_VERIFY.read_text()).body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return {elt.value for elt in node.value.args[0].elts}
    return set()


def reconcile(directory, step_id, root=None, units=running_eval_units, verifier=None, now=None):
    """Clear an unverified-restoration refusal ONLY on a fresh, complete restoration check.

    Under the existing testbed lock: the ownership record must name exactly this failed block (terminal
    record hash bound), no owner or evaluation service may be active, and the block's own restore inputs
    (runner restore record, pre-run snapshot, config from its frozen argv) must match the hashes retained at
    the block. restore_verify.py then runs afresh, unchanged, into a new directory. Only if it exits 0 with
    ok and no failures is an immutable reconciliation record written and the ownership record updated
    atomically; any other outcome writes an immutable refusal record and leaves the flag set. Original
    failure evidence is read, never modified."""
    directory, manifest, _ = load(Path(directory).resolve(strict=True))
    step = next((s for s in manifest['steps'] if s['id'] == step_id and s['kind'] == 'block'), None)
    if step is None:
        raise Refused('unknown block step')
    hardware = manifest['evidence_kind'] == 'hardware'
    root = Path(root) if root is not None else (HARDWARE_TESTBED if hardware else directory.parent / 'fixture_testbed')
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(time.time() if now is None else now))
    out = directory.parent / ('reconcile_%s_%s' % (step_id, stamp))
    with locked(root, 'active.lock', blocking=False):
        state_path = root / 'ownership.json'
        ownership = read_json(state_path)
        problems, bound = [], {'ownership': digest(state_path.read_bytes())}
        if ownership.get('active'):
            problems.append('an owner is active')
        if ownership.get('unsafe_restoration') is not True:
            problems.append('ownership records no unverified restoration')
        if ownership.get('campaign_dir') != str(directory) or ownership.get('step_id') != step_id:
            problems.append('ownership names a different campaign or step')
        terminal_path = directory / 'steps' / step_id / 'terminal.json'
        terminal = read_json(terminal_path) if terminal_path.is_file() else {}
        bound['terminal'] = digest(terminal_path.read_bytes()) if terminal_path.is_file() else None
        if bound['terminal'] is None or bound['terminal'] != ownership.get('terminal_sha256'):
            problems.append('terminal record missing or differs from the ownership binding')
        restoration = terminal.get('restoration') or {}
        original = Path(restoration.get('path', '/nonexistent'))
        if not original.is_file() or digest(original.read_bytes()) != restoration.get('sha256') or restoration.get('ok') is not False:
            problems.append('original failed restoration record missing or changed')
        else:
            bound['original_restore_verify'] = restoration['sha256']
        run_root = Path(step['run_root'])
        artifacts = {}
        try:
            manifest_ref = terminal['artifact_manifest']
            if digest(Path(manifest_ref['path']).read_bytes()) != manifest_ref['sha256']:
                raise ValueError('artifact manifest changed')
            artifacts = read_json(Path(manifest_ref['path']))['files']
        except (KeyError, TypeError, ValueError, OSError, Refused) as error:
            problems.append('retained artifact manifest unusable: %s' % error)
        inputs = [run_root / 'campaign_run.json'] + sorted(run_root.glob('*_prerun.json'))
        if len(inputs) != 2 or not all(p.is_file() for p in inputs):
            problems.append('block restore record and exactly one pre-run snapshot are required')
        for path in inputs:
            rel = str(path.relative_to(run_root))
            if path.is_file() and artifacts.get(rel, {}).get('sha256') != digest(path.read_bytes()):
                problems.append('restore input differs from the retained artifact hash: ' + rel)
        argv = step['argv']
        frozen = len(argv) >= 6 and argv[1].endswith('run_block_frozen.sh')
        config = argv[4] if frozen else None
        if hardware and (not frozen or not Path(config).is_file()):
            problems.append('hardware block config not resolvable from its frozen argv')
        elif hardware:
            # the config must be the one the block ran with: its freeze check (hash-retained) binds config_sha256
            freeze = run_root / 'freeze_check.json'
            if not freeze.is_file() or artifacts.get('freeze_check.json', {}).get('sha256') != digest(freeze.read_bytes()):
                problems.append('retained freeze check missing or changed')
            elif read_json(freeze).get('config_sha256') != digest(Path(config).read_bytes()):
                problems.append('block config changed since the block ran')
            else:
                bound['config'] = digest(Path(config).read_bytes())
        busy = units()
        if busy:
            problems.append('evaluation units still running: %s' % ', '.join(busy))
        out.mkdir()
        tool_commit = subprocess.run(['git', 'log', '-1', '--format=%H %cI %s', '--', RESTORE_VERIFY.name], cwd=str(HERE),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        tool_dirty = subprocess.run(['git', 'status', '--porcelain', '--', RESTORE_VERIFY.name], cwd=str(HERE),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        try:
            original_failures = json.loads(original.read_text()).get('checks', {}).get('snapshot', {}).get('errors')
        except (OSError, ValueError, AttributeError):
            original_failures = None
        record = dict(campaign_dir=str(directory), step_id=step_id, at=time.time(), bound_sha256=bound,
                      config=config, original_failures=original_failures,
                      restore_verify_tool=dict(path=str(RESTORE_VERIFY), sha256=digest(RESTORE_VERIFY.read_bytes()),
                                               last_commit=tool_commit, uncommitted_changes=bool(tool_dirty),
                                               volatile_tables=sorted(rv_rules('VOLATILE')),
                                               stripped_statistics=sorted(rv_rules('STATISTICS')),
                                               rule_note=('comparison rules as committed; the original failed check '
                                                          'may predate later rule commits (see last_commit)')),
                      earlier_reverifies={str(p): digest(p.read_bytes()) for p in sorted(directory.parent.glob('reverify_*/restore_verify.json'))})
        if problems:
            atomic_json(out / 'reconciliation_refused.json', dict(record, problems=problems, flag_left_set=True), exclusive=True)
            raise Refused('reconciliation refused: ' + '; '.join(problems))
        for path in inputs:
            (out / path.name).write_bytes(path.read_bytes())
        command = (verifier(config, out) if verifier is not None else
                   [sys.executable, str(RESTORE_VERIFY), '--config', config, '--run-root', str(out)])
        rc = command_to_log(command, out / 'restore_verify.log', out)
        fresh_path = out / 'restore_verify.json'
        try:
            fresh = json.loads(fresh_path.read_text())
        except (OSError, ValueError):
            fresh = None
        ok = rc == 0 and isinstance(fresh, dict) and fresh.get('ok') is True and not fresh.get('failures')
        record.update(command=command, rc=rc, fresh_restore_verify=digest(fresh_path.read_bytes()) if fresh_path.is_file() else None)
        if not ok:
            atomic_json(out / 'reconciliation_refused.json', dict(record, problems=['fresh restoration check did not pass'],
                                                                  flag_left_set=True), exclusive=True)
            raise Refused('fresh restoration check did not pass; unsafe_restoration left set')
        reconciliation = out / 'reconciliation.json'
        atomic_json(reconciliation, dict(record, result='restoration verified afresh; ownership update follows '
                                                        '(the clear is proven by reconciliation_sha256 in ownership.json)'),
                    exclusive=True)
        atomic_json(state_path, dict(active=False, unsafe_restoration=False, campaign_dir=str(directory),
                                     step_id=step_id, previous_terminal_sha256=ownership.get('terminal_sha256'),
                                     reconciliation=str(reconciliation),
                                     reconciliation_sha256=digest(reconciliation.read_bytes())))
        return reconciliation


def status(directory):
    directory = Path(directory).resolve(strict=True)
    with locked(directory):
        directory, manifest, state = load(directory)
        statuses = dict(state['steps'])
        # Read-only reconciliation exposes a finished independent block even if
        # its controller died before collecting the terminal record.
        if state['active_step']:
            step = next(s for s in manifest['steps'] if s['id'] == state['active_step'])
            if (directory / 'steps' / step['id'] / 'terminal.json').exists():
                statuses[step['id']] = terminal_record(directory, manifest, step, state['active_unit'])
        blocks = []
        for step in manifest['steps']:
            if step['kind'] == 'block':
                record = dict(statuses[step['id']])
                record.update(id=step['id'], run_root=step['run_root'])
                if record['status'] == 'running':
                    record['status'] = 'unexecuted'
                    record['active'] = True
                blocks.append(record)
        complete = all(statuses[s['id']]['status'] == 'completed' for s in manifest['steps'])
        return dict(state, blocks=blocks, result='COMPLETE' if complete else 'INCOMPLETE',
                    excluded_from_main_evidence=manifest['evidence_kind'] == 'supervision_fixture')


def record_refusal(directory, reason):
    """Record why the controller refused, so status shows it. The phase is NOT changed: a refusal (possibly
    transient, e.g. systemctl unreadable) must stay inspectable and resumable, and a block may still be live."""
    try:
        with locked(Path(directory).resolve(strict=True)):
            directory, manifest, state = load(directory)
            state['last_refusal'] = dict(reason=reason, at=time.time())
            atomic_json(directory / 'state.json', state)
    except Exception:
        return


def controller(directory):
    directory = Path(directory).resolve(strict=True)
    with locked(directory, 'controller.lock', blocking=False):
        while True:
            try:
                outcome = advance(directory)
            except Refused as error:
                record_refusal(directory, str(error))
                raise
            if outcome in ('complete', 'stopped'):
                return 0 if outcome == 'complete' else 1
            time.sleep(1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('init', 'start', 'status', 'resume', 'stop-after-current', 'reconcile', '_controller', '_block'):
        child = sub.add_parser(command)
        child.add_argument('path')
        if command in ('_block', 'reconcile'):
            child.add_argument('step_id')
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            print(initialize(args.path))
        elif args.command in ('start', 'resume'):
            print(launch_controller(args.path, resume=args.command == 'resume'))
        elif args.command == 'status':
            print(json.dumps(status(args.path), indent=2, sort_keys=True))
        elif args.command == 'stop-after-current':
            stop_after_current(args.path)
        elif args.command == '_controller':
            return controller(args.path)
        elif args.command == '_block':
            return run_step(args.path, args.step_id)
        elif args.command == 'reconcile':
            print(reconcile(args.path, args.step_id))
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        sys.stderr.write('REFUSED: %s\n' % error)
        return 2


if __name__ == '__main__':
    sys.exit(main())
