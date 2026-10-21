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


# Files guarded_block.py/restore_verify.py retain in a run root once a block may have entered hardware. Any one of
# them sends reconcile down the existing restoration path; only a run root with none of them is a no-contact case.
HARDWARE_EVIDENCE = ('campaign_run.json', '*_prerun.json', 'run_block_plan.out', 'run_block_run.out',
                     'restore_verify*.json', 'freeze_check.json')
# Lines a hardware run prints (run_block step markers `[switch] ... -> rc N`, `[local      ] ...` plan lines, restore
# steps, `$ ssh/scp ...` command echoes, the wrapper's entry/post-entry messages). command.log of a block that
# entered hardware carries the run output only when Campaign never created its root; any such line is ambiguous.
HARDWARE_MARKER_PREFIXES = ('[switch', '[vision', '[local', '[restore')
HARDWARE_MARKER_WORDS = ('ssh ', 'rsync ', 'scp ', 'bf_switchd', 'DEFENSE4_HW_AUTHORIZED', 'hardware entry',
                         'verifying restoration')
EXCEPTION_LINE = re.compile(r'[A-Za-z_][A-Za-z0-9_.]*(Error|Exception|Interrupt)(: .*)?\Z')
ARCH = HERE.parents[3]              # guarded_block.py: ARCH = HW.parents[3]
REPO = ARCH.parents[2]              # guarded_block.py chdirs here; freeze records hold repo-relative paths
RUN_BLOCK_LOG = HERE / 'run_block.log'  # guarded_block.log_event: START before entry, END/REFUSED after
FRESH_CHECKS_NOTE = ('restore_verify check 1 (runner restore record) is satisfied by the BASELINE block\'s historical '
                     'campaign_run.json copied here, not by a new restore; only checks 2-5 (running program, live '
                     'snapshot against the baseline pre-run snapshot, Vision state, ping) observe the testbed afresh')


def hardware_run_evidence(run_root):
    """Retained hardware-run files under a block's run root (empty when the root was never created)."""
    run_root = Path(run_root)
    if not run_root.is_dir():
        return []
    return sorted({str(p.relative_to(run_root)) for pattern in HARDWARE_EVIDENCE for p in run_root.rglob(pattern)})


def run_block_entries(run_block_log):
    """(event, run_id, fields) for every START/END/REFUSED line guarded_block.log_event wrote."""
    entries = []
    for line in Path(run_block_log).read_text(errors='replace').splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == 'START':
            entries.append(('START', fields[3], fields))
        elif len(fields) >= 3 and fields[1] in ('END', 'REFUSED'):
            entries.append((fields[1], fields[2], fields))
    return entries


def classify_step_evidence(run_root, command_log, terminal, run_id, run_block_log):
    """Pure, read-only: hardware_run | no_hardware_contact | ambiguous, with the evidence for the verdict.

    hardware_run: any hardware-run file under the run root. no_hardware_contact needs positive proof. Primary:
    the run root does not exist (os.path.lexists, so a dangling symlink counts as existing), the terminal record
    (hash-bound in ownership.json) has artifact_manifest null (retain_artifact_hashes returns None only when the
    root was not a directory at block end), and run_block.log has no START for this run ID (guarded_block logs
    START before entering hardware). Corroborating: command.log exists, ends in a Python traceback (exception line
    after the last 'Traceback' header) or a REFUSED line, and carries no hardware marker line. Anything else is
    ambiguous."""
    run_root, command_log = Path(run_root), Path(command_log)
    primary = dict(run_root=str(run_root), run_root_exists=os.path.lexists(str(run_root)),
                   terminal_artifact_manifest_null=isinstance(terminal, dict) and 'artifact_manifest' in terminal
                   and terminal['artifact_manifest'] is None,
                   run_block_log=str(run_block_log), run_block_log_entries=None, run_id=run_id)
    corroborating = dict(command_log=str(command_log), command_log_sha256=None, ending=None, markers=[])
    summary = dict(hardware_evidence=hardware_run_evidence(run_root), primary=primary,
                   corroborating=corroborating, reasons=[])
    if summary['hardware_evidence']:
        summary['classification'] = 'hardware_run'
        return summary
    reasons = summary['reasons']
    if primary['run_root_exists']:
        reasons.append('run root exists (possible hardware entry)')
    if not primary['terminal_artifact_manifest_null']:
        reasons.append('terminal artifact_manifest is not null (root was a directory at block end)')
    try:
        primary['run_block_log_entries'] = [' '.join(f) for _, rid, f in run_block_entries(run_block_log) if rid == run_id]
        if primary['run_block_log_entries']:
            reasons.append('run_block.log has entries for this run ID')
    except OSError as error:
        reasons.append('run_block.log unreadable: %s' % error)
    try:
        raw = command_log.read_bytes()
    except OSError as error:
        reasons.append('command.log unreadable: %s' % error)
        summary['classification'] = 'ambiguous'
        return summary
    corroborating['command_log_sha256'] = digest(raw)
    lines = raw.decode('utf-8', errors='replace').splitlines()
    corroborating['markers'] = [line for line in lines if line.lstrip().startswith(HARDWARE_MARKER_PREFIXES) or
                                any(word in line for word in HARDWARE_MARKER_WORDS)]
    filled = [line for line in lines if line.strip()]
    last = filled[-1] if filled else ''
    headers = [i for i, line in enumerate(filled) if line == 'Traceback (most recent call last):']
    if last.startswith('REFUSED'):
        corroborating['ending'] = 'refused'
    elif headers and headers[-1] < len(filled) - 1 and EXCEPTION_LINE.match(last):
        corroborating['ending'] = 'traceback'
    else:
        reasons.append('command.log does not end in a Python traceback or a REFUSED line')
    if corroborating['markers']:
        reasons.append('command.log carries hardware marker lines')
    summary['classification'] = 'ambiguous' if reasons else 'no_hardware_contact'
    return summary


def frozen_argv(step):
    """(config, run_id) from a run_block_frozen.sh argv: bash WRAPPER FREEZE TOOL CONFIG RUN_ID [ARGS...]."""
    argv = step['argv']
    if len(argv) < 6 or Path(argv[1]).name != 'run_block_frozen.sh':
        raise ValueError('step %s argv is not a run_block_frozen.sh invocation' % step['id'])
    # guarded_block writes run_block.log beside its own copy; the no-contact proof reads this checkout's log, so the
    # step must have run this checkout's wrapper (review W1).
    if Path(argv[1]).resolve() != (HERE / 'run_block_frozen.sh').resolve():
        raise ValueError('step %s ran a wrapper outside this checkout: %s' % (step['id'], argv[1]))
    return argv[4], argv[5]


def baseline_inputs(baseline_run_root, baseline_terminal, problems):
    """A prior block that passed restoration, bound three ways: its campaign terminal record (artifact manifest hash,
    restoration ok and hash), its hash-retained restore inputs, and the config from its campaign manifest argv
    (matching the freeze check's config_sha256). Returns (run root, shas, config, inputs, run_id)."""
    base = Path(baseline_run_root).resolve() if baseline_run_root is not None else None
    shas, config, run_id = {}, None, None
    try:
        if base is None or baseline_terminal is None:
            raise ValueError('--baseline-run-root and --baseline-terminal are both required')
        terminal_path = Path(baseline_terminal).resolve(strict=True)
        terminal = read_json(terminal_path)
        shas['terminal'] = digest(terminal_path.read_bytes())
        campaign = terminal_path.parents[2]
        manifest_raw = (campaign / 'manifest.json').read_bytes()
        if terminal.get('manifest_sha256') != digest(manifest_raw):
            raise ValueError('baseline terminal does not match its campaign manifest')
        step = next((s for s in json.loads(manifest_raw)['steps'] if s['id'] == terminal.get('id') ==
                     terminal_path.parent.name and s['kind'] == 'block'), None)
        if step is None or Path(step['run_root']).resolve() != base:
            raise ValueError('baseline terminal names a different block or run root')
        config, run_id = frozen_argv(step)
        artifacts_ref = terminal.get('artifact_manifest') or {}
        shas['artifact_manifest.json'] = digest((base / 'artifact_manifest.json').read_bytes())
        if (Path(artifacts_ref.get('path', '/nonexistent')).resolve() != base / 'artifact_manifest.json' or
                artifacts_ref.get('sha256') != shas['artifact_manifest.json']):
            raise ValueError('baseline artifact manifest is not the one its terminal record binds')
        restoration = terminal.get('restoration') or {}
        artifacts = read_json(base / 'artifact_manifest.json')['files']
        prerun = sorted(base.glob('*_prerun.json'))
        if len(prerun) != 1:
            raise ValueError('baseline needs exactly one pre-run snapshot, found %d' % len(prerun))
        for path in [base / 'campaign_run.json', prerun[0], base / 'restore_verify.json', base / 'freeze_check.json']:
            shas[path.name] = digest(path.read_bytes())
            if artifacts.get(path.name, {}).get('sha256') != shas[path.name]:
                raise ValueError('baseline %s differs from its retained artifact hash' % path.name)
        if (restoration.get('ok') is not True or restoration.get('sha256') != shas['restore_verify.json'] or
                Path(restoration.get('path', '/nonexistent')).resolve() != base / 'restore_verify.json'):
            raise ValueError('baseline terminal does not record this restore_verify.json as passed')
        verified = read_json(base / 'restore_verify.json')
        if verified.get('ok') is not True or verified.get('failures'):
            raise ValueError('baseline restore_verify.json did not pass (ok %r, failures %r)'
                             % (verified.get('ok'), verified.get('failures')))
        freeze = read_json(base / 'freeze_check.json')
        shas['config'] = digest(Path(config).read_bytes())
        if shas['config'] != freeze.get('config_sha256') or (REPO / freeze['config']).resolve() != Path(config).resolve():
            raise ValueError('baseline config changed since the baseline block ran, or is not the frozen one')
    except (KeyError, TypeError, ValueError, OSError, StopIteration, Refused) as error:
        problems.append('baseline restoration unusable: %s' % error)
        return base, shas, config, [], run_id
    return base, shas, config, [base / 'campaign_run.json', prerun[0]], run_id


def baseline_is_latest(run_block_log, run_id, problems):
    """The baseline's START/END must be the last block on the testbed, with restore_verify_rc=0."""
    entries = run_block_entries(run_block_log)
    starts = [i for i, entry in enumerate(entries) if entry[0] == 'START']
    if not starts or entries[starts[-1]][1] != run_id:
        problems.append('baseline is not the last block started on the testbed (run_block.log)')
        return
    ends = [entry for entry in entries[starts[-1] + 1:] if entry[0] == 'END' and entry[1] == run_id]
    if len(ends) != 1 or 'restore_verify_rc=0' not in ends[0][2]:
        problems.append('baseline has no single END with restore_verify_rc=0 after its START (run_block.log)')


def reconcile_no_contact(directory, step, root, units, verifier, stamp, baseline_run_root, baseline_terminal):
    """Clear an unverified-restoration flag for a block with NO hardware-run evidence.

    Records are written to the campaign's steps/<step>/reconcile_<ts>/ (created exclusively, never reused):
    reconciliation.json on a pass, reconciliation_refused.json otherwise, beside the copied baseline inputs and the
    fresh restore_verify.json/.log. Same shared guards as reconcile (testbed lock, no active owner, evaluation unit
    or reservation, ownership names exactly this step, terminal hash bound). The terminal record must be a failed
    unsafe_restoration with ok false for run_root/restore_verify.json, and the run root must be the one guarded_block
    derives from the config (ARCH / evidence_dir / RUN_ID). No-contact proof comes from classify_step_evidence. The
    testbed is checked afresh against a named baseline: the last block that ran (run_block.log), bound to its
    campaign terminal record, whose config has the same hosts and production as this step's. Its restore record and
    pre-run snapshot are copied in and restore_verify.py runs unchanged with its config. Only exit 0, ok and no
    failures, with units and ownership unchanged afterwards, clear the flag; anything else leaves a refusal."""
    step_id = step['id']
    records = directory / 'steps' / step_id
    out = records / ('reconcile_%s' % stamp)
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
        terminal_path = records / 'terminal.json'
        terminal = read_json(terminal_path) if terminal_path.is_file() else {}
        bound['terminal'] = digest(terminal_path.read_bytes()) if terminal_path.is_file() else None
        if bound['terminal'] is None or bound['terminal'] != ownership.get('terminal_sha256'):
            problems.append('terminal record missing or differs from the ownership binding')
        if (terminal.get('status'), terminal.get('reason')) != ('failed', 'unsafe_restoration') or not terminal.get('rc'):
            problems.append('terminal record is not a failed block with unsafe_restoration and a nonzero rc')
        restoration = terminal.get('restoration') or {}
        if restoration.get('ok') is not False or restoration.get('path') != str(Path(step['run_root']) / 'restore_verify.json'):
            problems.append('terminal restoration is not a failed check of this run root')
        config, run_id, step_cfg = None, None, {}
        try:
            config, run_id = frozen_argv(step)
            step_bytes = Path(config).read_bytes()
            step_cfg = json.loads(step_bytes)
            bound['step_config'] = digest(step_bytes)        # the version compared below (review W2)
            if (ARCH / step_cfg['evidence_dir'] / run_id).resolve() != Path(step['run_root']).resolve():
                problems.append('step run root is not the one guarded_block derives from its config and run ID')
        except (KeyError, TypeError, ValueError, OSError) as error:
            problems.append('step config/run root not derivable: %s' % error)
        bound['run_block_log'] = digest(RUN_BLOCK_LOG.read_bytes()) if RUN_BLOCK_LOG.is_file() else None
        evidence = classify_step_evidence(step['run_root'], records / 'command.log', terminal, run_id, RUN_BLOCK_LOG)
        bound['command_log'] = evidence['corroborating']['command_log_sha256']
        if evidence['classification'] != 'no_hardware_contact':
            problems.append('no positive proof of no hardware contact (%s): %s'
                            % (evidence['classification'], '; '.join(evidence['reasons'])))
        base, bound['baseline'], base_config, inputs, base_run_id = baseline_inputs(
            baseline_run_root, baseline_terminal, problems)
        if inputs:
            try:
                base_cfg = json.loads(Path(base_config).read_text())
                if any(key not in step_cfg or step_cfg[key] != base_cfg.get(key) for key in ('hosts', 'production')):
                    problems.append('step config hosts/production differ from the baseline config')
            except (OSError, ValueError) as error:
                problems.append('baseline config unreadable: %s' % error)
            try:
                baseline_is_latest(RUN_BLOCK_LOG, base_run_id, problems)
            except OSError as error:
                problems.append('baseline run_block.log unreadable: %s' % error)
        busy = units()
        if busy:
            problems.append('evaluation units still running: %s' % ', '.join(busy))
        out.mkdir()
        tool_commit = subprocess.run(['git', 'log', '-1', '--format=%H %cI %s', '--', RESTORE_VERIFY.name], cwd=str(HERE),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        tool_dirty = subprocess.run(['git', 'status', '--porcelain', '--', RESTORE_VERIFY.name], cwd=str(HERE),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        record = dict(campaign_dir=str(directory), step_id=step_id, at=time.time(), mode='no_hardware_contact',
                      bound_sha256=bound, no_contact_evidence=evidence, baseline_run_root=str(base) if base else None,
                      baseline_terminal=str(baseline_terminal) if baseline_terminal else None,
                      baseline_run_id=base_run_id, config=base_config, step_config=config,
                      fresh_checks_note=FRESH_CHECKS_NOTE,
                      restore_verify_tool=dict(path=str(RESTORE_VERIFY), sha256=digest(RESTORE_VERIFY.read_bytes()),
                                               last_commit=tool_commit, uncommitted_changes=bool(tool_dirty),
                                               volatile_tables=sorted(rv_rules('VOLATILE')),
                                               stripped_statistics=sorted(rv_rules('STATISTICS')),
                                               rule_note=('comparison rules as committed at reconcile time; the '
                                                          'baseline check may predate later rule commits (see '
                                                          'last_commit)')))

        def refuse(why):
            atomic_json(out / 'reconciliation_refused.json', dict(record, problems=why, flag_left_set=True), exclusive=True)
            raise Refused('reconciliation refused: ' + '; '.join(why))

        if problems:
            refuse(problems)
        for path in inputs:
            with open(str(out / path.name), 'xb') as stream:
                stream.write(path.read_bytes())
        bound['copied_inputs'] = {path.name: digest((out / path.name).read_bytes()) for path in inputs}
        if bound['copied_inputs'] != {path.name: bound['baseline'][path.name] for path in inputs}:
            refuse(['baseline inputs changed while copied'])
        command = (verifier(base_config, out) if verifier is not None else
                   [sys.executable, str(RESTORE_VERIFY), '--config', base_config, '--run-root', str(out)])
        rc = command_to_log(command, out / 'restore_verify.log', out)
        fresh_path = out / 'restore_verify.json'
        try:
            fresh = json.loads(fresh_path.read_text())
        except (OSError, ValueError):
            fresh = None
        ok = rc == 0 and isinstance(fresh, dict) and fresh.get('ok') is True and not fresh.get('failures')
        bound['fresh_restore_verify'] = digest(fresh_path.read_bytes()) if fresh_path.is_file() else None
        record.update(command=command, rc=rc)
        if not ok:
            refuse(['fresh restoration check did not pass'])
        # Immediately before the atomic update: nothing may have started or changed ownership during the check.
        late = []
        busy = units()
        if busy:
            late.append('evaluation units running after the fresh check: %s' % ', '.join(busy))
        if digest(state_path.read_bytes()) != bound['ownership']:
            late.append('ownership record changed after the fresh check')
        if (digest(RUN_BLOCK_LOG.read_bytes()) if RUN_BLOCK_LOG.is_file() else None) != bound['run_block_log']:
            late.append('run_block.log changed after the fresh check')
        if late:
            refuse(late)
        reconciliation = out / 'reconciliation.json'
        atomic_json(reconciliation, dict(record, result='no hardware contact proven and restoration verified afresh '
                                                        'against the baseline; ownership update follows (the clear is '
                                                        'proven by reconciliation_sha256 in ownership.json)'),
                    exclusive=True)
        atomic_json(state_path, dict(active=False, unsafe_restoration=False, campaign_dir=str(directory),
                                     step_id=step_id, previous_terminal_sha256=ownership.get('terminal_sha256'),
                                     reconciliation=str(reconciliation),
                                     reconciliation_sha256=digest(reconciliation.read_bytes())))
        return reconciliation


def reconcile(directory, step_id, root=None, units=running_eval_units, verifier=None, now=None,
              baseline_run_root=None, baseline_terminal=None):
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
    # A block with no hardware-run evidence in its run root takes the no-contact path; every other block takes the
    # existing path below, unchanged, and a baseline offered for it is refused rather than ignored.
    if not hardware_run_evidence(step['run_root']):
        return reconcile_no_contact(directory, step, root, units, verifier, stamp, baseline_run_root, baseline_terminal)
    if baseline_run_root is not None or baseline_terminal is not None:
        raise Refused('block has hardware-run evidence; reconcile it without --baseline-run-root/--baseline-terminal')
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
        if command == 'reconcile':
            child.add_argument('--baseline-run-root', default=None,
                               help='required for a block with no hardware-run evidence: run root of a prior block '
                                    'whose restore_verify.json passed; refused for a block that has evidence')
            child.add_argument('--baseline-terminal', default=None,
                               help='with --baseline-run-root: that block\'s campaign steps/<id>/terminal.json')
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
            print(reconcile(args.path, args.step_id, baseline_run_root=args.baseline_run_root,
                            baseline_terminal=args.baseline_terminal))
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        sys.stderr.write('REFUSED: %s\n' % error)
        return 2


if __name__ == '__main__':
    sys.exit(main())
