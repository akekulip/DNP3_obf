#!/usr/bin/env python3
"""Finish a block's switch restore after its bf_switchd stop did not complete, recorded for reconcile (Philip,
2026-10-30).

  python3 switch_process_repair.py CAMPAIGN_DIR STEP_ID              # check only: identify, refuse or report
  python3 switch_process_repair.py CAMPAIGN_DIR STEP_ID --apply      # end the candidate, restore, record
  python3 switch_process_repair.py CAMPAIGN_DIR STEP_ID --complete   # finish a partial repair (see below)

rc01_hw_c74diag_e2c_20261030_01: every trial ran, then the runner's final cold-swap (switch_swap.sh: SIGTERM, 20 s
wait) printed STILL_RUNNING: termination did not finish within that interval. Production never launched, so the port
replay, relay slot and ping failed after it; the Vision restore passed.

Refuses unless, under the testbed ownership lock: ownership names exactly this failed block with unsafe_restoration
set (terminal record hash bound) and its terminal restoration is this run root's failed restore_verify.json; no owner
or evaluation unit is active; the block's runner record, run output, freeze check and pre-run snapshot match the hashes
its artifact manifest retained, its config is unchanged, and the runner record names its run id; the failed runner
restore steps are exactly the cold-swap (rc 1, run output "<pid>" then STILL_RUNNING), the port replay, the relay slot
and the ping, and the Vision restore passed.

--apply, in order; a failure stops the sequence and nothing after it runs:
  1. the restore commands are built; the deployed switch tools in aux/ (campaign_base.switch_tools) must have the
     sha256 the block's freeze bound, and the switch's copy of the pre-run snapshot the retained sha256;
  2. the running bf_switchd processes are listed afresh (pid, start time, command line, /proc status). Exactly one
     may run: its --conf-file must be this block's composite and its pid the one the failed cold-swap printed.
     Anything else is refused untouched. Its per-thread state (comm, state, wchan, kernel stack), open files and the
     candidate log tail are written to pre_signal_state.json BEFORE any signal; a failed capture refuses;
  3. SIGTERM, a 60 s wait, then SIGKILL only if the same process (pid and start time) remains; each signal is sent by
     one remote command that re-reads the pid's comm and start time and signals only on a match. If the process still
     remains, nothing is launched;
  4. no bf_switchd may run and :50052 may not listen (an unreadable state counts as running);
  5. the runner's own commands for exactly the four failed restore steps (campaign_base.Campaign.restore), unchanged
     but for a new production log name: switch_swap.sh with the production launch script, restore_ports.py with the
     block's pre-run snapshot, switch_slot.py relay and the production ping. Unlike the runner's best-effort restore,
     the first failing command stops the sequence. The runner's Vision restore passed in the block and is not repeated:
     it consumes the pending receive-offload baseline, so a second run fails with nothing to restore (first repair of
     rc01_hw_c74diag_e2c_20261030_01); the fresh restore_verify checks the Vision state independently.

--complete finishes a partial repair whose latest record (bound to the same terminal and runner record) proved the
candidate exited, no bf_switchd before launch, and launch_production, replay_ports and relay_slot at rc 0, and failed
only after them. The switch must observe the production program (observe_program.py, read-only). It runs the ping and
writes a new record that binds the earlier one by sha256 and carries its evidence; the earlier record is untouched.
The record CAMPAIGN_DIR/steps/STEP_ID/switch_process_repair_<UTC>/repair.json is created exclusively, also when a step
raises (partial evidence kept). After production has launched, a second --apply refuses (production is not this
block's composite); a partial repair is finished only by --complete, once, never by chaining completions. The original
runner result is read, never rewritten; reconcile must still pass a complete fresh restore_verify and accepts its
historical-failure line only through evaluation_campaign.switch_process_acceptance. No reboot is ever attempted.
"""
import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import campaign_base  # noqa: E402
import evaluation_campaign as ec  # noqa: E402

STEPS = list(ec.SWITCH_PROCESS_STEPS)
STEP_NAMES = tuple(ec.SWITCH_PROCESS_STEP_NAMES)
FAILED_LINE = re.compile(r'^RESTORE STEP FAILED: (?P<step>.+?) \(rc (?P<rc>-?\d+)\)(?: (?P<detail>.*))?$')
TERM_WAIT_S, KILL_WAIT_S = 60, 30
SSH_OPTIONS = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'IdentityAgent=none', '-o', 'ControlMaster=no',
               '-o', 'ControlPath=none']
# Every bf_switchd on the switch (comm exactly bf_switchd, as pgrep -x): pid, start time in clock ticks (stat field 22,
# the PID-reuse guard), command line, selected /proc/PID/status lines and wchan. A bf_switchd whose details cannot be
# read is still listed (starttime None, error): it counts as running, never as exited or absent.
LIST_PROCS = r'''
import json, os
out = []
for pid in filter(str.isdigit, os.listdir('/proc')):
    try:
        if open('/proc/%s/comm' % pid).read().strip() != 'bf_switchd':
            continue
    except OSError:
        continue
    try:
        stat = open('/proc/%s/stat' % pid).read()
        start = int(stat[stat.rindex(')') + 2:].split()[19])
        cmd = open('/proc/%s/cmdline' % pid, 'rb').read().replace(b'\0', b' ').decode(errors='replace').strip()
        status = {l.split(':', 1)[0]: l.split(':', 1)[1].strip() for l in open('/proc/%s/status' % pid)
                  if l.split(':', 1)[0] in ('State', 'PPid', 'Threads', 'SigBlk', 'SigIgn', 'SigCgt', 'SigPnd', 'ShdPnd')}
        wchan = open('/proc/%s/wchan' % pid).read()
        out.append(dict(pid=int(pid), starttime=start, cmdline=cmd, status=status, wchan=wchan))
    except (OSError, ValueError, IndexError) as error:
        out.append(dict(pid=int(pid), starttime=None, cmdline='', status={}, wchan='', error=str(error)))
print(json.dumps(out))
'''
# Signal PID only if it is still bf_switchd with START (argv: pid start signal). Exit 0 sent, 3 no longer that process.
SIGNAL_IF_SAME = r'''
import os, signal, sys
pid, start, name = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
try:
    comm = open('/proc/%d/comm' % pid).read().strip()
    stat = open('/proc/%d/stat' % pid).read()
    now = int(stat[stat.rindex(')') + 2:].split()[19])
except (OSError, ValueError, IndexError):
    sys.exit(3)
if comm != 'bf_switchd' or now != start:
    sys.exit(3)
os.kill(pid, {'TERM': signal.SIGTERM, 'KILL': signal.SIGKILL}[name])
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bound_failure(campaign_run, run_out, relay_slot):
    """Pure. (failed restore record, problems). Problems is empty only when the failed runner restore steps are
    exactly STEPS with the cold-swap at rc 1, the Vision restore passed, and the run output's restore-failure lines
    are exactly STEPS in order, the cold-swap one printing a pid and followed by switch_swap.sh's STILL_RUNNING. The
    record carries that pid (recorded_pid)."""
    problems = []
    if not relay_slot:
        problems.append('only a production config with a relay slot (the failed steps include the slot)')
    restore = campaign_run.get('restore', [])
    failed = [s for s in restore if not s.get('ok')]
    if [s.get('step') for s in failed] != STEPS or failed[0].get('rc') != 1:
        problems.append('runner restore failures are %r, not exactly %r with the cold-swap at rc 1'
                        % ([(s.get('step'), s.get('rc')) for s in failed], STEPS))
    if not any(s.get('step') == ec.VISION_RESTORE_STEP and s.get('ok') for s in restore):
        problems.append('the Vision restore step did not pass')
    lines = run_out.splitlines()
    marks = [(i, FAILED_LINE.match(l)) for i, l in enumerate(lines) if l.startswith('RESTORE STEP FAILED')]
    recorded_pid = None
    if [m.group('step') if m else None for _, m in marks] != STEPS:
        problems.append('run output restore-failure lines are not exactly %r' % STEPS)
    else:
        detail = (marks[0][1].group('detail') or '').strip()
        recorded_pid = int(detail) if detail.isdigit() else None
        following = [l.strip() for l in lines[marks[0][0] + 1:marks[1][0]] if l.strip()]
        if recorded_pid is None or following != ['STILL_RUNNING']:
            problems.append('the cold-swap failure is not switch_swap.sh "<pid>" then STILL_RUNNING: %r %r'
                            % (detail, following))
    return {'steps': failed, 'lines': [lines[i] for i, _ in marks], 'recorded_pid': recorded_pid}, problems


def candidate(procs, remote_dir, run_id, recorded_pid):
    """Pure. (process or None, problems): the one running bf_switchd must be this block's composite (its --conf-file
    is REMOTE/response_only_hw_<run id>_physical_relay_...) with the pid the failed cold-swap printed. None with no
    problems means no bf_switchd runs."""
    marker = '--conf-file %s/response_only_hw_%s_physical_relay_' % (remote_dir, run_id)
    if not procs:
        return None, []
    others = [p['pid'] for p in procs if marker not in p['cmdline'] or p.get('starttime') is None]
    if others:
        return None, ['bf_switchd %s is not (readably) this block\'s composite; nothing is touched' % others]
    if len(procs) != 1:
        return None, ['%d bf_switchd processes run; exactly one is required' % len(procs)]
    if procs[0]['pid'] != recorded_pid:
        return None, ['the candidate pid %d is not the pid %r the failed cold-swap printed; nothing is touched'
                      % (procs[0]['pid'], recorded_pid)]
    return procs[0], []


def terminate(target, list_procs, kill, now=time.monotonic, sleep=time.sleep):
    """SIGTERM, wait up to TERM_WAIT_S, then SIGKILL only if the same process (pid and start time) remains."""
    def alive():
        return any(p['pid'] == target['pid'] and p.get('starttime') in (target['starttime'], None) for p in list_procs())
    out = dict(pid=target['pid'], starttime=target['starttime'], signals=[])
    for sig, wait in (('TERM', TERM_WAIT_S), ('KILL', KILL_WAIT_S)):
        out['signals'].append(sig)
        out['%s_rc' % sig.lower()] = kill(target, sig)
        start = now()
        while alive() and now() - start < wait:
            sleep(1)
        out['%s_wait_s' % sig.lower()] = now() - start
        if not alive():
            break
    out['exited'] = not alive()
    return out


def commands(config, run_id, stamp):
    """The runner's own commands for the four failed restore steps (campaign_base.Campaign.restore), with a new
    production log name."""
    R, p = config['hosts']['switch_remote_dir'], config['production']
    switch, vision, aux = config['hosts']['switch'], config['hosts']['vision'], R + '/aux'
    return [('launch_production', switch, 'bash %s/switch_swap.sh %s/switchd_production_%s_repair_%s.log %s'
             % (aux, R, run_id, stamp, p['launch_script'])),
            ('replay_ports', switch, 'python3 %s/restore_ports.py %s %s/snap/%s_prerun.json --apply --wait 35'
             % (aux, p['program'], R, run_id)),
            ('relay_slot', switch, 'python3 %s/switch_slot.py relay' % aux),
            ('ping', vision, 'ping -c %d -I %s %s' % (p['ping']['count'], p['ping']['src'], p['ping']['dst']))]


def candidate_log(target, remote_dir):
    """The candidate's bf_switchd log: campaign_base launches REMOTE/response_only_hw_<label>.conf into
    REMOTE/switchd_<label>.log."""
    m = re.search(r'--conf-file %s/response_only_hw_(\S+)\.conf(\s|$)' % re.escape(remote_dir), target['cmdline'])
    return '%s/switchd_%s.log' % (remote_dir, m.group(1)) if m else '/nonexistent'


def state_command(target, log):
    """Per-thread state, open files and the candidate log tail of one process (read-only)."""
    pid = int(target['pid'])
    script = ('for t in /proc/%d/task/*; do echo "== $t $(cat $t/comm) $(cut -d" " -f3 $t/stat) $(cat $t/wchan)"; '
              'sudo -n cat $t/stack || exit 1; done; echo "== fd"; sudo -n ls -l /proc/%d/fd || exit 1; '
              'echo "== log"; tail -n 60 %s || true' % (pid, pid, shlex.quote(log)))
    return 'bash -c %s' % shlex.quote(script)


def apply_repair(config, run_id, stamp, recorded_pid, run, list_procs, kill, listening, inputs_ok, save,
                 now=time.monotonic, sleep=time.sleep):
    """The repair sequence of the module docstring. Returns the evidence dict (partial on any exception); failures
    are recorded, never raised. save(name, data) writes a file into the repair record directory."""
    out = dict(errors=[], steps=[], absent_before_launch=None)
    try:
        _apply(out, config, run_id, stamp, recorded_pid, run, list_procs, kill, listening, inputs_ok, save, now, sleep)
    except BaseException as error:  # noqa: BLE001 - recorded as a failed repair (Ctrl-C included), never a pass
        out['errors'].append('repair raised: %r' % (error,))
    out['ok'] = not out['errors'] and [s['name'] for s in out['steps']] == list(STEP_NAMES)
    return out


def _apply(out, config, run_id, stamp, recorded_pid, run, list_procs, kill, listening, inputs_ok, save, now, sleep):
    planned = commands(config, run_id, stamp)          # built before any signal: a config fault stops here
    R, switch = config['hosts']['switch_remote_dir'], config['hosts']['switch']
    good, out['deployed_inputs'] = inputs_ok()
    if not good:
        out['errors'].append('deployed switch tools or the pre-run snapshot differ from the bound hashes; nothing touched')
        return
    out['processes_before'] = procs = list_procs()
    target, problems = candidate(procs, R, run_id, recorded_pid)
    if problems:
        out['errors'] += problems
        return
    if target is None:
        out['termination'] = dict(exited=True, signals=[], note='no bf_switchd was running')
    else:
        state = run(switch, state_command(target, candidate_log(target, R)))
        out['pre_signal_state'] = dict(rc=state.returncode, stdout=state.stdout[:4000000], stderr=state.stderr[-4000:],
                                       process=target)
        save('pre_signal_state.json', out['pre_signal_state'])
        if state.returncode:
            out['errors'].append('the pre-signal state capture failed (rc %d); nothing signalled' % state.returncode)
            return
        out['termination'] = terminate(target, list_procs, kill, now=now, sleep=sleep)
        if not out['termination']['exited']:
            out['errors'].append('the candidate bf_switchd did not exit after SIGTERM and SIGKILL; nothing launched')
            return
    remaining, port = list_procs(), listening()
    out['absent_before_launch'] = not remaining and not port
    if not out['absent_before_launch']:
        out['errors'].append('before launch: bf_switchd %r running, :50052 listening %s; nothing launched'
                             % ([p['pid'] for p in remaining], port))
        return
    for name, host, command in planned:
        r = run(host, command)
        out['steps'].append(dict(name=name, host=host, command=command, rc=r.returncode,
                                 stdout=r.stdout[-4000:], stderr=r.stderr[-2000:]))
        if r.returncode:
            out['errors'].append('%s exited %d' % (name, r.returncode))
            return


def continuable(previous, bound):
    """Pure. Problems with finishing PREVIOUS (the latest repair record of this step) by --complete ([] = allowed)."""
    problems = []
    names = [s.get('name') for s in previous.get('steps') or []]
    if previous.get('continues') is not None:
        problems.append('the latest repair record is itself a completion; completions do not chain')
    if previous.get('ok') is not False:
        problems.append('the latest repair record is not a failed repair')
    if previous.get('bound_sha256') != bound:
        problems.append('the latest repair record is bound to a different terminal, runner record or inputs')
    if (previous.get('termination') or {}).get('exited') is not True or previous.get('absent_before_launch') is not True:
        problems.append('the latest repair record does not prove the candidate exited before launch')
    done = [s for s in previous.get('steps') or [] if s.get('rc') == 0]
    if names[:3] != list(STEP_NAMES[:3]) or [s.get('name') for s in done][:3] != list(STEP_NAMES[:3]):
        problems.append('the latest repair record did not pass launch_production, replay_ports and relay_slot')
    return problems


def complete_repair(config, previous, run, observe):
    """Finish a partial repair: the switch must observe the production program, then the ping runs."""
    out = dict(errors=[], steps=[dict(s) for s in previous['steps'][:3]],
               continued_steps=[dict(name=s.get('name'), rc=s.get('rc')) for s in previous.get('steps') or []],
               continued_errors=list(previous.get('errors') or []))
    for key in ('termination', 'absent_before_launch', 'processes_before', 'deployed_inputs'):
        out[key] = previous.get(key)
    try:
        out['observed'] = observed = observe()
        program = observed.get('program')
        if program != config['production']['program']:
            out['errors'].append('the switch runs %r, not production %r; nothing run'
                                 % (program, config['production']['program']))
        else:
            name, host, command = commands(config, 'unused', 'unused')[3]
            r = run(host, command)
            out['steps'].append(dict(name=name, host=host, command=command, rc=r.returncode,
                                     stdout=r.stdout[-4000:], stderr=r.stderr[-2000:]))
            if r.returncode:
                out['errors'].append('%s exited %d' % (name, r.returncode))
    except BaseException as error:  # noqa: BLE001 - recorded as a failed completion, never a pass
        out['errors'].append('completion raised: %r' % (error,))
    out['ok'] = not out['errors'] and [s['name'] for s in out['steps']] == list(STEP_NAMES)
    return out


def observe_program(config):
    """The switch's running program (its whole JSON line), by the read-only tool restore_verify.py uses."""
    r = ssh(config['hosts']['switch'], 'python3 %s/aux/observe_program.py' % config['hosts']['switch_remote_dir'],
            timeout=120)
    return json.loads([l for l in r.stdout.splitlines() if l.startswith('{')][-1])


def ssh(host, command, timeout=1800):
    return subprocess.run(['ssh'] + SSH_OPTIONS + [host, command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout, stdin=subprocess.DEVNULL)


def live(config, run_id, freeze_files, prerun_sha256):
    """(list_procs, kill, listening, inputs_ok) bound to the block's switch over ssh."""
    host, R = config['hosts']['switch'], config['hosts']['switch_remote_dir']

    def list_procs():
        r = ssh(host, 'python3 -c %s' % shlex.quote(LIST_PROCS), timeout=60)
        if r.returncode:
            raise RuntimeError('listing bf_switchd failed: %s' % r.stderr[-300:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    def kill(target, sig):
        return ssh(host, 'sudo -n python3 -c %s %d %d %s' % (shlex.quote(SIGNAL_IF_SAME), int(target['pid']),
                                                             int(target['starttime']), sig), timeout=60).returncode

    def listening():
        return ssh(host, "ss -lnt | grep -q ':50052 '", timeout=60).returncode != 1      # unreadable counts as listening

    def inputs_ok():
        want = {'%s/aux/%s' % (R, name): (freeze_files.get(str(Path(path).resolve().relative_to(REPO))) or {}).get('sha256')
                for path, name in campaign_base.switch_tools()}
        want['%s/snap/%s_prerun.json' % (R, run_id)] = prerun_sha256
        r = ssh(host, 'sha256sum ' + ' '.join(shlex.quote(p) for p in sorted(want)), timeout=60)
        got = {l.split()[1]: l.split()[0] for l in r.stdout.splitlines() if len(l.split()) == 2}
        return r.returncode == 0 and None not in want.values() and got == want, dict(remote=got, bound=want)
    return list_procs, kill, listening, inputs_ok


def preconditions(directory, step, records, root):
    """(record, config, run_id, recorded_pid, live inputs, problems) for main(); reads files only."""
    problems, run_root = [], Path(step['run_root'])
    ownership = ec.read_json(root / 'ownership.json')
    terminal_path = records / 'terminal.json'
    terminal_raw = terminal_path.read_bytes() if terminal_path.is_file() else b''
    terminal = json.loads(terminal_raw) if terminal_raw else {}
    if ownership.get('active') or ownership.get('unsafe_restoration') is not True:
        problems.append('ownership does not record an inactive, unverified restoration')
    if ownership.get('campaign_dir') != str(directory) or ownership.get('step_id') != step['id']:
        problems.append('ownership names a different campaign or step')
    if not terminal_raw or sha(terminal_raw) != ownership.get('terminal_sha256'):
        problems.append('terminal record missing or differs from the ownership binding')
    if (terminal.get('status'), terminal.get('reason')) != ('failed', 'unsafe_restoration'):
        problems.append('terminal record is not a failed block with unsafe_restoration')
    restoration = terminal.get('restoration') or {}
    original = run_root / 'restore_verify.json'
    if (restoration.get('path') != str(original) or restoration.get('ok') is not False or not original.is_file()
            or sha(original.read_bytes()) != restoration.get('sha256')):
        problems.append('terminal restoration is not this run root\'s unchanged failed restore_verify.json')
    busy = ec.running_eval_units()
    if busy:
        problems.append('evaluation units still running: %s' % ', '.join(busy))
    bound = {'terminal': sha(terminal_raw) if terminal_raw else None}
    campaign_run, run_out, config, run_id, freeze_files, prerun_sha = {}, '', None, None, {}, None
    try:
        ref = terminal['artifact_manifest']
        manifest_raw = Path(ref['path']).read_bytes()
        if sha(manifest_raw) != ref['sha256']:
            raise ValueError('artifact manifest changed')
        artifact_files = json.loads(manifest_raw)['files']
        bound['artifact_manifest'] = ref['sha256']
        config_path, run_id = ec.frozen_argv(step)
        prerun = '%s_prerun.json' % run_id
        for name in ('campaign_run.json', 'run_block_run.out', 'freeze_check.json', prerun):
            raw = (run_root / name).read_bytes()
            if artifact_files.get(name, {}).get('sha256') != sha(raw):
                raise ValueError('%s differs from its retained hash' % name)
            bound[name] = sha(raw)
        prerun_sha = bound[prerun]
        campaign_run = json.loads((run_root / 'campaign_run.json').read_text())
        if campaign_run.get('run_id') != run_id:
            raise ValueError('runner record run id %r is not %r' % (campaign_run.get('run_id'), run_id))
        run_out = (run_root / 'run_block_run.out').read_text(errors='replace')
        freeze_check = json.loads((run_root / 'freeze_check.json').read_text())
        if freeze_check.get('config_sha256') != sha(Path(config_path).read_bytes()):
            raise ValueError('block config changed since the block ran')
        config = json.loads(Path(config_path).read_text())
        bound['config'] = freeze_check['config_sha256']
        freeze_files = json.loads((REPO / freeze_check['freeze']).read_text())['files']
    except (KeyError, TypeError, ValueError, OSError, IndexError) as error:
        problems.append('block records unusable: %s' % error)
    failure, more = bound_failure(campaign_run, run_out, bool((config or {}).get('production', {}).get('relay_slot')))
    problems += more
    if config is not None and config.get('endpoint_profile') != 'sel751':
        problems.append('only a sel751 block: the runner restore command differs for other profiles')
    record = dict(campaign_dir=str(directory), step_id=step['id'], run_root=str(run_root), run_id=run_id,
                  at=time.time(), bound_sha256=bound, failed_restoration=failure,
                  tool=dict(path=str(Path(__file__).resolve()), sha256=sha(Path(__file__).read_bytes())),
                  original_runner_result='left unchanged (failed)')
    return record, config, run_id, failure.get('recorded_pid'), (freeze_files, prerun_sha), problems


def complete_main(record, config, records, run, observe):
    """--complete under the lock main() holds: refuse unless the latest record is continuable, then record."""
    earlier = sorted(records.glob('switch_process_repair_*/repair.json'))
    if not earlier:
        sys.exit('REFUSED: no earlier switch_process_repair record to complete')
    raw = earlier[-1].read_bytes()
    previous = json.loads(raw)
    problems = continuable(previous, record['bound_sha256'])
    if problems:
        print(json.dumps(dict(record, problems=problems), indent=1, default=str))
        sys.exit('REFUSED: ' + '; '.join(problems))
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    out = records / ('switch_process_repair_%s' % stamp)
    out.mkdir()
    evidence = complete_repair(config, previous, run, lambda: observe(config))
    record.update(evidence, continues=dict(path=str(earlier[-1]), sha256=sha(raw)), finished_at=time.time())
    record['result'] = ('partial repair %s completed and passed' % earlier[-1].parent.name if evidence.get('ok')
                        else 'FAILED')
    ec.atomic_json(out / 'repair.json', record, exclusive=True)
    print(json.dumps({'ok': record.get('ok'), 'record': str(out / 'repair.json'), 'continues': record['continues'],
                      'errors': record.get('errors')}, default=str))
    return 0 if record.get('ok') else 1


def main(argv=None, root=None, live_inputs=live, run=ssh, observe=observe_program):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('campaign')
    ap.add_argument('step_id')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--complete', action='store_true')
    a = ap.parse_args(argv)
    directory, manifest, _ = ec.load(Path(a.campaign).resolve(strict=True))
    step = next((s for s in manifest['steps'] if s['id'] == a.step_id and s['kind'] == 'block'), None)
    if step is None or manifest['evidence_kind'] != 'hardware':
        sys.exit('REFUSED: unknown hardware block step')
    root = Path(root) if root is not None else ec.HARDWARE_TESTBED
    records = directory / 'steps' / a.step_id
    with ec.locked(root, 'active.lock', blocking=False):
        record, config, run_id, recorded_pid, (freeze_files, prerun_sha), problems = preconditions(
            directory, step, records, root)
        if problems:
            print(json.dumps(dict(record, problems=problems), indent=1, default=str))
            sys.exit('REFUSED: ' + '; '.join(problems))
        if a.complete:
            return complete_main(record, config, records, run, observe)
        list_procs, kill, listening, inputs_ok = live_inputs(config, run_id, freeze_files, prerun_sha)
        if not a.apply:
            procs = list_procs()
            target, _ = found = candidate(procs, config['hosts']['switch_remote_dir'], run_id, recorded_pid)
            rehearsal = None
            if target is not None:      # the read-only pre-signal capture, rehearsed (sudo -n, shell, size)
                r = run(config['hosts']['switch'],
                        state_command(target, candidate_log(target, config['hosts']['switch_remote_dir'])))
                rehearsal = dict(rc=r.returncode, stdout_chars=len(r.stdout), stderr=r.stderr[-1000:])
            print(json.dumps(dict(record, mode='check only', processes=procs, listening_50052=listening(),
                                  inputs_match=inputs_ok()[0], candidate=found, capture_rehearsal=rehearsal),
                             indent=1, default=str))
            return 0
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        out = records / ('switch_process_repair_%s' % stamp)
        out.mkdir()

        def save(name, data):
            ec.atomic_json(out / name, data, exclusive=True)
        evidence = apply_repair(config, run_id, stamp, recorded_pid, run, list_procs, kill, listening, inputs_ok, save)
        record.update(evidence, finished_at=time.time())
        record['result'] = 'switch restore finished and passed' if evidence.get('ok') else 'FAILED'
        ec.atomic_json(out / 'repair.json', record, exclusive=True)
        print(json.dumps({'ok': record.get('ok'), 'record': str(out / 'repair.json'),
                          'termination': record.get('termination'), 'errors': record.get('errors')}, default=str))
        return 0 if record.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
