#!/usr/bin/env python3
"""Bounded repair of a failed Vision RX-coalescing restore, recorded for reconcile (Philip, 2026-10-22).

  python3 nic_repair.py CAMPAIGN_DIR STEP_ID            # check only: prints the bound evidence, touches nothing
  python3 nic_repair.py CAMPAIGN_DIR STEP_ID --apply    # re-apply the original NIC settings and record it

Refuses unless, under the testbed ownership lock: ownership names exactly this failed block with
unsafe_restoration set (terminal record hash bound); no owner or evaluation unit is active; the block's runner
record (campaign_run.json) and run output (run_block_run.out) match the hashes its artifact manifest retained; the
ONLY failed runner restore step is the Vision restore; the run output's only restore failure is an RX-coalescing
restore failure (no receive-offload or CPU-latency failure) naming the original saved settings ("baseline adaptive X
rx-usecs N"), which must equal the committed pre-diagnostic reading (restore_baseline/vision_rx_coalesce_20261022.json).
The saved settings are bound by that hash-retained log line: the runner's own baseline file on Vision no longer
exists (the earlier ad hoc repair removed it after its read-back matched).

--apply deploys the COMMITTED capture_observation.py and wire_check.py (git HEAD blobs, recorded with the commit),
refuses unless that restore_rx_coalesce source hashes to the reviewed REVIEWED_RESTORE_RX_COALESCE_SHA256, stages
them in a fresh `mktemp -d` directory owned by the ssh user, re-hashes both inside the sudo process before importing
them, re-applies the bound settings unless the committed snapshot_rx_coalesce already reads them (then no ethtool -C
is written, as the offload restore never writes a value already at baseline), and verifies the ACTUAL settings with a separate read-only `ethtool -c` -- a
removed baseline file is never taken as proof. The record directory CAMPAIGN_DIR/steps/STEP_ID/nic_repair_<UTC>/ is
created exclusively and holds repair.json, the baseline copy and the failed restoration record. The record states
whether the NIC was already at baseline before this run (it was repaired ad hoc earlier, outside the testbed lock;
see read_complete_01/STATUS.md and commit 774300eed). The original runner result is read, never rewritten.
"""
import argparse
import hashlib
import importlib.util
import inspect
import json
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evaluation_campaign as ec  # noqa: E402

ARCH = HERE.parents[2]
REPO = ARCH.parents[2]
DEPLOYED = {'capture_observation.py': 'defense4/timing/case4_architecture/protocol/hw_vepa/capture_observation.py',
            'wire_check.py': 'defense4/timing/case4_architecture/protocol/hw_vepa/wire_check.py'}
INDEPENDENT_BASELINE = HERE / 'restore_baseline/vision_rx_coalesce_20261022.json'
VISION_STEP = ec.VISION_RESTORE_STEP
FAILED_LINE = re.compile(r'^RESTORE STEP FAILED: (?P<step>.+?) \(rc (?P<rc>-?\d+)\) (?P<detail>.*)$')
SAVED = re.compile(r'baseline adaptive (?P<adaptive>on|off) rx-usecs (?P<usecs>\d+)\s*$')
RX_ONLY = re.compile(r'^rx coalescing restore failed: ')
OTHER_RESTORES = ('receive offload', 'cpu latency')
EARLIER_REPAIR = ('the NIC was first repaired ad hoc, OUTSIDE the testbed lock and before this tool existed: the '
                  'operator staged capture_observation.py + wire_check.py in /tmp/rxfix_20261022 on Vision (stat: '
                  '2026-10-22 21:24:05 UTC; capture_observation.py sha256 483a47ae..., equal to the 774300eed blob) and '
                  'ran restore_rx_coalesce via sudo python3 against the runner\'s own baseline file, read back adaptive RX '
                  'on, rx-usecs 50 and the file removed (read_complete_01/STATUS.md, 2026-10-22 NIC repair entry)')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bound_failure(campaign_run, run_out, independent):
    """Pure. (saved settings dict, failed restore record, problems) from the block's runner record, run output text
    and the independent baseline. Problems is empty only for exactly one failed restore step, the Vision restore,
    whose single failure line is solely an RX-coalescing restore failure naming settings equal to the independent
    ones."""
    problems = []
    failed = [s for s in campaign_run.get('restore', []) if not s.get('ok')]
    if [s.get('step') for s in failed] != [VISION_STEP]:
        problems.append('runner restore failures are %r, not exactly the Vision restore' % [s.get('step') for s in failed])
    lines = [FAILED_LINE.match(l) for l in run_out.splitlines() if l.startswith('RESTORE STEP FAILED')]
    if len(lines) != 1 or lines[0] is None:
        problems.append('run output has %d restore-failure lines, need exactly one well-formed' % len(lines))
        return None, failed, problems
    m = lines[0]
    detail = m.group('detail')
    if m.group('step') != VISION_STEP or not RX_ONLY.match(detail) or any(o in detail for o in OTHER_RESTORES):
        problems.append('restore failure is not solely an RX-coalescing restore of the Vision step: %r' % m.group(0))
    saved = SAVED.search(detail)
    if saved is None:
        problems.append('restore failure does not name the original saved settings')
        return None, failed, problems
    settings = {'adaptive_rx': saved.group('adaptive'), 'rx_usecs': int(saved.group('usecs'))}
    if (settings['adaptive_rx'], settings['rx_usecs']) != (independent['adaptive_rx'], independent['rx_usecs']):
        problems.append('saved settings %r differ from the independent pre-diagnostic reading %r'
                        % (settings, {k: independent[k] for k in ('adaptive_rx', 'rx_usecs')}))
    return settings, {'steps': failed, 'line': m.group(0)}, problems


def committed_files(git=None):
    """({name: bytes}, provenance) for the files deployed: the git HEAD blobs, never the working copy."""
    git = git or (lambda *args: subprocess.run(['git', '-C', str(REPO)] + list(args), stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, check=True).stdout)
    commit = git('rev-parse', 'HEAD').decode().strip()
    files = {name: git('show', 'HEAD:%s' % path) for name, path in DEPLOYED.items()}
    provenance = {'commit': commit, 'blobs': {name: git('rev-parse', 'HEAD:%s' % path).decode().strip()
                                              for name, path in DEPLOYED.items()},
                  'sha256': {name: sha(data) for name, data in files.items()}}
    return files, provenance


def function_source_sha(files):
    """sha256 of restore_rx_coalesce's source in the given capture_observation.py bytes (imported from a temp dir)."""
    with tempfile.TemporaryDirectory() as temp:
        for name, data in files.items():
            Path(temp, name).write_bytes(data)
        sys.path.insert(0, temp)
        try:
            spec = importlib.util.spec_from_file_location('nic_repair_co', str(Path(temp, 'capture_observation.py')))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return sha(inspect.getsource(module.restore_rx_coalesce).encode())
        finally:
            sys.path.remove(temp)


def parse_coalesce(text):
    adaptive = re.search(r'^Adaptive RX:\s*(on|off)\b', text or '', re.M)
    usecs = re.search(r'^rx-usecs:\s*(\d+)\s*$', text or '', re.M)
    return None if not adaptive or not usecs else {'adaptive_rx': adaptive.group(1), 'rx_usecs': int(usecs.group(1))}


def ssh(host, command, timeout=120):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, command],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)


def put(host, remote_dir, files, timeout=120):
    """Write each file into remote_dir through ssh stdin (no scp, no intermediate local path)."""
    rcs = {}
    for name, data in files.items():
        r = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host,
                            'cat > %s' % shlex.quote('%s/%s' % (remote_dir, name))],
                           input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        rcs[name] = r.returncode
    return rcs


def apply_repair(host, interface, settings, files, provenance, run=ssh, upload=put):
    """Re-apply `settings` on host with the committed restore function; returns the evidence dict (ok computed
    from the independent read-back). Every failure is recorded, never raised."""
    out = {'remote_dir': None, 'errors': []}
    before = run(host, 'ethtool -c %s' % shlex.quote(interface))
    out['ethtool_before'] = before.stdout
    out['settings_before'] = parse_coalesce(before.stdout)
    out['already_at_baseline_before'] = out['settings_before'] == settings
    made = run(host, 'd=$(mktemp -d /tmp/nic_repair.XXXXXXXX) && stat -c "%U %a" "$d" && echo "$d"')
    lines = made.stdout.split()
    user = run(host, 'id -un').stdout.strip()
    if made.returncode or len(lines) != 3 or lines[0] != user or lines[1] != '700':
        out['errors'].append('remote staging directory not created privately: %r' % made.stdout)
        out['ok'] = False
        return out
    remote = lines[2]
    out['remote_dir'] = remote
    out['upload_rcs'] = upload(host, remote, files)
    expected = provenance['sha256']
    snippet = (
        'import hashlib, json, sys\n'
        'd = %r\n'
        'want = %r\n'
        'got = {n: hashlib.sha256(open(d + "/" + n, "rb").read()).hexdigest() for n in want}\n'
        'if got != want:\n'
        '    print(json.dumps({"errors": ["staged file hash mismatch: %%r" %% got]})); sys.exit(1)\n'
        'sys.path.insert(0, d)\n'
        'import capture_observation as co\n'
        'want_nic = %r\n'
        'now = co.snapshot_rx_coalesce(%r)\n'
        'if (now["adaptive_rx"], now["rx_usecs"]) == (want_nic["adaptive_rx"], want_nic["rx_usecs"]):\n'
        '    errors, action = [], "none: already at the bound settings (no ethtool -C written)"\n'
        'else:\n'
        '    p = d + "/rx_coalesce_baseline.json"\n'
        '    open(p, "w").write(json.dumps(want_nic))\n'
        '    errors, action = co.restore_rx_coalesce(p, %r), "restore_rx_coalesce re-applied the bound settings"\n'
        'print(json.dumps({"errors": errors, "staged_sha256": got, "action": action}))\n'
        % (remote, expected, dict(interface=interface, **settings), interface, interface))
    applied = run(host, 'sudo -n python3 -I -c %s' % shlex.quote(snippet))
    out['apply_output'] = applied.stdout + applied.stderr
    try:
        result = json.loads(applied.stdout.strip().splitlines()[-1])
        if not isinstance(result, dict) or not isinstance(result.get('errors'), list):
            raise ValueError('not an errors record')
        out['errors'] += result['errors']
        out['staged_sha256'] = result.get('staged_sha256')
        out['action'] = result.get('action')
    except (ValueError, IndexError):
        out['errors'].append('restore function output unreadable: %s' % out['apply_output'][-300:])
    after = run(host, 'ethtool -c %s' % shlex.quote(interface))     # separate read-only read-back: the actual settings
    out['ethtool_after'] = after.stdout
    out['actual_settings'] = parse_coalesce(after.stdout) if after.returncode == 0 else None
    out['ok'] = (not out['errors'] and out.get('staged_sha256') == expected and out['actual_settings'] == settings)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('campaign')
    ap.add_argument('step_id')
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args(argv)
    directory, manifest, _ = ec.load(Path(a.campaign).resolve(strict=True))
    step = next((s for s in manifest['steps'] if s['id'] == a.step_id and s['kind'] == 'block'), None)
    if step is None or manifest['evidence_kind'] != 'hardware':
        sys.exit('REFUSED: unknown hardware block step')
    root = ec.HARDWARE_TESTBED
    records = directory / 'steps' / a.step_id
    run_root = Path(step['run_root'])
    with ec.locked(root, 'active.lock', blocking=False):
        problems = []
        ownership = ec.read_json(root / 'ownership.json')
        terminal_path = records / 'terminal.json'
        terminal_raw = terminal_path.read_bytes() if terminal_path.is_file() else b''
        terminal = json.loads(terminal_raw) if terminal_raw else {}
        if ownership.get('active') or ownership.get('unsafe_restoration') is not True:
            problems.append('ownership does not record an inactive, unverified restoration')
        if ownership.get('campaign_dir') != str(directory) or ownership.get('step_id') != a.step_id:
            problems.append('ownership names a different campaign or step')
        if not terminal_raw or sha(terminal_raw) != ownership.get('terminal_sha256'):
            problems.append('terminal record missing or differs from the ownership binding')
        busy = ec.running_eval_units()
        if busy:
            problems.append('evaluation units still running: %s' % ', '.join(busy))
        bound = {'terminal': sha(terminal_raw) if terminal_raw else None}
        campaign_run, run_out = {}, ''
        try:
            ref = terminal['artifact_manifest']
            manifest_raw = Path(ref['path']).read_bytes()
            if sha(manifest_raw) != ref['sha256']:
                raise ValueError('artifact manifest changed')
            artifact_files = json.loads(manifest_raw)['files']
            bound['artifact_manifest'] = ref['sha256']
            for name in ('campaign_run.json', 'run_block_run.out', 'freeze_check.json'):
                raw = (run_root / name).read_bytes()
                if artifact_files.get(name, {}).get('sha256') != sha(raw):
                    raise ValueError('%s differs from its retained hash' % name)
                bound[name] = sha(raw)
            campaign_run = json.loads((run_root / 'campaign_run.json').read_text())
            run_out = (run_root / 'run_block_run.out').read_text(errors='replace')
            config_path = Path(step['argv'][4])
            if json.loads((run_root / 'freeze_check.json').read_text()).get('config_sha256') != sha(config_path.read_bytes()):
                raise ValueError('block config changed since the block ran')
            config = json.loads(config_path.read_text())
        except (KeyError, TypeError, ValueError, OSError, IndexError) as error:
            problems.append('block records unusable: %s' % error)
            config = None
        independent_raw = INDEPENDENT_BASELINE.read_bytes()
        independent = json.loads(independent_raw)
        settings, failure, more = bound_failure(campaign_run, run_out, independent)
        problems += more
        files, provenance = committed_files()
        function_sha = function_source_sha(files)
        if function_sha != ec.REVIEWED_RESTORE_RX_COALESCE_SHA256:
            problems.append('committed restore_rx_coalesce source %s is not the reviewed %s'
                            % (function_sha, ec.REVIEWED_RESTORE_RX_COALESCE_SHA256))
        record = dict(campaign_dir=str(directory), step_id=a.step_id, run_root=str(run_root), at=time.time(),
                      bound_sha256=bound, saved_settings=settings, saved_settings_source='run_block_run.out line',
                      failed_restoration=failure,
                      independent_baseline=dict(path=str(INDEPENDENT_BASELINE), sha256=sha(independent_raw)),
                      restore_function=dict(function='restore_rx_coalesce', source_sha256=function_sha,
                                            deployed=provenance),
                      earlier_repair=EARLIER_REPAIR, original_runner_result='left unchanged (failed)')
        if problems:
            print(json.dumps(dict(record, problems=problems), indent=1))
            sys.exit('REFUSED: ' + '; '.join(problems))
        if not a.apply:
            print(json.dumps(dict(record, mode='check only'), indent=1))
            return 0
        out = records / ('nic_repair_%s' % time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
        out.mkdir()
        with open(out / 'baseline_copy.json', 'xb') as stream:
            stream.write(independent_raw)
        ec.atomic_json(out / 'failed_restoration.json', failure, exclusive=True)
        try:
            evidence = apply_repair(config['hosts']['vision'], independent['interface'], settings, files, provenance)
        except Exception as error:      # noqa: BLE001 - recorded as a failed repair, never a pass
            evidence = {'ok': False, 'errors': ['repair raised: %s' % error]}
        record.update(evidence)
        record['result'] = ('re-applied and verified' + (' (the NIC was already at baseline before this run; the '
                            'earlier ad hoc repair is described in earlier_repair)' if evidence.get('already_at_baseline_before')
                            else '') if evidence.get('ok') else 'FAILED')
        ec.atomic_json(out / 'repair.json', record, exclusive=True)
        print(json.dumps({'ok': record.get('ok'), 'record': str(out / 'repair.json'),
                          'actual': record.get('actual_settings'), 'errors': record.get('errors'),
                          'already_at_baseline_before': record.get('already_at_baseline_before')}))
        return 0 if record.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
