#!/usr/bin/env python3
"""Run a block's Vision restore and ping that never reached Vision, recorded for reconcile (Philip, 2026-10-24).

  python3 vision_unreachable_repair.py CAMPAIGN_DIR STEP_ID --vision-host USER@HOST           # check only
  python3 vision_unreachable_repair.py CAMPAIGN_DIR STEP_ID --vision-host USER@HOST --apply   # run and record

rc01_hw_c51_20261024_05: Vision's management link failed during the block, so the runner's Vision restore and
ping both ended in ssh rc 255 ("No route to host") without executing; the switch restore steps all passed.
Vision later answered on another management address (Philip: "vision is 10.10.54.19").

Refuses unless, under the testbed ownership lock: ownership names exactly this failed block with
unsafe_restoration set (terminal record hash bound); no owner or evaluation unit is active; the block's runner record
(campaign_run.json), run output (run_block_run.out) and freeze check match the hashes its artifact manifest retained,
and its config is unchanged since the block ran; the ONLY failed runner restore steps are the Vision restore and the
ping, each rc 255, and the run output has exactly those two restore-failure lines, each an ssh connect failure to the
block's configured Vision host (so nothing ran remotely); every switch restore step passed.

--apply first proves the new host is Vision (hostname "vision" and the sel751 master data NIC MAC), then runs the
runner's own two commands there, unchanged: the relay-profile `vision_run.py restore --endpoint-profile sel751` in
the block's Vision run directory and `ping -c COUNT -I SRC DST` from the block's production config. The record
CAMPAIGN_DIR/steps/STEP_ID/vision_unreachable_repair_<UTC>/repair.json is created exclusively. The original runner
result is read, never rewritten; reconcile must still pass a complete fresh restore_verify.
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
sys.path.insert(0, str(HERE))
import evaluation_campaign as ec  # noqa: E402

RELAY_PYTHON = 'sudo -n /usr/bin/python3'          # protocol/hw_vepa/campaign.py RELAY_PYTHON
FAILED_LINE = re.compile(r'^RESTORE STEP FAILED: (?P<step>.+?) \(rc (?P<rc>-?\d+)\) (?P<detail>.*)$')
CONNECT_FAILED = re.compile(r'^ssh: connect to host (?P<host>\S+) port 22: '
                            r'(No route to host|Connection timed out|Connection refused)\s*$')
STEPS = [ec.VISION_RESTORE_STEP, ec.PING_STEP]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bound_failure(campaign_run, run_out, configured_host):
    """Pure. (failed restore record, problems). Problems is empty only when the failed runner restore steps are
    exactly the Vision restore and the ping, each rc 255, every other restore step passed, and the run output's
    restore-failure lines are exactly those two, each an ssh connect failure to the configured Vision address."""
    problems = []
    restore = campaign_run.get('restore', [])
    failed = [s for s in restore if not s.get('ok')]
    if [s.get('step') for s in failed] != STEPS or any(s.get('rc') != 255 for s in failed):
        problems.append('runner restore failures are %r, not exactly the Vision restore and ping with rc 255'
                        % [(s.get('step'), s.get('rc')) for s in failed])
    if not any(s.get('ok') for s in restore):
        problems.append('no switch restore step passed')
    lines = [FAILED_LINE.match(l) for l in run_out.splitlines() if l.startswith('RESTORE STEP FAILED')]
    if len(lines) != 2 or None in lines:
        problems.append('run output has %d restore-failure lines, need exactly two well-formed' % len(lines))
        return {'steps': failed}, problems
    address = configured_host.split('@')[-1]
    for step, m in zip(STEPS, lines):
        connect = CONNECT_FAILED.match(m.group('detail'))
        if m.group('step') != step or m.group('rc') != '255' or connect is None or connect.group('host') != address:
            problems.append('restore failure is not an ssh connect failure of %r to %s: %r' % (step, address, m.group(0)))
    return {'steps': failed, 'lines': [m.group(0) for m in lines]}, problems


def ssh(host, command, timeout=600):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, command],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)


def apply_repair(host, config, run=ssh):
    """Identity check, then the runner's two commands. Returns the evidence dict; failures recorded, never raised."""
    out = {'errors': []}
    ident = run(host, 'hostname; cat /sys/class/net/enp59s0f0np0/address')
    words = ident.stdout.split()
    out['identity'] = dict(rc=ident.returncode, hostname=words[0] if words else None,
                           data_mac=words[1] if len(words) > 1 else None)
    if ident.returncode or out['identity']['hostname'] != 'vision' or out['identity']['data_mac'] != ec.VISION_DATA_MAC:
        out['errors'].append('host %s is not Vision: %r' % (host, out['identity']))
        out['ok'] = False
        return out
    pg = config['production']['ping']
    commands = {'restore': '%s %s/vision_run.py restore --endpoint-profile sel751'
                           % (RELAY_PYTHON, shlex.quote(config['hosts']['vision_run_dir'])),
                'ping': 'ping -c %d -I %s %s' % (pg['count'], pg['src'], pg['dst'])}
    for name, command in commands.items():
        r = run(host, command)
        out[name] = dict(command=command, rc=r.returncode, stdout=r.stdout[-4000:], stderr=r.stderr[-2000:])
        if r.returncode:
            out['errors'].append('%s exited %d' % (name, r.returncode))
    out['ok'] = not out['errors']
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('campaign')
    ap.add_argument('step_id')
    ap.add_argument('--vision-host', required=True)
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
        campaign_run, run_out, config = {}, '', None
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
            bound['config'] = sha(config_path.read_bytes())
        except (KeyError, TypeError, ValueError, OSError, IndexError) as error:
            problems.append('block records unusable: %s' % error)
        failure, more = bound_failure(campaign_run, run_out, (config or {}).get('hosts', {}).get('vision', ''))
        problems += more
        if config is not None and config.get('endpoint_profile') != 'sel751':
            problems.append('only a sel751 block: the runner restore command differs for other profiles')
        if not ec.VISION_HOST.fullmatch(a.vision_host):
            problems.append('--vision-host %r is not user@host' % a.vision_host)
        record = dict(campaign_dir=str(directory), step_id=a.step_id, run_root=str(run_root), at=time.time(),
                      bound_sha256=bound, failed_restoration=failure, vision_host=a.vision_host,
                      configured_vision_host=(config or {}).get('hosts', {}).get('vision'),
                      original_runner_result='left unchanged (failed)')
        if problems:
            print(json.dumps(dict(record, problems=problems), indent=1))
            sys.exit('REFUSED: ' + '; '.join(problems))
        if not a.apply:
            print(json.dumps(dict(record, mode='check only'), indent=1))
            return 0
        out = records / ('vision_unreachable_repair_%s' % time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
        out.mkdir()
        try:
            evidence = apply_repair(a.vision_host, config)
        except Exception as error:      # noqa: BLE001 - recorded as a failed repair, never a pass
            evidence = {'ok': False, 'errors': ['repair raised: %s' % error]}
        record.update(evidence)
        record['result'] = 'Vision restore and ping run and passed' if evidence.get('ok') else 'FAILED'
        ec.atomic_json(out / 'repair.json', record, exclusive=True)
        print(json.dumps({'ok': record.get('ok'), 'record': str(out / 'repair.json'), 'identity': record.get('identity'),
                          'errors': record.get('errors')}))
        return 0 if record.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
