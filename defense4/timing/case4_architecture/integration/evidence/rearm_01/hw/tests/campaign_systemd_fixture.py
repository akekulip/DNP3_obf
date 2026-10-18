#!/usr/bin/env python3
"""Harmless real user-systemd disconnect/kill/resume check; NEVER runs hardware.

python3 campaign_systemd_fixture.py --output /persistent/path/new_fixture_dir

Retains manifest, logs, terminal records and report under --output. Only kills
its own uniquely named controller and stops its own fixture units on cleanup.
Every block is a local Python command that writes fixture restoration JSON.
"""
import argparse
import importlib.util
import json
import socket
from pathlib import Path
import subprocess
import sys
import time
import uuid

MODULE = Path(__file__).resolve().parents[1] / 'evaluation_campaign.py'


def load_module():
    spec = importlib.util.spec_from_file_location('evaluation_campaign', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait_for(predicate, description, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError('timed out: ' + description)


def run_fixture(output):
    c = load_module()
    c.Systemd().preflight()
    output = output.resolve()
    output.mkdir()  # exclusive retained evidence
    campaign_id = 'supervision-fixture-' + uuid.uuid4().hex[:12]
    release = output / 'release'
    steps = []
    for index in range(2):
        root = output / ('run%d' % index)
        count = output / ('count%d' % index)
        code = ('import json,time; from pathlib import Path\n'
                'root=Path(%r); root.mkdir()\n'
                'with open(%r,"x") as stream: stream.write("once")\n'
                'while not Path(%r).exists(): time.sleep(.1)\n'
                '(root/"restore_verify.json").write_text(json.dumps({"ok":True,"evidence_kind":"supervision_fixture"}))\n'
                % (str(root), str(count), str(release)))
        steps.append({'id': 'block%d' % index, 'kind': 'block',
                      'argv': [sys.executable, '-c', code], 'run_root': str(root)})
    source = output / 'fixture_manifest.json'
    source.write_text(json.dumps({'campaign_id': campaign_id,
                                 'evidence_kind': 'supervision_fixture', 'steps': steps}, indent=2))
    campaign = c.initialize(source)
    owned_units = set()
    report = {'evidence_kind': 'supervision_fixture', 'excluded_from_main_evidence': True,
              'campaign_dir': str(campaign), 'checks': {}, 'ok': False}
    try:
        # The CLI launcher returns while the service-owned block remains running.
        launched = subprocess.run([sys.executable, str(MODULE), 'start', str(campaign)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        if launched.returncode:
            raise RuntimeError(launched.stderr)
        owned_units.add(launched.stdout.strip())
        wait_for(lambda: (output / 'count0').exists(), 'first independent block entered')
        state = c.read_state(campaign)
        owned_units.add(state['active_unit'])
        original_deadline = state['deadline']
        report['checks']['launcher_disconnect'] = c.Systemd().state(state['active_unit']) == 'active'
        duplicate = subprocess.run([sys.executable, str(MODULE), 'start', str(campaign)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        report['checks']['duplicate_start'] = duplicate.returncode == 2
        # Kill only this fixture's controller, never a block or unrelated unit.
        killed = subprocess.run(['systemctl', '--user', 'kill', '--kill-who=main',
                                 '--signal=SIGKILL', state['controller_unit']],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if killed.returncode:
            raise RuntimeError(killed.stderr)
        wait_for(lambda: c.Systemd().state(state['controller_unit']) not in c.ACTIVE,
                 'controller death observed')
        report['checks']['block_survives_controller_kill'] = c.Systemd().state(state['active_unit']) == 'active'
        resumed = c.launch_controller(campaign, resume=True)
        owned_units.add(resumed)
        time.sleep(1.2)
        report['checks']['resume_unchanged_deadline'] = c.read_state(campaign)['deadline'] == original_deadline
        report['checks']['active_block_once'] = (output / 'count0').read_text() == 'once'
        release.touch()
        wait_for(lambda: c.status(campaign)['phase'] == 'complete', 'all fixture blocks complete')
        report['checks']['both_blocks_once'] = all((output / ('count%d' % index)).read_text() == 'once'
                                                   for index in range(2))
        report['checks']['independent_terminal_records'] = all(
            (campaign / 'steps' / ('block%d' % index) / 'terminal.json').exists() for index in range(2))
        report['ok'] = all(report['checks'].values())
        report['status'] = c.status(campaign)
        if not report['ok']:
            raise RuntimeError('fixture assertion failed')
        return report
    finally:
        # Release the harmless fixture even on failure; no hardware is present.
        release.touch(exist_ok=True)
        state = c.read_state(campaign)
        if state['active_unit']:
            owned_units.add(state['active_unit'])
        for entry in state['steps'].values():
            if entry.get('unit'):
                owned_units.add(entry['unit'])
        # This stop list is exclusively generated from this random fixture ID.
        for unit in sorted(owned_units):
            if not unit.startswith('dnp3-eval-' + campaign_id + '-'):
                raise RuntimeError('refuse cleanup outside unique fixture identity')
            subprocess.run(['systemctl', '--user', 'stop', unit],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output / 'fixture_report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


def run_boundary_fixture(output, mode):
    """Real services with an accelerated fixture-only clock; never hardware state."""
    c = load_module()
    output.mkdir()
    campaign_id = 'supervision-boundary-' + uuid.uuid4().hex[:12]
    release = output / 'release'
    steps = []
    for index in range(2):
        root = output / ('run%d' % index)
        marker = output / ('entered%d' % index)
        code = ('from pathlib import Path; import json,time\n'
                'p=Path(%r); p.mkdir(); Path(%r).write_text("once")\n'
                'while not Path(%r).exists(): time.sleep(.05)\n'
                '(p/"restore_verify.json").write_text(json.dumps({"ok":%r,"evidence_kind":"supervision_fixture"}))\n'
                % (str(root), str(marker), str(release), mode != 'failed_restore'))
        steps.append(dict(id='block%d' % index, kind='block', run_root=str(root),
                          argv=[sys.executable, '-c', code]))
    manifest = output / 'manifest.json'
    manifest.write_text(json.dumps(dict(campaign_id=campaign_id, evidence_kind='supervision_fixture', steps=steps)))
    campaign = c.initialize(manifest)
    units = set()
    report = dict(mode=mode, host=socket.gethostname(), evidence_kind='supervision_fixture',
                  excluded_from_main_evidence=True, accelerated_clock=mode != 'failed_restore')
    try:
        units.add(c.launch_controller(campaign))
        wait_for(lambda: (output / 'entered0').exists(), 'boundary fixture block entry')
        if mode == 'expiry':
            # Advancing fixture wall time is represented by an already elapsed
            # deadline, preserving the production invariant deadline=start+24h.
            with c.locked(campaign):
                state = c.read_state(campaign)
                state['deadline'] = time.time() - .1
                state['start'] = state['deadline'] - c.DAY
                c.atomic_json(campaign / 'state.json', state)
            report['active_survives_expiry'] = c.Systemd().state(c.read_state(campaign)['active_unit']) == 'active'
        release.touch()
        wait_for(lambda: c.status(campaign)['phase'] == 'stopped', 'boundary campaign stops')
        status = c.status(campaign)
        report.update(status=status, next_block_unexecuted=not (output / 'entered1').exists(),
                      block_once=(output / 'entered0').read_text() == 'once',
                      independent_terminal=(campaign / 'steps/block0/terminal.json').exists())
        expected_reason = 'deadline_expired' if mode == 'expiry' else 'unsafe_restoration'
        report['ok'] = (status['stop_reason'] == expected_reason and report['next_block_unexecuted']
                        and report['block_once'] and report['independent_terminal']
                        and status['blocks'][0]['restoration']['ok'] == (mode == 'expiry'))
        if not report['ok']:
            raise RuntimeError('boundary fixture assertion failed: ' + mode)
        return report
    finally:
        release.touch(exist_ok=True)
        state = c.read_state(campaign)
        for entry in state['steps'].values():
            if entry.get('unit'):
                units.add(entry['unit'])
        for unit in units:
            if not unit.startswith('dnp3-eval-' + campaign_id + '-'):
                raise RuntimeError('fixture cleanup outside owned units')
            subprocess.run(['systemctl', '--user', 'stop', unit], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output / 'fixture_report.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = run_fixture(args.output)
        boundaries = [run_boundary_fixture(args.output / mode, mode) for mode in ('expiry', 'failed_restore')]
        report.update(host=socket.gethostname(), boundary_checks={b['mode']: b['ok'] for b in boundaries})
        report['ok'] = report['ok'] and all(b['ok'] for b in boundaries)
        (args.output / 'fixture_report.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('FIXTURE FAILED: %s' % error, file=sys.stderr)
        return 1
    print(json.dumps({'ok': report['ok'], 'output': str(args.output.resolve()), 'checks': report['checks']}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
