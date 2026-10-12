#!/usr/bin/env python3
"""Serial precision follow-up; retain threshold failures and require complete rollback."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
RUNNER = ARCH / 'protocol/hw_vepa'
ROOT = HERE.parent


def admissible(record):
    restore = record.get('restore', [])
    if len(restore) != 5 or any(item.get('rc') != 0 or item.get('ok') is not True for item in restore):
        return False
    trials = [trial for arm in record.get('arms', []) for trial in arm.get('trials', [])]
    if not trials:
        return False
    failures = [failure for trial in trials for failure in trial.get('failures', [])]
    return record.get('ok') is True or (bool(failures) and all(f.startswith('READ precision:') for f in failures)
                                       and all(t.get('ok') or t.get('continuation', {}).get('allowed') is True
                                               for t in trials))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--after', required=True, help='wait up to 30 minutes for this active run to finish')
    args = parser.parse_args()
    if args.apply and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        parser.error('apply requires DEFENSE4_HW_AUTHORIZED=1')
    jobs = [('precision_25_800_characterization_14892.json', 'shape_14892', 'rearm_precision_25_800_01')]
    if args.apply:
        manifest = ARCH / 'integration/evidence/campaign_hw_vepa' / args.after / 'campaign_run.json'
        for _ in range(360):
            if manifest.is_file():
                break
            time.sleep(5)
        else:
            raise RuntimeError('prior run did not finish; no new hardware operation')
        if not admissible(json.loads(manifest.read_text())):
            raise RuntimeError('prior run has structural/application failure or incomplete restore')
    for name, preset, run_id in jobs:
        command = [sys.executable, '-u', str(RUNNER / 'campaign.py'), 'run' if args.apply else 'plan',
                   '--config', str(ROOT / 'config' / name), '--preset', preset, '--run-id', run_id]
        if args.apply:
            command.append('--apply')
        print(json.dumps(command), flush=True)
        with (ROOT / (run_id + ('_runner.log' if args.apply else '_plan.log'))).open('x') as stream:
            completed = subprocess.run(command, cwd=str(RUNNER), stdout=stream, stderr=subprocess.STDOUT)
        if args.apply:
            record = json.loads((ARCH / 'integration/evidence/campaign_hw_vepa' / run_id / 'campaign_run.json').read_text())
            print(json.dumps({'run_id': run_id, 'rc': completed.returncode, 'ok': record['ok'],
                              'restore': record['restore']}), flush=True)
            if not admissible(record):
                return 1
        elif completed.returncode:
            return completed.returncode
    return 0


if __name__ == '__main__':
    sys.exit(main())
