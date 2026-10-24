#!/usr/bin/env python3
"""Serial baseline experiment queue; stops on any failure or incomplete rollback."""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
RUNNER = ARCH / 'protocol' / 'hw_vepa'
EVIDENCE = HERE.parent
JOBS = [
    ('stale_diag_read_only_3723.json', 'shape_3723', 'rearm_stale_read_only_01'),
    ('precision_5ms_gap800us_14892.json', 'shape_14892', 'rearm_precision_5_800_01'),
    ('precision_5ms_gap950us_14892.json', 'shape_14892', 'rearm_precision_5_950_01'),
    ('precision_10ms_gap950us_14892.json', 'shape_14892', 'rearm_precision_10_950_01'),
    ('precision_25ms_gap800us_14892.json', 'shape_14892', 'rearm_precision_25_800_01'),
    ('precision_pause0_14892.json', 'shape_14892', 'rearm_precision_pause0_01'),
    ('fourarm_separate_ack_14892.json', 'shape_14892', 'rearm_fourarm_separate_01'),
    ('fourarm_piggyback_14892.json', 'shape_14892', 'rearm_fourarm_piggyback_01'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--start', type=int, default=0)
    parser.add_argument('--stop', type=int, default=len(JOBS))
    args = parser.parse_args()
    if not 0 <= args.start < args.stop <= len(JOBS):
        parser.error('invalid job interval')
    if args.apply and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        parser.error('apply requires DEFENSE4_HW_AUTHORIZED=1')
    journal_path = EVIDENCE / 'baseline_queue_journal.json'
    journal = json.loads(journal_path.read_text()) if journal_path.exists() else []
    for name, preset, run_id in JOBS[args.start:args.stop]:
        config = (EVIDENCE / 'config' / name if name.startswith('precision_pause0')
                  else RUNNER / 'config' / name)
        command = [sys.executable, '-u', str(RUNNER / 'campaign.py'),
                   'run' if args.apply else 'plan', '--config', str(config),
                   '--preset', preset, '--run-id', run_id]
        if args.apply:
            command.append('--apply')
        print('START ' + run_id, flush=True)
        log = EVIDENCE / (run_id + ('_runner.log' if args.apply else '_plan.log'))
        with log.open('x') as stream:
            result = subprocess.run(command, cwd=RUNNER, stdout=stream, stderr=subprocess.STDOUT)
        row = dict(run_id=run_id, applied=args.apply, config=str(config), command=command, rc=result.returncode,
                   log=str(log), restored=None)
        if args.apply:
            manifest = ARCH / 'integration/evidence/campaign_hw_vepa' / run_id / 'campaign_run.json'
            if manifest.is_file():
                evidence = json.loads(manifest.read_text())
                restores = evidence.get('restore', [])
                row.update(restored=len(restores) == 5 and all(x.get('ok') and x.get('rc') == 0 for x in restores),
                           failure=evidence.get('failure'), ok=evidence.get('ok'))
        journal.append(row)
        journal_path.write_text(json.dumps(journal, indent=2) + '\n')
        print('FINISH ' + json.dumps(row), flush=True)
        if result.returncode or (args.apply and not row['restored']):
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
