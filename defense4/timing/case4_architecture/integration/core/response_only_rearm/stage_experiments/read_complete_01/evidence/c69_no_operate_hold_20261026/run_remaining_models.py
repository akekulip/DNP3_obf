#!/usr/bin/env python3
"""Serial local-model gate continuation. Never invokes a hardware entry point."""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CTL = HERE.parents[2] / 'ctl_timing_01'
BUILD = 'm12p_c69_sdk9132'
DRIVERS = ('rearm', 'dup', 'repeat', 'select_lifecycle', 'control_timing', 'contention', 'abort',
           'policy', 'policy_boundary', 'two_read_robust', 'smoke_sizeoff', 'abandon', 'relay_sbo', 'fin_busy')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('drivers', nargs='*')
    args = parser.parse_args()
    if set(args.drivers) - set(DRIVERS):
        parser.error('unknown model driver')
    prerequisite = CTL / 'evidence' / ('model_response_ready_' + BUILD + '_04') / 'launch_command.json'
    while not prerequisite.is_file():
        time.sleep(2)
    if json.loads(prerequisite.read_text())['exit_code'] != 0:
        sys.exit('response-ready prerequisite failed; no remaining model launched')
    runs = []
    for driver in args.drivers or DRIVERS:
        prefix = 'model_' + driver + '_' + BUILD + '_'
        attempts = [int(p.name[len(prefix):]) for p in (CTL / 'evidence').glob(prefix + '[0-9][0-9]')]
        attempt = max(attempts, default=0) + 1
        command = [sys.executable, str(CTL / 'run_model.py'), str(CTL / 'evidence' / BUILD),
                   driver, str(attempt), '--milestone', 'm12']
        print('START', driver, attempt, flush=True)
        start = time.monotonic()
        with (HERE / ('%s_%02d_launch.txt' % (driver, attempt))).open('w') as output:
            result = subprocess.run(command, cwd=CTL, stdout=output, stderr=subprocess.STDOUT)
        runs.append(dict(driver=driver, attempt=attempt, command=command, exit_code=result.returncode,
                         elapsed_seconds=round(time.monotonic() - start, 3), hardware=False))
        (HERE / 'remaining_model_sequence.json').write_text(json.dumps(runs, indent=2) + '\n')
        print('END', driver, attempt, 'rc', result.returncode, flush=True)
        if result.returncode:
            sys.exit(result.returncode)
