"""Run a model driver unchanged while sampling the packet path once a second (diagnostic of contention attempt 04).

  launch_model.sh ... -d health_wrapper.py   with HEALTH_TARGET=<driver.py>, HEALTH_LOG=<file>

Each sample line: wall time, the veth interfaces present and their operational state, whether tofino-model and
bf_switchd are alive, and the driver's latest session output line count. Runs inside the launcher's namespace, so it
sees the same interfaces and processes the driver uses. Diagnostic only: it changes nothing.
"""
import json
import os
import runpy
import subprocess
import sys
import threading
import time
from pathlib import Path


def sample():
    links = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True).stdout.splitlines()
    veths = {}
    for line in links:
        parts = line.split()
        if len(parts) > 1 and parts[1].startswith('veth'):
            name = parts[1].split('@')[0].rstrip(':')
            veths[name] = 'UP' if 'state UP' in line or 'LOWER_UP' in line else 'DOWN'
    alive = {name: subprocess.run(['pgrep', '-f', name], capture_output=True).returncode == 0
             for name in ('tofino-model', 'bf_switchd')}
    return dict(t=round(time.time(), 3), veths=len(veths), veths_down=sorted(k for k, v in veths.items() if v != 'UP'),
                **alive)


def monitor(path, stop):
    with open(path, 'a') as log:
        while not stop.is_set():
            try:
                log.write(json.dumps(sample()) + '\n')
            except Exception as e:                       # a failed sample is itself evidence
                log.write(json.dumps(dict(t=round(time.time(), 3), sample_error=repr(e))) + '\n')
            log.flush()
            stop.wait(1.0)


def main():
    target = Path(os.environ['HEALTH_TARGET']).resolve()
    stop = threading.Event()
    threading.Thread(target=monitor, args=(os.environ['HEALTH_LOG'], stop), daemon=True).start()
    sys.argv = [str(target)] + sys.argv[1:]
    sys.path[0] = str(target.parent)
    try:
        runpy.run_path(str(target), run_name='__main__')
    finally:
        stop.set()


if __name__ == '__main__':
    main()
