"""Current relay endpoint command construction and JSON result extraction."""
import json
import os
import sys
PY=os.environ.get("RESEARCH_PYTHON",sys.executable)
V_RUN="/tmp/dnp3_current"

def last_json(text):
    return json.loads([l for l in text.splitlines() if l.startswith('{')][-1])

def vision_cmd(label, master_port, reads, rng, gap_ms, start_delay_ms=0, start_seed=0, connect_must_fail=False,
               drop=None, scenario=None, reconnect_port=None):
    """The Vision-side command for one run; shared by `run` here so the flags cannot drift from vision_run.py."""
    return ('sudo python3 %s/vision_run.py run %s --master-port %d --reads %d --range %d --gap-ms %d '
            '--start-delay-ms %d --start-seed %d%s%s%s' % (
                V_RUN, label, master_port, reads, rng, gap_ms, start_delay_ms, start_seed,
                ' --connect-must-fail' if connect_must_fail else '', ' --drop %s' % drop if drop else '',
                ' --scenario %s --reconnect-port %d' % (scenario, reconnect_port) if scenario else ''))
