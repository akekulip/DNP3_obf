#!/usr/bin/env python3
"""Read-only process/configuration/artifact identity capture."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

pids = subprocess.check_output(['pgrep', '-x', 'bf_switchd'], text=True).split()
if len(pids) != 1:
    raise SystemExit('Expected exactly one bf_switchd: ' + repr(pids))
pid = int(pids[0])
cmd = Path('/proc/%d/cmdline' % pid).read_bytes().decode().strip('\0').split('\0')
config = Path(cmd[cmd.index('--conf-file') + 1])
conf = json.loads(config.read_text())
programs = conf['p4_devices'][0]['p4_programs']
if len(programs) != 1:
    raise SystemExit('Expected exactly one program')
p = programs[0]
pipe = p['p4_pipelines'][0]
paths = {'bfrt.json': p['bfrt-config'], 'pipe/context.json': pipe['context'], 'pipe/tofino.bin': pipe['config']}
print(json.dumps({'time_ns': time.time_ns(), 'pid': pid, 'command': cmd,
    'config': str(config), 'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
    'program': p['program-name'], 'artifact_paths': paths,
    'artifact_sha256': {k: hashlib.sha256(Path(v).read_bytes()).hexdigest() for k,v in paths.items()}}, indent=2))
