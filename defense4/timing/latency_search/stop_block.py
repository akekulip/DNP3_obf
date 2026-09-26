"""Stop only the matching campaign-owned runner and wait before policy restoration."""
import os
from pathlib import Path
import signal
import sys
import time

root = Path(__file__).resolve().parent
label = sys.argv[1]
if Path(label).name != label:
    raise SystemExit('Invalid block label')
pidfile = root / label / 'runner.pid'
if not pidfile.exists():
    raise SystemExit(0)
pid = int(pidfile.read_text())
proc = Path('/proc') / str(pid)
try:
    words = (proc / 'cmdline').read_bytes().split(b'\0')
except FileNotFoundError:
    raise SystemExit(0)
if str(root / 'run_block.py').encode() not in words or label.encode() not in words:
    raise SystemExit('Refusing PID that does not match this block')
os.kill(pid, signal.SIGINT)
for _ in range(200):
    if not proc.exists():
        raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit('Runner did not exit; refuse to restore policy during live traffic')
