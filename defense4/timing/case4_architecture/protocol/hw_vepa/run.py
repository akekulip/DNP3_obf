#!/usr/bin/env python3
"""Drive one software-endpoint run through the switch from this workstation and collect its evidence.

  run.py deploy
  run.py setup | restore
  run.py run LABEL --master-port P --reads N --out EVIDENCE_DIR [--enable 0|1] [--no-forwarding]

`deploy` copies the switch tools to /home/decps/hw_vepa on the switch and vision_run.py to Vision.
`setup` / `restore` set or undo the namespace TCP profile and the NIC source-pruning flag on Vision; `restore`
also reinstalls the relay slot on the switch.
`run` installs the tuple for master port P in slot 0 (padding policy --enable; --no-forwarding leaves the port-9
forwarding row out), reads the switch counters, runs the endpoints on Vision, reads the counters again, copies
the run directory into EVIDENCE_DIR/LABEL and runs wire_check.py on the captures. Use a new master port for each
run: the previous tuple stays in TIME-WAIT for 60 s after its master closes."""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH, VISION = 'decps@10.10.54.81', 'decps@10.10.54.19'
SW_DIR, V_RUN = '/home/decps/hw_vepa', '/home/decps/pad58b_20261011'
PY = os.environ.get('RESEARCH_PYTHON', sys.executable)


def ssh(host, cmd, timeout=600, check=True):
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', host, cmd], capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        sys.exit('FAILED on %s: %s\n%s\n%s' % (host, cmd, r.stdout[-2000:], r.stderr[-2000:]))
    return r


def last_json(text):
    return json.loads([l for l in text.splitlines() if l.startswith('{')][-1])


def counters():
    return last_json(ssh(SWITCH, 'python3 %s/switch_counters.py' % SW_DIR).stdout)


ap = argparse.ArgumentParser()
ap.add_argument('mode', choices=('deploy', 'setup', 'restore', 'casea', 'run'))
ap.add_argument('label', nargs='?')
ap.add_argument('--master-port', type=int)
ap.add_argument('--reads', type=int, default=10)
ap.add_argument('--enable', type=int, choices=(0, 1), default=1)
ap.add_argument('--no-forwarding', action='store_true')
ap.add_argument('--range', type=int, choices=(8, 16), default=16)
ap.add_argument('--gap-ms', type=int, default=0)
ap.add_argument('--delay-ms', type=int, default=25)
ap.add_argument('--out')
a = ap.parse_args()

if a.mode == 'deploy':
    ssh(SWITCH, 'mkdir -p ' + SW_DIR)
    files = [os.path.join(HERE, f) for f in ('switch_slot.py', 'switch_counters.py')] + [os.path.join(HERE, '..', 'response_path_cp.py')]
    subprocess.run(['scp', '-q'] + files + ['%s:%s/' % (SWITCH, SW_DIR)], check=True)
    subprocess.run(['scp', '-q', os.path.join(HERE, 'vision_run.py'), '%s:%s/' % (VISION, V_RUN)], check=True)
    print(ssh(SWITCH, 'sha256sum %s/*.py' % SW_DIR).stdout + ssh(VISION, 'sha256sum %s/vision_run.py' % V_RUN).stdout)
    sys.exit(0)
if a.mode == 'casea':            # run.py casea on|off [--delay-ms D]: see vision_run.py
    print(ssh(VISION, 'sudo python3 %s/vision_run.py casea %s --delay-ms %d' % (V_RUN, a.label, a.delay_ms)).stdout)
    sys.exit(0)
if a.mode in ('setup', 'restore'):
    print(ssh(VISION, 'sudo python3 %s/vision_run.py %s' % (V_RUN, a.mode)).stdout)
    if a.mode == 'restore':
        print(last_json(ssh(SWITCH, 'python3 %s/switch_slot.py relay' % SW_DIR).stdout))
    sys.exit(0)

if not (a.label and a.master_port and a.out):
    ap.error('run needs LABEL, --master-port and --out')
dest = os.path.join(a.out, a.label)
os.makedirs(dest)
slot = last_json(ssh(SWITCH, 'python3 %s/switch_slot.py vepa --master-port %d --enable %d%s' %
                     (SW_DIR, a.master_port, a.enable, ' --no-forwarding' if a.no_forwarding else '')).stdout)
before = counters()
v = ssh(VISION, 'sudo python3 %s/vision_run.py run %s --master-port %d --reads %d --range %d --gap-ms %d%s' %
        (V_RUN, a.label, a.master_port, a.reads, a.range, a.gap_ms, ' --connect-must-fail' if a.no_forwarding else ''), check=False)
after = counters()
subprocess.run(['scp', '-q', '%s:%s/runs/%s/*' % (VISION, V_RUN, a.label), dest + '/'], check=True)
for stale in ('stop', 'stop.master'):
    if os.path.exists(os.path.join(dest, stale)):
        os.remove(os.path.join(dest, stale))
json.dump({'slot': slot, 'before': before, 'after': after}, open(os.path.join(dest, 'switch.json'), 'w'), indent=1)
wire = subprocess.run([PY, os.path.join(HERE, 'wire_check.py'), os.path.join(dest, 'out.pcap'), os.path.join(dest, 'in.pcap')],
                      capture_output=True, text=True)
open(os.path.join(dest, 'wire.json'), 'w').write(wire.stdout if wire.returncode == 0 else json.dumps({'error': wire.stderr[-800:]}))
subprocess.run([PY, os.path.join(HERE, 'clrt_check.py'), os.path.join(dest, 'out.pcap'), os.path.join(dest, 'in.pcap'),
                '--json', os.path.join(dest, 'timing.json')], capture_output=True, text=True)


def reg(snap, name, field=None):
    r = snap['regs'][name]
    return r[[k for k in r if field is None or k.endswith(field)][0]][0]


out = lambda s, code: int(s['outcome'].get(str(code), 0))
summary = {'vision': last_json(v.stdout) if '{' in v.stdout else {'error': (v.stdout + v.stderr)[-500:]},
           'commit_delta': out(after, 1) - out(before, 1), 'arm_map_delta': out(after, 13) - out(before, 13),
           'translate_delta': out(after, 2) - out(before, 2), 'rev_translate_delta': out(after, 9) - out(before, 9),
           'growth_bytes': (reg(after, 'acct', '.lo') - reg(after, 'front')) & 0xffffffff, 'unacked': reg(after, 'acct', '.hi'),
           'dev9_rx_delta': after['ports']['9']['rx'] - before['ports']['9']['rx'],
           'dev9_tx_delta': after['ports']['9']['tx'] - before['ports']['9']['tx']}
json.dump(summary, open(os.path.join(dest, 'summary.json'), 'w'), indent=1)
print(json.dumps(summary, indent=1))
