#!/usr/bin/env python3
"""Vision side of a software-endpoint run through the switch. Run with sudo python3 on Vision.

  vision_run.py setup            clean TCP profile in ns_vepa_a / ns_vepa_b, disable-source-pruning on
  vision_run.py restore          sysctls back to 1/1/1 and 32768 60999, disable-source-pruning off
  vision_run.py state            print the NIC flag and the namespace sysctls
  vision_run.py run LABEL --master-port P --reads N [--connect-must-fail]

`run` starts the OpenDNP3 outstation in ns_vepa_b (192.168.10.62:20000) and the master in ns_vepa_a
(192.168.10.61, source port pinned to P through that namespace's ip_local_port_range), does N READs
(Group 10 Var 2, points 0..22) and one SELECT/OPERATE, and writes everything into a NEW directory
RUNS/LABEL: out.pcap (tcpdump -Q out on the parent NIC: frames as the endpoints sent them), in.pcap
(-Q in: frames as the switch returned them), master.json, outstation.json, state.txt, result.json.
Nothing here touches the parent NIC's addresses or routes, or any global sysctl."""
import argparse
import json
import os
import re
import subprocess
import sys
import time

PARENT = 'enp59s0f0np0'
NS_M, NS_O = 'ns_vepa_a', 'ns_vepa_b'
IP_M, IP_O, PORT_O = '192.168.10.61', '192.168.10.62', 20000
HOME = '/home/decps/pad58b_20261011'
BIN, LIB, RUNS = HOME + '/case4_socket_gate_pad58b', HOME + '/lib', HOME + '/runs'
PROFILE = ('net.ipv4.tcp_timestamps', 'net.ipv4.tcp_sack', 'net.ipv4.tcp_window_scaling')
DEFAULT_RANGE = '32768 60999'


def sh(*cmd, **kw):
    return subprocess.run(list(cmd), capture_output=True, text=True, **kw)


def nsx(ns, *cmd, **kw):
    return sh('ip', 'netns', 'exec', ns, *cmd, **kw)


def state():
    flags = sh('ethtool', '--show-priv-flags', PARENT).stdout.splitlines()
    lines = [' '.join(next(l for l in flags if 'source-pruning' in l).split())]
    for ns in (NS_M, NS_O):
        lines.append(ns + ' ' + ' | '.join(nsx(ns, 'sysctl', *PROFILE, 'net.ipv4.ip_local_port_range').stdout.split('\n')).strip(' |'))
    return '\n'.join(lines)


def pruning(value):
    r = sh('ethtool', '--set-priv-flags', PARENT, 'disable-source-pruning', value)
    if r.returncode:
        sys.exit('ethtool failed: ' + r.stderr)
    time.sleep(8)          # the i40e PF resets on this change; wait for the link


def profile(value, port_range):
    for ns in (NS_M, NS_O):
        for k in PROFILE:
            nsx(ns, 'sysctl', '-w', '%s=%s' % (k, value))
    nsx(NS_M, 'sysctl', '-w', 'net.ipv4.ip_local_port_range=' + port_range)


ap = argparse.ArgumentParser()
ap.add_argument('mode', choices=('setup', 'restore', 'state', 'run'))
ap.add_argument('label', nargs='?')
ap.add_argument('--master-port', type=int)
ap.add_argument('--reads', type=int, default=10)
ap.add_argument('--connect-must-fail', action='store_true')
a = ap.parse_args()

if a.mode == 'setup':
    profile('0', DEFAULT_RANGE)
    if 'source-pruning : on' not in state():
        pruning('on')
if a.mode == 'restore':
    profile('1', DEFAULT_RANGE)
    if 'source-pruning : off' not in state():
        pruning('off')
if a.mode != 'run':
    print(state())
    sys.exit(0)

if not a.label or not re.fullmatch(r'[A-Za-z0-9_]+', a.label) or a.master_port is None:
    sys.exit('run needs LABEL and --master-port')
run_dir = os.path.join(RUNS, a.label)
os.makedirs(run_dir)                      # refuses to reuse a label
nsx(NS_M, 'sysctl', '-w', 'net.ipv4.ip_local_port_range=%d %d' % (a.master_port, a.master_port))
for _ in range(80):                       # a tuple just closed by its master sits in TIME-WAIT for 60 s
    if ':%d ' % a.master_port not in nsx(NS_M, 'ss', '-tan').stdout:
        break
    time.sleep(1)
else:
    sys.exit('master port %d still busy' % a.master_port)
open(os.path.join(run_dir, 'state.txt'), 'w').write(state() + '\n')
flt = 'tcp and host %s and host %s' % (IP_M, IP_O)
caps = [subprocess.Popen(['tcpdump', '-i', PARENT, '-Q', d, '-s0', '-U', '-n', '-w', os.path.join(run_dir, d + '.pcap'), flt],
                         stderr=subprocess.DEVNULL) for d in ('out', 'in')]
time.sleep(1.5)
env = ['env', 'CASE4_PAD58B_SOCKET_GATE=1', 'LD_LIBRARY_PATH=' + LIB]
stop = os.path.join(run_dir, 'stop')
ost = subprocess.Popen(['ip', 'netns', 'exec', NS_O] + env + [BIN, 'outstation', IP_O, str(PORT_O), stop, str(60 + a.reads // 5)],
                       stdout=subprocess.PIPE, text=True)
ready = ost.stdout.readline().strip()
result = {'label': a.label, 'master_port': a.master_port, 'reads': a.reads, 'outstation_ready': ready == 'READY'}
if ready == 'READY':
    t0 = time.time()
    mst = nsx(NS_M, *env, BIN, 'master', IP_O, str(PORT_O), stop + '.master', str(a.reads), IP_M, timeout=a.reads * 4 + 30)
    result.update(master_rc=mst.returncode, master_wall_s=round(time.time() - t0, 3))
    open(os.path.join(run_dir, 'master.json'), 'w').write(mst.stdout)
    time.sleep(1.0)
open(stop, 'w').close()
try:
    open(os.path.join(run_dir, 'outstation.json'), 'w').write(ost.communicate(timeout=30)[0])
except subprocess.TimeoutExpired:
    ost.kill()
time.sleep(1.0)
for c in caps:
    c.terminate()
    c.wait()
for d in ('out', 'in'):
    path = os.path.join(run_dir, d + '.pcap')
    result['frames_' + d] = len(sh('tcpdump', '-r', path, '-n').stdout.splitlines()) if os.path.getsize(path) > 24 else 0
result['ok'] = (result.get('master_rc') == 2) if a.connect_must_fail else (result.get('master_rc') == 0)
json.dump(result, open(os.path.join(run_dir, 'result.json'), 'w'), indent=1)
print(json.dumps(result))
sys.exit(0 if result['ok'] else 1)
