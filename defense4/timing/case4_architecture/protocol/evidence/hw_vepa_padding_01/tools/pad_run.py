"""Vision side of the active-padding run. sudo python3 pad_run.py MODE ...
  profile set|restore|show   per-namespace TCP profile (ns_vepa_a, ns_vepa_b only; nothing global)
  run LABEL READS            outstation in ns_vepa_b (.62:20000), master in ns_vepa_a (.61, source port pinned 54400),
                             READS ScanRange G10V2 0..22 then one SELECT/OPERATE; captures on the parent NIC:
                             /tmp/pad_LABEL_out.pcap (-Q out: as sent by the endpoints, before the switch)
                             /tmp/pad_LABEL_in.pcap  (-Q in: as returned by the switch)"""
import subprocess, sys, time, os, json
NS = ('ns_vepa_a', 'ns_vepa_b')
PARENT = 'enp59s0f0np0'
BIN = '/home/decps/pad58b_20261011/case4_socket_gate_pad58b'
LIB = '/home/decps/pad58b_20261011/lib'
CLEAN = {'net.ipv4.tcp_timestamps': '0', 'net.ipv4.tcp_sack': '0', 'net.ipv4.tcp_window_scaling': '0'}
DEFAULT = {'net.ipv4.tcp_timestamps': '1', 'net.ipv4.tcp_sack': '1', 'net.ipv4.tcp_window_scaling': '1'}
def nsx(ns, *cmd, **kw):
    return subprocess.run(['ip', 'netns', 'exec', ns] + list(cmd), capture_output=True, text=True, **kw)
def show():
    for ns in NS:
        keys = list(CLEAN) + ['net.ipv4.ip_local_port_range']
        print(ns, nsx(ns, 'sysctl', *keys).stdout.strip().replace('\n', ' | '))
mode = sys.argv[1]
if mode == 'profile':
    act = sys.argv[2]
    if act in ('set', 'restore'):
        vals = CLEAN if act == 'set' else DEFAULT
        for ns in NS:
            for k, v in vals.items(): nsx(ns, 'sysctl', '-w', '%s=%s' % (k, v))
        nsx('ns_vepa_a', 'sysctl', '-w', 'net.ipv4.ip_local_port_range=' + ('54400 54400' if act == 'set' else '32768 60999'))
    show(); sys.exit(0)
label, reads = sys.argv[2], sys.argv[3]
# the master's source port is pinned to one value, so a previous active close leaves it in TIME-WAIT for 60 s
for _ in range(80):
    if ':54400 ' not in nsx('ns_vepa_a', 'ss', '-tan').stdout: break
    time.sleep(1)
else:
    print('port 54400 still busy'); sys.exit(1)
stop = '/tmp/pad_%s.stop' % label
if os.path.exists(stop): os.remove(stop)
caps = []
for d in ('out', 'in'):
    caps.append(subprocess.Popen(['tcpdump', '-i', PARENT, '-Q', d, '-s0', '-U', '-n', '-w', '/tmp/pad_%s_%s.pcap' % (label, d),
                                  'tcp and host 192.168.10.62 and host 192.168.10.61'], stderr=subprocess.DEVNULL))
time.sleep(1.5)
env = ['env', 'CASE4_PAD58B_SOCKET_GATE=1', 'LD_LIBRARY_PATH=' + LIB]
lifetime = str(60 + int(reads) // 5)
ost = subprocess.Popen(['ip', 'netns', 'exec', 'ns_vepa_b'] + env + [BIN, 'outstation', '192.168.10.62', '20000', stop, lifetime],
                       stdout=subprocess.PIPE, text=True)
line = ost.stdout.readline().strip()
print('outstation:', line)
if line != 'READY':
    ost.kill(); [c.terminate() for c in caps]; sys.exit(1)
t0 = time.time()
mst = nsx('ns_vepa_a', *env, BIN, 'master', '192.168.10.62', '20000', '/tmp/pad_%s.mstop' % label, reads, '192.168.10.61',
          timeout=int(reads) * 4 + 30)
print('master rc=%d wall=%.2fs' % (mst.returncode, time.time() - t0))
print('master:', mst.stdout.strip()[:3000])
time.sleep(1.0)
open(stop, 'w').close()
print('outstation:', ost.communicate(timeout=30)[0].strip())
time.sleep(1.0)
for c in caps: c.terminate(); c.wait()
for d in ('out', 'in'):
    r = subprocess.run(['tcpdump', '-r', '/tmp/pad_%s_%s.pcap' % (label, d), '-n'], capture_output=True, text=True)
    print('%s: %d frames' % (d, len(r.stdout.splitlines())))
