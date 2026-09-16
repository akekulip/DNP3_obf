#!/usr/bin/env python3
"""Measure the MASTER's own TCP retransmission timer.

The outstation's timer was measured on 2026-09-15. The master's never was, and the two are
different quantities: the master's governs how long its request may go unacknowledged, which is
the bound the ACK hold consumes.

Method. Open one DNP3 connection, drop everything inbound from the outstation on this connection
only, then send one READ. Nothing can acknowledge the request, so the master's stack retransmits
it on its own timer, and the capture on this host's NIC records each attempt. Scoped to this
connection's 4-tuple; every iptables call is checked and the removal is verified.
"""
import json, socket, subprocess, sys, time

RELAY, PORT = '192.168.10.7', 20000
READ = bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
HOLD = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
IFACE = sys.argv[2] if len(sys.argv) > 2 else 'enp59s0f0np0'
PCAP = sys.argv[3] if len(sys.argv) > 3 else '/tmp/master_rto.pcap'


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True).returncode


rec = {}
s = socket.create_connection((RELAY, PORT), timeout=10)
sport = s.getsockname()[1]
rec['four_tuple'] = f"{s.getsockname()[0]}:{sport} -> {RELAY}:{PORT}"

cap = subprocess.Popen(['tcpdump', '-i', IFACE, '-w', PCAP, '--time-stamp-precision=nano',
                        '-U', '-s', '128', f'tcp port {sport}'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)

rule = ['-p', 'tcp', '-s', RELAY, '--sport', str(PORT),
        '--dport', str(sport), '-m', 'comment', '--comment', 'master-rto-probe', '-j', 'DROP']
rec['install_rc'] = run(['iptables', '-A', 'INPUT'] + rule)
rec['verify_installed_rc'] = run(['iptables', '-C', 'INPUT'] + rule)
try:
    t0 = time.time()
    s.sendall(READ)
    rec['sent_at'] = t0
    time.sleep(HOLD)
finally:
    rec['remove_rc'] = run(['iptables', '-D', 'INPUT'] + rule)
    rec['absent_rc'] = run(['iptables', '-C', 'INPUT'] + rule)   # 1 == absent
    rec['cleanup_verified'] = (rec['remove_rc'] == 0 and rec['absent_rc'] == 1)
    time.sleep(1.0)
    cap.terminate(); cap.wait(timeout=10)
    try:
        s.close()
    except Exception:
        pass
print(json.dumps(rec))
