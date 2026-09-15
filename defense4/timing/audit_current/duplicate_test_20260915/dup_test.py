#!/usr/bin/env python3
'''Duplicate-suppression test: is a loss-recovery retransmission delivered or suppressed?

Establishes one DNP3 connection, sends one READ, and drops the relay's RESPONSE inbound at this
host only, scoped to this connection's own 4-tuple. The kernel therefore never acknowledges the
response, the relay retransmits on its own timer, and the capture on the wire shows whether the
switch forwarded those copies or suppressed them.

READ only. No SELECT, no OPERATE, no retry. Every iptables call is checked and cleanup is
verified rather than announced.
'''
import json, socket, subprocess, sys, time

RELAY, PORT = '192.168.10.7', 20000
READ = bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
HOLD = float(sys.argv[1]) if len(sys.argv) > 1 else 25.0

def run(argv):
    p = subprocess.run(argv, capture_output=True, text=True)
    return p.returncode

s = socket.create_connection((RELAY, PORT), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
sport = s.getsockname()[1]
rule = ['-p','tcp','-s',RELAY,'--sport',str(PORT),'-d','192.168.10.1','--dport',str(sport),
        '-m','length','--length','101:101','-j','DROP']   # 20 IPv4 + 20 TCP + 49 DNP3 response
rec = {'source_port': sport, 'rule': ' '.join(rule)}
try:
    rec['install_rc'] = run(['iptables','-A','INPUT']+rule)
    rec['verify_installed_rc'] = run(['iptables','-C','INPUT']+rule)
    if rec['install_rc'] or rec['verify_installed_rc']:
        raise SystemExit('rule did not install: ' + json.dumps(rec))
    time.sleep(0.2)
    t0 = time.time()
    s.send(READ)
    rec['read_sent_at'] = t0
    time.sleep(HOLD)
finally:
    rec['remove_rc'] = run(['iptables','-D','INPUT']+rule)
    rec['still_present_rc'] = run(['iptables','-C','INPUT']+rule)   # non-zero once gone
    rec['cleanup_confirmed'] = (rec['remove_rc'] == 0 and rec['still_present_rc'] != 0)
    try: s.close()
    except Exception: pass
print(json.dumps(rec))
