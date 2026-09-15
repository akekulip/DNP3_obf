#!/usr/bin/env python3
'''Measure the SEL-751A TCP retransmission timeout.

Opens a DNP3 session, installs an iptables rule that drops only PURE ACKs toward the relay
(the connection is already established, and the READ itself carries PSH so it still goes out),
sends one READ, and lets the relay retransmit its unacknowledged response. The rule is removed
in a finally block and a detached watchdog removes it too, so a crash cannot strand it.
'''
import socket, subprocess, sys, time

RELAY_IP, RELAY_PORT = '192.168.10.7', 20000
READ = bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
HOLD = float(sys.argv[1]) if len(sys.argv) > 1 else 40.0
RULE = ['-p','tcp','-d',RELAY_IP,'--dport',str(RELAY_PORT),
        '--tcp-flags','SYN,RST,PSH,ACK','ACK','-j','DROP']

def ipt(action):
    subprocess.run(['iptables', action, 'OUTPUT'] + RULE,
                   check=False, capture_output=True)

subprocess.Popen(['bash','-c',
    'sleep %d; iptables -D OUTPUT %s 2>/dev/null' % (int(HOLD)+45, ' '.join(RULE))],
    start_new_session=True)

s = socket.create_connection((RELAY_IP, RELAY_PORT), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
print('connected  local=%s' % (s.getsockname(),), flush=True)
try:
    time.sleep(0.3)
    ipt('-A')
    time.sleep(0.2)
    t0 = time.time()
    s.send(READ)
    print('READ sent at t0; holding %.0f s with pure ACKs dropped' % HOLD, flush=True)
    time.sleep(HOLD)
finally:
    ipt('-D')
    print('iptables rule removed', flush=True)
    time.sleep(1.0)
    try: s.close()
    except Exception: pass
print('done', flush=True)
