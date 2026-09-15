#!/usr/bin/env python3
'''One complete DNP3 READ transaction against the relay, acknowledged normally.'''
import socket, sys, time
READ = bytes.fromhex('05640dc400000100f387c0c0010a020000165a2c')
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1
s = socket.create_connection(('192.168.10.7', 20000), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.settimeout(3.0)
time.sleep(0.3)
t0 = time.time()
ok = 0
for i in range(N):
    s.send(READ)
    got = 0
    try:
        while got < 40:
            b = s.recv(4096)
            if not b: break
            got += len(b)
    except socket.timeout:
        pass
    if got: ok += 1
    time.sleep(0.05)
print('transactions=%d answered=%d elapsed=%.3f s' % (N, ok, time.time()-t0))
s.close()
