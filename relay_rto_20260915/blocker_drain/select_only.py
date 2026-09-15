#!/usr/bin/env python3
'''Send one DNP3 SELECT and nothing else. SELECT arms; it does not actuate. No OPERATE is sent.'''
import socket, time
SELECT = bytes.fromhex('056424c4000001004a59c1c1030c011702010101c800000000007020000000030101c8000000000000000015ee')
s = socket.create_connection(('192.168.10.7', 20000), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); s.settimeout(3.0)
time.sleep(0.3)
s.send(SELECT)
got=b''
try:
    while len(got) < 40:
        c=s.recv(4096)
        if not c: break
        got+=c
except socket.timeout: pass
print('SELECT sent, response %d bytes: %s' % (len(got), got.hex()[:80]))
time.sleep(1.5); s.close()
