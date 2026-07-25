#!/usr/bin/env python3
"""Read-only DNP3 data-link address discovery via Request Link Status (function 9).

SAFETY: transmits ONLY Request-Link-Status frames (PRM=1, func=9), which are pure data-link
status queries an outstation answers for its own address. No RESET, no user data, no application
layer, no control. Refuses to build any other function code.
"""
import socket, sys, time
sys.path.insert(0, '/tmp')
from dnp3_crc import append_crc

def req_link_status(dst, src=1):
    ctl = 0xC9                      # DIR=1 PRM=1 FCB=0 FCV=0 func=9 (Request Link Status)
    assert (ctl & 0x0F) == 9, "refusing: not Request Link Status"
    return append_crc(bytes([0x05,0x64,0x05,ctl, dst&0xFF,(dst>>8)&0xFF, src&0xFF,(src>>8)&0xFF]))

src_ip, dst_ip = sys.argv[1], sys.argv[2]
addrs = [int(x) for x in sys.argv[3].split(',')]
s = socket.socket(); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.bind((src_ip, 0)); s.settimeout(2.5)
try:
    s.connect((dst_ip, 20000))
except Exception as e:
    print("CONNECT_FAILED %s" % e); sys.exit(1)
print("connected from %s" % (s.getsockname(),))
for a in addrs:
    f = req_link_status(a)
    s.sendall(f)
    time.sleep(0.05)
    got = b""
    try:
        got = s.recv(64)
    except socket.timeout:
        pass
    if got:
        ctl = got[3] if len(got) > 3 else 0
        fn = ctl & 0x0F
        print("  dst=%-4d -> REPLY %s  (link func=%d %s)" % (
            a, got[:12].hex(), fn,
            {11:'LINK_STATUS',0:'ACK',1:'NACK'}.get(fn,'?')))
    else:
        print("  dst=%-4d -> (silent)" % a)
s.close()
