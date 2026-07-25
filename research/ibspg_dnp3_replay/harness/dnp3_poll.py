#!/usr/bin/env python3
"""Single no-retry read-only DNP3 poll of the relay from a pinned source IP.

SAFETY: sends ONE captured Class-0 READ (function code 1) and nothing else. No WRITE, no control,
no SBO, no restart, no retry, no second connect. Read-only by construction — the only bytes
transmitted are the READ payload passed in.
"""
import socket, sys, time
src_ip = sys.argv[1]; dst_ip = sys.argv[2]; read_hex = sys.argv[3]
payload = bytes.fromhex(read_hex)
assert payload[:2] == b"\x05\x64", "not a DNP3 link frame"
assert payload[12] == 0x01, "refusing: application function code is not READ(1)"   # link10+tp1+appctl1 -> func at 12
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.bind((src_ip, 0))
t0 = time.monotonic()
try:
    s.connect((dst_ip, 20000))
except Exception as e:
    print("CONNECT_FAILED %s" % e); sys.exit(1)
tcon = time.monotonic()
local = s.getsockname()
print("CONNECTED from %s:%d in %.3f ms" % (local[0], local[1], (tcon-t0)*1000))
s.sendall(payload)
print("SENT %d-byte READ" % len(payload))
s.settimeout(4.0)
got = b""
fin = False
try:
    while len(got) < 512:
        d = s.recv(512)
        if not d:
            fin = True; break
        got += d
        if len(got) >= 4:
            break
except socket.timeout:
    pass
trx = time.monotonic()
print("RESULT bytes_rx=%d fin_before_data=%s elapsed_ms=%.3f" % (len(got), fin, (trx-tcon)*1000))
if got:
    print("  RESPONSE hex (first 64B): %s" % got[:64].hex())
    print("  starts 0x0564 = valid DNP3 response: %s" % (got[:2]==b'\x05\x64'))
else:
    print("  NO DNP3 BYTES — relay closed or stayed silent")
s.close()
