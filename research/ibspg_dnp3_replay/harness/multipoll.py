#!/usr/bin/env python3
"""N read-only Class-0 polls on one connection, incrementing the DNP3 app sequence per poll.
SAFETY: only READ (func 1) frames; app control masked to 0xC0|seq, func byte asserted ==1."""
import socket, sys, time
sys.path.insert(0,'/tmp'); from dnp3_crc import append_crc
src_ip, dst_ip, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
def read_frame(appseq):
    data = bytes([0xc0, 0xc0 | (appseq & 0x0f), 0x01, 0x1e,0x03,0x01,0x01,0x00,0x07,0x00])
    assert data[2] == 0x01, "refusing: not READ"
    hdr = bytes([0x05,0x64,0x0f,0xc4, 0x00,0x00, 0x01,0x00])
    return append_crc(hdr) + append_crc(data)
s=socket.socket(); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
s.bind((src_ip,0)); s.settimeout(3.0); s.connect((dst_ip,20000))
for i in range(n):
    s.sendall(read_frame(i))
    t=time.monotonic(); got=b""
    try:
        while len(got)<4: 
            d=s.recv(256)
            if not d: break
            got+=d
    except socket.timeout: pass
    print("poll %d appseq=%d rx=%dB rtt=%.2fms resp_func=0x%02x" % (i, i, len(got), (time.monotonic()-t)*1000, got[12] if len(got)>12 else 0))
    time.sleep(0.3)
s.close()
