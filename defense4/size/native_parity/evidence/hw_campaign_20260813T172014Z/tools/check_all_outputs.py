#!/usr/bin/env python3
"""check_all_outputs.py -- READ-ONLY: G10V2 read of binary output points 0..N-1 and decode
each status octet's ON/OFF (0x80) bit. Confirms ALL outputs are OPEN (bit clear). Sends only
DNP3 READ (func 0x01, asserted). NON-ACTUATING. master=1, outstation=0, 192.168.10.1->.7:20000."""
import socket, sys, json

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"
NPTS = int(sys.argv[1]) if len(sys.argv) > 1 else 32

def crc(d):
    c = 0
    for b in d:
        c ^= b
        for _ in range(8): c = (c >> 1) ^ 0xA6BC if (c & 1) else (c >> 1)
    return (c ^ 0xFFFF) & 0xFFFF
def cle(d): x = crc(d); return bytes([x & 0xFF, (x >> 8) & 0xFF])
def frame(app):
    hdr = bytes([0x05, 0x64, 5 + len(app), 0xC4, 0x00, 0x00, 0x01, 0x00])
    f = bytearray(hdr + cle(hdr))
    for i in range(0, len(app), 16):
        blk = app[i:i+16]; f += blk + cle(blk)
    return bytes(f)
def read_frame(seq, start, stop):
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x01, 0x0A, 0x02, 0x00, start, stop])
    assert app[2] == 0x01, "REFUSING: not a READ"
    return frame(app)
def deframe(buf):
    i = 0
    while i + 10 <= len(buf):
        if buf[i] != 0x05 or buf[i+1] != 0x64: i += 1; continue
        ulen = buf[i+2] - 5; nblk = (ulen + 15)//16 if ulen > 0 else 0
        total = 10 + ulen + 2*nblk
        if i + total > len(buf): break
        u = bytearray(); p = i + 10; rem = ulen
        while rem > 0:
            t = min(16, rem); u += buf[p:p+t]; p += t + 2; rem -= t
        return bytes(u)
    return b""
def txn(s, fr):
    s.sendall(fr); s.settimeout(2.0); buf = b""
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            buf += d
            if len(buf) > 8 and len(d) < 4096: break
    except socket.timeout: pass
    return deframe(buf)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind((SRC_IP, 0))
    except OSError: pass
    s.settimeout(5.0); s.connect((RELAY_IP, RELAY_PORT))
    u = txn(s, read_frame(1, 0, NPTS - 1))
    s.close()
    # user = [transport][app_ctrl][func][IIN1][IIN2][obj...]  -> objects start at u[5]
    o = u[5:]
    states = {}
    if len(o) >= 5 and o[0] == 0x0A:
        start = o[3]; data = o[5:]
        for i, b in enumerate(data):
            states[start + i] = "CLOSED" if (b & 0x80) else "OPEN"
    closed = [p for p, st in states.items() if st == "CLOSED"]
    print(json.dumps({"n_points": len(states), "all_open": len(closed) == 0,
                      "closed_points": closed, "states": states}))
    sys.exit(0 if (states and not closed) else 1)

if __name__ == "__main__":
    main()
