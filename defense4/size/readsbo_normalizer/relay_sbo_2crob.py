#!/usr/bin/env python3
"""relay_sbo_2crob.py -- 2-CROB SBO SELECT-only (NON-ACTUATING): real(even) + decoy(odd).

Captures the real+decoy dual-CROB select echo for the proof: one CROB to even point 0
(OUT_REAL) and one to odd point 1 (OUT_DECOY), in a single G12V1 object (count 2). SELECT
only arms; no OPERATE code path here, so nothing actuates. Reads points 0 and 1 before and
after to prove both stayed OPEN. master=1, outstation=0.
"""
import socket

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"
REAL, DECOY = 0, 1

def crc_dnp(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8): crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFF) & 0xFFFF
def _crc_le(d): c = crc_dnp(d); return bytes([c & 0xFF, (c >> 8) & 0xFF])
def frame(app):
    hdr = bytes([0x05, 0x64, 5 + len(app), 0xC4, 0x00, 0x00, 0x01, 0x00])
    f = bytearray(hdr + _crc_le(hdr))
    for i in range(0, len(app), 16):
        blk = app[i:i+16]; f += blk + _crc_le(blk)
    return bytes(f)
def read_g10(seq):
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x01, 0x0A, 0x00, 0x06]); assert app[2] == 0x01
    return frame(app)
def _crob(): return bytes([0x01, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # PULSE_ON on200
def select_2crob(seq):
    # G12V1, qual 0x17 (1-byte count + 1-byte index prefix), count 2: [idxREAL][crob][idxDECOY][crob]
    obj = bytes([0x0C, 0x01, 0x17, 0x02, REAL]) + _crob() + bytes([DECOY]) + _crob()
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x03]) + obj
    assert app[2] == 0x03 and app[2] not in (0x04, 0x05), "SELECT-only"
    return app, frame(app)
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
        yield bytes(u); i += total
def txn(sock, fr):
    sock.sendall(fr); sock.settimeout(2.0); buf = b""
    try:
        while True:
            d = sock.recv(4096)
            if not d: break
            buf += d
            if len(buf) > 8 and len(d) < 4096: break
    except socket.timeout: pass
    return buf, b"".join(u[1:] for u in deframe(buf))
def states(app):
    o = app[4:]; out = {}
    if len(o) >= 5 and o[0] == 0x0A:
        start = o[3]; data = o[5:]
        for pt in (REAL, DECOY):
            idx = pt - start
            out[pt] = (1 if (data[idx] & 0x80) else 0) if 0 <= idx < len(data) else None
    return out

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try: s.bind((SRC_IP, 0))
    except OSError: pass
    s.settimeout(5.0); s.connect((RELAY_IP, RELAY_PORT))
    print(f"connected {SRC_IP} -> {RELAY_IP}:{RELAY_PORT}  (2-CROB SELECT-only, NON-ACTUATING)")
    _, a0 = txn(s, read_g10(1)); b = states(a0)
    print(f"BEFORE: real(pt{REAL})={'CLOSED' if b.get(REAL)==1 else 'OPEN'}  decoy(pt{DECOY})={'CLOSED' if b.get(DECOY)==1 else 'OPEN'}")
    app_req, fr = select_2crob(2); buf, echo = txn(s, fr)
    print(f"2-CROB SELECT sent ({len(app_req)}B APDU).  select echo: {len(buf)}B on-wire")
    if len(echo) >= 4:
        st = echo[-1]
        print(f"  echo func=0x{echo[1]:02x} IIN={echo[2:4].hex()} first_obj_group=0x{echo[4]:02x} last_status=0x{st:02x}")
        print(f"  echo hex: {echo.hex()}")
    _, a1 = txn(s, read_g10(3)); af = states(a1)
    print(f"AFTER : real(pt{REAL})={'CLOSED' if af.get(REAL)==1 else 'OPEN'}  decoy(pt{DECOY})={'CLOSED' if af.get(DECOY)==1 else 'OPEN'}")
    print(f"\nRESULT: 2-CROB SELECT-only. Actuation: {'NONE (both OPEN)' if af.get(REAL)==0 and af.get(DECOY)==0 else 'CHANGED -- INVESTIGATE'}. No OPERATE sent.")
    s.close()

if __name__ == "__main__":
    main()
