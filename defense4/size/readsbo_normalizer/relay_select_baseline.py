#!/usr/bin/env python3
"""relay_select_baseline.py -- SELECT-ONLY SBO baseline on the SEL-751 (NON-ACTUATING).

Sends exactly ONE DNP3 SELECT (function 0x03) for a G12V1 CROB on output point 0, to
capture the real select-echo size/structure for the READ<->SBO proof. A SELECT only
ARMS the select buffer (IEEE 1815 s4.4.4) and clears on timeout; ONLY an OPERATE (0x04)
or DirectOperate (0x05) actuates. This program contains NO OPERATE/DirectOperate code
path -- it cannot actuate. It reads point 0 before and after to prove it stayed OPEN.

master=1, outstation=0. Bind 192.168.10.1 -> relay 192.168.10.7:20000.
"""
import socket, sys

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"
POINT = 0                       # even -> OUT_REAL, per the point convention

def crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFF) & 0xFFFF
def _crc_le(d): c = crc_dnp(d); return bytes([c & 0xFF, (c >> 8) & 0xFF])

def frame(app: bytes) -> bytes:
    ln = 5 + len(app)
    hdr = bytes([0x05, 0x64, ln, 0xC4, 0x00, 0x00, 0x01, 0x00])   # DEST=0, SRC=1
    f = bytearray(hdr + _crc_le(hdr))
    for i in range(0, len(app), 16):
        blk = app[i:i+16]; f += blk + _crc_le(blk)
    return bytes(f)

def read_g10_point0(seq):
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x01, 0x0A, 0x00, 0x06])  # READ G10 all
    assert app[2] == 0x01
    return frame(app)

def select_crob_point0(seq):
    """SELECT (func 0x03) a G12V1 CROB PULSE_ON, count 1, on=200ms, index=0."""
    crob = bytes([0x01, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # PULSE_ON,cnt1,on200,off0,status0
    obj = bytes([0x0C, 0x01, 0x17, 0x01, POINT]) + crob                                # G12V1, qual 0x17 (cnt+idx), cnt1, idx0
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x03]) + obj                               # FUNC=0x03 SELECT
    assert app[2] == 0x03, "refusing: not a SELECT"
    assert app[2] not in (0x04, 0x05), "refusing: OPERATE/DirectOperate must never be sent here"
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

def txn(sock, fr, label):
    sock.sendall(fr); sock.settimeout(2.0); buf = b""
    try:
        while True:
            d = sock.recv(4096)
            if not d: break
            buf += d
            if len(buf) > 8 and len(d) < 4096: break
    except socket.timeout: pass
    app = b"".join(u[1:] for u in deframe(buf))
    return buf, app

def point0_state(app):
    # G10 var2 response: skip app hdr(4), obj hdr 0A 00 00 <start><stop>, then 1 octet/point
    o = app[4:]
    if len(o) >= 5 and o[0] == 0x0A:
        start = o[3]; data = o[5:]
        idx = POINT - start
        if 0 <= idx < len(data):
            return 1 if (data[idx] & 0x80) else 0
    return None

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try: s.bind((SRC_IP, 0))
    except OSError: pass
    s.settimeout(5.0)
    s.connect((RELAY_IP, RELAY_PORT))
    print(f"connected {SRC_IP} -> {RELAY_IP}:{RELAY_PORT}  (SELECT-only, NON-ACTUATING; master=1 outstation=0)")

    _, a0 = txn(s, read_g10_point0(1), "before")
    before = point0_state(a0)
    print(f"BEFORE: output point {POINT} = {'CLOSED' if before==1 else 'OPEN' if before==0 else '?'}")

    app_req, fr = select_crob_point0(2)
    buf, echo = txn(s, fr, "select")
    print(f"SELECT sent ({len(app_req)} B APDU, func 0x03).  SELECT echo: {len(buf)} B on-wire.")
    if len(echo) >= 4:
        func = echo[1]; iin = echo[2:4]
        status = echo[-1] if len(echo) > 4 else None
        print(f"  echo app func=0x{func:02x} IIN={iin.hex()}  first_obj_group=0x{echo[4]:02x}"
              f"  CROB_status=0x{status:02x}" if status is not None else "")
        print(f"  echo hex: {echo.hex()}")

    _, a1 = txn(s, read_g10_point0(3), "after")
    after = point0_state(a1)
    print(f"AFTER : output point {POINT} = {'CLOSED' if after==1 else 'OPEN' if after==0 else '?'}")
    print(f"\nRESULT: SELECT-only complete. Actuation: {'NONE (point stayed OPEN)' if after==0 else 'POINT CHANGED -- INVESTIGATE'}. "
          f"No OPERATE was sent.")
    s.close()

if __name__ == "__main__":
    main()
