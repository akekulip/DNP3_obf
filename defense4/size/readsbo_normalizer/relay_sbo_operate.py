#!/usr/bin/env python3
"""relay_sbo_operate.py -- AUTHORIZED single SBO actuation of SEL-751 output point 0.

Philip authorized 2026-08-12: "operate it, point 0 is safe."
Runs ONE Select-Before-Operate to output point 0 with a G12V1 CROB PULSE_ON, on-time
200 ms (momentary, self-restoring). Captures the select echo AND the operate echo (the
full native SBO baseline), then reads point 0 back and, if it did not self-restore to
OPEN, issues a LATCH_OFF to restore it. master=1, outstation=0.

Control model: PULSE_ON (op-type 0x01), count 1, on 200 ms, off 0. The point self-releases
after the pulse. Exactly one OPERATE (func 0x04) is sent.
"""
import socket, sys, time

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"
POINT = 0

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
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x01, 0x0A, 0x00, 0x06])
    assert app[2] == 0x01
    return frame(app)

def crob_obj(optype):
    crob = bytes([optype & 0x0F, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # cnt1, on200, off0, status0
    return bytes([0x0C, 0x01, 0x17, 0x01, POINT]) + crob

def sbo_frame(func, seq, optype=0x01):
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), func]) + crob_obj(optype)
    assert func in (0x03, 0x04), "only SELECT(3)/OPERATE(4) here"
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

def status_of(echo):
    return echo[-1] if len(echo) > 4 else None

def point0(app):
    o = app[4:]
    if len(o) >= 5 and o[0] == 0x0A:
        start = o[3]; data = o[5:]; idx = POINT - start
        if 0 <= idx < len(data): return 1 if (data[idx] & 0x80) else 0
    return None

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try: s.bind((SRC_IP, 0))
    except OSError: pass
    s.settimeout(5.0); s.connect((RELAY_IP, RELAY_PORT))
    print(f"connected {SRC_IP} -> {RELAY_IP}:{RELAY_PORT}  (AUTHORIZED single SBO; master=1 outstation=0)")

    _, a0 = txn(s, read_g10(1)); print(f"BEFORE: point {POINT} = {'CLOSED' if point0(a0)==1 else 'OPEN'}")

    bsel, esel = txn(s, sbo_frame(0x03, 2))       # SELECT
    print(f"SELECT echo {len(bsel)}B  status=0x{status_of(esel):02x}  hex={esel.hex()}")
    if status_of(esel) != 0x00:
        print("SELECT not SUCCESS -> aborting, NOT sending OPERATE."); s.close(); return

    bop, eop = txn(s, sbo_frame(0x04, 3))         # OPERATE  <-- the single authorized actuation
    print(f"OPERATE echo {len(bop)}B  status=0x{status_of(eop):02x}  hex={eop.hex()}")

    time.sleep(0.6)                                # let the 200ms pulse complete
    _, a1 = txn(s, read_g10(4)); after = point0(a1)
    print(f"AFTER : point {POINT} = {'CLOSED' if after==1 else 'OPEN'}")

    if after == 1:                                 # did not self-restore -> LATCH_OFF to restore
        print("point did not self-restore -> sending SBO LATCH_OFF to restore OPEN")
        txn(s, sbo_frame(0x03, 5, optype=0x04)); txn(s, sbo_frame(0x04, 6, optype=0x04))
        time.sleep(0.3); _, a2 = txn(s, read_g10(7))
        print(f"RESTORE: point {POINT} = {'CLOSED (STILL!)' if point0(a2)==1 else 'OPEN'}")

    print(f"\nNATIVE SBO baseline: SELECT echo {len(bsel)}B + OPERATE echo {len(bop)}B, G12V1 CROB.")
    s.close()

if __name__ == "__main__":
    main()
