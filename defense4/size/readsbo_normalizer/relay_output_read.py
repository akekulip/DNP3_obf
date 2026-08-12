#!/usr/bin/env python3
"""relay_output_read.py -- READ-ONLY: report SEL-751 binary output/input states.

Sends only DNP3 Class-0 READ / static-group READ requests (application function 0x01),
asserted before every send. NO write, NO SELECT/OPERATE/DirectOperate, NO time sync,
NO restart, NO confirm-writes. Decodes Group 10 (Binary Output Status) and Group 1
(Binary Input) so we can see which outputs are open/closed and pick OUT_REAL/OUT_DECOY.

Link addressing: master=1, outstation=0 (verified on the wire). Bind 192.168.10.1 -> relay.
"""
import socket, sys

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"

def crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFF) & 0xFFFF

def _crc_le(d): c = crc_dnp(d); return bytes([c & 0xFF, (c >> 8) & 0xFF])

def build_read(obj_hdr: bytes, seq: int) -> bytes:
    """A DNP3 READ frame (function 0x01) carrying one object header."""
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x01]) + obj_hdr   # transport, app-ctrl, FUNC=READ, obj
    assert app[2] == 0x01, "REFUSING TO SEND: application function is not READ(1)"
    ln = 5 + len(app)
    hdr = bytes([0x05, 0x64, ln, 0xC4, 0x00, 0x00, 0x01, 0x00])   # LEN, CTRL, DEST=0, SRC=1
    frame = bytearray(hdr + _crc_le(hdr))
    for i in range(0, len(app), 16):
        blk = app[i:i+16]; frame += blk + _crc_le(blk)
    return bytes(frame)

def deframe(buf: bytes):
    """Yield the user bytes (transport+app) of every complete link frame in buf."""
    i = 0
    while i + 10 <= len(buf):
        if buf[i] != 0x05 or buf[i+1] != 0x64:
            i += 1; continue
        ln = buf[i+2]; ulen = ln - 5
        nblk = (ulen + 15)//16 if ulen > 0 else 0
        total = 10 + ulen + 2*nblk
        if i + total > len(buf): break
        user = bytearray()
        p = i + 10; rem = ulen
        while rem > 0:
            take = min(16, rem); user += buf[p:p+take]; p += take + 2; rem -= take
        yield bytes(user)
        i += total

def parse_static(app: bytes):
    """Parse a response application fragment; decode G1 and G10 point states."""
    if len(app) < 4: return None, None, []
    func = app[1]; iin = app[2:4]; o = app[4:]
    out = []
    k = 0
    while k + 3 <= len(o):
        group, var, qual = o[k], o[k+1], o[k+2]; k += 3
        rng = qual & 0x0F; pfx = (qual >> 4) & 0x07
        if rng == 0 and k+2 <= len(o):        # 1-octet start/stop
            start, stop = o[k], o[k+1]; k += 2; n = stop - start + 1
        elif rng == 1 and k+4 <= len(o):      # 2-octet start/stop
            start = o[k] | (o[k+1] << 8); stop = o[k+2] | (o[k+3] << 8); k += 4; n = stop - start + 1
        elif rng in (7, 8):                    # count
            if rng == 7: n = o[k]; k += 1
            else: n = o[k] | (o[k+1] << 8); k += 2
            start = 0
        else:
            out.append((group, var, qual, "unhandled-qualifier", [])); break
        pts = []
        if group in (1, 10) and var == 2:      # with-flags: 1 octet/point (+ optional prefix)
            for j in range(n):
                if pfx: k += pfx                # skip index prefix if present
                if k >= len(o): break
                octet = o[k]; k += 1
                pts.append((start + j, 1 if (octet & 0x80) else 0, octet & 0x01))
        elif group in (1, 10) and var == 1:    # packed: 1 bit/point
            nbytes = (n + 7)//8
            bits = o[k:k+nbytes]; k += nbytes
            for j in range(n):
                st = (bits[j//8] >> (j % 8)) & 1 if j//8 < len(bits) else 0
                pts.append((start + j, st, None))
        else:
            out.append((group, var, qual, f"group{group}var{var}-not-decoded(n={n})", [])); break
        out.append((group, var, qual, "ok", pts))
    return func, iin, out

def do_read(sock, label, obj_hdr, seq):
    sock.sendall(build_read(obj_hdr, seq))
    buf = b""
    sock.settimeout(2.0)
    try:
        while True:
            d = sock.recv(4096)
            if not d: break
            buf += d
            if len(buf) > 8 and len(d) < 4096: break
    except socket.timeout:
        pass
    print(f"\n=== {label}: rx {len(buf)} B ===")
    if not buf:
        print("  (no response)"); return
    app = b""
    for user in deframe(buf):
        app += user[1:]                        # strip 1 transport header byte per frame
    if len(app) < 4:
        print(f"  malformed/short app ({len(app)} B), raw head: {buf[:32].hex()}"); return
    func, iin, objs = parse_static(app)
    print(f"  app func=0x{func:02x}  IIN={iin.hex()}")
    for group, var, qual, status, pts in objs:
        gname = {1: "Binary Input (G1)", 10: "Binary Output Status (G10)"}.get(group, f"Group {group}")
        print(f"  {gname} var{var} qual0x{qual:02x}: {status}")
        for idx, st, online in pts:
            state = "CLOSED/ON " if st else "OPEN/OFF  "
            ol = "" if online is None else (" online" if online else " OFFLINE")
            print(f"     point {idx:>3}: {state}(bit={st}){ol}")

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try: s.bind((SRC_IP, 0))
    except OSError: pass
    s.settimeout(5.0)
    try:
        s.connect((RELAY_IP, RELAY_PORT))
    except Exception as e:
        sys.exit(f"FATAL: cannot connect {SRC_IP} -> {RELAY_IP}:{RELAY_PORT} ({e})")
    print(f"connected {SRC_IP} -> {RELAY_IP}:{RELAY_PORT}  (READ-only; master=1 outstation=0)")
    do_read(s, "Binary Output Status  READ G10 var0 all (0A 00 06)", bytes([0x0A, 0x00, 0x06]), 1)
    do_read(s, "Binary Input          READ G1  var0 all (01 00 06)", bytes([0x01, 0x00, 0x06]), 2)
    do_read(s, "Class-0 integrity     READ G60 var1     (3C 01 06)", bytes([0x3C, 0x01, 0x06]), 3)
    s.close()
    print("\nDONE (READ-only; no controls were ever transmitted).")

if __name__ == "__main__":
    main()
