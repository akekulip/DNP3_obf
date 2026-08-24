#!/usr/bin/env python3
"""relay_read_g10_23.py -- READ-ONLY: intended 23-point Group 10 V2 READ to the SEL-751.

Phase 2 of the hardware run: does the relay natively produce a 49-byte TCP payload for a
G10V2 binary-output-status read of points 0..22? Sends only function 0x01 (READ), asserted.
master=1, outstation=0, bind 192.168.10.1 -> 192.168.10.7:20000. Reports wire size, parsed
group/var/qualifier/range/count, and whether all 23 points came back in one frame.
"""
import socket, sys, json

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"
START, STOP = 0, 22  # 23 points

def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8): c = (c >> 1) ^ 0xA6BC if (c & 1) else (c >> 1)
    return (c ^ 0xFFFF) & 0xFFFF
def cle(d): x = crc(d); return bytes([x & 0xFF, (x >> 8) & 0xFF])

def read_frame(seq):
    # func 0x01 READ, obj G10(0x0A) var2, qualifier 0x00 (1-byte start/stop), range START..STOP
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x01, 0x0A, 0x02, 0x00, START, STOP])
    assert app[2] == 0x01, "REFUSING: not a READ"
    hdr = bytes([0x05, 0x64, 5 + len(app), 0xC4, 0x00, 0x00, 0x01, 0x00])
    f = bytearray(hdr + cle(hdr))
    for i in range(0, len(app), 16):
        blk = app[i:i+16]; f += blk + cle(blk)
    return bytes(f)

def deframe(buf):
    frames = []
    i = 0
    while i + 10 <= len(buf):
        if buf[i] != 0x05 or buf[i+1] != 0x64: i += 1; continue
        ulen = buf[i+2] - 5; nblk = (ulen + 15)//16 if ulen > 0 else 0
        total = 10 + ulen + 2*nblk
        if i + total > len(buf): break
        u = bytearray(); p = i + 10; rem = ulen
        while rem > 0:
            t = min(16, rem); u += buf[p:p+t]; p += t + 2; rem -= t
        frames.append((total, bytes(u))); i += total
    return frames

def poll(s, seq):
    s.sendall(read_frame(seq)); s.settimeout(2.0); buf = b""
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            buf += d
            if len(buf) > 8 and len(d) < 4096: break
    except socket.timeout: pass
    return buf

def analyze(buf):
    frames = deframe(buf)
    r = {"wire_bytes": len(buf), "n_link_frames": len(frames)}
    if frames:
        total, user = frames[0]
        app = user[1:]
        r["link_frame_bytes"] = total
        r["app_func"] = f"0x{app[1]:02x}" if len(app) > 1 else "?"
        r["iin"] = app[2:4].hex() if len(app) >= 4 else "?"
        o = app[4:]
        if len(o) >= 5:
            r["obj_group"], r["obj_var"], r["qual"] = o[0], o[1], f"0x{o[2]:02x}"
            r["range"] = [o[3], o[4]] if (o[2] & 0x0F) == 0 else "?"
            r["count"] = (o[4]-o[3]+1) if (o[2] & 0x0F) == 0 else "?"
    r["coalesced_frames_in_one_tcp"] = len(frames) > 1
    return r

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 11
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try: s.bind((SRC_IP, 40000))
    except OSError: pass
    s.settimeout(5.0); s.connect((RELAY_IP, RELAY_PORT))
    print(f"connected {SRC_IP} -> {RELAY_IP}:{RELAY_PORT} (READ-only G10V2 pts {START}..{STOP})")
    sizes = []
    for i in range(n):
        buf = poll(s, i)
        a = analyze(buf); sizes.append(a["wire_bytes"])
        tag = "INSPECT" if i == 0 else f"poll{i}"
        if i == 0:
            print(f"[{tag}] {json.dumps(a)}")
        else:
            print(f"[{tag}] wire={a['wire_bytes']}B group={a.get('obj_group')} var={a.get('obj_var')} count={a.get('count')}")
    s.close()
    uniq = sorted(set(sizes))
    print(f"\nSIZES over {n}: {sizes}")
    print(f"UNIQUE: {uniq}  -> {'STABLE 49B' if uniq==[49] else 'NOT all 49B'}")

if __name__ == "__main__":
    main()
