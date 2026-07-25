#!/usr/bin/env python3
"""READ-ONLY probe of the SEL-751 telnet interface, with minimal telnet negotiation.

SAFETY: only strings in ALLOWED can be transmitted. Nothing that changes relay state is in it.
"""
import socket, sys, time
ALLOWED = {"", "ACC", "ID", "STA", "SHO", "SHO P", "SHO 1", "QUI", "?"}
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
host, port = "192.168.10.7", 23
cmds = sys.argv[1:]
for c in cmds:
    if c not in ALLOWED:
        print("REFUSED (not in read-only allowlist): %r" % c); sys.exit(3)
s = socket.create_connection((host, port), timeout=6); s.settimeout(2.0)

def pump(sec=3.0):
    """Read, answering telnet negotiation with a flat refusal; return printable payload."""
    out, end = b"", time.time() + sec
    while time.time() < end:
        try:
            d = s.recv(4096)
        except socket.timeout:
            break
        if not d:
            break
        i, reply = 0, b""
        while i < len(d):
            if d[i] == IAC and i + 2 < len(d):
                cmd, opt = d[i+1], d[i+2]
                if cmd == DO:    reply += bytes([IAC, WONT, opt])
                elif cmd == WILL: reply += bytes([IAC, DONT, opt])
                i += 3
            elif d[i] == IAC and i + 1 < len(d) and d[i+1] == SB:
                j = d.find(bytes([IAC, SE]), i)
                i = (j + 2) if j > 0 else len(d)
            else:
                out += bytes([d[i]]); i += 1
        if reply:
            s.sendall(reply)
    return out

txt = pump(4.0)
print("--- after negotiation (%d printable bytes) ---" % len(txt))
print(txt.decode('ascii', 'replace')[-800:] or "(nothing)")
if not txt.strip():
    print("--- nudging with a bare CR ---")
    s.sendall(b"\r\n"); print(pump(3.0).decode('ascii','replace')[-800:] or "(still nothing)")
for c in cmds:
    print("\n--- sending %r (read-only) ---" % c)
    s.sendall((c + "\r\n").encode())
    print(pump(4.0).decode('ascii', 'replace')[-2000:] or "(no response)")
s.close()
