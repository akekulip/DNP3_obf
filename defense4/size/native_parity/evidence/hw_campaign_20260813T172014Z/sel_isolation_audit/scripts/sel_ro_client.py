#!/usr/bin/env python3
"""READ-ONLY SEL ASCII client (telnet 23). SAFETY: caps at Access Level 1.
Refuses to send any Level-2 / control / setting-change command. Whitelist only.
Never sends: SET, CON, OPE(N), CLO(SE), PUL, 2AC, BRE, TRIG-that-writes, DAT/TIM w/ args.
Usage: sel_ro_client.py <L1_password> <cmd1> [cmd2 ...]
Prints raw framed output per command."""
import socket, sys, time, re

HOST, PORT = "192.168.10.7", 23
# Hard read-only whitelist (first token, upper). ACC = raise to L1 (read priv only).
ALLOWED = {"ID","STA","STATUS","SHO","SHOW","TAR","TARGET","MET","METER","HIS","HISTORY",
           "EVE","EVENT","DNP","PORT","SER","QUI","QUIT","ACC"}
# Absolutely barred (actuation / write / L2):
BARRED = {"SET","CON","CONTROL","OPE","OPEN","CLO","CLOSE","PUL","PULSE","2AC","BAC","CAL",
          "BRE","BREAKER","COP","PAS","PASSWORD","R_S","L_D","DAT","TIM","CLK"}

def barred(cmd):
    t = cmd.strip().upper().split()[0] if cmd.strip() else ""
    if t in BARRED: return t
    if t and t not in ALLOWED: return t   # default-deny anything unknown
    return None

def negotiate(sock, data):
    """Respond to telnet IAC: refuse all options (DONT/WONT). Return stripped payload."""
    out=bytearray(); i=0
    while i < len(data):
        if data[i]==0xff and i+2 < len(data):
            cmd=data[i+1]; opt=data[i+2]
            if cmd in (0xfb,0xfc):      # WILL/WONT -> DONT
                sock.sendall(bytes([0xff,0xfe,opt]))
            elif cmd in (0xfd,0xfe):    # DO/DONT -> WONT
                sock.sendall(bytes([0xff,0xfc,opt]))
            i+=3
        elif data[i]==0xff and i+1<len(data) and data[i+1]==0xff:
            out.append(0xff); i+=2
        else:
            out.append(data[i]); i+=1
    return bytes(out)

def rd(sock, t=3.0):
    sock.settimeout(t); raw=b""
    try:
        while True:
            b=sock.recv(4096)
            if not b: break
            raw+=b
            if b"=>" in raw or raw.rstrip().endswith(b"=") or b"Password" in raw or b"?" in raw[-3:]:
                # likely reached a prompt; small grace read then stop
                sock.settimeout(0.6)
    except socket.timeout:
        pass
    return raw

def clean(raw, sock):
    return negotiate(sock, raw)

pw = sys.argv[1]
cmds = sys.argv[2:]
s=socket.create_connection((HOST,PORT),timeout=8)
_=clean(rd(s,2.5),s)
s.sendall(b"\r\n"); _=clean(rd(s,2.0),s)

# Raise to Access Level 1
s.sendall(b"ACC\r\n")
r=clean(rd(s,2.5),s)
sys.stdout.write("### ACC ->\n"+r.decode('latin-1')+"\n")
if b"Password" in r or b"assword" in r or b"?" in r:
    s.sendall(pw.encode()+b"\r\n")
    r=clean(rd(s,3.0),s)
    sys.stdout.write("### PW ->\n"+r.decode('latin-1')+"\n")
level1 = b"=>" in r or b"=>" in r.replace(b"=>>",b"")
sys.stdout.write("### LEVEL1_PROMPT_SEEN=%s\n" % ("=>" in r.decode('latin-1')))

for c in cmds:
    b=barred(c)
    if b:
        sys.stdout.write("### REFUSED (not read-only whitelist): %r token=%s\n" % (c,b)); continue
    s.sendall(c.encode()+b"\r\n")
    time.sleep(0.4)
    r=clean(rd(s,4.0),s)
    sys.stdout.write("\n### CMD: %s\n" % c)
    sys.stdout.write(r.decode('latin-1'))
    sys.stdout.write("\n### END %s\n" % c)

s.sendall(b"QUI\r\n"); time.sleep(0.3)
s.close()
