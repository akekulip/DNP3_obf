"""One campaign block: N polls on ONE connection, with a capture, then parse the
capture into per-transaction wire rows. The WIRE is where a passive observer sits, so
the concealment measurement comes from here and not from the switch."""
import binascii, json, os, re, socket, subprocess, sys, time

LABEL = sys.argv[1]; N = int(sys.argv[2]); GAP = float(sys.argv[3])
FRAMES = [binascii.unhexlify(h) for h in ["05640bc4000001002aecc0c0013c0106ff50", "05640bc4000001002aecc0c1013c0106f973", "05640bc4000001002aecc0c2013c0106f316", "05640bc4000001002aecc0c3013c0106f535", "05640bc4000001002aecc0c4013c0106e7dc", "05640bc4000001002aecc0c5013c0106e1ff", "05640bc4000001002aecc0c6013c0106eb9a", "05640bc4000001002aecc0c7013c0106edb9", "05640bc4000001002aecc0c8013c0106b605", "05640bc4000001002aecc0c9013c0106b026", "05640bc4000001002aecc0ca013c0106ba43", "05640bc4000001002aecc0cb013c0106bc60", "05640bc4000001002aecc0cc013c0106ae89", "05640bc4000001002aecc0cd013c0106a8aa", "05640bc4000001002aecc0ce013c0106a2cf", "05640bc4000001002aecc0cf013c0106a4ec"]]
PC = os.path.expanduser("~/d3phys/blk_%s.pcap" % LABEL)
if os.path.exists(PC):
    os.remove(PC)
dc = subprocess.Popen(["dumpcap", "-i", "enp59s0f0np0", "-f", "host 192.168.10.7",
                       "-w", PC, "-q"], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL)
time.sleep(2.0)
res = {"label": LABEL, "attempted": 0, "sent": 0, "responded": 0, "errors": []}
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(8); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
try:
    s.bind(("192.168.10.1", 0)); s.connect(("192.168.10.7", 20000))
    res["local_port"] = s.getsockname()[1]
    time.sleep(0.6)                      # let the data plane learn the session
    for i in range(N):
        res["attempted"] += 1            # ATTEMPTED, counted before anything can fail
        try:
            s.sendall(FRAMES[i % 16]); res["sent"] += 1
            s.settimeout(4.0); got = s.recv(4096)
            if got:
                res["responded"] += 1
            else:
                res["errors"].append("poll %d: peer closed" % i); break
        except Exception as e:
            res["errors"].append("poll %d: %r" % (i, e)); break
        time.sleep(GAP)
except Exception as e:
    res["errors"].append("setup: %r" % (e,))
finally:
    try: s.close()
    except Exception: pass
time.sleep(1.0); dc.terminate(); time.sleep(1.5)

# ---- parse the capture: READ (master, len 18) / relay pure ACK / relay RESPONSE ----
txt = subprocess.run(["tcpdump", "-r", PC, "-nn", "-tt"], capture_output=True,
                     text=True).stdout.splitlines()
RE = re.compile(r"^(\d+\.\d+) IP (\S+?)\.(\d+) > (\S+?)\.(\d+): Flags \[([^\]]*)\],"
                r".*?length (\d+)")
ev = []
for ln in txt:
    m = RE.match(ln)
    if not m:
        continue
    t, sip, sp, dip, dp, fl, ln_ = m.groups()
    ev.append({"t": float(t), "from_relay": sip == "192.168.10.7",
               "flags": fl, "len": int(ln_)})
rows, cur = [], None
for e in ev:
    if not e["from_relay"] and e["len"] == 18:            # a READ
        if cur: rows.append(cur)
        cur = {"t_read": e["t"], "t_ack": None, "t_resp": None}
    elif cur and e["from_relay"] and e["len"] == 0 and e["flags"] == ".":
        if cur["t_ack"] is None: cur["t_ack"] = e["t"]     # the separate pure ACK
    elif cur and e["from_relay"] and e["len"] > 0:
        if cur["t_resp"] is None: cur["t_resp"] = e["t"]   # the DNP3 RESPONSE
if cur: rows.append(cur)
for r in rows:
    r["read_to_ack_ms"] = None if r["t_ack"] is None else (r["t_ack"]-r["t_read"])*1e3
    r["clrt_ms"] = (None if (r["t_ack"] is None or r["t_resp"] is None)
                    else (r["t_resp"]-r["t_ack"])*1e3)
    r["read_to_resp_ms"] = None if r["t_resp"] is None else (r["t_resp"]-r["t_read"])*1e3
    r["ack_before_resp"] = (None if (r["t_ack"] is None or r["t_resp"] is None)
                            else r["t_ack"] <= r["t_resp"])
res["rows"] = rows
res["pcap"] = PC
print("BLOCK " + json.dumps(res, default=str))
