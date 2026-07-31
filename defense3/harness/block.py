"""One campaign block: N polls on ONE connection, with a capture, then parse the
capture into per-transaction wire rows. The WIRE is where a passive observer sits, so
the concealment measurement comes from here and not from the switch.

CORRECTIONS.md §4.4/§5.2 hardening (still a single-connection laboratory reconstructor,
not a general publication-grade one, but no longer silently permissive):
  - the capture interface and endpoints are configuration, not hardcoded literals;
  - dumpcap is verified to have STARTED (pcap file grows) before any poll is sent;
  - the capture is FLUSHED with terminate()+wait() before it is read;
  - rows are bound to THIS connection's TCP 4-tuple (our ephemeral local port), so
    keepalives on an idle socket and any unrelated relay session are excluded;
  - ordering uses a STRICT inequality and equal software timestamps are flagged
    inconclusive rather than counted as ordered;
  - the response's TCP segment length is recorded so a multi-segment response (only the
    first segment of which is timed here) is visible rather than assumed complete.
"""
import binascii, json, os, re, socket, subprocess, sys, time

LABEL = sys.argv[1]; N = int(sys.argv[2]); GAP = float(sys.argv[3])
IFACE = os.environ.get("D3_IFACE", "enp59s0f0np0")
RELAY_IP = os.environ.get("D3_RELAY_IP", "192.168.10.7")
MASTER_IP = os.environ.get("D3_MASTER_IP", "192.168.10.1")
DNP3_PORT = int(os.environ.get("D3_DNP3_PORT", "20000"))
FRAMES = [binascii.unhexlify(h) for h in ["05640bc4000001002aecc0c0013c0106ff50", "05640bc4000001002aecc0c1013c0106f973", "05640bc4000001002aecc0c2013c0106f316", "05640bc4000001002aecc0c3013c0106f535", "05640bc4000001002aecc0c4013c0106e7dc", "05640bc4000001002aecc0c5013c0106e1ff", "05640bc4000001002aecc0c6013c0106eb9a", "05640bc4000001002aecc0c7013c0106edb9", "05640bc4000001002aecc0c8013c0106b605", "05640bc4000001002aecc0c9013c0106b026", "05640bc4000001002aecc0ca013c0106ba43", "05640bc4000001002aecc0cb013c0106bc60", "05640bc4000001002aecc0cc013c0106ae89", "05640bc4000001002aecc0cd013c0106a8aa", "05640bc4000001002aecc0ce013c0106a2cf", "05640bc4000001002aecc0cf013c0106a4ec"]]
PC = os.path.expanduser("~/d3phys/blk_%s.pcap" % LABEL)
if os.path.exists(PC):
    os.remove(PC)

res = {"label": LABEL, "attempted": 0, "sent": 0, "responded": 0, "errors": [],
       "capture_ok": False}

# ---- start the capture and VERIFY it actually started (CORRECTIONS §4.4) --------------
dc = subprocess.Popen(["dumpcap", "-i", IFACE, "-f", "host %s" % RELAY_IP,
                       "-w", PC, "-q"], stdout=subprocess.DEVNULL,
                      stderr=subprocess.PIPE)
# dumpcap creates the file within ~1-2 s once it is capturing; poll for it.
for _ in range(30):
    time.sleep(0.1)
    if dc.poll() is not None:            # dumpcap exited early = failure
        err = (dc.stderr.read() or b"").decode(errors="replace")[:200] if dc.stderr else ""
        res["errors"].append("dumpcap exited early: %s" % err)
        break
    if os.path.exists(PC):
        res["capture_ok"] = True
        break
if not res["capture_ok"]:
    res["errors"].append("dumpcap did not start (no pcap on %s)" % IFACE)
    print("BLOCK " + json.dumps(res, default=str))
    sys.exit(2)                          # fail closed: no capture -> invalid block
time.sleep(1.0)                          # let it settle before the first poll

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(8); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
try:
    s.bind((MASTER_IP, 0)); s.connect((RELAY_IP, DNP3_PORT))
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

# ---- flush the capture: terminate then WAIT (CORRECTIONS §4.4) ------------------------
time.sleep(1.0)
dc.terminate()
try:
    dc.wait(timeout=5)
except Exception:
    dc.kill()

LOCAL_PORT = res.get("local_port")

# ---- parse: bind to OUR 4-tuple; -S for absolute seq so multi-segment is visible ------
txt = subprocess.run(["tcpdump", "-r", PC, "-nn", "-tt", "-S"],
                     capture_output=True, text=True).stdout.splitlines()
RE = re.compile(r"^(\d+\.\d+) IP (\S+?)\.(\d+) > (\S+?)\.(\d+): Flags \[([^\]]*)\],"
                r".*?length (\d+)")
ev = []
for ln in txt:
    m = RE.match(ln)
    if not m:
        continue
    t, sip, sp, dip, dp, fl, ln_ = m.groups()
    sp, dp, ln_ = int(sp), int(dp), int(ln_)
    from_relay = (sip == RELAY_IP and sp == DNP3_PORT)
    from_master = (sip == MASTER_IP and dp == DNP3_PORT)
    # bind to THIS connection: our ephemeral port on the master side, DNP3 port on the
    # relay side. Anything else (other sessions, keepalives on a different socket) drops.
    if LOCAL_PORT is not None:
        if from_master and sp != LOCAL_PORT:
            continue
        if from_relay and dp != LOCAL_PORT:
            continue
    if not (from_relay or from_master):
        continue
    ev.append({"t": float(t), "from_relay": from_relay, "flags": fl, "len": ln_})

rows, cur = [], None
for e in ev:
    if (not e["from_relay"]) and e["len"] == 18:            # a READ from the master
        if cur: rows.append(cur)
        cur = {"t_read": e["t"], "t_ack": None, "t_resp": None, "resp_len": None}
    elif cur and e["from_relay"] and e["len"] == 0 and e["flags"] in (".", "P."):
        # the separate pure ACK. On an actively-polled socket the first pure ACK after a
        # READ and before the RESPONSE is the response's TCP ACK, not a keepalive (a
        # keepalive only fires on an idle socket, which this is not between READ and RESP).
        if cur["t_ack"] is None and cur["t_resp"] is None:
            cur["t_ack"] = e["t"]
    elif cur and e["from_relay"] and e["len"] > 0:
        if cur["t_resp"] is None:
            cur["t_resp"] = e["t"]; cur["resp_len"] = e["len"]   # FIRST DNP3 segment
if cur: rows.append(cur)

for r in rows:
    r["read_to_ack_ms"] = None if r["t_ack"] is None else (r["t_ack"]-r["t_read"])*1e3
    r["clrt_ms"] = (None if (r["t_ack"] is None or r["t_resp"] is None)
                    else (r["t_resp"]-r["t_ack"])*1e3)
    r["read_to_resp_ms"] = None if r["t_resp"] is None else (r["t_resp"]-r["t_read"])*1e3
    if r["t_ack"] is None or r["t_resp"] is None:
        r["ack_before_resp"] = None
        r["order_inconclusive"] = None
    else:
        # STRICT inequality; equal software timestamps do NOT prove order (CORRECTIONS §5.2)
        r["ack_before_resp"] = r["t_ack"] < r["t_resp"]
        r["order_inconclusive"] = (r["t_ack"] == r["t_resp"])
res["rows"] = rows
res["pcap"] = PC
print("BLOCK " + json.dumps(res, default=str))
